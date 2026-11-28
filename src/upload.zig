//! Session-scoped packing and incremental file input
//!
//! One Xorb can span completed files. Calling `close` seals the input
//! stream. The last Xorb is then queued like every full one, so callers see all
//! Xorb storage through `next`.

const std = @import("std");
const module = @This();
const builtin = @import("builtin");
const dedup = @import("dedup.zig");
const hashing = @import("hash.zig");
const shard = @import("shard.zig");
const storage = @import("store.zig");

pub const FileId = usize;

pub const Options = struct {
    dedup_source: ?dedup.Source = null,
    /// Enables parallel hashing of large canonical writes.
    io: ?std.Io = null,
};

const Work = union(enum) {
    store: storage.Object,
    reference: struct {
        file_id: FileId,
        xorb_hash: hashing.Hash,
        chunk_index_start: u32,
        nodes: []const hashing.Node,
    },

    fn deinit(self: Work, allocator: std.mem.Allocator) void {
        switch (self) {
            .store => |object| allocator.free(object.data),
            .reference => |ref| allocator.free(ref.nodes),
        }
    }
};

/// Owns the payload and borrows its session. Complete or deinitialize exactly once.
pub const Operation = struct {
    work: Work,
    session: *Session,

    pub fn complete(self: *Operation) void {
        self.release(false);
    }

    /// Cancelling an issued operation prevents publication.
    pub fn deinit(self: *Operation) void {
        self.release(true);
    }

    fn release(self: *Operation, failed: bool) void {
        self.work.deinit(self.session.allocator);
        self.session.completeOperation(failed);
        self.* = undefined;
    }
};

const QueueNode = struct {
    gen: ?u64,
    work: Work,
};

/// Interleaves a completion between the two publication checks in a test
const test_hook = if (builtin.is_test) struct {
    const Hook = struct {
        context: *anyopaque,
        callback: *const fn (context: *anyopaque) void,
    };

    var finish: ?Hook = null;
} else struct {};

/// Planning and `next` are single-threaded; worker-thread completions free payloads on the allocator
pub const Session = struct {
    pub const File = module.File;
    pub const Operation = module.Operation;
    pub const Options = module.Options;
    pub const FileOptions = storage.PackOptions;
    pub const Result = storage.PublishResult;
    pub const Source = dedup.Source;
    pub const Match = dedup.Match;

    allocator: std.mem.Allocator,
    external_source: ?dedup.Source,
    index: dedup.SessionIndex,
    packing: storage.Packing,
    io: ?std.Io,
    queue: std.ArrayList(QueueNode) = .empty,
    queue_head: usize = 0,
    /// Bookkeeping only, so they do not make the allocator thread-safe
    in_flight: std.atomic.Value(usize) = .init(0),
    operation_failed: std.atomic.Value(bool) = .init(false),
    /// Set by a successful `close`, after which no file can begin
    closed: bool = false,
    active: ?u64 = null,
    next_id: u64 = 0,

    point_gen: ?u64 = null,
    point: ?dedup.SessionIndex.Checkpoint = null,

    /// The session and destination must remain at stable addresses while in use
    pub fn init(
        allocator: std.mem.Allocator,
        destination: storage.Store,
        opts: module.Options,
    ) Session {
        return .{
            .allocator = allocator,
            .external_source = opts.dedup_source,
            .index = .init(allocator),
            .packing = .init(allocator, storage.noStore(), destination, .lz4),
            .io = opts.io,
        };
    }

    /// Queued work is discarded; every issued operation must be completed first
    pub fn deinit(self: *Session) void {
        std.debug.assert(self.active == null);
        std.debug.assert(self.in_flight.load(.acquire) == 0);
        for (self.queue.items[self.queue_head..]) |node| {
            node.work.deinit(self.allocator);
        }
        self.queue.deinit(self.allocator);
        self.packing.deinit();
        self.index.deinit();
        self.* = undefined;
    }

    /// The file must remain at its initialized address until deinit
    pub fn beginFile(
        self: *Session,
        file: *module.File,
        file_id: FileId,
        opts: storage.PackOptions,
    ) !void {
        if (self.packing.batch.finished) return error.AlreadyFinished;
        if (self.closed) return error.InputClosed;
        if (self.operation_failed.load(
            .acquire,
        ) or self.packing.writer.lost) return error.OperationFailed;
        if (self.active != null) return error.ActiveFile;
        const id = self.next_id;
        self.next_id +%= 1;
        self.active = id;
        self.point_gen = id;
        self.point = self.index.checkpoint();
        var pub_opts = storage.PublisherOptions.fromPack(opts);
        pub_opts.dedup_source = self.source();
        pub_opts.io = self.io;
        // A writer listener cannot outlive the session's address, so install it here
        self.packing.writer.new_xorb_listener = .{ .context = self, .callback = addXorb };
        file.init(self, id, file_id, pub_opts) catch |err| {
            self.rollback(id);
            return err;
        };
    }

    pub fn addFile(
        self: *Session,
        file_id: FileId,
        input: []const u8,
        opts: storage.PackOptions,
    ) !storage.PublishResult {
        var file: module.File = undefined;
        try self.beginFile(&file, file_id, opts);
        defer file.deinit();
        try file.write(input);
        return file.finish();
    }

    /// Transfers one owned operation to the caller for immediate or async execution
    pub fn next(self: *Session) ?module.Operation {
        if (self.queue_head == self.queue.items.len) return null;
        const node = self.queue.items[self.queue_head];
        self.queue_head += 1;
        _ = self.in_flight.fetchAdd(1, .acq_rel);
        self.compact();
        return .{ .work = node.work, .session = self };
    }

    /// Ends input permanently, queuing the last Xorb only before any failure
    pub fn close(self: *Session) !void {
        if (self.closed) return;
        if (self.active != null) return error.ActiveFile;
        if (self.operation_failed.load(
            .acquire,
        ) or self.packing.writer.lost) return error.OperationFailed;
        if (self.packing.writer.count() == 0) {
            self.closed = true;
            return;
        }
        _ = self.packing.writer.installOperationListener(.{
            .context = self,
            .callback = enqueueFinal,
        });
        try self.packing.seal();
        self.closed = true;
    }

    /// Publication needs every issued operation drained and no Xorb left open
    pub fn finish(self: *Session) !void {
        if (self.active != null) return error.ActiveFile;
        if (self.operation_failed.load(
            .acquire,
        ) or self.packing.writer.lost) return error.OperationFailed;
        if (builtin.is_test) {
            // One-shot, so a retry never reuses a released operation
            if (test_hook.finish) |hook| {
                test_hook.finish = null;
                hook.callback(hook.context);
            }
        }
        if (self.pending() != 0) return error.PendingOperations;
        // A worker can record failure while the drain above observed zero
        if (self.operation_failed.load(
            .acquire,
        ) or self.packing.writer.lost) return error.OperationFailed;
        if (!self.closed) return error.InputOpen;
        return self.packing.publish();
    }

    pub fn pending(self: *const Session) usize {
        return self.queue.items.len - self.queue_head + self.in_flight.load(.acquire);
    }

    fn source(self: *Session) dedup.Source {
        return .{ .context = self, .query_fn = query };
    }

    fn query(
        raw: *anyopaque,
        allocator: std.mem.Allocator,
        hashes: []const hashing.Hash,
    ) !?dedup.Match {
        const self: *Session = @ptrCast(@alignCast(raw));
        if (try self.index.source().query(allocator, hashes)) |found| return found;
        if (self.external_source) |external| return external.query(allocator, hashes);
        return null;
    }

    fn enqueue(raw: *anyopaque, operation: storage.Operation) !storage.OperationDisposition {
        const self: *module.File = @ptrCast(@alignCast(raw));
        return self.session.push(self.id, self.file_id, operation);
    }

    /// The final Xorb belongs to the session, even if its chunks span files.
    fn enqueueFinal(raw: *anyopaque, operation: storage.Operation) !storage.OperationDisposition {
        const self: *Session = @ptrCast(@alignCast(raw));
        if (operation == .reference) return .release;
        return self.push(null, null, operation);
    }

    fn push(
        self: *Session,
        gen: ?u64,
        file_id: ?FileId,
        operation: storage.Operation,
    ) !storage.OperationDisposition {
        try self.queue.ensureUnusedCapacity(self.allocator, 1);
        const work: Work = switch (operation) {
            .store => |owned| .{ .store = owned.item },
            .reference => |ref| .{ .reference = .{
                .file_id = file_id orelse return error.MissingFile,
                .xorb_hash = ref.xorb_hash,
                .chunk_index_start = ref.chunk_index_start,
                .nodes = try self.allocator.dupe(hashing.Node, ref.nodes),
            } },
        };
        // A queued object holding earlier files survives the active file's rollback.
        const owner = if (work == .store and self.packing.writer.carries_committed) null else gen;
        self.queue.appendAssumeCapacity(.{ .gen = owner, .work = work });
        return if (operation == .store) .retain else .release;
    }

    /// Amortized compaction keeps storage proportional to outstanding work
    fn compact(self: *Session) void {
        if (self.queue_head == self.queue.items.len) {
            self.queue.clearRetainingCapacity();
            self.queue_head = 0;
            return;
        }
        if (self.queue_head < 4 or self.queue_head < self.queue.items.len - self.queue_head) return;
        std.mem.copyForwards(QueueNode, self.queue.items, self.queue.items[self.queue_head..]);
        self.queue.shrinkRetainingCapacity(self.queue.items.len - self.queue_head);
        self.queue_head = 0;
    }

    /// Discards unissued work for one generation while issued operations stay owned by callers
    fn rollback(self: *Session, id: u64) void {
        if (self.active == id) self.active = null;
        if (self.point_gen == id) {
            self.point_gen = null;
            self.packing.writer.new_xorb_listener = .{ .context = self, .callback = addXorb };
            self.index.rollback(&self.point);
        }
        var keep = self.queue_head;
        for (self.queue.items[self.queue_head..]) |node| {
            if (node.gen == id) {
                node.work.deinit(self.allocator);
            } else {
                self.queue.items[keep] = node;
                keep += 1;
            }
        }
        self.queue.shrinkRetainingCapacity(keep);
        if (self.queue_head == self.queue.items.len) {
            self.queue.clearAndFree(self.allocator);
            self.queue_head = 0;
        }
    }

    fn addXorb(raw: *anyopaque, object: shard.Xorb) !void {
        const self: *Session = @ptrCast(@alignCast(raw));
        try self.index.addXorb(object);
    }

    fn commit(self: *Session) void {
        if (self.point) |*point| point.deinit(self.allocator);
        self.point = null;
        self.point_gen = null;
    }

    fn completeOperation(self: *Session, failed: bool) void {
        if (failed) self.operation_failed.store(true, .release);
        const previous = self.in_flight.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
    }
};

pub const File = struct {
    session: *Session,
    id: u64,
    file_id: FileId,
    publisher: storage.Publisher,
    /// Unbuffered standard writer. On WriteFailed, err retains the underlying error.
    interface: std.Io.Writer,
    err: ?anyerror,
    state: enum { active, finished, failed } = .active,

    fn init(
        self: *File,
        session: *Session,
        id: u64,
        file_id: FileId,
        opts: storage.PublisherOptions,
    ) !void {
        self.session = session;
        self.id = id;
        self.file_id = file_id;
        self.state = .active;
        self.interface = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} };
        self.err = null;
        var file_opts = opts;
        file_opts.operation_listener = .{ .context = self, .callback = Session.enqueue };
        self.publisher = try session.packing.begin(
            file_opts,
            .{ .context = session, .callback = Session.enqueueFinal },
        );
    }

    pub fn deinit(self: *File) void {
        if (self.session.active == self.id and self.state != .finished) {
            // The writer drops this file's chunks, which only its owner may do
            self.publisher.abort();
            self.session.rollback(self.id);
        }
        self.publisher.deinit();
        self.* = undefined;
    }

    pub fn write(self: *File, input: []const u8) !void {
        if (self.state == .failed) return error.WriteFailed;
        if (self.state == .finished) return error.AlreadyFinished;
        self.publisher.write(input) catch |err| {
            self.state = .failed;
            self.publisher.abort();
            self.session.rollback(self.id);
            return err;
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *File = @alignCast(@fieldParentPtr("interface", w));
        for (data[0 .. data.len - 1]) |part| self.write(part) catch |err| {
            self.err = err;
            return error.WriteFailed;
        };
        for (0..splat) |_| self.write(data[data.len - 1]) catch |err| {
            self.err = err;
            return error.WriteFailed;
        };
        return std.Io.Writer.countSplat(data, splat);
    }

    pub fn finish(self: *File) !storage.PublishResult {
        if (self.state == .failed) return error.WriteFailed;
        if (self.state == .finished) return error.AlreadyFinished;
        self.state = .finished;
        errdefer self.state = .failed;
        const session = self.session;
        errdefer session.rollback(self.id);
        // Plan failure drops the abandoned chunks with the Xorbs only it filled
        errdefer self.publisher.abort();
        const result = try session.packing.endFile(&self.publisher);
        session.commit();
        // Dedup callbacks may re-enter the session, so release the guard last
        if (session.active == self.id) session.active = null;
        return result;
    }
};

test "finish refuses to publish when a worker fails while it drains" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    const Hook = struct {
        operation: *Operation,
        fired: bool = false,

        fn cancel(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.operation.deinit();
            self.fired = true;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = Session.init(allocator, destination.store(), .{});
    defer session.deinit();
    // A one-chunk limit closes the Xorb, leaving only its store operation queued
    _ = try session.addFile(1, "alpha", .{ .compression = .none, .max_xorb_chunks = 1 });
    var operation = session.next().?;
    var hook = Hook{ .operation = &operation };
    test_hook.finish = .{ .context = &hook, .callback = Hook.cancel };
    defer test_hook.finish = null;

    try std.testing.expectError(error.OperationFailed, session.finish());
    try std.testing.expect(hook.fired);
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}
