//! File-scoped incremental upload operations

const std = @import("std");
const dedup = @import("dedup.zig");
const hashing = @import("hash.zig");
const shard = @import("shard.zig");
const storage = @import("store.zig");

pub const FileId = usize;

pub const Options = struct {
    dedup_source: ?dedup.Source = null,
};

pub const Reference = struct {
    file_id: FileId,
    value: storage.ReferenceOperation,
    session: *Session,
    allocator: std.mem.Allocator,
};

/// Owns `value.data` until the operation completes or is cancelled
pub const Store = struct {
    file_id: FileId,
    value: storage.Object,
    session: *Session,
    allocator: std.mem.Allocator,
};

pub const Operation = union(enum) {
    reference: Reference,
    store: Store,

    /// Acknowledges successful execution and releases the owned operation
    pub fn complete(self: *Operation) void {
        self.release(false);
    }

    /// Cancels the operation and prevents session metadata publication
    pub fn deinit(self: *Operation) void {
        self.release(true);
    }

    fn release(self: *Operation, failed: bool) void {
        const session = switch (self.*) {
            .reference => |value| value.session,
            .store => |value| value.session,
        };
        freePayload(self.*);
        session.completeOperation(failed);
        self.* = undefined;
    }
};

const QueueNode = struct {
    gen: u64,
    operation: Operation,
};

/// Planning and `next` are single-threaded; worker-thread completions free payloads on the allocator
pub const Session = struct {
    allocator: std.mem.Allocator,
    external_source: ?dedup.Source,
    index: dedup.SessionIndex,
    batch: storage.BatchPublisher,
    queue: std.ArrayList(*QueueNode) = .empty,
    queue_head: usize = 0,
    /// Bookkeeping only, so they do not make the allocator thread-safe
    in_flight: std.atomic.Value(usize) = .init(0),
    operation_failed: std.atomic.Value(bool) = .init(false),
    active: ?u64 = null,
    next_id: u64 = 0,
    point_gen: ?u64 = null,
    point: ?dedup.SessionIndex.Checkpoint = null,

    /// The session and destination must remain at stable addresses while in use
    pub fn init(
        allocator: std.mem.Allocator,
        destination: storage.Store,
        opts: Options,
    ) Session {
        return .{
            .allocator = allocator,
            .external_source = opts.dedup_source,
            .index = .init(allocator),
            .batch = .init(allocator, destination),
        };
    }

    /// Queued work is discarded; every issued operation must be completed first
    pub fn deinit(self: *Session) void {
        std.debug.assert(self.active == null);
        std.debug.assert(self.in_flight.load(.acquire) == 0);
        for (self.queue.items[self.queue_head..]) |node| {
            freePayload(node.operation);
            self.allocator.destroy(node);
        }
        self.queue.deinit(self.allocator);
        self.batch.deinit();
        self.index.deinit();
        self.* = undefined;
    }

    /// The file must remain at its initialized address until deinit
    pub fn beginFile(
        self: *Session,
        file: *File,
        file_id: FileId,
        opts: storage.PackOptions,
    ) !void {
        if (self.batch.finished) return error.AlreadyFinished;
        if (self.operation_failed.load(.acquire)) return error.OperationFailed;
        if (self.active != null) return error.ActiveFile;
        const id = self.next_id;
        self.next_id +%= 1;
        self.active = id;
        self.point_gen = id;
        self.point = self.index.checkpoint();
        var pub_opts = storage.PublisherOptions.fromPack(opts);
        pub_opts.dedup_source = self.source();
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
    ) !void {
        var file: File = undefined;
        try self.beginFile(&file, file_id, opts);
        defer file.deinit();
        try file.write(input);
        return file.finish();
    }

    /// Transfers one owned operation to the caller for immediate or async execution
    pub fn next(self: *Session) !?Operation {
        if (self.queue_head == self.queue.items.len) return null;
        const node = self.queue.items[self.queue_head];
        self.queue_head += 1;
        _ = self.in_flight.fetchAdd(1, .acq_rel);
        const operation = node.operation;
        self.allocator.destroy(node);
        self.compact();
        return operation;
    }

    /// Requires every emitted operation to complete successfully before publication
    pub fn finish(self: *Session) !void {
        if (self.active != null) return error.ActiveFile;
        if (self.pending() != 0) return error.PendingOperations;
        if (self.operation_failed.load(.acquire)) return error.OperationFailed;
        return self.batch.finish();
    }

    pub fn pending(self: *const Session) usize {
        return self.queue.items.len - self.queue_head + self.in_flight.load(.acquire);
    }

    pub fn plans(self: *const Session) []const storage.Plan {
        return self.batch.plans.items;
    }

    fn source(self: *Session) dedup.Source {
        return .{ .context = self, .query_fn = query };
    }

    fn query(raw: *anyopaque, allocator: std.mem.Allocator, hashes: []const hashing.Hash) !?dedup.Match {
        const self: *Session = @ptrCast(@alignCast(raw));
        if (try self.index.source().query(allocator, hashes)) |found| return found;
        if (self.external_source) |external| return external.query(allocator, hashes);
        return null;
    }

    fn enqueue(raw: *anyopaque, operation: storage.Operation) !storage.OperationDisposition {
        const self: *File = @ptrCast(@alignCast(raw));
        const session = self.session;
        const node = try session.allocator.create(QueueNode);
        errdefer session.allocator.destroy(node);
        switch (operation) {
            .reference => |value| {
                const nodes = try session.allocator.dupe(hashing.Node, value.nodes);
                errdefer session.allocator.free(nodes);
                node.* = .{ .gen = self.id, .operation = .{ .reference = .{
                    .file_id = self.file_id,
                    .value = .{
                        .xorb_hash = value.xorb_hash,
                        .chunk_index_start = value.chunk_index_start,
                        .nodes = nodes,
                    },
                    .session = session,
                    .allocator = session.allocator,
                } } };
            },
            .store => |value| node.* = .{ .gen = self.id, .operation = .{ .store = .{
                .file_id = self.file_id,
                .value = value,
                .session = session,
                .allocator = session.allocator,
            } } },
        }
        session.queue.append(session.allocator, node) catch |err| {
            if (operation == .reference) freePayload(node.operation);
            return err;
        };
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
        std.mem.copyForwards(*QueueNode, self.queue.items, self.queue.items[self.queue_head..]);
        self.queue.shrinkRetainingCapacity(self.queue.items.len - self.queue_head);
        self.queue_head = 0;
    }

    fn releaseFile(self: *Session, id: u64) void {
        if (self.active != id) return;
        self.active = null;
    }

    /// Discards unissued work for one generation while issued operations stay owned by callers
    fn rollback(self: *Session, id: u64) void {
        if (self.active == id) self.active = null;
        if (self.point_gen == id) {
            self.point_gen = null;
            self.index.rollback(&self.point);
        }
        var keep = self.queue_head;
        for (self.queue.items[self.queue_head..]) |node| {
            if (node.gen == id) {
                freePayload(node.operation);
                self.allocator.destroy(node);
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
        var file_opts = opts;
        file_opts.operation_listener = .{ .context = self, .callback = Session.enqueue };
        file_opts.new_xorb_listener = .{ .context = self, .callback = newXorb };
        self.publisher = try storage.Publisher.init(session.allocator, noStore(), file_opts);
    }

    pub fn deinit(self: *File) void {
        if (self.session.active == self.id and self.state != .finished) self.session.rollback(self.id);
        self.publisher.deinit();
        self.* = undefined;
    }

    pub fn write(self: *File, input: []const u8) !void {
        if (self.state == .failed) return error.WriteFailed;
        if (self.state == .finished) return error.AlreadyFinished;
        self.publisher.write(input) catch |err| {
            self.state = .failed;
            self.session.rollback(self.id);
            return err;
        };
    }

    pub fn finish(self: *File) !void {
        if (self.state == .failed) return error.WriteFailed;
        if (self.state == .finished) return error.AlreadyFinished;
        self.state = .finished;
        errdefer self.state = .failed;
        const session = self.session;
        errdefer session.rollback(self.id);
        var plan = try self.publisher.finishPlan();
        errdefer plan.deinit(session.allocator);
        try session.batch.append(&plan);
        session.commit();
        // Dedup callbacks may re-enter the session, so release the guard last
        session.releaseFile(self.id);
    }

    fn newXorb(raw: *anyopaque, object: shard.Xorb) !void {
        const self: *File = @ptrCast(@alignCast(raw));
        return self.session.index.addXorb(object);
    }
};

fn freePayload(operation: Operation) void {
    switch (operation) {
        .reference => |value| value.allocator.free(value.value.nodes),
        .store => |value| value.allocator.free(value.value.data),
    }
}

fn noStore() storage.Store {
    return .{ .context = undefined, .put_fn = discard };
}

fn discard(_: *anyopaque, object: storage.Object) !void {
    if (object.kind == .shard) return error.InvalidOperation;
}
