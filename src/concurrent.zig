//! Bounded concurrent transfer helpers built on `std.Io.Select`

const std = @import("std");
const constants = @import("constants.zig");
const hashing = @import("hash.zig");
const verify = @import("verify.zig");
const reconstruction = @import("reconstruction.zig");
const storage = @import("store.zig");
const stream = @import("stream.zig");
const xorb = @import("xorb.zig");

const UploadCompletion = union(enum) { result: ?*UploadTask };
const TermCompletion = union(enum) { result: ?*TermTask };

/// Copies up to `window` in-flight Xorbs and requires a thread-safe allocator and store
pub const UploadStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    downstream: storage.Store,
    tasks: []UploadCompletion,
    select: std.Io.Select(UploadCompletion),
    in_flight: usize = 0,
    first_error: ?anyerror = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        downstream: storage.Store,
        window: usize,
    ) !UploadStore {
        if (window == 0) return error.InvalidConcurrency;
        const tasks = try allocator.alloc(UploadCompletion, window);
        @memset(tasks, .{ .result = null });
        return .{
            .allocator = allocator,
            .io = io,
            .downstream = downstream,
            .tasks = tasks,
            .select = .init(io, tasks),
        };
    }

    pub fn deinit(self: *UploadStore) void {
        while (self.select.cancel()) |completed| {
            if (completed.result) |task| task.deinit(self.allocator);
        }
        self.allocator.free(self.tasks);
    }

    pub fn store(self: *UploadStore) storage.Store {
        return .{ .context = self, .put_fn = put };
    }

    fn put(raw: *anyopaque, object: storage.Object) !void {
        const self: *UploadStore = @ptrCast(@alignCast(raw));
        if (object.kind == .shard) {
            try self.finish();
            return self.downstream.put(object);
        }
        if (self.first_error) |err| return err;
        if (self.in_flight == self.tasks.len) {
            try self.awaitOne();
            if (self.first_error) |err| return err;
        }
        const task = try self.allocator.create(UploadTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .parent = self,
            .data = try self.allocator.dupe(u8, object.data),
            .hash = object.hash,
            .raw_size = object.raw_size,
        };
        self.in_flight += 1;
        self.select.concurrent(.result, upload, .{task}) catch |err| switch (err) {
            error.ConcurrencyUnavailable => self.select.async(.result, upload, .{task}),
        };
    }

    fn upload(task: *UploadTask) ?*UploadTask {
        const self = task.parent;
        self.downstream.put(.{
            .kind = .xorb,
            .hash = task.hash,
            .data = task.data,
            .raw_size = task.raw_size,
        }) catch |err| {
            task.err = err;
        };
        return task;
    }

    fn awaitOne(self: *UploadStore) !void {
        const task = (try self.select.await()).result.?;
        if (self.first_error == null) self.first_error = task.err;
        task.deinit(self.allocator);
        self.in_flight -= 1;
    }

    pub fn finish(self: *UploadStore) !void {
        while (self.in_flight != 0) try self.awaitOne();
        if (self.first_error) |err| return err;
    }
};

const UploadTask = struct {
    parent: *UploadStore,
    data: []u8,
    hash: hashing.Hash,
    raw_size: u64,
    err: ?anyerror = null,

    fn deinit(self: *UploadTask, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        allocator.destroy(self);
    }
};

pub const ConsumeOptions = struct {
    window: usize = 4,
    /// Bounds prefetch by `window * max_term_size` and streams larger terms
    max_term_size: usize = constants.max_xorb_size,
};

/// Decode prefetched terms in file order
pub fn consume(
    allocator: std.mem.Allocator,
    io: std.Io,
    plan: *const reconstruction.Plan,
    opener: stream.Opener,
    sink: *std.Io.Writer,
    options: ConsumeOptions,
) !u64 {
    if (options.window == 0 or options.max_term_size == 0) return error.InvalidConcurrency;
    try plan.validate();
    const wanted = plan.output_length orelse blk: {
        var total: u64 = 0;
        for (plan.terms) |term| total += term.unpacked_length;
        break :blk total - plan.offset_into_first_range;
    };
    for (plan.terms) |term| {
        const location = reconstruction.findLocation(plan.locations, term) orelse return error.MissingLocation;
        const byte_range = location.byte_range orelse
            return reconstruction.consume(allocator, plan, opener, sink);
        const size = try stream.rangeLength(byte_range);
        if (size > options.max_term_size)
            return reconstruction.consume(allocator, plan, opener, sink);
    }

    var verifier: ?verify.Verifier = if (plan.file_hash != null)
        verify.Verifier.init(allocator, sink)
    else
        null;
    defer if (verifier) |*value| value.deinit();
    var context = Context{
        .allocator = allocator,
        .opener = opener,
        .sink = if (verifier) |*value| &value.interface else sink,
        .plan = plan,
        .wanted = wanted,
        .skip = plan.offset_into_first_range,
    };
    const completions = try allocator.alloc(TermCompletion, options.window);
    defer allocator.free(completions);
    var select: std.Io.Select(TermCompletion) = .init(io, completions);
    const tasks = try allocator.alloc(?*TermTask, options.window);
    defer allocator.free(tasks);
    @memset(tasks, null);
    defer for (tasks) |maybe_task| {
        if (maybe_task) |task| task.deinit();
    };
    const completed = try allocator.alloc(bool, options.window);
    defer allocator.free(completed);
    @memset(completed, false);
    // Workers must stop before their tasks and context are freed
    defer select.cancelDiscard();

    var next: usize = 0;
    var current: usize = 0;
    while (current < plan.terms.len and context.written != wanted) {
        while (next - current < options.window and next < plan.terms.len) {
            const task = try allocator.create(TermTask);
            errdefer allocator.destroy(task);
            task.* = .{ .context = &context, .index = next };
            tasks[next % options.window] = task;
            completed[next % options.window] = false;
            next += 1;
            select.concurrent(.result, fetch, .{task}) catch |err| switch (err) {
                error.ConcurrencyUnavailable => select.async(.result, fetch, .{task}),
            };
        }
        const task = tasks[current % options.window].?;
        while (!completed[current % options.window]) {
            const finished = (try select.await()).result.?;
            // Await synchronizes task writes. Results may complete out of order
            completed[finished.index % options.window] = true;
            if (finished.err) |err| return err;
        }
        tasks[current % options.window] = null;
        const decoded = decode(task, &context) catch |err| {
            task.deinit();
            if (verifier) |*value| return value.failure(err);
            return err;
        };
        task.deinit();
        current += 1;
        if (decoded != plan.terms[current - 1].unpacked_length) return error.SizeMismatch;
    }
    if (context.skip != 0 or context.written != wanted) return error.SizeMismatch;
    if (verifier) |*value| value.finish(plan.file_hash.?) catch |err| return value.failure(err);
    return context.written;
}

const Context = struct {
    allocator: std.mem.Allocator,
    opener: stream.Opener,
    sink: *std.Io.Writer,
    plan: *const reconstruction.Plan,
    wanted: u64,
    skip: u64,
    written: u64 = 0,
};

const TermTask = struct {
    context: *Context,
    index: usize,
    data: []u8 = &.{},
    err: ?anyerror = null,

    fn deinit(self: *TermTask) void {
        self.context.allocator.free(self.data);
        self.context.allocator.destroy(self);
    }
};

fn fetch(task: *TermTask) ?*TermTask {
    fetchInner(task) catch |err| {
        task.err = err;
    };
    return task;
}

fn fetchInner(task: *TermTask) !void {
    const context = task.context;
    const term = context.plan.terms[task.index];
    const location = reconstruction.findLocation(context.plan.locations, term) orelse return error.MissingLocation;
    const source = try context.opener.open(.{
        .hash = location.hash,
        .url = location.url,
        .byte_range = location.byte_range,
    });
    defer context.opener.close(source);
    const byte_range = location.byte_range orelse return error.InvalidSize;
    const size_u64 = try stream.rangeLength(byte_range);
    const size = std.math.cast(usize, size_u64) orelse return error.InvalidSize;
    task.data = try context.allocator.alloc(u8, size);
    source.readSliceAll(task.data) catch |err| switch (err) {
        error.EndOfStream => return error.InvalidSize,
        error.ReadFailed => return context.opener.readError(source, error.ReadFailed),
    };
}

fn decode(task: *TermTask, context: *Context) !u64 {
    var source: std.Io.Reader = .fixed(task.data);
    var output = reconstruction.RangeWriter{
        .output = context.sink,
        .skip = &context.skip,
        .wanted = context.wanted,
        .written = &context.written,
    };
    return reconstruction.decodeTerm(context.allocator, context.plan, task.index, &source, &output.writer);
}

const TestFetch = struct {
    const Failure = enum { none, fetch, decode, sink };

    bytes: []const u8,
    failure: Failure = .none,
    active: std.atomic.Value(usize) = .init(0),
    overlapped: std.atomic.Value(bool) = .init(false),
    opened: std.atomic.Value(usize) = .init(0),
    output: std.ArrayList(u8) = .empty,
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    ordered: bool = false,
    finished: [6]std.atomic.Value(bool) = @splat(.init(false)),
    completion_log: [6]usize = @splat(0),
    completion_count: [2]std.atomic.Value(usize) = @splat(.init(0)),

    const State = struct {
        parent: *TestFetch,
        position: usize = 0,
        index: usize,
        delayed: bool = false,
        failure: ?anyerror = null,
        reader: std.Io.Reader = .{ .vtable = &.{ .stream = read }, .buffer = &.{}, .seek = 0, .end = 0 },
    };

    fn open(raw: *anyopaque, _: stream.Request) !*std.Io.Reader {
        const self: *TestFetch = @ptrCast(@alignCast(raw));
        const state = try std.testing.allocator.create(State);
        state.* = .{ .parent = self, .index = self.opened.fetchAdd(1, .monotonic) };
        if (self.active.fetchAdd(1, .acq_rel) != 0) self.overlapped.store(true, .release);
        return &state.reader;
    }

    fn read(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *State = @fieldParentPtr("reader", reader);
        const parent = self.parent;
        if (parent.failure == .fetch and self.index == 0) {
            self.failure = error.InjectedFailure;
            return error.ReadFailed;
        }
        if (parent.failure == .decode and self.index == 0 and self.position == 0) {
            try writer.writeAll(&.{1}); // Unsupported chunk version
            self.position = 1;
            return 1;
        }
        if (parent.failure == .none and !parent.ordered and self.index == 0 and !self.delayed) {
            self.delayed = true;
            for (0..1000) |_| {
                if (parent.active.load(.acquire) > 1) break;
                std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
            }
        }
        if (parent.ordered and !self.delayed) {
            self.delayed = true;
            const prerequisite: ?usize = switch (self.index) {
                0 => 1,
                1 => 2,
                4 => 3,
                5 => 4,
                else => null,
            };
            if (prerequisite) |index| {
                for (0..1000) |_| {
                    if (parent.finished[index].load(.acquire)) break;
                    std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
                }
            }
        }
        if (parent.failure != .none and self.index != 0 and !self.delayed) {
            self.delayed = true;
            std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
        }
        if (self.position == parent.bytes.len or limit == .nothing) return error.EndOfStream;
        const count = @min(limit.minInt(3), parent.bytes.len - self.position);
        try writer.writeAll(parent.bytes[self.position..][0..count]);
        self.position += count;
        if (parent.failure == .none and !parent.ordered and self.index % 3 != 0) {
            std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(2), .awake) catch {};
        }
        if (self.position == parent.bytes.len) {
            parent.finished[self.index].store(true, .release);
            const window = self.index / 3;
            const slot = parent.completion_count[window].fetchAdd(1, .acq_rel);
            parent.completion_log[window * 3 + slot] = self.index;
        }
        return count;
    }

    fn readError(_: *anyopaque, reader: *std.Io.Reader) ?anyerror {
        const self: *State = @fieldParentPtr("reader", reader);
        return self.failure;
    }

    fn close(_: *anyopaque, reader: *std.Io.Reader) void {
        const self: *State = @fieldParentPtr("reader", reader);
        _ = self.parent.active.fetchSub(1, .acq_rel);
        std.testing.allocator.destroy(self);
    }

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *TestFetch = @fieldParentPtr("writer", writer);
        if (self.failure == .sink) return error.WriteFailed;
        const bytes = std.Io.Writer.countSplat(data, splat);
        for (data[0 .. data.len - 1]) |part| self.output.appendSlice(std.testing.allocator, part) catch
            return error.WriteFailed;
        for (0..splat) |_| self.output.appendSlice(std.testing.allocator, data[data.len - 1]) catch
            return error.WriteFailed;
        return bytes;
    }
};

test "small-term prefetch overlaps reads and preserves output order" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "alpha", .hash = hashing.data("alpha") },
        .{ .data = "beta", .hash = hashing.data("beta") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]reconstruction.Term{
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
    };
    const locations = [_]reconstruction.Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try reconstruction.Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    var test_fetch = TestFetch{ .bytes = object.bytes };
    defer test_fetch.output.deinit(allocator);
    const count = try consume(allocator, std.testing.io, &plan, .{
        .context = &test_fetch,
        .open_fn = TestFetch.open,
        .close_fn = TestFetch.close,
        .read_error_fn = TestFetch.readError,
    }, &test_fetch.writer, .{
        .window = 2,
        .max_term_size = object.bytes.len,
    });
    try std.testing.expectEqual(@as(u64, 27), count);
    try std.testing.expectEqualStrings("alphabetaalphabetaalphabeta", test_fetch.output.items);
    try std.testing.expect(test_fetch.overlapped.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), test_fetch.active.load(.acquire));
}

test "default concurrent reads cover normal xorb sizes without empty writes" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, constants.max_xorb_size), (ConsumeOptions{}).max_term_size);
    const chunks = [_]xorb.Chunk{
        .{ .data = "AAA", .hash = hashing.data("AAA") },
        .{ .data = "BBB", .hash = hashing.data("BBB") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]reconstruction.Term{
        .{ .hash = object.hash, .unpacked_length = 6, .range = .{ .start = 0, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 6, .range = .{ .start = 0, .end = 2 } },
    };
    const locations = [_]reconstruction.Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try reconstruction.Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    plan.output_length = 1;
    const Counting = struct {
        empty: usize = 0,
        writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
        fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", writer);
            if (std.Io.Writer.countSplat(data, splat) == 0) self.empty += 1;
            return std.Io.Writer.countSplat(data, splat);
        }
    };
    var counting = Counting{};
    var test_fetch = TestFetch{ .bytes = object.bytes };
    defer test_fetch.output.deinit(allocator);
    _ = try consume(allocator, std.testing.io, &plan, .{
        .context = &test_fetch,
        .open_fn = TestFetch.open,
        .close_fn = TestFetch.close,
        .read_error_fn = TestFetch.readError,
    }, &counting.writer, .{});
    try std.testing.expectEqual(@as(usize, 0), counting.empty);
}

test "concurrent consumption rejects overflowing byte ranges before opening" {
    const allocator = std.testing.allocator;
    const hash = hashing.data("object");
    var terms = [_]reconstruction.Term{.{
        .hash = hash,
        .unpacked_length = 1,
        .range = .{ .start = 0, .end = 1 },
    }};
    var locations = [_]reconstruction.Location{.{
        .hash = hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = std.math.maxInt(u64) },
    }};
    var plan = reconstruction.Plan{
        .terms = &terms,
        .locations = &locations,
    };
    var test_fetch = TestFetch{ .bytes = "" };
    defer test_fetch.output.deinit(allocator);
    try std.testing.expectError(error.InvalidRange, consume(
        allocator,
        std.testing.io,
        &plan,
        .{ .context = &test_fetch, .open_fn = TestFetch.open, .close_fn = TestFetch.close },
        &test_fetch.writer,
        .{},
    ));
    try std.testing.expectEqual(@as(usize, 0), test_fetch.opened.load(.monotonic));
}

test "consumer tracks current and out-of-order completions by task identity" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "alpha", .hash = hashing.data("alpha") },
        .{ .data = "beta", .hash = hashing.data("beta") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]reconstruction.Term{
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
    };
    const locations = [_]reconstruction.Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try reconstruction.Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    var test_fetch = TestFetch{ .bytes = object.bytes, .ordered = true };
    defer test_fetch.output.deinit(allocator);
    const count = try consume(allocator, std.testing.io, &plan, .{
        .context = &test_fetch,
        .open_fn = TestFetch.open,
        .close_fn = TestFetch.close,
        .read_error_fn = TestFetch.readError,
    }, &test_fetch.writer, .{
        .window = 3,
        .max_term_size = object.bytes.len,
    });
    try std.testing.expectEqual(@as(u64, 27), count);
    try std.testing.expectEqualStrings("alphabetaalphabetaalphabeta", test_fetch.output.items);
    try std.testing.expectEqualSlices(usize, &.{ 2, 1, 0, 3, 4, 5 }, &test_fetch.completion_log);
    try std.testing.expectEqual(@as(usize, 0), test_fetch.active.load(.acquire));
}

test "download failures cancel outstanding reads before freeing tasks" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "alpha", .hash = hashing.data("alpha") },
        .{ .data = "beta", .hash = hashing.data("beta") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]reconstruction.Term{
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
    };
    const locations = [_]reconstruction.Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};

    for ([_]TestFetch.Failure{ .fetch, .decode, .sink }) |failure| {
        var plan = try reconstruction.Plan.init(allocator, &terms, &locations);
        defer plan.deinit(allocator);
        var test_fetch = TestFetch{ .bytes = object.bytes, .failure = failure };
        defer test_fetch.output.deinit(allocator);
        const expected = switch (failure) {
            .fetch => error.InjectedFailure,
            .decode => error.UnsupportedVersion,
            .sink => error.WriteFailed,
            .none => unreachable,
        };
        const result = consume(allocator, std.testing.io, &plan, .{
            .context = &test_fetch,
            .open_fn = TestFetch.open,
            .close_fn = TestFetch.close,
            .read_error_fn = TestFetch.readError,
        }, &test_fetch.writer, .{
            .window = 4,
            .max_term_size = object.bytes.len,
        });
        if (result) |_| {
            return error.TestUnexpectedResult;
        } else |err| {
            if (err != expected) return err;
        }
        try std.testing.expectEqual(@as(usize, 0), test_fetch.active.load(.acquire));
    }
}

test "whole-file identity rejects corruption without changing the consume API" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "alpha", .hash = hashing.data("alpha") },
        .{ .data = "beta!", .hash = hashing.data("beta!") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]reconstruction.Term{.{
        .hash = object.hash,
        .unpacked_length = 10,
        .range = .{ .start = 0, .end = 2 },
    }};
    const locations = [_]reconstruction.Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://verified",
        .byte_range = .{ .start = 0, .end = @intCast(object.body_length - 1) },
    }};
    var plan = try reconstruction.Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    const canonical = try @import("chunker.zig").chunkBuffer(allocator, "alphabeta!");
    defer allocator.free(canonical);
    const nodes = try allocator.alloc(hashing.Node, canonical.len);
    defer allocator.free(nodes);
    for (canonical, nodes) |chunk, *node| node.* = .{ .hash = chunk.hash, .size = chunk.data.len };
    plan.file_hash = try hashing.file(allocator, nodes);
    var test_fetch = TestFetch{ .bytes = object.bytes };
    defer test_fetch.output.deinit(allocator);
    const count = try consume(allocator, std.testing.io, &plan, .{
        .context = &test_fetch,
        .open_fn = TestFetch.open,
        .close_fn = TestFetch.close,
        .read_error_fn = TestFetch.readError,
    }, &test_fetch.writer, .{
        .window = 2,
        .max_term_size = object.body_length,
    });
    try std.testing.expectEqual(@as(u64, 10), count);
    try std.testing.expectEqualStrings("alphabeta!", test_fetch.output.items);

    @memcpy(object.bytes[21..26], "gamma");
    test_fetch.output.clearRetainingCapacity();
    try std.testing.expectError(error.HashMismatch, consume(allocator, std.testing.io, &plan, .{
        .context = &test_fetch,
        .open_fn = TestFetch.open,
        .close_fn = TestFetch.close,
        .read_error_fn = TestFetch.readError,
    }, &test_fetch.writer, .{
        .window = 2,
        .max_term_size = object.body_length,
    }));
}

test "upload errors drain outstanding tasks before returning" {
    const allocator = std.testing.allocator;
    const TestStore = struct {
        calls: usize = 0,
        fn put(raw: *anyopaque, object: storage.Object) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            if (self.calls == 1) return error.InjectedFailure;
            _ = object;
        }
    };
    var test_store = TestStore{};
    var uploader = try UploadStore.init(allocator, std.testing.io, .{
        .context = &test_store,
        .put_fn = TestStore.put,
    }, 3);
    defer uploader.deinit();
    const destination = uploader.store();
    for (0..3) |_| try destination.put(.{
        .kind = .xorb,
        .hash = hashing.zero,
        .data = "x",
        .raw_size = 1,
    });
    try std.testing.expectError(error.InjectedFailure, uploader.finish());
    try std.testing.expectEqual(@as(usize, 0), uploader.in_flight);
}

test "concurrent upload sends the shard after every xorb" {
    const allocator = std.testing.allocator;
    const TestStore = struct {
        completed: usize = 0,
        shard_after_complete: bool = false,
        fn put(raw: *anyopaque, object: storage.Object) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (object.kind == .shard) {
                self.shard_after_complete = self.completed == 8;
                return;
            }
            self.completed += 1;
        }
    };
    var test_store = TestStore{};
    var uploader = try UploadStore.init(allocator, std.testing.io, .{
        .context = &test_store,
        .put_fn = TestStore.put,
    }, 3);
    defer uploader.deinit();
    const destination = uploader.store();
    for (0..8) |_| try destination.put(.{
        .kind = .xorb,
        .hash = hashing.zero,
        .data = "x",
        .raw_size = 1,
    });
    try destination.put(.{ .kind = .shard, .hash = hashing.zero, .data = "s", .raw_size = 1 });
    try std.testing.expect(test_store.shard_after_complete);
}
