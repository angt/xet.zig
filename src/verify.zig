const std = @import("std");
const hashing = @import("hash.zig");
const chunker = @import("chunker.zig");

pub const parallel_threshold = 4 * 1024 * 1024;

/// Recomputes a complete file identity while optionally passing bytes through
pub const Verifier = struct {
    allocator: std.mem.Allocator,
    chunker: chunker.Chunker,
    nodes: hashing.Aggregator = .{},
    output: ?*std.Io.Writer,
    interface: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    error_value: ?anyerror = null,

    /// A null strategy verifies the canonical Xet file identity
    pub fn initWith(
        allocator: std.mem.Allocator,
        output: ?*std.Io.Writer,
        strategy: ?chunker.Strategy,
    ) Verifier {
        return .{
            .allocator = allocator,
            .chunker = if (strategy) |value|
                chunker.Chunker.initWith(value)
            else
                chunker.Chunker.init(),
            .output = output,
        };
    }

    pub fn deinit(self: *Verifier) void {
        self.chunker.deinit(self.allocator);
    }

    pub fn failure(self: *const Verifier, err: anyerror) anyerror {
        return self.error_value orelse err;
    }

    fn drain(
        interface: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *Verifier = @fieldParentPtr("interface", interface);
        for (data[0 .. data.len - 1]) |bytes| {
            self.write(bytes) catch |err| {
                self.error_value = err;
                return error.WriteFailed;
            };
        }
        for (0..splat) |_| {
            self.write(data[data.len - 1]) catch |err| {
                self.error_value = err;
                return error.WriteFailed;
            };
        }
        return std.Io.Writer.countSplat(data, splat);
    }

    fn update(self: *Verifier, input: []const u8) !void {
        var bytes = input;
        while (bytes.len != 0) {
            const result = try self.chunker.next(self.allocator, bytes, false);
            if (result.chunk) |chunk| try self.nodes.add(.{
                .hash = chunk.hash,
                .size = chunk.data.len,
            });
            bytes = bytes[result.consumed..];
        }
    }

    fn write(self: *Verifier, input: []const u8) !void {
        try self.update(input);
        if (self.output) |output| try output.writeAll(input);
    }

    /// Workers hash complete canonical chunks starting at a term boundary.
    /// If the preceding term ends mid-chunk, rechunk this term in stream order.
    pub fn writeTerm(self: *Verifier, input: []const u8, nodes: []const hashing.Node) !void {
        if (self.chunker.pending.items.len != 0 and !self.chunker.returned_pending)
            return self.write(input);
        var covered: usize = 0;
        for (nodes) |node| {
            try self.nodes.add(node);
            covered += @intCast(node.size);
        }
        try self.update(input[covered..]);
        if (self.output) |sink| try sink.writeAll(input);
    }

    pub fn finish(self: *Verifier, expected: hashing.Hash) !void {
        const final = try self.chunker.finish(self.allocator);
        if (final.chunk) |chunk| try self.nodes.add(.{
            .hash = chunk.hash,
            .size = chunk.data.len,
        });
        if (!hashing.eql(expected, try self.nodes.fileHash())) return error.HashMismatch;
    }
};

test "verifier writer preserves allocation failures and releases pending input" {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator, .fail_at = 0 };
    defer tracker.deinit();
    var verifier = Verifier.initWith(tracker.allocator(), null, null);
    defer verifier.deinit();
    try std.testing.expectError(error.WriteFailed, verifier.interface.writeAll("pending"));
    try std.testing.expectEqual(error.OutOfMemory, verifier.failure(error.WriteFailed));
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "verifier writer consumes every splat repetition once" {
    const allocator = std.testing.allocator;
    var bytes: [9]u8 = undefined;
    var output: std.Io.Writer = .fixed(&bytes);
    var verifier = Verifier.initWith(allocator, &output, null);
    defer verifier.deinit();
    var parts = [_][]const u8{"abc"};
    try verifier.interface.writeSplatAll(&parts, 3);
    try verifier.finish(try hashing.file(allocator, &.{.{
        .hash = hashing.data("abcabcabc"),
        .size = 9,
    }}));
    try std.testing.expectEqualStrings("abcabcabc", output.buffered());
}

test "a term beginning mid-chunk is verified with the preceding bytes" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 3 * @import("constants.zig").max_chunk_size);
    defer allocator.free(data);
    @memset(data, 0x77);
    var scalar = Verifier.initWith(allocator, null, null);
    defer scalar.deinit();
    try scalar.write(data);
    const expected = try scalar.nodes.fileHash(); // Three forced 128 KiB cuts.
    var checked = Verifier.initWith(allocator, null, null);
    defer checked.deinit();
    const size = data.len / 3;
    const node = hashing.Node{ .hash = hashing.data(data[0..size]), .size = size };
    try checked.writeTerm(data[0 .. size + 1], &.{node});
    try checked.writeTerm(data[size + 1 ..], &.{node});
    try checked.finish(expected);
}
