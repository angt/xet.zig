const std = @import("std");
const hashing = @import("hash.zig");
const chunker = @import("chunker.zig");

/// Recomputes a complete file identity while optionally passing bytes through
pub const Verifier = struct {
    allocator: std.mem.Allocator,
    chunker: chunker.Chunker,
    nodes: hashing.Aggregator = .{},
    output: ?*std.Io.Writer,
    interface: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    error_value: ?anyerror = null,

    pub fn init(allocator: std.mem.Allocator, output: ?*std.Io.Writer) Verifier {
        return initWith(allocator, output, null);
    }

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

    fn drain(interface: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
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

    fn write(self: *Verifier, input: []const u8) !void {
        var remaining = input;
        while (remaining.len != 0) {
            const next = try self.chunker.next(self.allocator, remaining, false);
            if (next.chunk) |chunk| try self.nodes.add(.{
                .hash = chunk.hash,
                .size = chunk.data.len,
            });
            remaining = remaining[next.consumed..];
        }
        if (self.output) |output| try output.writeAll(input);
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
    var verifier = Verifier.init(tracker.allocator(), null);
    defer verifier.deinit();
    try std.testing.expectError(error.WriteFailed, verifier.interface.writeAll("pending"));
    try std.testing.expectEqual(error.OutOfMemory, verifier.failure(error.WriteFailed));
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "verifier writer consumes every splat repetition once" {
    const allocator = std.testing.allocator;
    var bytes: [9]u8 = undefined;
    var output: std.Io.Writer = .fixed(&bytes);
    var verifier = Verifier.init(allocator, &output);
    defer verifier.deinit();
    var parts = [_][]const u8{"abc"};
    try verifier.interface.writeSplatAll(&parts, 3);
    try verifier.finish(try hashing.file(allocator, &.{.{
        .hash = hashing.data("abcabcabc"),
        .size = 9,
    }}));
    try std.testing.expectEqualStrings("abcabcabc", output.buffered());
}
