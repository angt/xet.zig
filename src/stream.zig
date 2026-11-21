//! Transport requests and lifecycle around standard Zig incremental readers.

const std = @import("std");
const hashing = @import("hash.zig");

pub const scratch_buffer_size = 4 * 1024;

pub const ByteRange = struct {
    start: u64,
    end: u64,
};

pub fn rangeLength(range: ByteRange) error{InvalidRange}!u64 {
    if (range.start > range.end) return error.InvalidRange;
    return std.math.add(u64, range.end - range.start, 1) catch error.InvalidRange;
}

pub const Request = struct {
    hash: hashing.Hash,
    url: []const u8,
    /// Null requests the complete object.
    byte_range: ?ByteRange,
};

/// Returned readers are owned by the opener and must not outlive `close`.
pub const Opener = struct {
    context: *anyopaque,
    open_fn: *const fn (context: *anyopaque, request: Request) anyerror!*std.Io.Reader,
    close_fn: *const fn (context: *anyopaque, reader: *std.Io.Reader) void,
    read_error_fn: ?*const fn (context: *anyopaque, reader: *std.Io.Reader) ?anyerror = null,

    pub fn open(self: Opener, request: Request) !*std.Io.Reader {
        return self.open_fn(self.context, request);
    }

    pub fn close(self: Opener, reader: *std.Io.Reader) void {
        self.close_fn(self.context, reader);
    }

    pub fn readError(self: Opener, reader: *std.Io.Reader, fallback: anyerror) anyerror {
        const diagnostics = self.read_error_fn orelse return fallback;
        return diagnostics(self.context, reader) orelse fallback;
    }
};
