const std = @import("std");
const constants = @import("constants.zig");
const hashing = @import("hash.zig");

pub const Chunk = struct {
    data: []const u8,
    hash: hashing.Hash,
};

pub const Result = struct {
    chunk: ?Chunk,
    consumed: usize,
};

/// Chunks borrow input or internal storage until `next`, `reset`, or `deinit`
pub const Chunker = struct {
    pending: std.ArrayList(u8),
    hash: u64 = 0,
    returned_pending: bool = false,

    pub fn init() Chunker {
        return .{ .pending = .empty };
    }

    pub fn deinit(self: *Chunker, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
    }

    pub fn reset(self: *Chunker) void {
        self.pending.clearRetainingCapacity();
        self.hash = 0;
        self.returned_pending = false;
    }

    /// Set `final` only when no later input belongs to the same file
    pub fn next(self: *Chunker, allocator: std.mem.Allocator, input: []const u8, final: bool) !Result {
        if (self.returned_pending) {
            self.pending.clearRetainingCapacity();
            self.returned_pending = false;
        }

        const consumed = self.findBoundary(input) orelse blk: {
            if (!final) {
                try self.pending.appendSlice(allocator, input);
                return .{ .chunk = null, .consumed = input.len };
            }
            if (self.pending.items.len == 0 and input.len == 0) return .{
                .chunk = null,
                .consumed = 0,
            };
            break :blk input.len;
        };
        if (self.pending.items.len == 0) {
            const bytes = input[0..consumed];
            self.hash = 0;
            return .{
                .chunk = .{ .data = bytes, .hash = hashing.data(bytes) },
                .consumed = consumed,
            };
        }
        try self.pending.appendSlice(allocator, input[0..consumed]);
        self.hash = 0;
        self.returned_pending = true;
        const bytes = self.pending.items;
        return .{
            .chunk = .{ .data = bytes, .hash = hashing.data(bytes) },
            .consumed = consumed,
        };
    }

    pub fn finish(self: *Chunker, allocator: std.mem.Allocator) !Result {
        return self.next(allocator, &.{}, true);
    }

    fn findBoundary(self: *Chunker, input: []const u8) ?usize {
        if (input.len == 0) return null;
        const previous_len = self.pending.items.len;
        var index: usize = 0;
        if (previous_len + 64 < constants.min_chunk_size) {
            index = @min(
                constants.min_chunk_size - previous_len - 64 - 1,
                input.len,
            );
        }
        const read_end = @min(input.len, constants.max_chunk_size - previous_len);
        const minimum_end = constants.min_chunk_size -| previous_len;
        var hash = self.hash;

        const warmup_end = @min(read_end, minimum_end -| 1);
        while (index < warmup_end) : (index += 1) {
            hash = hash +% hash +% constants.gear_table[input[index]];
        }
        while (index < read_end) : (index += 1) {
            hash = hash +% hash +% constants.gear_table[input[index]];
            if ((hash & constants.gear_mask) == 0) {
                self.hash = hash;
                return @min(index + 1, constants.max_chunk_size - previous_len);
            }
        }
        self.hash = hash;
        if (read_end + previous_len >= constants.max_chunk_size) {
            return constants.max_chunk_size - previous_len;
        }
        return null;
    }
};

/// Returned data slices borrow `input`
pub fn chunkBuffer(allocator: std.mem.Allocator, input: []const u8) ![]Chunk {
    var chunker = Chunker.init();
    defer chunker.deinit(allocator);
    var chunks: std.ArrayList(Chunk) = .empty;
    errdefer chunks.deinit(allocator);

    var position: usize = 0;
    while (position < input.len) {
        const result = try chunker.next(allocator, input[position..], true);
        if (result.chunk) |chunk| try chunks.append(allocator, chunk);
        position += result.consumed;
    }
    return chunks.toOwnedSlice(allocator);
}

fn fillRandom(output: []u8, initial_state: u64) void {
    var state = initial_state;
    var position: usize = 0;
    while (position < output.len) {
        state +%= 0x9e3779b97f4a7c15;
        var z = state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        z ^= z >> 31;
        const count = @min(8, output.len - position);
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, z, .little);
        @memcpy(output[position..][0..count], bytes[0..count]);
        position += count;
    }
}

test "canonical one-megabyte boundaries" {
    const data = try std.testing.allocator.alloc(u8, 1_000_000);
    defer std.testing.allocator.free(data);
    fillRandom(data, 0);
    const expected = [_]usize{
        84493,  134421, 144853,  243318, 271793, 336457, 467529, 494581,
        582000, 596735, 616815,  653164, 678202, 724510, 815591, 827760,
        958832, 991092, 1000000,
    };
    const chunks = try chunkBuffer(std.testing.allocator, data);
    defer std.testing.allocator.free(chunks);
    try std.testing.expectEqual(@as(u8, 175), data[0]);
    try std.testing.expectEqual(@as(u8, 132), data[127]);
    try std.testing.expectEqual(@as(u8, 118), data[111111]);
    try std.testing.expectEqual(expected.len, chunks.len);
    var offset: usize = 0;
    for (chunks, expected) |chunk, end| {
        offset += chunk.data.len;
        try std.testing.expectEqual(end, offset);
    }
}

test "streaming and contiguous chunking agree" {
    const allocator = std.testing.allocator;
    const data = try std.testing.allocator.alloc(u8, 256_000);
    defer std.testing.allocator.free(data);
    fillRandom(data, 1);
    const contiguous = try chunkBuffer(std.testing.allocator, data);
    defer std.testing.allocator.free(contiguous);

    for ([_]usize{ 1, 37, 255, 8191 }) |step| {
        var chunker = Chunker.init();
        defer chunker.deinit(allocator);
        var streamed_data: std.ArrayList(u8) = .empty;
        defer streamed_data.deinit(std.testing.allocator);
        var streamed: std.ArrayList(Chunk) = .empty;
        defer streamed.deinit(std.testing.allocator);
        var position: usize = 0;
        while (position < data.len) {
            const end = @min(position + step, data.len);
            var input = data[position..end];
            while (input.len > 0) {
                const result = try chunker.next(allocator, input, false);
                if (result.chunk) |chunk| {
                    const offset = streamed_data.items.len;
                    try streamed_data.appendSlice(std.testing.allocator, chunk.data);
                    try streamed.append(std.testing.allocator, .{
                        .data = streamed_data.items[offset..],
                        .hash = chunk.hash,
                    });
                }
                input = input[result.consumed..];
            }
            position = end;
        }
        const final = try chunker.finish(allocator);
        if (final.chunk) |chunk| {
            try streamed_data.appendSlice(std.testing.allocator, chunk.data);
            try streamed.append(std.testing.allocator, chunk);
        }
        try std.testing.expectEqualSlices(u8, data, streamed_data.items);
        try std.testing.expectEqual(contiguous.len, streamed.items.len);
        for (contiguous, streamed.items) |a, b| {
            try std.testing.expectEqual(a.data.len, b.data.len);
            try std.testing.expectEqual(a.hash, b.hash);
        }
    }
}

test "constant data uses maximum-size chunks" {
    const data: [1_000_000]u8 = @splat(59);
    const chunks = try chunkBuffer(std.testing.allocator, &data);
    defer std.testing.allocator.free(chunks);
    const expected = [_]usize{ 131072, 262144, 393216, 524288, 655360, 786432, 917504, 1000000 };
    var offset: usize = 0;
    try std.testing.expectEqual(expected.len, chunks.len);
    for (chunks, expected) |chunk, end| {
        offset += chunk.data.len;
        try std.testing.expectEqual(end, offset);
    }
}

test "chunkBuffer borrows every chunk from the input" {
    const allocator = std.testing.allocator;
    for ([_]usize{ 1, constants.min_chunk_size, constants.max_chunk_size, 300_000 }) |size| {
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);
        fillRandom(data, size);
        const chunks = try chunkBuffer(allocator, data);
        defer allocator.free(chunks);
        for (chunks) |chunk| {
            const address = @intFromPtr(chunk.data.ptr);
            try std.testing.expect(address >= @intFromPtr(data.ptr));
            try std.testing.expect(address + chunk.data.len <= @intFromPtr(data.ptr) + data.len);
        }
    }
}

test "a boundary match beyond the maximum still cuts at the maximum" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc(u8, constants.max_chunk_size + constants.min_chunk_size);
    defer allocator.free(input);
    var found = false;
    for (0..256) |seed| {
        fillRandom(input, seed);
        var hash: u64 = 0;
        var index: usize = constants.min_chunk_size - 64 - 1;
        var first_boundary: ?usize = null;
        while (index < input.len) : (index += 1) {
            hash = hash +% hash +% constants.gear_table[input[index]];
            if ((hash & constants.gear_mask) == 0) {
                first_boundary = index + 1;
                break;
            }
        }
        if (first_boundary) |boundary| {
            if (boundary > constants.max_chunk_size and boundary < input.len) {
                found = true;
                break;
            }
        }
    }
    try std.testing.expect(found);
    var chunker = Chunker.init();
    defer chunker.deinit(allocator);
    const result = try chunker.next(allocator, input, false);
    try std.testing.expectEqual(constants.max_chunk_size, result.consumed);
    try std.testing.expectEqual(constants.max_chunk_size, result.chunk.?.data.len);
}

test "empty and tiny inputs" {
    const empty = try chunkBuffer(std.testing.allocator, "");
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    const tiny = try chunkBuffer(std.testing.allocator, "hello");
    defer std.testing.allocator.free(tiny);
    try std.testing.expectEqual(@as(usize, 1), tiny.len);
    try std.testing.expectEqualStrings("hello", tiny[0].data);
}
