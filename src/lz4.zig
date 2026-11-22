//! LZ4 codec. Decodes linked blocks and encodes independent 64 KiB blocks

const std = @import("std");

const magic: u32 = 0x184d2204;
const block_size = 64 * 1024;
const last_literals = 5;
const match_end_padding = 12;

pub const Error = error{
    InvalidFrame,
    UnsupportedFrame,
    ChecksumMismatch,
    InvalidSize,
};

fn checksum(data: []const u8) u32 {
    return std.hash.XxHash32.hash(0, data);
}

fn lenSize(n: usize) usize {
    return if (n >= 15) (n - 15) / 255 + 1 else 0;
}

fn writeLen(dst: []u8, pos: *usize, n: usize) void {
    var left = n;
    while (left >= 255) : (left -= 255) {
        dst[pos.*] = 255;
        pos.* += 1;
    }
    dst[pos.*] = @intCast(left);
    pos.* += 1;
}

fn writeSeq(
    dst: []u8,
    pos: *usize,
    lits: []const u8,
    match: ?struct { offset: usize, len: usize },
) bool {
    const match_len = if (match) |m| m.len - 4 else 0;
    const needed = 1 + lenSize(lits.len) + lits.len +
        if (match != null) 2 + lenSize(match_len) else 0;
    if (pos.* + needed >= dst.len) return false;

    const lit_token: u8 = @intCast(@min(lits.len, 15));
    const match_token: u8 = @intCast(@min(match_len, 15));
    dst[pos.*] = (lit_token << 4) | match_token;
    pos.* += 1;
    if (lits.len >= 15) writeLen(dst, pos, lits.len - 15);
    @memcpy(dst[pos.*..][0..lits.len], lits);
    pos.* += lits.len;
    if (match) |m| {
        std.mem.writeInt(u16, dst[pos.*..][0..2], @intCast(m.offset), .little);
        pos.* += 2;
        if (match_len >= 15) writeLen(dst, pos, match_len - 15);
    }
    return true;
}

fn readLen(src: []const u8, pos: *usize, initial: usize) !usize {
    if (initial != 15) return initial;
    var len = initial;
    while (true) {
        if (pos.* >= src.len) return error.InvalidFrame;
        const byte = src[pos.*];
        pos.* += 1;
        len = std.math.add(usize, len, byte) catch return error.InvalidFrame;
        if (byte != 255) return len;
    }
}

pub const Scratch = struct {
    table: [1 << 13]u16 = undefined,
};

/// `dst` must have `input.len` bytes. Returns `null` unless compression shrinks
fn encodeBlock(scratch: *Scratch, input: []const u8, dst: []u8) ?usize {
    std.debug.assert(input.len <= block_size);
    std.debug.assert(dst.len == input.len);
    @memset(&scratch.table, std.math.maxInt(u16));

    var out_pos: usize = 0;
    var anchor: usize = 0;
    var pos: usize = 0;
    var search: usize = 0;
    while (pos + match_end_padding <= input.len) {
        const word = std.mem.readInt(u32, input[pos..][0..4], .little);
        const slot: usize = @intCast((word *% 2654435761) >> 19);
        const prev = scratch.table[slot];
        scratch.table[slot] = @intCast(pos);
        const mismatch = prev == std.math.maxInt(u16) or
            std.mem.readInt(u32, input[prev..][0..4], .little) != word;
        if (mismatch) {
            pos += 1 + ((pos - search) >> 6);
            continue;
        }

        const limit = input.len - last_literals;
        var len: usize = 4;
        while (pos + len + 8 <= limit) {
            const diff = std.mem.readInt(u64, input[pos + len ..][0..8], .little) ^
                std.mem.readInt(u64, input[prev + len ..][0..8], .little);
            if (diff != 0) {
                len += @ctz(diff) >> 3;
                break;
            }
            len += 8;
        }
        while (pos + len < limit and input[prev + len] == input[pos + len]) : (len += 1) {}
        if (!writeSeq(dst, &out_pos, input[anchor..pos], .{
            .offset = pos - prev,
            .len = len,
        })) return null;
        pos += len;
        anchor = pos;
        search = pos;
    }
    if (!writeSeq(dst, &out_pos, input[anchor..], null)) return null;
    return out_pos;
}

fn decodeBlock(
    src: []const u8,
    dst: []u8,
    dst_pos: *usize,
    history: usize,
) !void {
    var pos: usize = 0;
    var out = dst_pos.*;
    defer dst_pos.* = out;

    while (pos < src.len) {
        const token = src[pos];
        pos += 1;

        const lit_len = try readLen(src, &pos, token >> 4);
        const too_long = lit_len > src.len - pos or
            lit_len > dst.len - out;
        if (too_long) {
            return error.InvalidFrame;
        }
        @memcpy(dst[out..][0..lit_len], src[pos..][0..lit_len]);
        pos += lit_len;
        out += lit_len;
        if (pos == src.len) {
            if (token & 0x0f != 0) return error.InvalidFrame;
            return;
        }
        if (src.len - pos < 2) return error.InvalidFrame;

        const offset = std.mem.readInt(u16, src[pos..][0..2], .little);
        pos += 2;
        if (offset == 0 or offset > out - history) return error.InvalidFrame;
        const short_len = try readLen(src, &pos, token & 0x0f);
        const match_len = std.math.add(usize, short_len, 4) catch
            return error.InvalidFrame;
        if (match_len > dst.len - out) return error.InvalidFrame;

        if (offset >= match_len) {
            @memcpy(dst[out..][0..match_len], dst[out - offset ..][0..match_len]);
        } else if (offset == 1) {
            @memset(dst[out..][0..match_len], dst[out - 1]);
        } else {
            @memcpy(dst[out..][0..offset], dst[out - offset ..][0..offset]);
            var copied: usize = offset;
            while (copied < match_len) {
                const n = @min(copied, match_len - copied);
                @memcpy(dst[out + copied ..][0..n], dst[out..][0..n]);
                copied += n;
            }
        }
        out += match_len;
    }
}

pub fn decompress(
    allocator: std.mem.Allocator,
    input: []const u8,
    expected_size: usize,
) (Error || std.mem.Allocator.Error)![]u8 {
    const output = try allocator.alloc(u8, expected_size);
    errdefer allocator.free(output);
    try decompressInto(input, output);
    return output;
}

pub fn decompressInto(input: []const u8, output: []u8) Error!void {
    const expected_size = output.len;
    if (input.len < 7 or std.mem.readInt(u32, input[0..4], .little) != magic)
        return error.InvalidFrame;
    const flags = input[4];
    const descriptor = input[5];
    if (flags >> 6 != 1 or flags & 0x02 != 0 or descriptor & 0x8f != 0)
        return error.UnsupportedFrame;
    const block_code = (descriptor >> 4) & 0x07;
    if (block_code < 4) return error.UnsupportedFrame;
    const maximum_block_size: usize = @as(usize, 64 * 1024) << @intCast(block_code - 4);

    const has_content_size = flags & 0x08 != 0;
    const has_dictionary = flags & 0x01 != 0;
    if (has_dictionary) return error.UnsupportedFrame;
    const descriptor_length: usize = 2 + @as(usize, if (has_content_size) 8 else 0);
    if (input.len < 4 + descriptor_length + 1) return error.InvalidFrame;
    if (@as(u8, @truncate(checksum(input[4 .. 4 + descriptor_length]) >> 8)) !=
        input[4 + descriptor_length]) return error.ChecksumMismatch;

    if (has_content_size) {
        const declared_size = std.mem.readInt(u64, input[6..14], .little);
        if (declared_size != expected_size) return error.InvalidSize;
    }

    var output_position: usize = 0;
    var position: usize = 4 + descriptor_length + 1;
    const independent = flags & 0x20 != 0;
    const has_block_checksum = flags & 0x10 != 0;
    const has_content_checksum = flags & 0x04 != 0;

    while (true) {
        if (position > input.len or input.len - position < 4) return error.InvalidFrame;
        const block_header = std.mem.readInt(u32, input[position..][0..4], .little);
        position += 4;
        if (block_header == 0) break;
        const size: usize = block_header & 0x7fffffff;
        if (size > maximum_block_size or size > input.len - position) return error.InvalidFrame;
        const block = input[position..][0..size];
        position += size;
        if (has_block_checksum) {
            if (position > input.len or input.len - position < 4) return error.InvalidFrame;
            const expected = std.mem.readInt(u32, input[position..][0..4], .little);
            position += 4;
            if (checksum(block) != expected) return error.ChecksumMismatch;
        }

        const history_start = if (independent) output_position else 0;
        if (block_header & 0x80000000 != 0) {
            if (size > output.len - output_position) return error.InvalidSize;
            @memcpy(output[output_position..][0..size], block);
            output_position += size;
        } else {
            try decodeBlock(block, output, &output_position, history_start);
        }
    }

    if (has_content_checksum) {
        if (position > input.len or input.len - position < 4) return error.InvalidFrame;
        const expected = std.mem.readInt(u32, input[position..][0..4], .little);
        position += 4;
        if (checksum(output) != expected) return error.ChecksumMismatch;
    }
    if (position != input.len or output_position != output.len) return error.InvalidSize;
}

pub fn compressInto(
    allocator: std.mem.Allocator,
    input: []const u8,
    output: *std.ArrayList(u8),
    scratch: *Scratch,
) !void {
    const frame_start = output.items.len;
    errdefer output.shrinkRetainingCapacity(frame_start);
    const block_count = (input.len + block_size - 1) / block_size;
    try output.ensureUnusedCapacity(allocator, 15 + input.len + block_count * 4 + 8);

    var header: [15]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], magic, .little);
    header[4] = 0x6c; // Version 1, independent blocks, content size and checksum
    header[5] = 0x40; // 64 KiB maximum block size
    std.mem.writeInt(u64, header[6..14], input.len, .little);
    header[14] = @truncate(checksum(header[4..14]) >> 8);
    output.appendSliceAssumeCapacity(&header);

    var pos: usize = 0;
    while (pos < input.len) {
        const size = @min(block_size, input.len - pos);
        const block = input[pos..][0..size];
        output.items.len += 4;
        const payload_pos = output.items.len;
        output.items.len += size;
        const dst = output.items[payload_pos..][0..size];

        if (encodeBlock(scratch, block, dst)) |encoded_size| {
            output.items.len = payload_pos + encoded_size;
            std.mem.writeInt(
                u32,
                output.items[payload_pos - 4 ..][0..4],
                @intCast(encoded_size),
                .little,
            );
        } else {
            @memcpy(dst, block);
            std.mem.writeInt(
                u32,
                output.items[payload_pos - 4 ..][0..4],
                @as(u32, @intCast(size)) | 0x80000000,
                .little,
            );
        }
        pos += size;
    }

    var trailer: [8]u8 = @splat(0);
    std.mem.writeInt(u32, trailer[4..8], checksum(input), .little);
    output.appendSliceAssumeCapacity(&trailer);
}

/// Allocates scratch internally. Use `compressInto` to supply scratch
pub fn compress(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const scratch = try allocator.create(Scratch);
    defer allocator.destroy(scratch);
    try compressInto(allocator, input, &output, scratch);
    return output.toOwnedSlice(allocator);
}

test "block decoder handles non-overlapping and repeating matches" {
    const allocator = std.testing.allocator;
    var prefix: [128]u8 = undefined;
    for (&prefix, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% 11);
    for ([_]usize{ 1, 2, 3, 4, 7, 16, 64, 128 }) |offset| {
        for ([_]usize{ 4, 5, 15, 16, 19, 20, 64, 255, 1024 }) |match_length| {
            var encoded_buf: [256]u8 = undefined;
            var encoded_len: usize = 0;
            try std.testing.expect(writeSeq(&encoded_buf, &encoded_len, prefix[0..offset], .{
                .offset = offset,
                .len = match_length,
            }));

            const expected = try allocator.alloc(u8, offset + match_length);
            defer allocator.free(expected);
            @memcpy(expected[0..offset], prefix[0..offset]);
            for (offset..expected.len) |index| expected[index] = expected[index - offset];

            const decoded = try allocator.alloc(u8, expected.len);
            defer allocator.free(decoded);
            var decoded_length: usize = 0;
            try decodeBlock(encoded_buf[0..encoded_len], decoded, &decoded_length, 0);
            try std.testing.expectEqual(decoded.len, decoded_length);
            try std.testing.expectEqualSlices(u8, expected, decoded);
        }
    }
}

test "LZ4 round trips and compresses repeated data" {
    const allocator = std.testing.allocator;
    const phrase = "the quick brown fox jumps over the lazy dog; ";
    var original: [phrase.len * 3000]u8 = undefined;
    for (0..3000) |i| @memcpy(original[i * phrase.len ..][0..phrase.len], phrase);
    const encoded = try compress(allocator, &original);
    defer allocator.free(encoded);
    try std.testing.expect(encoded.len < original.len / 2);
    const decoded = try decompress(allocator, encoded, original.len);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(&original, decoded);
    const direct = try allocator.alloc(u8, original.len);
    defer allocator.free(direct);
    try decompressInto(encoded, direct);
    try std.testing.expectEqualSlices(u8, &original, direct);
}

test "LZ4 round trips many sizes and incompressible blocks" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(42);
    for ([_]usize{ 0, 1, 15, 16, 255, 4096, 65535, 65536, 65537, 200000 }) |size| {
        const original = try allocator.alloc(u8, size);
        defer allocator.free(original);
        prng.random().bytes(original);
        const encoded = try compress(allocator, original);
        defer allocator.free(encoded);
        const decoded = try decompress(allocator, encoded, size);
        defer allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, original, decoded);
    }
}

test "every truncated frame is rejected without reading out of bounds" {
    const allocator = std.testing.allocator;
    const encoded = try compress(allocator, "hello hello hello hello");
    defer allocator.free(encoded);
    for (0..encoded.len) |length| {
        if (decompress(allocator, encoded[0..length], 23)) |decoded| {
            allocator.free(decoded);
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    const raw = [_]u8{
        0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82,
        1, 0, 0, 0, 0x01, // Compressed block with an invalid final token
        0, 0, 0, 0, // End mark
    };
    try std.testing.expectError(error.InvalidFrame, decompress(allocator, &raw, 0));
}

test "LZ4 rejects corruption and wrong output size" {
    const allocator = std.testing.allocator;
    const encoded = try compress(allocator, "hello hello hello hello");
    defer allocator.free(encoded);
    try std.testing.expectError(error.InvalidSize, decompress(allocator, encoded, 2));
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, decompress(allocator, encoded, 23));
}
