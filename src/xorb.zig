//! Xorb chunk streams and V1 object footers

const std = @import("std");
const constants = @import("constants.zig");
const hashing = @import("hash.zig");
const lz4 = @import("lz4.zig");
const shard = @import("shard.zig");
const stream = @import("stream.zig");

pub const Compression = enum(u8) {
    none = 0,
    lz4 = 1,
    bg4_lz4 = 2,
};

pub const Chunk = struct {
    data: []const u8,
    hash: hashing.Hash,
};

pub const Serialized = struct {
    bytes: []u8,
    body_length: usize,
    hash: hashing.Hash,
    raw_size: u64,
    chunks: []shard.Chunk,
    nodes: []hashing.Node,

    pub fn deinit(self: *Serialized, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.chunks);
        allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn verificationHash(self: *const Serialized) hashing.Hash {
        return hashing.verificationNodes(self.nodes);
    }
};

pub const Error = error{
    InvalidXorb,
    UnsupportedVersion,
    UnsupportedCompression,
    InvalidChunkSize,
    InvalidRange,
    HashMismatch,
    SizeMismatch,
};

fn getU24(input: []const u8) usize {
    return input[0] | @as(usize, input[1]) << 8 | @as(usize, input[2]) << 16;
}

fn putU32(output: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try output.appendSlice(allocator, &bytes);
}

fn group4(input: []const u8, output: []u8) void {
    std.debug.assert(output.len == input.len);
    const split = input.len / 4;
    const remainder = input.len % 4;
    const g1 = split + @as(usize, @intFromBool(remainder >= 1));
    const g2 = g1 + split + @as(usize, @intFromBool(remainder >= 2));
    const g3 = g2 + split + @as(usize, @intFromBool(remainder >= 3));
    for (0..split) |i| {
        output[i] = input[4 * i];
        output[g1 + i] = input[4 * i + 1];
        output[g2 + i] = input[4 * i + 2];
        output[g3 + i] = input[4 * i + 3];
    }
    for (0..remainder) |i| {
        const starts = [_]usize{ 0, g1, g2 };
        output[starts[i] + split] = input[4 * split + i];
    }
}

fn ungroup4(input: []const u8, output: []u8) void {
    const split = input.len / 4;
    const remainder = input.len % 4;
    const g1 = split + @as(usize, @intFromBool(remainder >= 1));
    const g2 = g1 + split + @as(usize, @intFromBool(remainder >= 2));
    const g3 = g2 + split + @as(usize, @intFromBool(remainder >= 3));
    for (0..split) |i| {
        output[4 * i] = input[i];
        output[4 * i + 1] = input[g1 + i];
        output[4 * i + 2] = input[g2 + i];
        output[4 * i + 3] = input[g3 + i];
    }
    for (0..remainder) |i| {
        const starts = [_]usize{ 0, g1, g2 };
        output[4 * split + i] = input[starts[i] + split];
    }
}

fn compressChunk(
    allocator: std.mem.Allocator,
    input: []const u8,
    compression: Compression,
    output: *std.ArrayList(u8),
    scratch: ?*lz4.Scratch,
    transformed: *std.ArrayList(u8),
) !void {
    const frame_start = output.items.len;
    errdefer output.shrinkRetainingCapacity(frame_start);
    try output.appendNTimes(allocator, 0, 8);
    const payload_start = output.items.len;
    if (compression != .none) {
        const source = if (compression == .bg4_lz4) source: {
            try transformed.resize(allocator, input.len);
            group4(input, transformed.items);
            break :source transformed.items;
        } else input;
        try lz4.compressInto(allocator, source, output, scratch orelse unreachable);
    }
    const actual = if (compression == .none or output.items.len - payload_start >= input.len)
        Compression.none
    else
        compression;
    if (actual == .none) {
        output.shrinkRetainingCapacity(payload_start);
        try output.appendSlice(allocator, input);
    }
    const payload_length = output.items.len - payload_start;
    const header = output.items[payload_start - 8 .. payload_start];
    header[0] = 0;
    std.mem.writeInt(u24, header[1..4], @intCast(payload_length), .little);
    header[4] = @backingInt(actual);
    std.mem.writeInt(u24, header[5..8], @intCast(input.len), .little);
}

fn footerLength(chunk_count: usize) u32 {
    return @intCast(92 + 40 * chunk_count);
}

/// Borrows chunk data only during `add`
pub const Serializer = struct {
    compression: Compression,
    output: std.ArrayList(u8) = .empty,
    chunks: std.ArrayList(shard.Chunk) = .empty,
    nodes: std.ArrayList(hashing.Node) = .empty,
    packed_boundaries: std.ArrayList(u32) = .empty,
    raw_size: u64 = 0,
    scratch: ?*lz4.Scratch = null,
    transformed: std.ArrayList(u8) = .empty,

    pub fn init(compression: Compression) Serializer {
        return .{ .compression = compression };
    }

    pub fn deinit(self: *Serializer, allocator: std.mem.Allocator) void {
        self.output.deinit(allocator);
        self.chunks.deinit(allocator);
        self.nodes.deinit(allocator);
        self.packed_boundaries.deinit(allocator);
        if (self.scratch) |scratch| allocator.destroy(scratch);
        self.transformed.deinit(allocator);
        self.* = undefined;
    }

    pub fn add(self: *Serializer, allocator: std.mem.Allocator, chunk: Chunk) !void {
        if (self.chunks.items.len == constants.max_xorb_chunks) return error.InvalidRange;
        if (chunk.data.len == 0 or chunk.data.len > constants.max_chunk_size)
            return error.InvalidChunkSize;
        const raw_size = std.math.add(u64, self.raw_size, chunk.data.len) catch
            return error.InvalidChunkSize;
        if (raw_size > constants.max_xorb_size) return error.InvalidChunkSize;

        const output_length = self.output.items.len;
        const chunk_count = self.chunks.items.len;
        const node_count = self.nodes.items.len;
        errdefer self.output.shrinkRetainingCapacity(output_length);
        errdefer self.chunks.shrinkRetainingCapacity(chunk_count);
        errdefer self.nodes.shrinkRetainingCapacity(node_count);
        try self.chunks.append(allocator, .{
            .hash = chunk.hash,
            .byte_range_start = @intCast(self.raw_size),
            .unpacked_segment_bytes = @intCast(chunk.data.len),
        });
        try self.nodes.append(allocator, .{ .hash = chunk.hash, .size = chunk.data.len });
        if (self.compression != .none and self.scratch == null) {
            self.scratch = try allocator.create(lz4.Scratch);
        }
        try compressChunk(
            allocator,
            chunk.data,
            self.compression,
            &self.output,
            self.scratch,
            &self.transformed,
        );
        try self.packed_boundaries.append(allocator, @intCast(self.output.items.len));
        self.raw_size = raw_size;
    }

    pub fn finish(self: *Serializer, allocator: std.mem.Allocator) !Serialized {
        const chunk_count = self.chunks.items.len;
        if (chunk_count == 0) return error.InvalidRange;
        const object_hash = try hashing.xorb(allocator, self.nodes.items);
        const body_length = self.output.items.len;
        errdefer self.output.shrinkRetainingCapacity(body_length);
        try self.output.appendSlice(allocator, "XETBLOB");
        try self.output.append(allocator, 1);
        try self.output.appendSlice(allocator, &object_hash);
        try self.output.appendSlice(allocator, "XBLBHSH");
        try self.output.append(allocator, 0);
        try putU32(&self.output, allocator, @intCast(chunk_count));
        for (self.nodes.items) |node| try self.output.appendSlice(allocator, &node.hash);
        try self.output.appendSlice(allocator, "XBLBBND");
        try self.output.append(allocator, 1);
        try putU32(&self.output, allocator, @intCast(chunk_count));
        for (self.packed_boundaries.items) |boundary| try putU32(&self.output, allocator, boundary);
        for (self.chunks.items) |entry| try putU32(
            &self.output,
            allocator,
            entry.byte_range_start + entry.unpacked_segment_bytes,
        );
        try putU32(&self.output, allocator, @intCast(chunk_count));
        try putU32(&self.output, allocator, @intCast(52 + 40 * chunk_count));
        try putU32(&self.output, allocator, @intCast(40 + 8 * chunk_count));
        try self.output.appendNTimes(allocator, 0, 16);
        const info_length = footerLength(chunk_count);
        if (self.output.items.len - body_length != info_length) return error.InvalidXorb;
        try putU32(&self.output, allocator, info_length);

        const chunks = try allocator.dupe(shard.Chunk, self.chunks.items);
        errdefer allocator.free(chunks);
        const nodes = try allocator.dupe(hashing.Node, self.nodes.items);
        errdefer allocator.free(nodes);
        const bytes = try self.output.toOwnedSlice(allocator);

        const raw_size = self.raw_size;
        self.chunks.clearRetainingCapacity();
        self.nodes.clearRetainingCapacity();
        self.packed_boundaries.clearRetainingCapacity();
        self.raw_size = 0;
        return .{
            .bytes = bytes,
            .body_length = body_length,
            .hash = object_hash,
            .raw_size = raw_size,
            .chunks = chunks,
            .nodes = nodes,
        };
    }
};

/// Borrows chunks only for this call
pub fn serialize(
    allocator: std.mem.Allocator,
    chunks: []const Chunk,
    compression: Compression,
) !Serialized {
    var serializer: Serializer = .init(compression);
    defer serializer.deinit(allocator);
    for (chunks) |chunk| try serializer.add(allocator, chunk);
    return serializer.finish(allocator);
}

const Footer = struct {
    body_length: usize,
    chunk_count: usize,
    hash: hashing.Hash,
};

pub fn parseFooter(input: []const u8) !Footer {
    if (input.len < 4 + 60) return error.InvalidXorb;
    const info_length = std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little);
    if (info_length < 60 or info_length > input.len - 4) return error.InvalidXorb;
    const start = input.len - 4 - info_length;
    const info = input[start .. input.len - 4];
    if (!std.mem.eql(u8, info[0..7], "XETBLOB")) return error.InvalidXorb;
    if (info[7] != 1) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, info[40..47], "XBLBHSH") or info[47] != 0)
        return error.InvalidXorb;
    const count = std.mem.readInt(u32, info[48..52], .little);
    if (info_length != 92 + 40 * @as(u64, count)) return error.InvalidXorb;
    const hash = info[8..40].*;
    const boundary_start = 52 + 32 * count;
    if (!std.mem.eql(u8, info[boundary_start..][0..7], "XBLBBND") or
        info[boundary_start + 7] != 1) return error.InvalidXorb;
    const boundary_count = std.mem.readInt(u32, info[boundary_start + 8 ..][0..4], .little);
    if (boundary_count != count) return error.InvalidXorb;
    const boundaries = info[boundary_start + 12 ..][0 .. 4 * count];
    var previous: u32 = 0;
    for (0..count) |i| {
        const end = std.mem.readInt(u32, boundaries[i * 4 ..][0..4], .little);
        if (end <= previous or end > start) return error.InvalidXorb;
        previous = end;
    }
    if (previous != start) return error.InvalidXorb;
    return .{ .body_length = start, .chunk_count = count, .hash = hash };
}

pub const Decoded = struct {
    bytes: []u8,
    chunk_lengths: []u32,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.chunk_lengths);
        self.* = undefined;
    }
};

/// Decode a complete Xorb or a raw range of chunk-stream records
pub fn decodeRange(
    allocator: std.mem.Allocator,
    input: []const u8,
    start: u32,
    end: u32,
) !Decoded {
    if (start >= end) return error.InvalidRange;
    const body_length = if (parseFooter(input)) |footer| blk: {
        if (end > footer.chunk_count) return error.InvalidRange;
        break :blk footer.body_length;
    } else |_| input.len;

    var lengths: std.ArrayList(u32) = .empty;
    errdefer lengths.deinit(allocator);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(allocator);
    var position: usize = 0;
    var index: u32 = 0;
    while (position < body_length and index < end) : (index += 1) {
        if (body_length - position < 8) return error.InvalidXorb;
        const header = input[position..][0..8];
        position += 8;
        if (header[0] != 0) return error.UnsupportedVersion;
        const compressed_size = getU24(header[1..4]);
        const raw_size = getU24(header[5..8]);
        if (compressed_size > body_length - position or
            compressed_size > 2 * constants.max_chunk_size or
            raw_size == 0 or raw_size > constants.max_chunk_size) return error.InvalidChunkSize;
        const payload = input[position..][0..compressed_size];
        position += compressed_size;
        if (index < start) continue;
        const compression = std.enums.fromInt(Compression, header[4]) orelse
            return error.UnsupportedCompression;
        switch (compression) {
            .none => {
                if (payload.len != raw_size) return error.SizeMismatch;
                try output.appendSlice(allocator, payload);
            },
            .lz4, .bg4_lz4 => {
                const old_length = output.items.len;
                try output.resize(allocator, old_length + raw_size);
                const decoded = output.items[old_length..];
                if (compression == .lz4) {
                    lz4.decompressInto(payload, decoded) catch return error.InvalidXorb;
                } else {
                    try scratch.resize(allocator, raw_size);
                    lz4.decompressInto(payload, scratch.items) catch return error.InvalidXorb;
                    ungroup4(scratch.items, decoded);
                }
            },
        }
        try lengths.append(allocator, @intCast(raw_size));
    }
    if (index != end) return error.InvalidRange;
    const bytes = try output.toOwnedSlice(allocator);
    errdefer allocator.free(bytes);
    const chunk_lengths = try lengths.toOwnedSlice(allocator);
    return .{
        .bytes = bytes,
        .chunk_lengths = chunk_lengths,
    };
}

fn readExact(source: *std.Io.Reader, output: []u8) !void {
    source.readSliceAll(output) catch |err| switch (err) {
        error.EndOfStream => return error.InvalidXorb,
        error.ReadFailed => return error.ReadFailed,
    };
}

fn discardExact(source: *std.Io.Reader, count: usize) !void {
    source.discardAll(count) catch |err| switch (err) {
        error.EndOfStream => return error.InvalidXorb,
        error.ReadFailed => return error.ReadFailed,
    };
}

/// Discards skipped chunks and retains one compressed and one decompressed chunk
pub fn decodeStream(
    allocator: std.mem.Allocator,
    source: *std.Io.Reader,
    start: u32,
    end: u32,
    sink: *std.Io.Writer,
) !u64 {
    if (start >= end) return error.InvalidRange;
    var compressed: std.ArrayList(u8) = .empty;
    defer compressed.deinit(allocator);
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);
    var total: u64 = 0;
    var index: u32 = 0;
    while (index < end) : (index += 1) {
        var header: [8]u8 = undefined;
        try readExact(source, &header);
        if (header[0] != 0) return error.UnsupportedVersion;
        const compressed_size = getU24(header[1..4]);
        const raw_size = getU24(header[5..8]);
        if (compressed_size > 2 * constants.max_chunk_size or
            raw_size == 0 or raw_size > constants.max_chunk_size) return error.InvalidChunkSize;
        if (index < start) {
            try discardExact(source, compressed_size);
            continue;
        }

        const compression = std.enums.fromInt(Compression, header[4]) orelse
            return error.UnsupportedCompression;
        switch (compression) {
            .none => {
                if (compressed_size != raw_size) return error.SizeMismatch;
                var buffer: [stream.scratch_buffer_size]u8 = undefined;
                var remaining = raw_size;
                while (remaining != 0) {
                    const count = @min(remaining, buffer.len);
                    try readExact(source, buffer[0..count]);
                    try sink.writeAll(buffer[0..count]);
                    total += count;
                    remaining -= count;
                }
            },
            .lz4, .bg4_lz4 => {
                try compressed.resize(allocator, compressed_size);
                try readExact(source, compressed.items);
                try decoded.resize(allocator, raw_size);
                lz4.decompressInto(compressed.items, decoded.items) catch return error.InvalidXorb;
                if (compression == .lz4) {
                    try sink.writeAll(decoded.items);
                } else {
                    try compressed.resize(allocator, raw_size);
                    ungroup4(decoded.items, compressed.items);
                    try sink.writeAll(compressed.items);
                }
                total += raw_size;
            },
        }
    }
    return total;
}

/// Verifies a complete V1 Xorb against the expected object hash
pub fn verifyHash(allocator: std.mem.Allocator, input: []const u8, expected: hashing.Hash) !void {
    const footer = try parseFooter(input);
    if (!hashing.eql(expected, footer.hash)) return error.HashMismatch;
    return verify(allocator, input);
}

/// Verifies chunks, footer metadata, and object hash
pub fn verify(allocator: std.mem.Allocator, input: []const u8) !void {
    const footer = try parseFooter(input);
    const info = input[footer.body_length .. input.len - 4];
    const hashes = info[52..][0 .. 32 * footer.chunk_count];
    const boundaries_start = 64 + 32 * footer.chunk_count;
    const packed_boundaries = info[boundaries_start..][0 .. 4 * footer.chunk_count];
    const unpacked_boundaries = info[boundaries_start + 4 * footer.chunk_count ..][0 .. 4 * footer.chunk_count];

    var nodes: std.ArrayList(hashing.Node) = .empty;
    defer nodes.deinit(allocator);
    try nodes.ensureTotalCapacity(allocator, footer.chunk_count);
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(allocator);
    var position: usize = 0;
    var unpacked: u64 = 0;
    for (0..footer.chunk_count) |index| {
        if (position > footer.body_length or footer.body_length - position < 8) return error.InvalidXorb;
        const header = input[position..][0..8];
        position += 8;
        if (header[0] != 0) return error.UnsupportedVersion;
        const compressed_size = getU24(header[1..4]);
        const raw_size = getU24(header[5..8]);
        if (compressed_size > footer.body_length - position or
            compressed_size > 2 * constants.max_chunk_size or
            raw_size == 0 or raw_size > constants.max_chunk_size) return error.InvalidChunkSize;
        const payload = input[position..][0..compressed_size];
        const compression = std.enums.fromInt(Compression, header[4]) orelse
            return error.UnsupportedCompression;
        const chunk_bytes = switch (compression) {
            .none => blk: {
                if (payload.len != raw_size) return error.SizeMismatch;
                break :blk payload;
            },
            .lz4, .bg4_lz4 => blk: {
                try decoded.resize(allocator, raw_size);
                if (compression == .lz4) {
                    lz4.decompressInto(payload, decoded.items) catch return error.InvalidXorb;
                } else {
                    try scratch.resize(allocator, raw_size);
                    lz4.decompressInto(payload, scratch.items) catch return error.InvalidXorb;
                    ungroup4(scratch.items, decoded.items);
                }
                break :blk decoded.items;
            },
        };
        const chunk_hash = hashing.data(chunk_bytes);
        if (!hashing.eql(chunk_hash, hashes[index * 32 ..][0..32].*)) return error.HashMismatch;
        nodes.appendAssumeCapacity(.{ .hash = chunk_hash, .size = raw_size });

        position = std.math.add(usize, position, compressed_size) catch return error.InvalidXorb;
        if (position > footer.body_length) return error.InvalidXorb;
        const packed_end = std.mem.readInt(u32, packed_boundaries[index * 4 ..][0..4], .little);
        if (packed_end != position) return error.InvalidXorb;
        unpacked = std.math.add(u64, unpacked, raw_size) catch return error.InvalidChunkSize;
        const unpacked_end = std.mem.readInt(u32, unpacked_boundaries[index * 4 ..][0..4], .little);
        if (unpacked_end != unpacked) return error.InvalidXorb;
    }
    if (position != footer.body_length) return error.InvalidXorb;
    const actual = try hashing.xorb(allocator, nodes.items);
    if (!hashing.eql(actual, footer.hash)) return error.HashMismatch;
}

test "serialize releases direct compression scratch after allocation failures" {
    const support = @import("test_support");
    var first: [65_536]u8 = undefined;
    var second: [32_768]u8 = undefined;
    for (&first, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% index / 131);
    for (&second, 0..) |*byte, index| byte.* = @truncate(index *% 37 +% index / 79);
    const chunks = [_]Chunk{
        .{ .data = &first, .hash = hashing.data(&first) },
        .{ .data = &second, .hash = hashing.data(&second) },
    };

    for ([_]Compression{ .lz4, .bg4_lz4 }) |compression| {
        var baseline = support.TrackingAllocator{ .backing = std.testing.allocator };
        defer baseline.deinit();
        var object = try serialize(baseline.allocator(), &chunks, compression);
        object.deinit(baseline.allocator());
        try std.testing.expectEqual(@as(usize, 0), baseline.outstanding());

        for (0..baseline.allocation_count) |fail_at| {
            var tracker = support.TrackingAllocator{
                .backing = std.testing.allocator,
                .fail_at = fail_at,
            };
            defer tracker.deinit();
            if (serialize(tracker.allocator(), &chunks, compression)) |value| {
                var serialized = value;
                serialized.deinit(tracker.allocator());
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
            }
            try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
            try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
            try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
        }
    }
}

test "incremental serialization is identical and retryable after allocation failure" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(42);
    var input: [128 * 1024]u8 = undefined;
    prng.random().bytes(&input);
    const chunk = Chunk{ .data = &input, .hash = hashing.data(&input) };
    for ([_]Compression{ .lz4, .bg4_lz4 }) |compression| {
        var expected = try serialize(allocator, &.{chunk}, compression);
        defer expected.deinit(allocator);

        var baseline: support.TrackingAllocator = .{ .backing = allocator };
        defer baseline.deinit();
        var baseline_serializer: Serializer = .init(compression);
        try baseline_serializer.add(baseline.allocator(), chunk);
        const add_allocations = baseline.allocation_count;
        var baseline_object = try baseline_serializer.finish(baseline.allocator());
        const finish_allocations = baseline.allocation_count - add_allocations;
        baseline_object.deinit(baseline.allocator());
        baseline_serializer.deinit(baseline.allocator());
        try std.testing.expectEqual(@as(usize, 0), baseline.outstanding());

        for (0..add_allocations + finish_allocations) |fail_at| {
            var tracker: support.TrackingAllocator = .{
                .backing = allocator,
                .fail_at = fail_at,
            };
            defer tracker.deinit();
            var serializer: Serializer = .init(compression);
            errdefer serializer.deinit(tracker.allocator());
            if (fail_at < add_allocations) {
                try std.testing.expectError(error.OutOfMemory, serializer.add(tracker.allocator(), chunk));
                try std.testing.expectEqual(@as(usize, 0), serializer.output.items.len);
                try std.testing.expectEqual(@as(usize, 0), serializer.chunks.items.len);
                try std.testing.expectEqual(@as(usize, 0), serializer.nodes.items.len);
                tracker.fail_at = null;
                try serializer.add(tracker.allocator(), chunk);
            } else {
                try serializer.add(tracker.allocator(), chunk);
                try std.testing.expectError(error.OutOfMemory, serializer.finish(tracker.allocator()));
                try std.testing.expectEqualSlices(u8, expected.bytes[0..expected.body_length], serializer.output.items);
                try std.testing.expectEqual(@as(usize, 1), serializer.chunks.items.len);
                try std.testing.expectEqual(@as(usize, 1), serializer.nodes.items.len);
                try std.testing.expectEqual(@as(usize, 1), serializer.packed_boundaries.items.len);
                try std.testing.expectEqual(@as(u64, input.len), serializer.raw_size);
                tracker.fail_at = null;
            }
            var actual = try serializer.finish(tracker.allocator());
            try std.testing.expectEqualSlices(u8, expected.bytes, actual.bytes);
            try std.testing.expectEqualSlices(shard.Chunk, expected.chunks, actual.chunks);
            try std.testing.expectEqualSlices(hashing.Node, expected.nodes, actual.nodes);
            actual.deinit(tracker.allocator());
            serializer.deinit(tracker.allocator());
            try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
        }
    }
}

test "Serializer is unmanaged and allocates scratch only for compression" {
    const allocator = std.testing.allocator;
    const chunk = Chunk{ .data = "chunk", .hash = hashing.data("chunk") };
    var plain: Serializer = .init(.none);
    defer plain.deinit(allocator);
    try std.testing.expect(plain.scratch == null);
    try plain.add(allocator, chunk);
    try std.testing.expect(plain.scratch == null);
    var plain_object = try plain.finish(allocator);
    defer plain_object.deinit(allocator);

    var compressed: Serializer = .init(.lz4);
    defer compressed.deinit(allocator);
    try compressed.add(allocator, chunk);
    try std.testing.expect(compressed.scratch != null);
    var compressed_object = try compressed.finish(allocator);
    defer compressed_object.deinit(allocator);
    try std.testing.expect(compressed.scratch != null);
}

test "V1 Xorb round trip and footer verification" {
    const allocator = std.testing.allocator;
    const chunks = [_]Chunk{
        .{ .data = "first chunk", .hash = hashing.data("first chunk") },
        .{ .data = "second chunk", .hash = hashing.data("second chunk") },
        .{ .data = "third chunk", .hash = hashing.data("third chunk") },
    };
    for ([_]Compression{ .none, .lz4, .bg4_lz4 }) |compression| {
        var object = try serialize(allocator, &chunks, compression);
        defer object.deinit(allocator);
        try verify(allocator, object.bytes);
        var decoded = try decodeRange(allocator, object.bytes, 1, 3);
        defer decoded.deinit(allocator);
        try std.testing.expectEqualStrings("second chunkthird chunk", decoded.bytes);
        try std.testing.expectEqualSlices(u32, &.{ 12, 11 }, decoded.chunk_lengths);
    }
}

test "incremental decoding handles one-byte reads and skipped chunks" {
    const allocator = std.testing.allocator;
    const first = try allocator.alloc(u8, 100_000);
    defer allocator.free(first);
    @memset(first, 0x41);
    const chunks = [_]Chunk{
        .{ .data = first, .hash = hashing.data(first) },
        .{ .data = "second chunk", .hash = hashing.data("second chunk") },
        .{ .data = "third chunk", .hash = hashing.data("third chunk") },
    };
    for ([_]Compression{ .none, .lz4, .bg4_lz4 }) |compression| {
        var object = try serialize(allocator, &chunks, compression);
        defer object.deinit(allocator);
        const Context = struct {
            bytes: []const u8,
            position: usize = 0,
            reader: std.Io.Reader = .{ .vtable = &.{ .stream = streamOne }, .buffer = &.{}, .seek = 0, .end = 0 },

            fn streamOne(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                const self: *@This() = @fieldParentPtr("reader", reader);
                if (self.position == self.bytes.len or limit == .nothing) return error.EndOfStream;
                try writer.writeAll(self.bytes[self.position..][0..1]);
                self.position += 1;
                return 1;
            }
        };
        var context = Context{ .bytes = object.bytes[0 .. object.bytes.len - footerLength(chunks.len) - 4] };
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        const count = try decodeStream(allocator, &context.reader, 1, 3, &output.writer);
        try std.testing.expectEqual(@as(u64, 23), count);
        try std.testing.expectEqualStrings("second chunkthird chunk", output.written());
        try std.testing.expectEqual(context.bytes.len, context.position);
    }
}

test "compressed decoders reuse scratch across every chunk" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    const chunks = [_]Chunk{
        .{ .data = "first", .hash = hashing.data("first") },
        .{ .data = "second", .hash = hashing.data("second") },
        .{ .data = "three", .hash = hashing.data("three") },
        .{ .data = "fifth", .hash = hashing.data("fifth") },
    };
    for ([_]Compression{ .lz4, .bg4_lz4 }) |compression| {
        var object = try serialize(allocator, &chunks, compression);
        defer object.deinit(allocator);
        var pair = try serialize(allocator, chunks[0..2], compression);
        defer pair.deinit(allocator);
        const footer = try parseFooter(object.bytes);

        var stream_tracker: support.TrackingAllocator = .{ .backing = allocator };
        defer stream_tracker.deinit();
        var source: std.Io.Reader = .fixed(object.bytes[0..footer.body_length]);
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        try std.testing.expectEqual(@as(u64, 21), try decodeStream(
            stream_tracker.allocator(),
            &source,
            0,
            chunks.len,
            &output.writer,
        ));
        try std.testing.expectEqualStrings("firstsecondthreefifth", output.written());
        try std.testing.expect(stream_tracker.allocation_count <= 2);
        try std.testing.expectEqual(@as(usize, 0), stream_tracker.outstanding());

        var pair_tracker: support.TrackingAllocator = .{ .backing = allocator };
        defer pair_tracker.deinit();
        var pair_decoded = try decodeRange(pair_tracker.allocator(), pair.bytes, 0, 2);
        pair_decoded.deinit(pair_tracker.allocator());
        try std.testing.expectEqual(@as(usize, 0), pair_tracker.outstanding());

        var range_tracker: support.TrackingAllocator = .{ .backing = allocator };
        defer range_tracker.deinit();
        var decoded = try decodeRange(range_tracker.allocator(), object.bytes, 0, chunks.len);
        try std.testing.expectEqualStrings("firstsecondthreefifth", decoded.bytes);
        decoded.deinit(range_tracker.allocator());
        try std.testing.expect(range_tracker.allocation_count - pair_tracker.allocation_count <= 1);
        try std.testing.expectEqual(@as(usize, 0), range_tracker.outstanding());
    }
}

test "verification decode allocations do not scale with chunk count" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    const first: [256]u8 = @splat(1);
    const second: [256]u8 = @splat(2);
    const third: [256]u8 = @splat(3);
    const fourth: [256]u8 = @splat(4);
    const chunks = [_]Chunk{
        .{ .data = &first, .hash = hashing.data(&first) },
        .{ .data = &second, .hash = hashing.data(&second) },
        .{ .data = &third, .hash = hashing.data(&third) },
        .{ .data = &fourth, .hash = hashing.data(&fourth) },
    };
    for ([_]Compression{ .none, .lz4, .bg4_lz4 }) |compression| {
        var pair = try serialize(allocator, chunks[0..2], compression);
        defer pair.deinit(allocator);
        var object = try serialize(allocator, &chunks, compression);
        defer object.deinit(allocator);
        var position: usize = 0;
        for (chunks) |_| {
            const header = object.bytes[position..][0..8];
            try std.testing.expectEqual(compression, std.enums.fromInt(Compression, header[4]));
            position += 8 + getU24(header[1..4]);
        }

        var pair_tracker: support.TrackingAllocator = .{ .backing = allocator };
        defer pair_tracker.deinit();
        try verify(pair_tracker.allocator(), pair.bytes);
        try std.testing.expectEqual(@as(usize, 0), pair_tracker.outstanding());

        var object_tracker: support.TrackingAllocator = .{ .backing = allocator };
        defer object_tracker.deinit();
        try verify(object_tracker.allocator(), object.bytes);
        try std.testing.expectEqual(pair_tracker.allocation_count, object_tracker.allocation_count);
        if (compression == .none) {
            try std.testing.expectEqual(@as(usize, 2), object_tracker.allocation_count);
        }
        try std.testing.expectEqual(@as(usize, 0), object_tracker.outstanding());
    }
}

test "BG4 streaming ungroups multiple actually compressed chunks" {
    const allocator = std.testing.allocator;
    var first: [64 * 1024]u8 = undefined;
    var second: [64 * 1024]u8 = undefined;
    var third: [64 * 1024]u8 = undefined;
    for (&first, 0..) |*byte, index| byte.* = @truncate(index % 16);
    for (&second, 0..) |*byte, index| byte.* = @truncate(index % 16 + 1);
    for (&third, 0..) |*byte, index| byte.* = @truncate(index % 16 + 2);
    const inputs = [_][]const u8{ &first, &second, &third };
    const chunks = [_]Chunk{
        .{ .data = &first, .hash = hashing.data(&first) },
        .{ .data = &second, .hash = hashing.data(&second) },
        .{ .data = &third, .hash = hashing.data(&third) },
    };
    var object = try serialize(allocator, &chunks, .bg4_lz4);
    defer object.deinit(allocator);
    const footer = try parseFooter(object.bytes);

    var position: usize = 0;
    for (inputs) |input| {
        const header = object.bytes[position..][0..8];
        const compressed_size = getU24(header[1..4]);
        const raw_size = getU24(header[5..8]);
        try std.testing.expectEqual(Compression.bg4_lz4, std.enums.fromInt(Compression, header[4]));
        try std.testing.expectEqual(input.len, raw_size);
        try std.testing.expect(compressed_size < raw_size);
        position += 8 + compressed_size;
    }
    try std.testing.expectEqual(footer.body_length, position);

    var source: std.Io.Reader = .fixed(object.bytes[0..footer.body_length]);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectEqual(@as(u64, 3 * 64 * 1024), try decodeStream(
        allocator,
        &source,
        0,
        chunks.len,
        &output.writer,
    ));
    try std.testing.expectEqualSlices(u8, &first, output.written()[0..first.len]);
    try std.testing.expectEqualSlices(u8, &second, output.written()[first.len..][0..second.len]);
    try std.testing.expectEqualSlices(u8, &third, output.written()[first.len + second.len ..]);
    try std.testing.expectEqual(@as(usize, 3 * 64 * 1024), output.written().len);
}

test "incremental decoding composes with fixed standard readers and writers" {
    const allocator = std.testing.allocator;
    const chunks = [_]Chunk{
        .{ .data = "first", .hash = hashing.data("first") },
        .{ .data = "second", .hash = hashing.data("second") },
    };
    var object = try serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const footer = try parseFooter(object.bytes);
    var source: std.Io.Reader = .fixed(object.bytes[0..footer.body_length]);
    var bytes: [11]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.testing.expectEqual(@as(u64, 11), try decodeStream(allocator, &source, 0, 2, &writer));
    try std.testing.expectEqualStrings("firstsecond", writer.buffered());
}

test "footerless raw xorb decodes the requested chunk range" {
    const allocator = std.testing.allocator;
    const chunks = [_]Chunk{
        .{ .data = "zero", .hash = hashing.data("zero") },
        .{ .data = "one", .hash = hashing.data("one") },
    };
    var object = try serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const footer = try parseFooter(object.bytes);
    var decoded = try decodeRange(allocator, object.bytes[0..footer.body_length], 0, 2);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("zeroone", decoded.bytes);
}

test "xorb decoding rejects an empty requested range" {
    const chunks = [_]Chunk{.{ .data = "chunk", .hash = hashing.data("chunk") }};
    var object = try serialize(std.testing.allocator, &chunks, .none);
    defer object.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidRange, decodeRange(std.testing.allocator, object.bytes, 1, 1));
}

test "xorb verification rejects a corrupted footer length" {
    const chunks = [_]Chunk{.{ .data = "chunk", .hash = hashing.data("chunk") }};
    var object = try serialize(std.testing.allocator, &chunks, .none);
    defer object.deinit(std.testing.allocator);
    object.bytes[object.bytes.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidXorb, verify(std.testing.allocator, object.bytes));
}

test "verification binds every footer hash and boundary to its chunk" {
    const allocator = std.testing.allocator;
    const chunks = [_]Chunk{
        .{ .data = "first", .hash = hashing.data("first") },
        .{ .data = "second", .hash = hashing.data("second") },
    };
    var object = try serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const footer = try parseFooter(object.bytes);
    const info = object.bytes[footer.body_length .. object.bytes.len - 4];
    const count = chunks.len;
    const hash_offset = footer.body_length + 52;
    const packed_offset = footer.body_length + 64 + 32 * count;
    const unpacked_offset = packed_offset + 4 * count;
    try std.testing.expectEqualStrings("XBLBBND", info[52 + 32 * count ..][0..7]);

    object.bytes[hash_offset] ^= 1;
    try std.testing.expectError(error.HashMismatch, verify(allocator, object.bytes));
    object.bytes[hash_offset] ^= 1;

    const original_packed = std.mem.readInt(u32, object.bytes[packed_offset..][0..4], .little);
    std.mem.writeInt(u32, object.bytes[packed_offset..][0..4], original_packed + 1, .little);
    try std.testing.expectError(error.InvalidXorb, verify(allocator, object.bytes));
    std.mem.writeInt(u32, object.bytes[packed_offset..][0..4], original_packed, .little);

    const original_unpacked = std.mem.readInt(u32, object.bytes[unpacked_offset..][0..4], .little);
    std.mem.writeInt(u32, object.bytes[unpacked_offset..][0..4], original_unpacked + 1, .little);
    try std.testing.expectError(error.InvalidXorb, verify(allocator, object.bytes));
    std.mem.writeInt(u32, object.bytes[unpacked_offset..][0..4], original_unpacked, .little);
    try verify(allocator, object.bytes);
}

test "decoders reject zero-length chunks" {
    const allocator = std.testing.allocator;
    const record: [8]u8 = @splat(0);
    try std.testing.expectError(error.InvalidChunkSize, decodeRange(allocator, &record, 0, 1));
    var source: std.Io.Reader = .fixed(&record);
    var output: [1]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try std.testing.expectError(error.InvalidChunkSize, decodeStream(
        allocator,
        &source,
        0,
        1,
        &writer,
    ));
}

test "decodeRange allocation failures release every completed transfer" {
    const support = @import("test_support");
    const chunks = [_]Chunk{
        .{ .data = "zero", .hash = hashing.data("zero") },
        .{ .data = "one", .hash = hashing.data("one") },
    };
    var object = try serialize(std.testing.allocator, &chunks, .none);
    defer object.deinit(std.testing.allocator);

    var baseline = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer baseline.deinit();
    var decoded = try decodeRange(baseline.allocator(), object.bytes, 0, 1);
    decoded.deinit(baseline.allocator());
    try std.testing.expectEqual(@as(usize, 0), baseline.outstanding());

    for (0..baseline.allocation_count) |fail_at| {
        var tracker = support.TrackingAllocator{
            .backing = std.testing.allocator,
            .fail_at = fail_at,
        };
        defer tracker.deinit();
        if (decodeRange(tracker.allocator(), object.bytes, 0, 1)) |value| {
            var decoded_value = value;
            decoded_value.deinit(tracker.allocator());
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
        try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
        try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
        try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    }
}
