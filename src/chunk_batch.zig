//! Parallel fast path for a contiguous input beginning on a canonical Xet cut.
const std = @import("std");
const constants = @import("constants.zig");
const chunker = @import("chunker.zig");
const hashing = @import("hash.zig");

pub const block_size = 2 * 1024 * 1024;
const lanes = 4;
const min_batch = block_size / 4;

const Candidates = struct {
    offsets: [128]u32 = undefined,
    count: usize = 0,

    fn scan(self: *Candidates, input: []const u8, start: usize, end: usize) void {
        var hash: u64 = 0;
        // After 64 shifts, the Gear state is independent of all preceding bytes.
        for (input[start -| 64..start]) |b| hash = hash *% 2 +% constants.gear_table[b];
        var i = start;
        while (i < end) {
            const group_end = @min(i + 32, end);
            const byte = input[i];
            // For a uniform run the rolling state stabilizes at -Gear[byte].
            if (group_end - i == 32 and hash == 0 -% constants.gear_table[byte] and hash & constants.gear_mask != 0) {
                const run: @Vector(32, u8) = input[i..][0..32].*;
                if (@reduce(.And, run == @as(@Vector(32, u8), @splat(byte)))) {
                    i = group_end;
                    continue;
                }
            }
            while (i < group_end) : (i += 1) {
                hash = hash *% 2 +% constants.gear_table[input[i]];
                if (hash & constants.gear_mask == 0) {
                    if (self.count == self.offsets.len) {
                        self.count += 1;
                        return;
                    }
                    self.offsets[self.count] = @intCast(i + 1);
                    self.count += 1;
                }
            }
        }
    }
};

const Batch = struct {
    chunks: [block_size / constants.min_chunk_size]chunker.Chunk = undefined,

    /// Returns complete canonical chunks. The caller feeds the tail to its normal
    /// chunker. A dense candidate set uses the scalar path with bounded scratch.
    fn collect(self: *Batch, io: std.Io, bytes: []const u8) []const chunker.Chunk {
        const input = bytes[0..@min(bytes.len, block_size)];
        var candidates: [lanes]Candidates = @splat(.{});
        var jobs: [lanes - 1]std.Io.Future(void) = undefined;
        for (&jobs, 0..) |*job, i| {
            job.* = io.async(Candidates.scan, .{
                &candidates[i],
                input,
                i * input.len / lanes,
                (i + 1) * input.len / lanes,
            });
        }
        candidates[lanes - 1].scan(input, (lanes - 1) * input.len / lanes, input.len);
        for (&jobs) |*job| job.await(io);
        var count: usize = 0;
        var start: usize = 0;
        for (&candidates) |*lane| {
            if (lane.count > lane.offsets.len) return &.{};
            for (lane.offsets[0..lane.count]) |end| {
                while (end > start + constants.max_chunk_size)
                    self.cut(input, &start, &count, start + constants.max_chunk_size);
                if (end >= start + constants.min_chunk_size)
                    self.cut(input, &start, &count, end);
            }
        }
        while (input.len - start >= constants.max_chunk_size)
            self.cut(input, &start, &count, start + constants.max_chunk_size);
        const chunks = self.chunks[0..count];
        for (&jobs, 0..) |*job, i| {
            job.* = io.async(hashChunks, .{chunks[i * count / lanes .. (i + 1) * count / lanes]});
        }
        hashChunks(chunks[(lanes - 1) * count / lanes ..]);
        for (&jobs) |*job| job.await(io);
        return chunks;
    }

    fn cut(self: *Batch, input: []const u8, start: *usize, count: *usize, end: usize) void {
        self.chunks[count.*].data = input[start.*..end];
        count.* += 1;
        start.* = end;
    }

    fn hashChunks(chunks: []chunker.Chunk) void {
        for (chunks) |*chunk| chunk.hash = hashing.data(chunk.data);
    }
};

pub fn canBatch(size: usize) bool {
    return size >= min_batch;
}

/// Each yielded chunk borrows the input or the chunker's pending bytes until next().
pub const Iterator = struct {
    io: ?std.Io,
    input: []const u8,
    ready: []const chunker.Chunk = &.{},
    batch: Batch = undefined,
    from_input: bool = false,

    pub fn next(
        self: *Iterator,
        c: *chunker.Chunker,
        allocator: std.mem.Allocator,
    ) !?chunker.Chunk {
        while (self.input.len != 0) {
            if (self.ready.len == 0) {
                if (self.io) |io| {
                    if (canBatch(self.input.len) and c.strategy == null and
                        (c.pending.items.len == 0 or c.returned_pending))
                    {
                        self.ready = self.batch.collect(io, self.input);
                        if (self.ready.len == 0) self.io = null; // Dense candidates: scan this input once.
                    }
                }
            }
            if (self.ready.len != 0) {
                self.from_input = true;
                const result = self.ready[0];
                self.ready = self.ready[1..];
                self.input = self.input[result.data.len..];
                return result;
            }
            const result = try c.next(allocator, self.input, false);
            self.input = self.input[result.consumed..];
            if (result.chunk) |chunk| {
                self.from_input = !c.returned_pending;
                return chunk;
            }
        }
        return null;
    }
};

test "parallel chunks agree with scalar cuts and hashes across input fragments" {
    const allocator = std.testing.allocator;
    const bytes = try allocator.alloc(u8, 3 * block_size + 77);
    defer allocator.free(bytes);
    var rng = std.Random.DefaultPrng.init(96);
    rng.random().bytes(bytes);
    @memset(bytes[block_size - 77 .. 2 * block_size + 1], 0);
    var expected = chunker.Chunker.init();
    defer expected.deinit(allocator);
    var actual = chunker.Chunker.init();
    defer actual.deinit(allocator);
    var pos: usize = 0;
    var consumed: usize = 0;
    for ([_]usize{ 37, block_size + 503, bytes.len }) |end| {
        var it = Iterator{ .io = std.testing.io, .input = bytes[pos..end] };
        while (try it.next(&actual, allocator)) |found| {
            const next = try expected.next(allocator, bytes[consumed..], true);
            try std.testing.expectEqual(next.chunk.?.hash, found.hash);
            try std.testing.expectEqual(next.consumed, found.data.len);
            consumed += found.data.len;
        }
        pos = end;
    }
    const tail = try actual.finish(allocator);
    if (tail.chunk) |last| {
        try std.testing.expectEqual(hashing.data(bytes[consumed..]), last.hash);
        consumed += last.data.len;
    }
    try std.testing.expectEqual(bytes.len, consumed);
}
