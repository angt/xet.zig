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

/// Chooses chunk boundaries, and stateful contexts must not be shared concurrently
pub const Strategy = struct {
    context: *anyopaque,
    next_fn: *const fn (
        context: *anyopaque,
        previous: []const u8,
        input: []const u8,
    ) anyerror!?usize,
    reset_fn: ?*const fn (context: *anyopaque) void = null,

    /// Returns a boundary relative to input, or null when more bytes are needed
    pub fn next(self: Strategy, previous: []const u8, input: []const u8) !?usize {
        const boundary = try self.next_fn(self.context, previous, input) orelse return null;
        if (boundary == 0 or boundary > input.len) return error.InvalidChunkBoundary;
        return boundary;
    }

    pub fn reset(self: Strategy) void {
        if (self.reset_fn) |reset_fn| reset_fn(self.context);
    }
};

pub const Fixed = struct {
    size: u32,

    pub fn init(size: u32) !Fixed {
        if (size == 0 or size > constants.max_chunk_size) return error.InvalidChunkSize;
        return .{ .size = size };
    }

    pub fn strategy(self: *Fixed) Strategy {
        return .{ .context = self, .next_fn = next };
    }

    fn next(raw: *anyopaque, previous: []const u8, input: []const u8) !?usize {
        const self: *Fixed = @ptrCast(@alignCast(raw));
        const remaining = self.size -| previous.len;
        if (remaining == 0) return error.InvalidChunkBoundary;
        if (input.len < remaining) return null;
        return remaining;
    }
};

/// Chunks borrow input or internal storage until `next`, `reset`, or `deinit`
pub const Chunker = struct {
    pending: std.ArrayList(u8),
    hash: u64 = 0,
    returned_pending: bool = false,
    strategy: ?Strategy = null,

    pub fn init() Chunker {
        return .{ .pending = .empty };
    }

    /// The strategy context is borrowed and reset before each file and chunk
    pub fn initWith(strategy: Strategy) Chunker {
        strategy.reset();
        return .{ .pending = .empty, .strategy = strategy };
    }

    pub fn deinit(self: *Chunker, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
    }

    pub fn reset(self: *Chunker) void {
        self.pending.clearRetainingCapacity();
        self.hash = 0;
        self.returned_pending = false;
        if (self.strategy) |strategy| strategy.reset();
    }

    /// Set `final` only when no later input belongs to the same file
    pub fn next(self: *Chunker, allocator: std.mem.Allocator, input: []const u8, final: bool) !Result {
        if (self.returned_pending) {
            self.pending.clearRetainingCapacity();
            self.returned_pending = false;
        }

        const consumed = try self.findBoundary(input) orelse blk: {
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
            if (self.strategy) |strategy| strategy.reset();
            return .{
                .chunk = .{ .data = bytes, .hash = hashing.data(bytes) },
                .consumed = consumed,
            };
        }
        try self.pending.appendSlice(allocator, input[0..consumed]);
        self.hash = 0;
        self.returned_pending = true;
        const bytes = self.pending.items;
        if (self.strategy) |strategy| strategy.reset();
        return .{
            .chunk = .{ .data = bytes, .hash = hashing.data(bytes) },
            .consumed = consumed,
        };
    }

    pub fn finish(self: *Chunker, allocator: std.mem.Allocator) !Result {
        return self.next(allocator, &.{}, true);
    }

    fn findBoundary(self: *Chunker, input: []const u8) !?usize {
        const strategy = self.strategy orelse return self.findDefault(input);
        const capacity = constants.max_chunk_size - self.pending.items.len;
        const available = input[0..@min(input.len, capacity)];
        if (try strategy.next(self.pending.items, available)) |boundary| return boundary;
        if (available.len == capacity) return capacity;
        return null;
    }

    fn findDefault(self: *Chunker, input: []const u8) ?usize {
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
    return chunkWith(allocator, input, null);
}

/// A null strategy preserves the canonical Xet boundaries
pub fn chunkWith(
    allocator: std.mem.Allocator,
    input: []const u8,
    strategy: ?Strategy,
) ![]Chunk {
    var current = if (strategy) |value| Chunker.initWith(value) else Chunker.init();
    defer current.deinit(allocator);
    var chunks: std.ArrayList(Chunk) = .empty;
    errdefer chunks.deinit(allocator);

    var position: usize = 0;
    while (position < input.len) {
        const result = try current.next(allocator, input[position..], true);
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

test "empty input produces no chunks" {
    const empty = try chunkBuffer(std.testing.allocator, "");
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "tiny input produces one complete chunk" {
    const tiny = try chunkBuffer(std.testing.allocator, "hello");
    defer std.testing.allocator.free(tiny);
    try std.testing.expectEqual(@as(usize, 1), tiny.len);
    try std.testing.expectEqualStrings("hello", tiny[0].data);
}

/// Returns an owned copy of every chunk produced by `step`-sized writes
fn streamSteps(
    allocator: std.mem.Allocator,
    strategy: Strategy,
    input: []const u8,
    step: usize,
) !std.ArrayList(Chunk) {
    var streamed: std.ArrayList(Chunk) = .empty;
    errdefer freeChunks(allocator, &streamed);
    var current = Chunker.initWith(strategy);
    defer current.deinit(allocator);
    var position: usize = 0;
    while (position < input.len) {
        const end = @min(position + step, input.len);
        var remaining = input[position..end];
        while (remaining.len != 0) {
            const result = try current.next(allocator, remaining, false);
            try appendCopy(allocator, &streamed, result.chunk);
            remaining = remaining[result.consumed..];
        }
        position = end;
    }
    try appendCopy(allocator, &streamed, (try current.finish(allocator)).chunk);
    return streamed;
}

/// The list owns the copy only once the append succeeds
fn appendCopy(allocator: std.mem.Allocator, streamed: *std.ArrayList(Chunk), chunk: ?Chunk) !void {
    const value = chunk orelse return;
    const copy = try allocator.dupe(u8, value.data);
    errdefer allocator.free(copy);
    try streamed.append(allocator, .{ .data = copy, .hash = value.hash });
}

fn freeChunks(allocator: std.mem.Allocator, streamed: *std.ArrayList(Chunk)) void {
    for (streamed.items) |chunk| allocator.free(chunk.data);
    streamed.deinit(allocator);
}

test "fixed chunks preserve data across fragmented input" {
    const allocator = std.testing.allocator;
    const input = "abcdefghij";
    var fixed = try Fixed.init(4);
    const contiguous = try chunkWith(allocator, input, fixed.strategy());
    defer allocator.free(contiguous);
    try std.testing.expectEqual(@as(usize, 3), contiguous.len);
    try std.testing.expectEqualStrings("abcd", contiguous[0].data);
    try std.testing.expectEqualStrings("efgh", contiguous[1].data);
    try std.testing.expectEqualStrings("ij", contiguous[2].data);

    var streamed = try streamSteps(allocator, fixed.strategy(), input, 1);
    defer freeChunks(allocator, &streamed);
    try std.testing.expectEqual(contiguous.len, streamed.items.len);
    for (contiguous, streamed.items) |expected, actual| {
        try std.testing.expectEqualSlices(u8, expected.data, actual.data);
        try std.testing.expect(hashing.eql(expected.hash, actual.hash));
    }
}

/// Rolling hash proving boundaries survive fragmentation and resets
const RollingHash = struct {
    hash: u64 = 0,
    processed: usize = 0,

    fn strategy(self: *RollingHash) Strategy {
        return .{ .context = self, .next_fn = next, .reset_fn = reset };
    }

    fn reset(raw: *anyopaque) void {
        const self: *RollingHash = @ptrCast(@alignCast(raw));
        self.* = .{};
    }

    fn next(raw: *anyopaque, previous: []const u8, input: []const u8) !?usize {
        const self: *RollingHash = @ptrCast(@alignCast(raw));
        try std.testing.expectEqual(previous.len, self.processed);
        for (input, 0..) |byte, index| {
            self.hash = self.hash *% 31 +% byte;
            self.processed += 1;
            if (self.processed >= 4 and ((self.hash & 3) == 0 or self.processed % 16 == 0))
                return index + 1;
        }
        return null;
    }
};

test "custom rolling hash boundaries agree across input fragmentation" {
    const allocator = std.testing.allocator;
    const input = "a rolling hash chooses boundaries independently of write calls";
    var rolling: RollingHash = .{};
    const expected = try chunkWith(allocator, input, rolling.strategy());
    defer allocator.free(expected);
    try std.testing.expect(expected.len > 1);

    var streamed = try streamSteps(allocator, rolling.strategy(), input, 3);
    defer freeChunks(allocator, &streamed);
    try std.testing.expectEqual(expected.len, streamed.items.len);
    for (expected, streamed.items) |expected_chunk, actual| {
        try std.testing.expectEqualSlices(u8, expected_chunk.data, actual.data);
        try std.testing.expect(hashing.eql(expected_chunk.hash, actual.hash));
    }
}

test "a used strategy context resumes from a clean state on the next file" {
    const allocator = std.testing.allocator;
    const single = "reusing one borrowed context must not leak state between files";
    const longer = "reusing one borrowed context must not leak state between files or writes";

    // A brand-new context is the only valid expectation for a second file
    var new_context: RollingHash = .{};
    const expected = try chunkWith(allocator, longer, new_context.strategy());
    defer allocator.free(expected);

    // Leave the borrowed context mid-chunk, as a caller reusing a handle would
    var used_context: RollingHash = .{};
    const first = try chunkWith(allocator, single, used_context.strategy());
    defer allocator.free(first);
    used_context.hash = 0xffff;
    used_context.processed = 3;

    const resumed = try chunkWith(allocator, longer, used_context.strategy());
    defer allocator.free(resumed);

    try std.testing.expectEqual(expected.len, resumed.len);
    for (expected, resumed) |want, got| {
        try std.testing.expectEqualSlices(u8, want.data, got.data);
        try std.testing.expect(hashing.eql(want.hash, got.hash));
    }
    try std.testing.expectEqual(new_context.processed, used_context.processed);
}

test "initWith resets borrowed state before the first chunk" {
    var context: RollingHash = .{ .hash = 0xffff, .processed = 9 };
    var current = Chunker.initWith(context.strategy());
    defer current.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 0), context.hash);
    try std.testing.expectEqual(@as(usize, 0), context.processed);
}

/// Never returns a boundary, so only the maximum size can force a cut
const NeverCuts = struct {
    starts: usize = 0,
    stale_starts: usize = 0,
    awaiting_reset: bool = true,

    fn strategy(self: *NeverCuts) Strategy {
        return .{ .context = self, .next_fn = next, .reset_fn = reset };
    }

    fn reset(raw: *anyopaque) void {
        const self: *NeverCuts = @ptrCast(@alignCast(raw));
        self.awaiting_reset = true;
    }

    fn next(raw: *anyopaque, previous: []const u8, input: []const u8) !?usize {
        const self: *NeverCuts = @ptrCast(@alignCast(raw));
        _ = input;
        if (self.awaiting_reset) {
            if (previous.len != 0) self.stale_starts += 1;
            self.starts += 1;
            self.awaiting_reset = false;
        }
        return null;
    }
};

test "a strategy that never cuts still forces a cut at the maximum size" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc(u8, constants.max_chunk_size);
    defer allocator.free(input);
    fillRandom(input, 7);
    var never: NeverCuts = .{};

    const chunks = try chunkWith(allocator, input, never.strategy());
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    try std.testing.expectEqual(constants.max_chunk_size, chunks[0].data.len);
    try std.testing.expectEqualSlices(u8, input, chunks[0].data);

    try std.testing.expectEqual(@as(usize, 1), never.starts);
    try std.testing.expectEqual(@as(usize, 0), never.stale_starts);
}

test "a forced maximum-size cut resets the strategy for the following chunk" {
    const allocator = std.testing.allocator;
    const size = constants.max_chunk_size + 5;
    const input = try allocator.alloc(u8, size);
    defer allocator.free(input);
    fillRandom(input, 11);
    var never: NeverCuts = .{};

    const chunks = try chunkWith(allocator, input, never.strategy());
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    try std.testing.expectEqual(constants.max_chunk_size, chunks[0].data.len);
    try std.testing.expectEqual(@as(usize, 5), chunks[1].data.len);
    try std.testing.expectEqualSlices(u8, input[0..constants.max_chunk_size], chunks[0].data);
    try std.testing.expectEqualSlices(u8, input[constants.max_chunk_size..], chunks[1].data);
    try std.testing.expect(hashing.eql(chunks[1].hash, hashing.data(input[constants.max_chunk_size..])));

    try std.testing.expectEqual(@as(usize, 2), never.starts);
    try std.testing.expectEqual(@as(usize, 0), never.stale_starts);
}

test "fragmented input forces one maximum-size cut and flushes the tail once" {
    const allocator = std.testing.allocator;
    const size = constants.max_chunk_size + 5;
    const input = try allocator.alloc(u8, size);
    defer allocator.free(input);
    fillRandom(input, 19);
    var never: NeverCuts = .{};

    var streamed = try streamSteps(allocator, never.strategy(), input, 7);
    defer freeChunks(allocator, &streamed);
    try std.testing.expectEqual(@as(usize, 2), streamed.items.len);
    try std.testing.expectEqual(constants.max_chunk_size, streamed.items[0].data.len);
    try std.testing.expectEqual(@as(usize, 5), streamed.items[1].data.len);
    try std.testing.expectEqualSlices(u8, input[0..constants.max_chunk_size], streamed.items[0].data);
    try std.testing.expectEqualSlices(u8, input[constants.max_chunk_size..], streamed.items[1].data);
    try std.testing.expect(hashing.eql(streamed.items[0].hash, hashing.data(input[0..constants.max_chunk_size])));
    try std.testing.expect(hashing.eql(streamed.items[1].hash, hashing.data(input[constants.max_chunk_size..])));

    try std.testing.expectEqual(@as(usize, 2), never.starts);
    try std.testing.expectEqual(@as(usize, 0), never.stale_starts);
}

test "a reused context starts each file with a cleared strategy" {
    const allocator = std.testing.allocator;
    const size = constants.max_chunk_size + 5;
    const input = try allocator.alloc(u8, size);
    defer allocator.free(input);
    fillRandom(input, 17);
    var never: NeverCuts = .{};

    for (0..2) |_| {
        const chunks = try chunkWith(allocator, input, never.strategy());
        defer allocator.free(chunks);
        try std.testing.expectEqual(@as(usize, 2), chunks.len);
    }
    try std.testing.expectEqual(@as(usize, 4), never.starts);
    try std.testing.expectEqual(@as(usize, 0), never.stale_starts);
}

test "an exact multiple of the maximum size emits no trailing empty chunk" {
    const allocator = std.testing.allocator;
    const size = constants.max_chunk_size * 2;
    const input = try allocator.alloc(u8, size);
    defer allocator.free(input);
    fillRandom(input, 13);
    var never: NeverCuts = .{};

    const chunks = try chunkWith(allocator, input, never.strategy());
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 2), chunks.len);
    for (chunks) |chunk| try std.testing.expectEqual(constants.max_chunk_size, chunk.data.len);
    try std.testing.expectEqual(@as(usize, 2), never.starts);
    try std.testing.expectEqual(@as(usize, 0), never.stale_starts);

    // Fragmenting every write at the limit must not add an empty trailing chunk
    var streamed = try streamSteps(allocator, never.strategy(), input, constants.max_chunk_size);
    defer freeChunks(allocator, &streamed);
    try std.testing.expectEqual(@as(usize, 2), streamed.items.len);
    for (streamed.items) |chunk| try std.testing.expectEqual(constants.max_chunk_size, chunk.data.len);
    for (chunks, streamed.items) |expected, actual| {
        try std.testing.expectEqualSlices(u8, expected.data, actual.data);
        try std.testing.expect(hashing.eql(expected.hash, actual.hash));
    }
    try std.testing.expectEqual(@as(usize, 0), never.stale_starts);
}

test "fragmented copies stay owned across append failures and later errors" {
    const support = @import("test_support");
    for ([_]bool{ false, true }) |has_previous| {
        var tracker: support.TrackingAllocator = .{ .backing = std.testing.allocator };
        defer tracker.deinit();
        const allocator = tracker.allocator();
        var streamed: std.ArrayList(Chunk) = .empty;
        if (has_previous) {
            const previous = Chunk{ .data = "first", .hash = hashing.data("first") };
            try appendCopy(allocator, &streamed, previous);
            streamed.shrinkAndFree(allocator, streamed.items.len);
            try std.testing.expectEqual(streamed.items.len, streamed.capacity);
        }
        tracker.fail_at = tracker.allocation_count + 1;
        const next = Chunk{ .data = "second", .hash = hashing.data("second") };
        try std.testing.expectError(error.OutOfMemory, appendCopy(allocator, &streamed, next));
        freeChunks(allocator, &streamed);
        try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
        try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
        try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    }
}

fn streamStepsAllocates(allocator: std.mem.Allocator) !void {
    var fixed = try Fixed.init(4);
    var streamed = try streamSteps(allocator, fixed.strategy(), "abcdefghijkl", 1);
    defer freeChunks(allocator, &streamed);
    try std.testing.expectEqual(@as(usize, 3), streamed.items.len);
    for (streamed.items, [_][]const u8{ "abcd", "efgh", "ijkl" }) |chunk, expected| {
        try std.testing.expectEqualStrings(expected, chunk.data);
    }
}

test "fragmented strategy streaming releases copies on allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        streamStepsAllocates,
        .{},
    );
}

fn rollingStepsAllocates(allocator: std.mem.Allocator) !void {
    const input = "rolling boundaries under failure";
    var rolling: RollingHash = .{};
    const expected = try chunkWith(allocator, input, rolling.strategy());
    defer allocator.free(expected);
    var streamed = try streamSteps(allocator, rolling.strategy(), input, 3);
    defer freeChunks(allocator, &streamed);
    try std.testing.expectEqual(expected.len, streamed.items.len);
    for (expected, streamed.items) |want, got| try std.testing.expectEqualSlices(u8, want.data, got.data);
}
test "rolling strategy streaming releases copies on allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        rollingStepsAllocates,
        .{},
    );
}

test "chunk strategies reject invalid boundaries and sizes" {
    const Invalid = struct {
        fn zero(_: *anyopaque, _: []const u8, _: []const u8) !?usize {
            return 0;
        }

        fn oversized(_: *anyopaque, _: []const u8, input: []const u8) !?usize {
            return input.len + 1;
        }
    };
    var context: u8 = 0;
    try std.testing.expectError(error.InvalidChunkBoundary, chunkWith(
        std.testing.allocator,
        "data",
        .{ .context = &context, .next_fn = Invalid.zero },
    ));
    try std.testing.expectError(error.InvalidChunkBoundary, chunkWith(
        std.testing.allocator,
        "data",
        .{ .context = &context, .next_fn = Invalid.oversized },
    ));
    try std.testing.expectError(error.InvalidChunkSize, Fixed.init(0));
    try std.testing.expectError(error.InvalidChunkSize, Fixed.init(constants.max_chunk_size + 1));
}
