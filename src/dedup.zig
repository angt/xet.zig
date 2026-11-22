//! Global and session chunk deduplication

const std = @import("std");
const hashing = @import("hash.zig");
const shard = @import("shard.zig");

/// Release owned nodes with the allocator passed to `query`
pub const Match = struct {
    nodes: []hashing.Node,
    xorb_hash: hashing.Hash,
    chunk_index_start: u32,

    pub fn deinit(self: *Match, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn unpackedBytes(self: *const Match) !u32 {
        var total: u64 = 0;
        for (self.nodes) |node| total += node.size;
        return std.math.cast(u32, total) orelse error.InvalidDedupMatch;
    }
};

/// Returns the longest existing prefix of the supplied chunks, or null
pub const Source = struct {
    context: *anyopaque,
    query_fn: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        chunk_hashes: []const hashing.Hash,
    ) anyerror!?Match,

    pub fn query(self: Source, allocator: std.mem.Allocator, hashes: []const hashing.Hash) !?Match {
        if (hashes.len == 0 or hashes.len > std.math.maxInt(u32)) return error.InvalidDedupQuery;
        const result = try self.query_fn(self.context, allocator, hashes);
        if (result) |found| {
            var match = found;
            errdefer match.deinit(allocator);
            const invalid = match.nodes.len == 0 or match.nodes.len > hashes.len or
                match.nodes.len > std.math.maxInt(u32) - match.chunk_index_start;
            if (invalid) {
                return error.InvalidDedupMatch;
            }
            _ = try match.unpackedBytes();
            for (match.nodes, hashes[0..match.nodes.len]) |node, expected| {
                if (node.size == 0 or !hashing.eql(node.hash, expected)) {
                    return error.InvalidDedupMatch;
                }
            }
        }
        return result;
    }
};

/// Matches chunk hashes with each shard's HMAC key
pub const ShardIndex = struct {
    shards: std.ArrayList(Shard) = .empty,

    const Shard = struct {
        bytes: []u8,
        reader: shard.Reader,
    };

    pub fn deinit(self: *ShardIndex, allocator: std.mem.Allocator) void {
        for (self.shards.items) |item| allocator.free(item.bytes);
        self.shards.deinit(allocator);
        self.* = .{};
    }

    /// Takes ownership of `bytes`, even on failure. Returns false if expired
    pub fn addOwned(self: *ShardIndex, allocator: std.mem.Allocator, bytes: []u8, now: i64) !bool {
        errdefer allocator.free(bytes);
        const reader = try shard.Reader.init(bytes);
        if (reader.footer.expiry != 0 and reader.footer.expiry <= now) {
            allocator.free(bytes);
            return false;
        }
        try self.shards.append(allocator, .{ .bytes = bytes, .reader = reader });
        return true;
    }

    pub fn find(self: *const ShardIndex, allocator: std.mem.Allocator, hashes: []const hashing.Hash) !?Match {
        if (hashes.len == 0) return null;
        var index = self.shards.items.len;
        while (index != 0) {
            index -= 1;
            const item = self.shards.items[index];
            if (findInShard(item.reader, hashes)) |located| {
                const nodes = try allocator.alloc(hashing.Node, located.count);
                errdefer allocator.free(nodes);
                for (nodes, 0..) |*node, i| {
                    const entry = try located.object.chunk(@intCast(located.chunk_index + i));
                    node.* = .{ .hash = hashes[i], .size = entry.unpacked_segment_bytes };
                }
                return .{
                    .nodes = nodes,
                    .xorb_hash = located.object.hash,
                    .chunk_index_start = located.chunk_index,
                };
            }
        }
        return null;
    }
};

pub fn eligible(chunk_hash: hashing.Hash) bool {
    return std.mem.readInt(u64, chunk_hash[24..32], .little) % 1024 == 0;
}

/// Local metadata uses raw hashes. Global shards retain their HMAC keys
pub const SessionIndex = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMapUnmanaged(hashing.Hash, Location) = .empty,
    xorbs: std.ArrayList(Xorb) = .empty,
    global: ShardIndex = .{},

    const Xorb = struct {
        hash: hashing.Hash,
        chunks: []shard.Chunk,
    };

    const Location = struct {
        xorb_index: usize,
        chunk_index: u32,
    };

    pub fn init(allocator: std.mem.Allocator) SessionIndex {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SessionIndex) void {
        self.entries.deinit(self.allocator);
        for (self.xorbs.items) |object| self.allocator.free(object.chunks);
        self.xorbs.deinit(self.allocator);
        self.global.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addGlobalOwned(self: *SessionIndex, bytes: []u8, now: i64) !bool {
        return self.global.addOwned(self.allocator, bytes, now);
    }

    /// Copies the chunk metadata so it can outlive the publisher's current Xorb
    pub fn addXorb(self: *SessionIndex, object: shard.Xorb) !void {
        const xorb_index = self.xorbs.items.len;
        const chunks = try self.allocator.dupe(shard.Chunk, object.chunks);
        errdefer self.allocator.free(chunks);
        try self.xorbs.ensureUnusedCapacity(self.allocator, 1);
        errdefer _ = self.xorbs.pop();
        try self.entries.ensureUnusedCapacity(self.allocator, @intCast(chunks.len));
        self.xorbs.appendAssumeCapacity(.{ .hash = object.hash, .chunks = chunks });
        for (chunks, 0..) |chunk, index| {
            self.entries.getOrPutAssumeCapacity(chunk.hash).value_ptr.* = .{
                .xorb_index = xorb_index,
                .chunk_index = @intCast(index),
            };
        }
    }

    pub fn source(self: *SessionIndex) Source {
        return .{ .context = self, .query_fn = query };
    }

    fn query(raw: *anyopaque, allocator: std.mem.Allocator, hashes: []const hashing.Hash) !?Match {
        const self: *SessionIndex = @ptrCast(@alignCast(raw));
        const first = self.entries.get(hashes[0]) orelse
            return self.global.find(allocator, hashes);
        const object = self.xorbs.items[first.xorb_index];
        var count: usize = 1;
        while (count < hashes.len and first.chunk_index + count < object.chunks.len) : (count += 1) {
            const next = object.chunks[first.chunk_index + count];
            if (!hashing.eql(next.hash, hashes[count])) break;
        }
        const nodes = try allocator.alloc(hashing.Node, count);
        for (nodes, object.chunks[first.chunk_index..][0..count]) |*node, chunk| {
            node.* = .{ .hash = chunk.hash, .size = chunk.unpacked_segment_bytes };
        }
        return .{
            .nodes = nodes,
            .xorb_hash = object.hash,
            .chunk_index_start = first.chunk_index,
        };
    }
};

const Located = struct {
    object: shard.XorbInfo,
    chunk_index: u32,
    count: u32,
};

fn findInShard(reader: shard.Reader, hashes: []const hashing.Hash) ?Located {
    const target = keyed(reader.footer.chunk_hash_key, hashes[0]);
    if (reader.footer.chunk_lookup_offset != reader.footer.footer_offset) {
        var best: ?Located = null;
        var lookup = reader.findChunks(target) catch return null;
        while (lookup.next() catch return null) |first| {
            const located = contiguousRun(reader, first.object, first.index, hashes) orelse return null;
            if (best == null or located.count > best.?.count) best = located;
            if (best.?.count == hashes.len) break;
        }
        return best;
    }

    var best: ?Located = null;
    var record: u32 = 0;
    for (0..reader.footer.xorb_count) |_| {
        const object = reader.xorbAt(record) catch return null;
        record += object.count + 1;
        for (0..object.count) |i| {
            const first = object.chunk(@intCast(i)) catch return null;
            if (!hashing.eql(target, first.hash)) continue;
            if (contiguousRun(reader, object, @intCast(i), hashes)) |located| {
                if (best == null or located.count > best.?.count) best = located;
            }
        }
    }
    return best;
}

fn contiguousRun(reader: shard.Reader, object: shard.XorbInfo, start: u32, hashes: []const hashing.Hash) ?Located {
    var count: u32 = 1;
    while (count < hashes.len and start + count < object.count) : (count += 1) {
        const next = object.chunk(start + count) catch return null;
        const next_hash = keyed(reader.footer.chunk_hash_key, hashes[count]);
        if (!hashing.eql(next_hash, next.hash)) break;
    }
    return .{ .object = object, .chunk_index = start, .count = count };
}

fn keyed(key: hashing.Hash, hash: hashing.Hash) hashing.Hash {
    if (hashing.eql(key, hashing.zero)) return hash;
    return hashing.keyed(key, &hash);
}

test "session lookup owns Xorb metadata and returns contiguous runs" {
    const allocator = std.testing.allocator;
    const hashes = [_]hashing.Hash{ hashing.data("A"), hashing.data("B"), hashing.data("C") };
    var chunks: [3]shard.Chunk = undefined;
    for (&chunks, hashes, 0..) |*chunk, hash, index| chunk.* = .{
        .hash = hash,
        .byte_range_start = @intCast(index),
        .unpacked_segment_bytes = 1,
    };
    var session = SessionIndex.init(allocator);
    defer session.deinit();
    try session.addXorb(.{
        .hash = hashing.data("xorb"),
        .chunks = &chunks,
        .raw_size = 3,
        .serialized_size = 3,
    });
    @memset(&chunks, std.mem.zeroes(shard.Chunk));
    var match = (try session.source().query(allocator, &hashes)).?;
    defer match.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), match.nodes.len);
    try std.testing.expectEqual(@as(u32, 3), try match.unpackedBytes());
}

test "global shard lookup honors HMAC keys and contiguous runs" {
    const allocator = std.testing.allocator;
    const key = hashing.data("key");
    const chunk_hashes = [_]hashing.Hash{ hashing.data("A"), hashing.data("B"), hashing.data("C") };
    var metadata: [3]shard.Chunk = undefined;
    var offset: u32 = 0;
    for (&metadata, chunk_hashes) |*entry, hash| {
        entry.* = .{ .hash = keyed(key, hash), .byte_range_start = offset, .unpacked_segment_bytes = 1 };
        offset += 1;
    }
    const object = shard.Xorb{
        .hash = hashing.data("xorb"),
        .chunks = &metadata,
        .raw_size = 3,
        .serialized_size = 3,
    };
    const bytes = try shard.serialize(allocator, &.{}, &.{object});
    const footer_start = bytes.len - shard.footer_size;
    @memcpy(bytes[footer_start + 72 ..][0..32], &key);
    var index: ShardIndex = .{};
    defer index.deinit(allocator);
    try std.testing.expect(try index.addOwned(allocator, bytes, 0));
    var match = (try index.find(allocator, &chunk_hashes)).?;
    defer match.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), match.nodes.len);
    try std.testing.expectEqual(@as(u32, 3), try match.unpackedBytes());
    const partial = [_]hashing.Hash{ chunk_hashes[1], hashing.data("unknown") };
    var partial_match = (try index.find(allocator, &partial)).?;
    defer partial_match.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), partial_match.nodes.len);
    try std.testing.expect((try index.find(allocator, &.{hashing.data("unknown")})) == null);
}

test "global shard lookup falls back to footerless chunk records" {
    const allocator = std.testing.allocator;
    const chunk_hash = hashing.data("chunk");
    const bytes = try shard.serialize(allocator, &.{}, &.{.{
        .hash = hashing.data("xorb"),
        .chunks = &.{.{
            .hash = chunk_hash,
            .byte_range_start = 0,
            .unpacked_segment_bytes = 5,
        }},
        .raw_size = 5,
        .serialized_size = 5,
    }});
    defer allocator.free(bytes);
    const reader = try shard.Reader.init(bytes);
    const footerless = try allocator.dupe(u8, bytes[0..reader.footer.file_lookup_offset]);
    std.mem.writeInt(u64, footerless[40..48], 0, .little);

    var index: ShardIndex = .{};
    defer index.deinit(allocator);
    try std.testing.expect(try index.addOwned(allocator, footerless, 0));
    var match = (try index.find(allocator, &.{chunk_hash})).?;
    defer match.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), match.nodes[0].size);
}

test "global dedup eligibility uses the last little-endian word" {
    var hash = hashing.zero;
    try std.testing.expect(eligible(hash));
    hash[24] = 1;
    try std.testing.expect(!eligible(hash));
}
