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
        if (hashes.len == 0) return error.InvalidDedupQuery;
        const result = try self.query_fn(self.context, allocator, hashes);
        if (hashes.len > std.math.maxInt(u32)) return error.InvalidDedupQuery;
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
    global: ShardIndex = .{},

    const Location = struct {
        xorb_hash: hashing.Hash,
        chunk_index: u32,
        chunk_size: u32,
    };

    pub fn init(allocator: std.mem.Allocator) SessionIndex {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SessionIndex) void {
        self.entries.deinit(self.allocator);
        self.global.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addGlobalOwned(self: *SessionIndex, bytes: []u8, now: i64) !bool {
        return self.global.addOwned(self.allocator, bytes, now);
    }

    pub fn addXorb(self: *SessionIndex, object: shard.Xorb) !void {
        for (object.chunks, 0..) |chunk, index| {
            try self.entries.put(self.allocator, chunk.hash, .{
                .xorb_hash = object.hash,
                .chunk_index = @intCast(index),
                .chunk_size = chunk.unpacked_segment_bytes,
            });
        }
    }

    pub fn source(self: *SessionIndex) Source {
        return .{ .context = self, .query_fn = query };
    }

    fn query(raw: *anyopaque, allocator: std.mem.Allocator, hashes: []const hashing.Hash) !?Match {
        const self: *SessionIndex = @ptrCast(@alignCast(raw));
        const first = self.entries.get(hashes[0]) orelse
            return self.global.find(allocator, hashes);
        const nodes = try allocator.alloc(hashing.Node, 1);
        nodes[0] = .{ .hash = hashes[0], .size = first.chunk_size };
        return .{
            .nodes = nodes,
            .xorb_hash = first.xorb_hash,
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
    var best: ?Located = null;
    var record: u32 = 0;
    for (0..reader.footer.xorb_count) |_| {
        const object = reader.xorbAt(record) catch return null;
        record += object.count + 1;
        for (0..object.count) |i| {
            const first = object.chunk(@intCast(i)) catch return null;
            const hash = keyed(reader.footer.chunk_hash_key, hashes[0]);
            if (!hashing.eql(hash, first.hash)) continue;
            var count: u32 = 1;
            while (count < hashes.len and i + count < object.count) : (count += 1) {
                const next = object.chunk(@intCast(i + count)) catch return null;
                const next_hash = keyed(reader.footer.chunk_hash_key, hashes[count]);
                if (!hashing.eql(next_hash, next.hash)) break;
            }
            if (best == null or count > best.?.count) best = .{
                .object = object,
                .chunk_index = @intCast(i),
                .count = count,
            };
        }
    }
    return best;
}

fn keyed(key: hashing.Hash, hash: hashing.Hash) hashing.Hash {
    if (hashing.eql(key, hashing.zero)) return hash;
    return hashing.keyed(key, &hash);
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

test "global dedup eligibility uses the last little-endian word" {
    var hash = hashing.zero;
    try std.testing.expect(eligible(hash));
    hash[24] = 1;
    try std.testing.expect(!eligible(hash));
}
