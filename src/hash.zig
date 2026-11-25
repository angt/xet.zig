const std = @import("std");
const constants = @import("constants.zig");

/// A Xet hash in its binary, little-endian-word representation
pub const Hash = [32]u8;

pub const zero: Hash = @splat(0);

/// Converts a big-endian digest to Xet's little-endian u64 words
pub fn fromStandard(digest: [32]u8) Hash {
    var out: Hash = undefined;
    for (0..4) |word| {
        for (0..8) |byte| out[word * 8 + byte] = digest[word * 8 + 7 - byte];
    }
    return out;
}

pub const Node = struct {
    hash: Hash,
    size: u64,
};

pub fn keyed(key: Hash, message: []const u8) Hash {
    var out: Hash = undefined;
    std.crypto.hash.Blake3.hash(message, &out, .{ .key = key });
    return out;
}

pub fn data(bytes: []const u8) Hash {
    return keyed(constants.data_key, bytes);
}

pub fn internal(bytes: []const u8) Hash {
    return keyed(constants.internal_node_key, bytes);
}

pub fn verification(hashes: []const Hash) Hash {
    var hasher = std.crypto.hash.Blake3.init(.{ .key = constants.verification_key });
    for (hashes) |item| hasher.update(&item);
    var out: Hash = undefined;
    hasher.final(&out);
    return out;
}

pub fn verificationNodes(nodes: []const Node) Hash {
    var hasher = std.crypto.hash.Blake3.init(.{ .key = constants.verification_key });
    for (nodes) |node| hasher.update(&node.hash);
    var out: Hash = undefined;
    hasher.final(&out);
    return out;
}

/// Formats four little-endian u64 words as hexadecimal
pub fn toHex(value: Hash) [64]u8 {
    const hex = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (0..4) |i| {
        const word = std.mem.readInt(u64, value[i * 8 ..][0..8], .little);
        for (0..16) |digit| {
            out[i * 16 + digit] = hex[@as(u4, @truncate(word >> @intCast(60 - 4 * digit)))];
        }
    }
    return out;
}

pub fn fromHex(text: []const u8) error{InvalidHash}!Hash {
    if (text.len != 64) return error.InvalidHash;
    var out: Hash = undefined;
    for (0..4) |i| {
        const word = std.fmt.parseInt(u64, text[i * 16 ..][0..16], 16) catch
            return error.InvalidHash;
        std.mem.writeInt(u64, out[i * 8 ..][0..8], word, .little);
    }
    return out;
}

pub fn eql(a: Hash, b: Hash) bool {
    return std.mem.eql(u8, &a, &b);
}

pub fn order(a: Hash, b: Hash) std.math.Order {
    for (0..4) |i| {
        const a_word = std.mem.readInt(u64, a[i * 8 ..][0..8], .little);
        const b_word = std.mem.readInt(u64, b[i * 8 ..][0..8], .little);
        const result = std.math.order(a_word, b_word);
        if (result != .eq) return result;
    }
    return .eq;
}

pub fn truncated(value: Hash) u64 {
    return std.mem.readInt(u64, value[0..8], .little);
}

fn naturalCut(value: Hash) bool {
    return std.mem.readInt(u64, value[24..32], .little) % 4 == 0;
}

fn nextCut(nodes: []const Node) usize {
    if (nodes.len <= 2) return nodes.len;
    const end = @min(nodes.len, 9);
    for (2..end) |i| {
        if (naturalCut(nodes[i].hash)) return i + 1;
    }
    return end;
}

fn merge(nodes: []const Node) Node {
    std.debug.assert(nodes.len <= 9);
    var buffer: [9 * 88]u8 = undefined;
    var stream = std.Io.Writer.fixed(&buffer);
    var total: u64 = 0;
    for (nodes) |node| {
        const hex = toHex(node.hash);
        stream.print("{s} : {d}\n", .{ hex, node.size }) catch unreachable;
        total += node.size;
    }
    return .{ .hash = internal(stream.buffered()), .size = total };
}

/// Aggregate chunk nodes using Xet's content-defined Merkle tree
pub fn aggregate(allocator: std.mem.Allocator, nodes: []const Node) !Hash {
    if (nodes.len == 0) return zero;
    if (nodes.len == 1) return nodes[0].hash;

    const work = try allocator.dupe(Node, nodes);
    defer allocator.free(work);
    var len = work.len;
    while (len > 1) {
        var src: usize = 0;
        var dst: usize = 0;
        while (src < len) {
            const end = src + nextCut(work[src..len]);
            work[dst] = merge(work[src..end]);
            src = end;
            dst += 1;
        }
        len = dst;
    }
    return work[0].hash;
}

pub fn xorb(allocator: std.mem.Allocator, nodes: []const Node) !Hash {
    return aggregate(allocator, nodes);
}

pub fn file(allocator: std.mem.Allocator, nodes: []const Node) !Hash {
    if (nodes.len == 0) return zero;
    const root = try aggregate(allocator, nodes);
    return keyed(zero, &root);
}

/// Bounded-memory Xet Merkle aggregation
pub const Aggregator = struct {
    levels: [max_levels]Level = @splat(.{}),
    leaves: u64 = 0,

    const max_levels = 32;
    const Level = struct {
        nodes: [10]Node = undefined,
        len: u4 = 0,
    };

    pub fn add(self: *Aggregator, node: Node) !void {
        self.leaves = std.math.add(u64, self.leaves, 1) catch return error.TooManyChunks;
        try self.addAt(0, node);
    }

    fn addAt(self: *Aggregator, level: usize, node: Node) !void {
        if (level == max_levels) return error.TooManyChunks;
        var current = &self.levels[level];
        current.nodes[current.len] = node;
        current.len += 1;
        if (current.len != current.nodes.len) return;
        const cut = nextCut(current.nodes[0 .. current.nodes.len - 1]);
        const parent = merge(current.nodes[0..cut]);
        const remaining = current.nodes.len - cut;
        std.mem.copyForwards(
            Node,
            current.nodes[0..remaining],
            current.nodes[cut..current.nodes.len],
        );
        current.len = @intCast(remaining);
        try self.addAt(level + 1, parent);
    }

    pub fn root(self: *const Aggregator) !Hash {
        var work = self.*;
        if (work.leaves == 0) return zero;
        if (work.leaves == 1) return work.levels[0].nodes[0].hash;
        for (0..max_levels) |i| {
            const level = &work.levels[i];
            if (level.len == 0) continue;
            const higher = for (work.levels[i + 1 ..]) |other| {
                if (other.len != 0) break true;
            } else false;
            if (level.len == 1 and !higher) return level.nodes[0].hash;

            var pos: usize = 0;
            while (pos < level.len) {
                const cut = nextCut(level.nodes[pos..level.len]);
                try work.addAt(i + 1, merge(level.nodes[pos..][0..cut]));
                pos += cut;
            }
            level.len = 0;
        }
        return error.TooManyChunks;
    }

    pub fn fileHash(self: *const Aggregator) !Hash {
        if (self.leaves == 0) return zero;
        const value = try self.root();
        return keyed(zero, &value);
    }
};

test "incremental aggregation matches every small tree" {
    const base = try fromHex("cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6");
    for (1..150) |count| {
        const nodes = try std.testing.allocator.alloc(Node, count);
        defer std.testing.allocator.free(nodes);
        for (nodes, 0..) |*node, index| {
            var value = base;
            value[0] = @truncate(index * 37);
            value[24] = @truncate(index * 19);
            node.* = .{ .hash = value, .size = index + 1 };
        }
        var aggregator = Aggregator{};
        for (nodes) |node| try aggregator.add(node);
        const expected = try aggregate(std.testing.allocator, nodes);
        const actual = try aggregator.root();
        if (!eql(expected, actual)) {
            std.debug.print("incremental mismatch at {d}: levels", .{count});
            for (aggregator.levels) |level| {
                if (level.len != 0) std.debug.print(" {d}", .{level.len});
            }
            std.debug.print(" expected {s} actual {s}\n", .{ toHex(expected), toHex(actual) });
            return error.TestExpectedEqual;
        }
    }
}

test "Merkle roots are repeatable and do not consume pending nodes" {
    const allocator = std.testing.allocator;
    for (1..150) |count| {
        var nodes = try allocator.alloc(Node, count + 1);
        defer allocator.free(nodes);
        for (nodes, 0..) |*node, index| {
            node.* = .{ .hash = data(&.{@truncate(index *% 37)}), .size = index + 1 };
        }
        var aggregator = Aggregator{};
        for (nodes[0..count]) |node| try aggregator.add(node);
        const expected = try aggregate(allocator, nodes[0..count]);
        try std.testing.expectEqual(expected, try aggregator.root());
        try std.testing.expectEqual(expected, try aggregator.root());
        try std.testing.expectEqual(keyed(zero, &expected), try aggregator.fileHash());
        try aggregator.add(nodes[count]);
        try std.testing.expectEqual(try aggregate(allocator, nodes), try aggregator.root());
    }
}

test "verification hashes nodes without converting them" {
    const nodes = [_]Node{
        .{ .hash = data("first"), .size = 5 },
        .{ .hash = data("second"), .size = 6 },
    };
    const hashes = [_]Hash{ nodes[0].hash, nodes[1].hash };
    try std.testing.expectEqual(verification(&hashes), verificationNodes(&nodes));
}

test "Rust Merkle reference vectors" {
    const a = try fromHex("cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6");
    const b = try fromHex("c3e67584b5c4fc2a89837ec39e40f2c8a6bb0b2987ac94cd4b31e5fbdd210a72");
    const c = try fromHex("0d2beb91b9196929a5ddec9f6e306924ddf4a24268e3e59fd8464738d525af37");
    const nodes = [_]Node{
        .{ .hash = a, .size = 100 },
        .{ .hash = b, .size = 200 },
        .{ .hash = c, .size = 300 },
    };
    const root = try aggregate(std.testing.allocator, &nodes);
    try std.testing.expectEqualStrings(
        "71ec1275fca074724e2dd666921b3277c7cee603e4d025bcab2d4050015be2bc",
        &toHex(root),
    );
    const file_hash = try file(std.testing.allocator, &nodes);
    try std.testing.expectEqualStrings(
        "54e55dccc6653c612bdb5576c5d3cb34bb31bc4e100248abccf4c908b3ef7715",
        &toHex(file_hash),
    );
}

test "32 identical nodes match the Rust reference" {
    const item = try fromHex("cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6");
    const nodes: [32]Node = @splat(.{ .hash = item, .size = 100 });
    const root = try aggregate(std.testing.allocator, &nodes);
    try std.testing.expectEqualStrings(
        "0a0123c1617921883b7e13902095fcb86676e77c49120c33b233003b0af0e0a6",
        &toHex(root),
    );
}

test "empty file hash is zero" {
    try std.testing.expectEqual(zero, try file(std.testing.allocator, &.{}));
}

test "hash hex uses Xet word order" {
    const raw = [32]u8{
        22,  175, 58, 132, 4,   75,  131, 214, 190, 153, 138, 66,  226, 3,   153, 242,
        204, 86,  80, 234, 249, 153, 80,  99,  159, 80,  65,  138, 236, 231, 149, 78,
    };
    const text = "d6834b04843aaf16f29903e2428a99be635099f9ea5056cc4e95e7ec8a41509f";
    try std.testing.expectEqualStrings(text, &toHex(raw));
    try std.testing.expectEqual(raw, try fromHex(text));
    try std.testing.expectError(error.InvalidHash, fromHex("abc"));
}
