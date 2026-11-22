//! File reconstruction through caller-provided Xorb retrieval

const std = @import("std");
const constants = @import("constants.zig");
const hashing = @import("hash.zig");
const verify = @import("verify.zig");
const stream = @import("stream.zig");
const xorb = @import("xorb.zig");
const shard = @import("shard.zig");

pub const Range = struct {
    start: u32,
    end: u32,
};

pub const Term = struct {
    hash: hashing.Hash,
    unpacked_length: u32,
    range: Range,
};

/// Inclusive HTTP-style byte range, matching the CAS reconstruction response
pub const ByteRange = stream.ByteRange;

pub const Location = struct {
    hash: hashing.Hash,
    range: Range,
    url: []const u8,
    /// Null requests the complete object
    byte_range: ?ByteRange,
};

pub const Plan = struct {
    terms: []Term,
    locations: []Location,
    offset_into_first_range: u64 = 0,
    output_length: ?u64 = null,
    /// Enables complete-file verification. Ranged output is unsupported
    file_hash: ?hashing.Hash = null,

    pub fn init(
        allocator: std.mem.Allocator,
        terms: []const Term,
        locations: []const Location,
    ) !Plan {
        const owned_terms = try allocator.dupe(Term, terms);
        errdefer allocator.free(owned_terms);
        const owned_locations = try allocator.alloc(Location, locations.len);
        errdefer allocator.free(owned_locations);
        var initialized: usize = 0;
        errdefer for (owned_locations[0..initialized]) |location| allocator.free(location.url);
        for (locations, owned_locations) |location, *owned| {
            owned.* = location;
            owned.url = try allocator.dupe(u8, location.url);
            initialized += 1;
        }
        return .{
            .terms = owned_terms,
            .locations = owned_locations,
        };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        for (self.locations) |location| allocator.free(location.url);
        allocator.free(self.locations);
        allocator.free(self.terms);
        self.* = undefined;
    }

    pub fn validate(self: *const Plan) !void {
        if (self.file_hash != null and
            (self.offset_into_first_range != 0 or self.output_length != null))
            return error.UnsupportedRange;
        for (self.terms) |term| {
            if (term.range.start >= term.range.end) return error.InvalidRange;
            if (findLocation(self.locations, term) == null) return error.MissingLocation;
        }
        var total: u64 = 0;
        for (self.terms) |term| total = std.math.add(u64, total, term.unpacked_length) catch
            return error.InvalidSize;
        if (self.offset_into_first_range > total) return error.InvalidRange;
        if (self.output_length) |length| {
            const end = std.math.add(u64, self.offset_into_first_range, length) catch
                return error.InvalidRange;
            if (end > total) return error.InvalidRange;
        }
    }
};

pub const Request = stream.Request;
pub const Opener = stream.Opener;

pub const Error = error{
    InvalidRange,
    InvalidSize,
    MissingLocation,
    SizeMismatch,
};

/// Returns the initialized prefix of the caller-owned output
pub fn reconstructInto(
    allocator: std.mem.Allocator,
    output: []u8,
    plan: *const Plan,
    opener: Opener,
) ![]u8 {
    var writer: std.Io.Writer = .fixed(output);
    _ = try consume(allocator, plan, opener, &writer);
    return writer.buffered();
}

/// Returns an allocated reconstruction of the plan or requested range
pub fn reconstruct(allocator: std.mem.Allocator, plan: *const Plan, opener: Opener) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    _ = try consume(allocator, plan, opener, &output.writer);
    return output.toOwnedSlice();
}

/// Streams reconstruction without buffering a complete encoded range or term
pub fn consume(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    opener: Opener,
    sink: *std.Io.Writer,
) !u64 {
    if (plan.file_hash) |expected| {
        var verifier = verify.Verifier.init(allocator, sink);
        defer verifier.deinit();
        const written = consumeUnverified(allocator, plan, opener, &verifier.interface) catch |err|
            return verifier.failure(err);
        try verifier.finish(expected);
        return written;
    }
    return consumeUnverified(allocator, plan, opener, sink);
}

pub fn decodeTerm(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    term_index: usize,
    source: *std.Io.Reader,
    sink: *std.Io.Writer,
) !u64 {
    if (term_index >= plan.terms.len) return error.InvalidRange;
    const term = plan.terms[term_index];
    const location = findLocation(plan.locations, term) orelse return error.MissingLocation;
    return xorb.decodeStream(
        allocator,
        source,
        term.range.start - location.range.start,
        term.range.end - location.range.start,
        sink,
    );
}

fn consumeUnverified(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    opener: Opener,
    sink: *std.Io.Writer,
) !u64 {
    try plan.validate();
    const wanted = plan.output_length orelse blk: {
        var total: u64 = 0;
        for (plan.terms) |term| total += term.unpacked_length;
        break :blk total - plan.offset_into_first_range;
    };
    var skip = plan.offset_into_first_range;
    var written: u64 = 0;
    for (plan.terms, 0..) |term, index| {
        if (written == wanted) break;
        const location = findLocation(plan.locations, term) orelse return error.MissingLocation;
        const source = try opener.open(.{
            .hash = location.hash,
            .url = location.url,
            .byte_range = location.byte_range,
        });
        defer opener.close(source);

        var context = RangeWriter{
            .output = sink,
            .skip = &skip,
            .wanted = wanted,
            .written = &written,
        };
        const decoded = decodeTerm(allocator, plan, index, source, &context.writer) catch |err| switch (err) {
            error.ReadFailed => return opener.readError(source, err),
            else => return err,
        };
        if (decoded != term.unpacked_length) return error.SizeMismatch;
    }
    if (skip != 0 or written != wanted) return error.SizeMismatch;
    return written;
}

pub const RangeWriter = struct {
    output: *std.Io.Writer,
    skip: *u64,
    wanted: u64,
    written: *u64,
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *RangeWriter = @fieldParentPtr("writer", writer);
        for (data[0 .. data.len - 1]) |bytes| try self.write(bytes);
        for (0..splat) |_| try self.write(data[data.len - 1]);
        return std.Io.Writer.countSplat(data, splat);
    }

    fn write(self: *RangeWriter, input: []const u8) !void {
        var bytes = input;
        if (self.skip.* != 0) {
            const count: usize = @intCast(@min(self.skip.*, bytes.len));
            self.skip.* -= count;
            bytes = bytes[count..];
        }
        const count: usize = @intCast(@min(@as(u64, bytes.len), self.wanted - self.written.*));
        if (count != 0) try self.output.writeAll(bytes[0..count]);
        self.written.* += count;
    }
};

pub const ExpectedChunk = struct {
    hash: hashing.Hash,
    size: u32,
};

pub const ShardPlan = struct {
    size: u64,
    plan: Plan,
    chunks: []ExpectedChunk,

    pub fn deinit(self: *ShardPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.chunks);
        self.plan.deinit(allocator);
        self.* = undefined;
    }
};

/// Validates file hashes and verification records. Null requires one file in the shard
pub fn validateShardFile(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    file_hash: ?hashing.Hash,
) !hashing.Hash {
    const reader = try shard.Reader.init(bytes);
    if (file_hash == null and reader.footer.file_count != 1) return error.InvalidShard;
    const info = if (file_hash) |expected|
        (try reader.findFile(expected)) orelse return error.NotFound
    else
        try reader.fileAt(0);
    var nodes: std.ArrayList(hashing.Node) = .empty;
    defer nodes.deinit(allocator);
    for (0..info.count) |index| {
        const segment = try info.segment(@intCast(index));
        const object = try findShardXorb(reader, segment.xorb_hash);
        if (segment.chunk_index_start >= segment.chunk_index_end or
            segment.chunk_index_end > object.count) return error.InvalidRange;
        if (object.raw_size == 0) return error.InvalidShard;
        const segment_start = nodes.items.len;
        var unpacked: u64 = 0;
        for (segment.chunk_index_start..segment.chunk_index_end) |chunk_index| {
            const chunk = try object.chunk(@intCast(chunk_index));
            if (chunk.unpacked_segment_bytes == 0 or
                chunk.unpacked_segment_bytes > constants.max_chunk_size)
                return error.InvalidChunkSize;
            try nodes.append(allocator, .{
                .hash = chunk.hash,
                .size = chunk.unpacked_segment_bytes,
            });
            unpacked += chunk.unpacked_segment_bytes;
        }
        if (unpacked != segment.unpacked_segment_bytes or unpacked > object.raw_size) return error.SizeMismatch;
        if (info.flags & shard.verification_flag != 0) {
            if (!hashing.eql(
                try info.verification(@intCast(index)),
                hashing.verificationNodes(nodes.items[segment_start..]),
            )) return error.HashMismatch;
        }
    }
    if (!hashing.eql(info.hash, try hashing.file(allocator, nodes.items))) return error.HashMismatch;
    return info.hash;
}

/// Builds a verified whole-file plan using complete Xorbs and empty transport URLs
pub fn planFromShard(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    file_hash: hashing.Hash,
) !ShardPlan {
    _ = try validateShardFile(allocator, bytes, file_hash);
    const reader = try shard.Reader.init(bytes);
    const info = (try reader.findFile(file_hash)) orelse return error.NotFound;
    const terms = try allocator.alloc(Term, info.count);
    defer allocator.free(terms);
    const locations = try allocator.alloc(Location, info.count);
    defer allocator.free(locations);

    var chunk_count: usize = 0;
    for (0..info.count) |index| {
        const segment = try info.segment(@intCast(index));
        chunk_count = std.math.add(usize, segment.chunk_index_end - segment.chunk_index_start, chunk_count) catch
            return error.InvalidShard;
    }
    const chunks = try allocator.alloc(ExpectedChunk, chunk_count);
    errdefer allocator.free(chunks);
    var next_chunk: usize = 0;
    var size: u64 = 0;
    for (0..info.count) |index| {
        const segment = try info.segment(@intCast(index));
        terms[index] = .{
            .hash = segment.xorb_hash,
            .unpacked_length = segment.unpacked_segment_bytes,
            .range = .{ .start = segment.chunk_index_start, .end = segment.chunk_index_end },
        };
        const object = try findShardXorb(reader, segment.xorb_hash);
        locations[index] = .{
            .hash = segment.xorb_hash,
            .range = .{ .start = 0, .end = object.count },
            .url = "",
            .byte_range = if (object.serialized_size == 0)
                null
            else
                .{ .start = 0, .end = object.serialized_size - 1 },
        };
        for (segment.chunk_index_start..segment.chunk_index_end) |chunk_index| {
            const chunk = try object.chunk(@intCast(chunk_index));
            chunks[next_chunk] = .{ .hash = chunk.hash, .size = chunk.unpacked_segment_bytes };
            next_chunk += 1;
        }
        size = std.math.add(u64, size, segment.unpacked_segment_bytes) catch return error.InvalidSize;
    }
    var plan = try Plan.init(allocator, terms, locations);
    errdefer plan.deinit(allocator);
    plan.file_hash = file_hash;
    try plan.validate();
    return .{ .size = size, .plan = plan, .chunks = chunks };
}

/// Verifies whole plans before forwarding with one retained chunk and an optional sink
pub fn consumeVerified(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    opener: Opener,
    expected: []const ExpectedChunk,
    sink: ?*std.Io.Writer,
) !u64 {
    if (plan.offset_into_first_range != 0 or plan.output_length != null) return error.UnsupportedRange;
    var verifier = ChunkVerifier{ .allocator = allocator, .expected = expected, .output = sink };
    defer verifier.pending.deinit(allocator);
    const count = consume(allocator, plan, opener, &verifier.writer) catch |err|
        return verifier.error_value orelse err;
    if (verifier.index != expected.len or verifier.pending.items.len != 0) return error.SizeMismatch;
    return count;
}

const ChunkVerifier = struct {
    allocator: std.mem.Allocator,
    expected: []const ExpectedChunk,
    output: ?*std.Io.Writer,
    index: usize = 0,
    pending: std.ArrayList(u8) = .empty,
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    error_value: ?anyerror = null,

    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *ChunkVerifier = @fieldParentPtr("writer", writer);
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

    fn write(self: *ChunkVerifier, input: []const u8) !void {
        var remaining = input;
        while (remaining.len != 0) {
            if (self.index == self.expected.len) return error.SizeMismatch;
            const expected = self.expected[self.index];
            if (expected.size == 0 or expected.size > constants.max_chunk_size) return error.InvalidChunkSize;
            if (self.pending.items.len > expected.size) return error.SizeMismatch;
            const needed = expected.size - self.pending.items.len;
            const count = @min(needed, remaining.len);
            try self.pending.appendSlice(self.allocator, remaining[0..count]);
            remaining = remaining[count..];
            if (self.pending.items.len != expected.size) continue;
            if (!hashing.eql(hashing.data(self.pending.items), expected.hash)) return error.HashMismatch;
            if (self.output) |sink| try sink.writeAll(self.pending.items);
            self.pending.clearRetainingCapacity();
            self.index += 1;
        }
    }
};

fn findShardXorb(reader: shard.Reader, hash: hashing.Hash) !shard.XorbInfo {
    return (try reader.findXorb(hash)) orelse error.NotFound;
}

pub fn findLocation(locations: []const Location, term: Term) ?Location {
    for (locations) |location| {
        if (hashing.eql(location.hash, term.hash) and
            location.range.start <= term.range.start and
            location.range.end >= term.range.end and
            (location.byte_range == null or
                location.byte_range.?.start <= location.byte_range.?.end))
            return location;
    }
    return null;
}

test "plans reject output ranges beyond their declared contents before I/O" {
    const hash = hashing.data("object");
    var terms = [_]Term{.{
        .hash = hash,
        .unpacked_length = 100,
        .range = .{ .start = 0, .end = 1 },
    }};
    var locations = [_]Location{.{
        .hash = hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://object",
        .byte_range = null,
    }};
    var plan = Plan{
        .terms = &terms,
        .locations = &locations,
        .offset_into_first_range = 20,
        .output_length = 81,
    };
    try std.testing.expectError(error.InvalidRange, plan.validate());
    plan.output_length = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidRange, plan.validate());

    const Context = struct {
        calls: usize = 0,
        reader: std.Io.Reader = .fixed(""),
        fn open(raw: *anyopaque, _: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{};
    try std.testing.expectError(error.InvalidRange, reconstruct(
        std.testing.allocator,
        &plan,
        .{ .context = &context, .open_fn = Context.open, .close_fn = Context.close },
    ));
    try std.testing.expectEqual(@as(usize, 0), context.calls);
    plan.output_length = 80;
    try plan.validate();
}

test "location lookup skips inverted ranges even when a valid duplicate follows" {
    const hash = hashing.data("object");
    const term = Term{
        .hash = hash,
        .unpacked_length = 3,
        .range = .{ .start = 0, .end = 1 },
    };
    const locations = [_]Location{
        .{
            .hash = hash,
            .range = .{ .start = 0, .end = 1 },
            .url = "memory://invalid",
            .byte_range = .{ .start = 2, .end = 1 },
        },
        .{
            .hash = hash,
            .range = .{ .start = 0, .end = 1 },
            .url = "memory://valid",
            .byte_range = .{ .start = 0, .end = 10 },
        },
    };
    var terms = [_]Term{term};
    var owned_locations = locations;
    var plan = Plan{
        .terms = &terms,
        .locations = &owned_locations,
    };
    try plan.validate();
    try std.testing.expectEqualStrings("memory://valid", findLocation(&locations, term).?.url);
}

fn expectNoEmptyWrites() !void {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "AAA", .hash = hashing.data("AAA") },
        .{ .data = "BBB", .hash = hashing.data("BBB") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]Term{
        .{ .hash = object.hash, .unpacked_length = 6, .range = .{ .start = 0, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 6, .range = .{ .start = 0, .end = 2 } },
    };
    const locations = [_]Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    plan.output_length = 1;

    const Context = struct {
        bytes: []const u8,
        reader: std.Io.Reader = undefined,
        empty_writes: usize = 0,
        output: std.Io.Writer.Allocating,
        writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },

        fn open(raw: *anyopaque, _: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.reader = .fixed(self.bytes);
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
        fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", writer);
            const count = std.Io.Writer.countSplat(data, splat);
            if (count == 0) self.empty_writes += 1;
            for (data[0 .. data.len - 1]) |part| self.output.writer.writeAll(part) catch return error.WriteFailed;
            for (0..splat) |_| self.output.writer.writeAll(data[data.len - 1]) catch return error.WriteFailed;
            return count;
        }
    };
    var context = Context{ .bytes = object.bytes, .output = .init(allocator) };
    defer context.output.deinit();
    _ = try consume(allocator, &plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    }, &context.writer);
    try std.testing.expectEqualStrings("A", context.output.written());
    try std.testing.expectEqual(@as(usize, 0), context.empty_writes);
}

test "reconstruction does not emit empty writes" {
    try expectNoEmptyWrites();
}

test "shard plans validate Merkle roots and preserve every selected chunk" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 300_000);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% index / 97);
    const package = try @import("store.zig").pack(allocator, data, .{ .max_xorb_size = 64 * 1024 });
    defer {
        var mutable = package;
        mutable.deinit(allocator);
    }
    try std.testing.expect(package.objects.len > 1);
    try std.testing.expectEqual(package.file_hash, try validateShardFile(allocator, package.shard_bytes, null));
    var result = try planFromShard(allocator, package.shard_bytes, package.file_hash);
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(u64, data.len), result.size);
    try std.testing.expectEqual(package.objects.len, result.plan.terms.len);
    var total: u64 = 0;
    for (result.chunks) |chunk| total += chunk.size;
    try std.testing.expectEqual(@as(u64, data.len), total);
    try std.testing.expectError(error.NotFound, validateShardFile(allocator, package.shard_bytes, hashing.zero));

    const empty = try @import("store.zig").pack(allocator, "", .{});
    defer {
        var mutable = empty;
        mutable.deinit(allocator);
    }
    var empty_plan = try planFromShard(allocator, empty.shard_bytes, empty.file_hash);
    defer empty_plan.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), empty_plan.size);
    try std.testing.expectEqual(@as(usize, 0), empty_plan.chunks.len);
    @memset(empty.shard_bytes[shard.header_size..][0..hashing.zero.len], 1);
    try std.testing.expectError(error.HashMismatch, validateShardFile(allocator, empty.shard_bytes, null));
}

test "verified streaming reconstructs fragmented chunks and rejects wrong data" {
    const allocator = std.testing.allocator;
    const first = try allocator.alloc(u8, 10_000);
    defer allocator.free(first);
    for (first, 0..) |*byte, index| byte.* = @truncate(index *% 37);
    const chunks = [_]xorb.Chunk{
        .{ .data = first, .hash = hashing.data(first) },
        .{ .data = "second", .hash = hashing.data("second") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]Term{.{
        .hash = object.hash,
        .unpacked_length = @intCast(first.len + 6),
        .range = .{ .start = 0, .end = 2 },
    }};
    const locations = [_]Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://verified",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    const expected = [_]ExpectedChunk{
        .{ .hash = hashing.data(first), .size = @intCast(first.len) },
        .{ .hash = hashing.data("second"), .size = 6 },
    };
    const Context = struct {
        bytes: []const u8,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, _: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.reader = .fixed(self.bytes);
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .bytes = object.bytes };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const opener = Opener{ .context = &context, .open_fn = Context.open, .close_fn = Context.close };
    const count = try consumeVerified(allocator, &plan, opener, &expected, &output.writer);
    try std.testing.expectEqual(@as(u64, first.len + 6), count);
    try std.testing.expectEqualSlices(u8, first, output.written()[0..first.len]);
    try std.testing.expectEqualStrings("second", output.written()[first.len..]);

    var wrong = expected;
    wrong[0].hash = hashing.data("wrong");
    output.clearRetainingCapacity();
    try std.testing.expectError(error.HashMismatch, consumeVerified(allocator, &plan, opener, &wrong, &output.writer));
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
    try std.testing.expectError(error.HashMismatch, consumeVerified(allocator, &plan, opener, &wrong, null));

    var ranged = try Plan.init(allocator, &terms, &locations);
    defer ranged.deinit(allocator);
    ranged.output_length = 5;
    try std.testing.expectError(error.UnsupportedRange, consumeVerified(allocator, &ranged, opener, &expected, null));
}

test "streaming reconstruction honors offsets and closes every source" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "alpha", .hash = hashing.data("alpha") },
        .{ .data = "beta", .hash = hashing.data("beta") },
        .{ .data = "gamma", .hash = hashing.data("gamma") },
    };
    var object = try xorb.serialize(allocator, &chunks, .lz4);
    defer object.deinit(allocator);
    const terms = [_]Term{
        .{ .hash = object.hash, .unpacked_length = 4, .range = .{ .start = 1, .end = 2 } },
        .{ .hash = object.hash, .unpacked_length = 5, .range = .{ .start = 2, .end = 3 } },
    };
    const locations = [_]Location{.{
        .hash = object.hash,
        .range = .{ .start = 1, .end = 3 },
        .url = "memory://range",
        .byte_range = .{ .start = 8, .end = 20 },
    }};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    plan.offset_into_first_range = 1;
    plan.output_length = 7;

    const Context = struct {
        bytes: []const u8,
        opens: usize = 0,
        closes: usize = 0,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            try std.testing.expectEqualStrings("memory://range", request.url);
            self.opens += 1;
            self.reader = .fixed(self.bytes);
            return &self.reader;
        }
        fn close(raw: *anyopaque, _: *std.Io.Reader) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.closes += 1;
        }
    };
    const header_size = 8 + chunks[0].data.len;
    var context = Context{ .bytes = object.bytes[header_size .. object.bytes.len - 4 - 92 - 40 * chunks.len] };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const count = try consume(allocator, &plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    }, &output.writer);
    try std.testing.expectEqual(@as(u64, 7), count);
    try std.testing.expectEqualStrings("etagamm", output.written());
    try std.testing.expectEqual(@as(usize, 2), context.opens);
    try std.testing.expectEqual(context.opens, context.closes);
}

test "reconstruct ranges through a generic opener" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "alpha", .hash = hashing.data("alpha") },
        .{ .data = "beta", .hash = hashing.data("beta") },
        .{ .data = "gamma", .hash = hashing.data("gamma") },
    };
    var object = try xorb.serialize(allocator, &chunks, .lz4);
    defer object.deinit(allocator);
    const terms = [_]Term{.{
        .hash = object.hash,
        .unpacked_length = 9,
        .range = .{ .start = 1, .end = 3 },
    }};
    const locations = [_]Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 3 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    plan.offset_into_first_range = 2;
    plan.output_length = 5;

    const Context = struct {
        bytes: []const u8,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            try std.testing.expectEqualStrings("memory://object", request.url);
            self.reader = .fixed(self.bytes);
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .bytes = object.bytes };
    const result = try reconstruct(allocator, &plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("tagam", result);
}

test "range writer consumes every splat repetition once" {
    var bytes: [9]u8 = undefined;
    var output: std.Io.Writer = .fixed(&bytes);
    var skip: u64 = 1;
    var written: u64 = 0;
    var range = RangeWriter{
        .output = &output,
        .skip = &skip,
        .wanted = 9,
        .written = &written,
    };
    var parts = [_][]const u8{"abcd"};
    try range.writer.writeSplatAll(&parts, 3);
    try std.testing.expectEqual(@as(u64, 0), skip);
    try std.testing.expectEqual(@as(u64, 9), written);
    try std.testing.expectEqualStrings("bcdabcdab", output.buffered());
}

test "chunk verifier consumes every splat repetition once" {
    const allocator = std.testing.allocator;
    const expected = [_]ExpectedChunk{
        .{ .hash = hashing.data("abc"), .size = 3 },
        .{ .hash = hashing.data("abc"), .size = 3 },
        .{ .hash = hashing.data("abc"), .size = 3 },
    };
    var bytes: [9]u8 = undefined;
    var output: std.Io.Writer = .fixed(&bytes);
    var verifier = ChunkVerifier{
        .allocator = allocator,
        .expected = &expected,
        .output = &output,
    };
    defer verifier.pending.deinit(allocator);
    var parts = [_][]const u8{"abc"};
    try verifier.writer.writeSplatAll(&parts, 3);
    try std.testing.expectEqual(@as(usize, 3), verifier.index);
    try std.testing.expectEqualStrings("abcabcabc", output.buffered());
}
