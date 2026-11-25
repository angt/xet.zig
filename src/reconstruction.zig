//! File reconstruction through caller-provided Xorb retrieval

const std = @import("std");
const chunker = @import("chunker.zig");
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

pub const ByteRange = stream.ByteRange;

pub const Location = struct {
    hash: hashing.Hash,
    range: Range,
    url: []const u8,
    byte_range: ?ByteRange,
};

pub const Plan = struct {
    terms: []Term,
    locations: []Location,
    offset_into_first_range: u64 = 0,
    output_length: ?u64 = null,
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
        _ = try self.checkedLength();
    }

    fn checkedLength(self: *const Plan) !u64 {
        if (self.file_hash != null and
            (self.offset_into_first_range != 0 or self.output_length != null))
            return error.UnsupportedRange;
        for (self.terms) |term| {
            try validateTermRange(term);
            try checkLocation(self.locations, term);
        }
        return self.decodedLength();
    }

    fn decodedLength(self: *const Plan) !u64 {
        var total: u64 = 0;
        for (self.terms) |term| total = std.math.add(u64, total, term.unpacked_length) catch
            return error.InvalidSize;
        if (self.offset_into_first_range > total) return error.InvalidRange;
        if (self.output_length) |length| {
            const end = std.math.add(u64, self.offset_into_first_range, length) catch
                return error.InvalidRange;
            if (end > total) return error.InvalidRange;
        }
        return self.output_length orelse total - self.offset_into_first_range;
    }
};

pub const Request = stream.Request;
pub const Opener = stream.Opener;

pub const Error = error{
    InvalidRange,
    InvalidSize,
    MissingLocation,
    SizeMismatch,
    UnsupportedFileHash,
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
    return consumeWith(allocator, plan, opener, sink, null);
}

/// File hashes only match when the strategy matches the one used during upload
pub fn consumeWith(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    opener: Opener,
    sink: *std.Io.Writer,
    strategy: ?chunker.Strategy,
) !u64 {
    if (plan.file_hash) |expected| {
        var verifier = verify.Verifier.initWith(allocator, sink, strategy);
        defer verifier.deinit();
        const written = consumeUnverified(allocator, plan, opener, &verifier.interface, null) catch |err|
            return verifier.failure(err);
        try verifier.finish(expected);
        return written;
    }
    return consumeUnverified(allocator, plan, opener, sink, null);
}

/// Decodes and verifies an opened single-term plan against every target chunk
pub fn decodeOpenedTermVerified(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    source: *std.Io.Reader,
    expected: []const ExpectedChunk,
    sink: *std.Io.Writer,
) !u64 {
    if (plan.terms.len != 1 or plan.locations.len != 1) return error.InvalidRange;
    if (plan.offset_into_first_range != 0 or plan.output_length != null) return error.UnsupportedRange;
    if (plan.file_hash != null) return error.UnsupportedFileHash;
    try plan.validate();
    try validateTermChunks(plan.terms[0], expected);
    var verifier = ChunkVerifier{ .allocator = allocator, .expected = expected, .output = sink };
    defer verifier.pending.deinit(allocator);
    const decoded = decodeTermAt(allocator, plan.terms[0], plan.locations[0], source, &verifier.writer, expected) catch |err|
        return verifier.error_value orelse err;
    if (decoded != plan.terms[0].unpacked_length) return error.SizeMismatch;
    if (verifier.index != expected.len or verifier.pending.items.len != 0) return error.SizeMismatch;
    return decoded;
}

fn validateTermRange(term: Term) !void {
    if (term.range.start >= term.range.end) return error.InvalidRange;
}

fn termChunkCount(term: Term) !usize {
    try validateTermRange(term);
    return term.range.end - term.range.start;
}

fn validateTermChunks(term: Term, expected: []const ExpectedChunk) !void {
    const count = try termChunkCount(term);
    if (expected.len != count) return error.SizeMismatch;
    var total: u64 = 0;
    for (expected) |chunk| {
        if (chunk.size == 0 or chunk.size > constants.max_chunk_size) return error.InvalidChunkSize;
        total = std.math.add(u64, total, chunk.size) catch return error.InvalidSize;
    }
    if (total != term.unpacked_length) return error.SizeMismatch;
}

fn validatePlanChunks(plan: *const Plan, expected: []const ExpectedChunk) !void {
    var next: usize = 0;
    for (plan.terms) |term| {
        const count = try termChunkCount(term);
        if (count > expected.len -| next) return error.SizeMismatch;
        try validateTermChunks(term, expected[next..][0..count]);
        next += count;
    }
    if (next != expected.len) return error.SizeMismatch;
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
    try validateTermRange(term);
    const location = findLocation(plan.locations, term) orelse
        return if (hasLocation(plan.locations, term)) error.InvalidRange else error.MissingLocation;
    return decodeTermAt(allocator, term, location, source, sink, null);
}

/// Decodes through a caller-selected location that must cover the term
pub fn decodeLocatedTerm(
    allocator: std.mem.Allocator,
    term: Term,
    location: Location,
    source: *std.Io.Reader,
    sink: *std.Io.Writer,
) !u64 {
    try validateTermRange(term);
    if (!covers(location, term)) return error.MissingLocation;
    if (!hasUsableRange(location)) return error.InvalidRange;
    return decodeTermAt(allocator, term, location, source, sink, null);
}

fn decodeTermAt(
    allocator: std.mem.Allocator,
    term: Term,
    location: Location,
    source: *std.Io.Reader,
    sink: *std.Io.Writer,
    expected: ?[]const ExpectedChunk,
) !u64 {
    const base = if (location.byte_range == null) 0 else location.range.start;
    return xorb.decodeStreamSized(
        allocator,
        source,
        term.range.start - base,
        term.range.end - base,
        expected,
        sink,
    );
}

fn takeTermChunks(
    chunks: ?[]const ExpectedChunk,
    next: *usize,
    count: usize,
) ?[]const ExpectedChunk {
    const all = chunks orelse return null;
    const taken = all[next.*..][0..count];
    next.* += count;
    return taken;
}

fn consumeUnverified(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    opener: Opener,
    sink: *std.Io.Writer,
    chunks: ?[]const ExpectedChunk,
) !u64 {
    const wanted = try plan.checkedLength();
    var skip = plan.offset_into_first_range;
    var written: u64 = 0;
    var next_chunk: usize = 0;
    var locator = Locator.init(allocator, plan.locations);
    defer locator.deinit();
    for (plan.terms) |term| {
        if (written == wanted) break;
        const location = try locator.find(term) orelse return error.MissingLocation;
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
        const count = try termChunkCount(term);
        const term_chunks = takeTermChunks(chunks, &next_chunk, count);
        const decoded = decodeTermAt(allocator, term, location, source, &context.writer, term_chunks) catch |err| switch (err) {
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

pub const ExpectedChunk = xorb.ExpectedChunk;

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

/// A null file hash requires exactly one file in the shard
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
        const object = (try reader.findXorb(segment.xorb_hash)) orelse return error.NotFound;
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
        const object = (try reader.findXorb(segment.xorb_hash)) orelse return error.NotFound;
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

/// Rejects a wrong file root before opening any source
pub fn consumeVerified(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    opener: Opener,
    expected: []const ExpectedChunk,
    sink: ?*std.Io.Writer,
) !u64 {
    if (plan.offset_into_first_range != 0 or plan.output_length != null) return error.UnsupportedRange;
    try plan.validate();
    try validatePlanChunks(plan, expected);
    if (plan.file_hash) |root| {
        if (!hashing.eql(root, try expectedFileHash(expected))) return error.HashMismatch;
    }
    var verifier = ChunkVerifier{ .allocator = allocator, .expected = expected, .output = sink };
    defer verifier.pending.deinit(allocator);
    const count = consumeUnverified(allocator, plan, opener, &verifier.writer, expected) catch |err|
        return verifier.error_value orelse err;
    if (verifier.index != expected.len or verifier.pending.items.len != 0) return error.SizeMismatch;
    return count;
}

fn expectedFileHash(expected: []const ExpectedChunk) !hashing.Hash {
    var nodes: hashing.Aggregator = .{};
    for (expected) |chunk| try nodes.add(.{ .hash = chunk.hash, .size = chunk.size });
    return nodes.fileHash();
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

pub fn hasLocation(locations: []const Location, term: Term) bool {
    for (locations) |location| {
        if (covers(location, term)) return true;
    }
    return false;
}

fn checkLocation(locations: []const Location, term: Term) !void {
    var covered = false;
    for (locations) |location| {
        if (!covers(location, term)) continue;
        if (hasUsableRange(location)) return;
        covered = true;
    }
    if (covered) return error.InvalidRange;
    return error.MissingLocation;
}

/// Best covering location that can serve a request, null when none can
pub fn findLocation(locations: []const Location, term: Term) ?Location {
    var best: ?Location = null;
    for (locations) |location| {
        if (!covers(location, term)) continue;
        if (!hasUsableRange(location)) continue;
        if (best) |current| {
            if (!betterRequest(location, current)) continue;
        }
        best = location;
    }
    return best;
}

fn hasUsableRange(location: Location) bool {
    const bytes = location.byte_range orelse return true;
    _ = stream.rangeLength(bytes) catch return false;
    return true;
}

fn betterRequest(candidate: Location, current: Location) bool {
    const bytes = candidate.byte_range orelse return false;
    const current_bytes = current.byte_range orelse return true;
    const span = bytes.end - bytes.start;
    const current_span = current_bytes.end - current_bytes.start;
    if (span != current_span) return span < current_span;
    return candidate.range.end - candidate.range.start < current.range.end - current.range.start;
}

fn covers(location: Location, term: Term) bool {
    if (term.range.start >= term.range.end) return false;
    if (!hashing.eql(location.hash, term.hash)) return false;
    if (location.range.start > term.range.start or location.range.end < term.range.end) return false;
    if (location.byte_range) |range| {
        if (range.start > range.end) return false;
    }
    return true;
}

/// Memoizes rankings for one pass, so each distinct query scans the list once
pub const Locator = struct {
    allocator: std.mem.Allocator,
    locations: []const Location,
    entries: std.AutoHashMapUnmanaged(Key, ?Location) = .empty,
    scans: usize = 0,

    const Key = struct {
        hash: hashing.Hash,
        range: Range,
    };

    pub fn init(allocator: std.mem.Allocator, locations: []const Location) Locator {
        return .{ .allocator = allocator, .locations = locations };
    }

    pub fn deinit(self: *Locator) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn find(self: *Locator, term: Term) !?Location {
        const key = Key{ .hash = term.hash, .range = term.range };
        const entry = try self.entries.getOrPut(self.allocator, key);
        if (entry.found_existing) return entry.value_ptr.*;
        self.scans += 1;
        entry.value_ptr.* = findLocation(self.locations, term);
        return entry.value_ptr.*;
    }
};

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
    var locations = [_]Location{
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
    var plan = Plan{
        .terms = &terms,
        .locations = &locations,
    };
    try plan.validate();
    try std.testing.expectEqualStrings("memory://valid", findLocation(&locations, term).?.url);
}

test "public lookups reject empty and inverted chunk ranges" {
    const allocator = std.testing.allocator;
    const hash = hashing.data("object");
    const location = Location{
        .hash = hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://object",
        .byte_range = null,
    };
    var locations = [_]Location{location};
    const empty = Term{ .hash = hash, .unpacked_length = 0, .range = .{ .start = 1, .end = 1 } };
    const inverted = Term{ .hash = hash, .unpacked_length = 0, .range = .{ .start = 2, .end = 1 } };
    for ([_]Term{ empty, inverted }) |term| {
        try std.testing.expect(!hasLocation(&locations, term));
        try std.testing.expect(findLocation(&locations, term) == null);
        var locator = Locator.init(allocator, &locations);
        defer locator.deinit();
        try std.testing.expect((try locator.find(term)) == null);

        var terms = [_]Term{term};
        var plan = Plan{ .terms = &terms, .locations = &locations };
        try std.testing.expectError(error.InvalidRange, plan.validate());
    }
}

test "repeated terms resolve the covering location and decode its chunk" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "aa", .hash = hashing.data("aa") },
        .{ .data = "bb", .hash = hashing.data("bb") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const count = 64;
    const terms = try allocator.alloc(Term, count);
    defer allocator.free(terms);
    for (terms) |*term| term.* = .{
        .hash = object.hash,
        .unpacked_length = 2,
        .range = .{ .start = 1, .end = 2 },
    };
    const locations = [_]Location{
        .{
            .hash = object.hash,
            .range = .{ .start = 0, .end = 1 },
            .url = "memory://decoy",
            .byte_range = null,
        },
        .{
            .hash = object.hash,
            .range = .{ .start = 1, .end = 2 },
            .url = "memory://covering",
            .byte_range = null,
        },
    };
    var plan = try Plan.init(allocator, terms, &locations);
    defer plan.deinit(allocator);
    try plan.validate();
    for (plan.terms) |term|
        try std.testing.expectEqualStrings("memory://covering", findLocation(plan.locations, term).?.url);

    var source: std.Io.Reader = .fixed(object.bytes);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectEqual(@as(u64, 2), try decodeTerm(allocator, &plan, count - 1, &source, &output.writer));
    try std.testing.expectEqualStrings("bb", output.written());
}

test "located decoding rejects a term whose location names another object" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "aa", .hash = hashing.data("aa") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const foreign_chunks = [_]xorb.Chunk{
        .{ .data = "bb", .hash = hashing.data("bb") },
    };
    var foreign = try xorb.serialize(allocator, &foreign_chunks, .none);
    defer foreign.deinit(allocator);
    const term = Term{
        .hash = object.hash,
        .unpacked_length = 2,
        .range = .{ .start = 0, .end = 1 },
    };
    const location = Location{
        .hash = foreign.hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://foreign",
        .byte_range = null,
    };
    var source: std.Io.Reader = .fixed(foreign.bytes);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.MissingLocation,
        decodeLocatedTerm(allocator, term, location, &source, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "located decoding rejects a location that does not cover the term" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "aa", .hash = hashing.data("aa") },
        .{ .data = "bb", .hash = hashing.data("bb") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const term = Term{
        .hash = object.hash,
        .unpacked_length = 4,
        .range = .{ .start = 0, .end = 2 },
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const later = Location{
        .hash = object.hash,
        .range = .{ .start = 1, .end = 2 },
        .url = "memory://later",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    };
    var source: std.Io.Reader = .fixed(object.bytes);
    try std.testing.expectError(
        error.MissingLocation,
        decodeLocatedTerm(allocator, term, later, &source, &output.writer),
    );

    const shorter = Location{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://shorter",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    };
    source = .fixed(object.bytes);
    try std.testing.expectError(
        error.MissingLocation,
        decodeLocatedTerm(allocator, term, shorter, &source, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "location lookup prefers a tighter location listed last" {
    const allocator = std.testing.allocator;
    const count = 4096;
    const hash = hashing.data("shared");
    const locations = try allocator.alloc(Location, count);
    defer allocator.free(locations);
    for (locations) |*location| location.* = .{
        .hash = hash,
        .range = .{ .start = 0, .end = 4 },
        .url = "memory://broad",
        .byte_range = .{ .start = 0, .end = 39 },
    };
    locations[count - 1] = .{
        .hash = hash,
        .range = .{ .start = 1, .end = 4 },
        .url = "memory://tighter",
        .byte_range = .{ .start = 10, .end = 39 },
    };
    const term = Term{ .hash = hash, .unpacked_length = 2, .range = .{ .start = 1, .end = 3 } };
    try std.testing.expectEqualStrings("memory://tighter", findLocation(locations, term).?.url);
}

test "locator reuses the ranked location for repeated queries" {
    const allocator = std.testing.allocator;
    const count = 8192;
    const hash = hashing.data("shared");
    const locations = try allocator.alloc(Location, count);
    defer allocator.free(locations);
    for (locations) |*location| location.* = .{
        .hash = hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://broad",
        .byte_range = .{ .start = 0, .end = 99 },
    };
    locations[count - 1] = .{
        .hash = hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://tight",
        .byte_range = .{ .start = 0, .end = 39 },
    };
    const terms = try allocator.alloc(Term, count);
    defer allocator.free(terms);
    for (terms) |*term| term.* = .{
        .hash = hash,
        .unpacked_length = 1,
        .range = .{ .start = 0, .end = 1 },
    };
    var locator = Locator.init(allocator, locations);
    defer locator.deinit();
    for (terms) |term|
        try std.testing.expectEqualStrings("memory://tight", (try locator.find(term)).?.url);
    try std.testing.expectEqual(@as(usize, 1), locator.scans);
}

test "locator ranks each distinct query once while terms cycle through ranges" {
    const allocator = std.testing.allocator;
    const count = 8192;
    const cycle = 16;
    const hash = hashing.data("shared");
    const locations = try allocator.alloc(Location, count);
    defer allocator.free(locations);
    for (locations) |*location| location.* = .{
        .hash = hash,
        .range = .{ .start = 0, .end = cycle },
        .url = "memory://packed",
        .byte_range = .{ .start = 0, .end = 999 },
    };
    const terms = try allocator.alloc(Term, count);
    defer allocator.free(terms);
    for (terms, 0..) |*term, index| {
        const start: u32 = @intCast(index % cycle);
        term.* = .{
            .hash = hash,
            .unpacked_length = 1,
            .range = .{ .start = start, .end = start + 1 },
        };
    }
    var locator = Locator.init(allocator, locations);
    defer locator.deinit();
    for (terms) |term|
        try std.testing.expectEqualStrings("memory://packed", (try locator.find(term)).?.url);
    try std.testing.expectEqual(@as(usize, cycle), locator.scans);
}

test "repeated queries decode through the better location listed last" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "a", .hash = hashing.data("a") },
        .{ .data = "b", .hash = hashing.data("b") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const count = 512;
    const terms = try allocator.alloc(Term, count);
    defer allocator.free(terms);
    for (terms) |*term| term.* = .{
        .hash = object.hash,
        .unpacked_length = 1,
        .range = .{ .start = 1, .end = 2 },
    };
    const locations = try allocator.alloc(Location, count);
    defer allocator.free(locations);
    for (locations) |*location| location.* = .{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 2 },
        .url = "memory://decoy",
        .byte_range = .{ .start = 0, .end = @intCast(object.body_length - 1) },
    };
    const packed_start: u64 = 8 + chunks[0].data.len;
    const packed_end = packed_start + 8 + chunks[1].data.len - 1;
    locations[count - 1] = .{
        .hash = object.hash,
        .range = .{ .start = 1, .end = 2 },
        .url = "memory://better",
        .byte_range = .{ .start = packed_start, .end = packed_end },
    };
    var plan = try Plan.init(allocator, terms, locations);
    defer plan.deinit(allocator);

    const Context = struct {
        bytes: []const u8,
        requests: usize = 0,
        range: ?ByteRange = null,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.requests += 1;
            self.range = request.byte_range;
            try std.testing.expectEqualStrings("memory://better", request.url);
            const range = request.byte_range orelse return error.TestMissingRequest;
            self.reader = .fixed(self.bytes[@intCast(range.start)..][0..@intCast(range.end - range.start + 1)]);
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .bytes = object.bytes };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const written = try consume(allocator, &plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    }, &output.writer);
    try std.testing.expectEqual(@as(u64, count), written);
    try std.testing.expectEqual(count, context.requests);
    const requested = context.range.?;
    try std.testing.expectEqual(packed_start, requested.start);
    try std.testing.expectEqual(packed_end, requested.end);
    try std.testing.expectEqual(count, output.written().len);
    for (output.written()) |byte| try std.testing.expectEqual(@as(u8, 'b'), byte);
}

test "cycled ranges decode through their own selected location" {
    const allocator = std.testing.allocator;
    const cycle = 16;
    const pattern = "abcdefghijklmnop";
    var chunks: [cycle]xorb.Chunk = undefined;
    for (&chunks, 0..) |*chunk, index| {
        const byte = pattern[index..][0..1];
        chunk.* = .{ .data = byte, .hash = hashing.data(byte) };
    }
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);

    const count = 512;
    const terms = try allocator.alloc(Term, count);
    defer allocator.free(terms);
    for (terms, 0..) |*term, index| {
        const start: u32 = @intCast(index % cycle);
        term.* = .{
            .hash = object.hash,
            .unpacked_length = 1,
            .range = .{ .start = start, .end = start + 1 },
        };
    }
    const locations = try allocator.alloc(Location, count);
    defer allocator.free(locations);
    for (locations) |*location| location.* = .{
        .hash = object.hash,
        .range = .{ .start = 0, .end = cycle },
        .url = "memory://broad",
        .byte_range = .{ .start = 0, .end = @intCast(object.body_length - 1) },
    };
    for (0..cycle) |index| {
        const start: u64 = index * 9;
        locations[count - cycle + index] = .{
            .hash = object.hash,
            .range = .{ .start = @intCast(index), .end = @intCast(index + 1) },
            .url = "memory://tight",
            .byte_range = .{ .start = start, .end = start + 8 },
        };
    }
    var plan = try Plan.init(allocator, terms, locations);
    defer plan.deinit(allocator);

    const Context = struct {
        bytes: []const u8,
        calls: usize = 0,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const start: u64 = (self.calls % cycle) * 9;
            try std.testing.expectEqualStrings("memory://tight", request.url);
            const range = request.byte_range orelse return error.TestMissingRequest;
            try std.testing.expectEqual(start, range.start);
            try std.testing.expectEqual(start + 8, range.end);
            self.calls += 1;
            self.reader = .fixed(self.bytes[@intCast(range.start)..][0..@intCast(range.end - range.start + 1)]);
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .bytes = object.bytes };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const written = try consume(allocator, &plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    }, &output.writer);
    try std.testing.expectEqual(@as(u64, count), written);
    try std.testing.expectEqual(count, context.calls);
    for (output.written(), 0..) |byte, index|
        try std.testing.expectEqual(@as(u8, pattern[index % cycle]), byte);
}

test "location lookup keeps a whole object when a packed range overflows" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "abc", .hash = hashing.data("abc") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const whole = Location{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://whole",
        .byte_range = null,
    };
    const overflowing = Location{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://overflowing",
        .byte_range = .{ .start = 0, .end = std.math.maxInt(u64) },
    };
    const term = Term{ .hash = object.hash, .unpacked_length = 3, .range = .{ .start = 0, .end = 1 } };
    var orders = [_][2]Location{
        .{ whole, overflowing },
        .{ overflowing, whole },
    };
    for (&orders) |*locations| {
        try std.testing.expectEqualStrings("memory://whole", findLocation(locations, term).?.url);

        const Context = struct {
            bytes: []const u8,
            opens: usize = 0,
            reader: std.Io.Reader = undefined,
            fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
                const self: *@This() = @ptrCast(@alignCast(raw));
                self.opens += 1;
                try std.testing.expect(request.byte_range == null);
                try std.testing.expectEqualStrings("memory://whole", request.url);
                self.reader = .fixed(self.bytes);
                return &self.reader;
            }
            fn close(_: *anyopaque, _: *std.Io.Reader) void {}
        };
        const terms = [_]Term{term};
        var plan = try Plan.init(allocator, &terms, locations);
        defer plan.deinit(allocator);
        var context = Context{ .bytes = object.bytes };
        const result = try reconstruct(allocator, &plan, .{
            .context = &context,
            .open_fn = Context.open,
            .close_fn = Context.close,
        });
        defer allocator.free(result);
        try std.testing.expectEqualStrings("abc", result);
        try std.testing.expectEqual(@as(usize, 1), context.opens);
    }
}

test "reconstruction rejects an overflow-only location before opening or writing" {
    const allocator = std.testing.allocator;
    const hash = hashing.data("object");
    const terms = [_]Term{.{
        .hash = hash,
        .unpacked_length = 1,
        .range = .{ .start = 0, .end = 1 },
    }};
    const locations = [_]Location{.{
        .hash = hash,
        .range = .{ .start = 0, .end = 1 },
        .url = "memory://overflowing",
        .byte_range = .{ .start = 0, .end = std.math.maxInt(u64) },
    }};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    try std.testing.expectError(error.InvalidRange, plan.validate());
    try std.testing.expect(findLocation(plan.locations, terms[0]) == null);

    const Context = struct {
        opens: usize = 0,
        reader: std.Io.Reader = .fixed(""),
        fn open(raw: *anyopaque, _: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.opens += 1;
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{};
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(error.InvalidRange, consume(allocator, &plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    }, &output.writer));
    try std.testing.expectEqual(@as(usize, 0), context.opens);
    try std.testing.expectEqual(@as(usize, 0), output.written().len);

    var source: std.Io.Reader = .fixed("");
    try std.testing.expectError(
        error.InvalidRange,
        decodeLocatedTerm(allocator, terms[0], locations[0], &source, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "location lookup prefers the tightest covering range" {
    const hash = hashing.data("object");
    const term = Term{
        .hash = hash,
        .unpacked_length = 3,
        .range = .{ .start = 1, .end = 2 },
    };
    const locations = [_]Location{
        .{
            .hash = hash,
            .range = .{ .start = 0, .end = 3 },
            .url = "memory://broad",
            .byte_range = .{ .start = 0, .end = 29 },
        },
        .{
            .hash = hash,
            .range = .{ .start = 1, .end = 2 },
            .url = "memory://tight",
            .byte_range = .{ .start = 10, .end = 19 },
        },
    };
    try std.testing.expectEqualStrings("memory://tight", findLocation(&locations, term).?.url);
}

test "location lookup keeps a range without packed offsets as a fallback" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "aa", .hash = hashing.data("aa") },
        .{ .data = "bb", .hash = hashing.data("bb") },
        .{ .data = "cc", .hash = hashing.data("cc") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const term = Term{
        .hash = object.hash,
        .unpacked_length = 2,
        .range = .{ .start = 1, .end = 2 },
    };
    const locations = [_]Location{
        .{
            .hash = object.hash,
            .range = .{ .start = 0, .end = 3 },
            .url = "memory://broad",
            .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
        },
        .{
            .hash = object.hash,
            .range = .{ .start = 1, .end = 2 },
            .url = "memory://tight",
            .byte_range = null,
        },
    };
    try std.testing.expectEqualStrings("memory://broad", findLocation(&locations, term).?.url);
    try std.testing.expectEqualStrings("memory://tight", findLocation(locations[1..], term).?.url);

    const terms = [_]Term{term};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    var source: std.Io.Reader = .fixed(object.bytes);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectEqual(@as(u64, 2), try decodeTerm(allocator, &plan, 0, &source, &output.writer));
    try std.testing.expectEqualStrings("bb", output.written());
}

test "location lookup ranks candidates by the transport request they serve" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "a", .hash = hashing.data("a") },
        .{ .data = "b", .hash = hashing.data("b") },
        .{ .data = "c", .hash = hashing.data("c") },
        .{ .data = "d", .hash = hashing.data("d") },
        .{ .data = "e", .hash = hashing.data("e") },
        .{ .data = "f", .hash = hashing.data("f") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const bounded = Location{
        .hash = object.hash,
        .range = .{ .start = 4, .end = 6 },
        .url = "memory://bounded",
        .byte_range = .{ .start = 36, .end = 53 },
    };
    const whole = Location{
        .hash = object.hash,
        .range = .{ .start = 5, .end = 6 },
        .url = "memory://whole",
        .byte_range = null,
    };
    const term = Term{ .hash = object.hash, .unpacked_length = 1, .range = .{ .start = 5, .end = 6 } };
    const orders = [_][2]Location{
        .{ bounded, whole },
        .{ whole, bounded },
    };
    for (orders) |locations| {
        const Context = struct {
            bytes: []const u8,
            range: ?ByteRange = null,
            reader: std.Io.Reader = undefined,
            fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
                const self: *@This() = @ptrCast(@alignCast(raw));
                self.range = request.byte_range;
                const range = request.byte_range orelse ByteRange{
                    .start = 0,
                    .end = @intCast(self.bytes.len - 1),
                };
                self.reader = .fixed(self.bytes[@intCast(range.start)..][0..@intCast(range.end - range.start + 1)]);
                return &self.reader;
            }
            fn close(_: *anyopaque, _: *std.Io.Reader) void {}
        };
        const terms = [_]Term{term};
        var plan = try Plan.init(allocator, &terms, &locations);
        defer plan.deinit(allocator);
        var context = Context{ .bytes = object.bytes };
        const result = try reconstruct(allocator, &plan, .{
            .context = &context,
            .open_fn = Context.open,
            .close_fn = Context.close,
        });
        defer allocator.free(result);
        try std.testing.expectEqualStrings("f", result);
        const requested = context.range orelse return error.TestMissingRequest;
        try std.testing.expectEqual(@as(u64, 36), requested.start);
        try std.testing.expectEqual(@as(u64, 53), requested.end);
    }
}

test "whole-object locations decode terms from absolute chunk indices" {
    const allocator = std.testing.allocator;
    const chunks = [_]xorb.Chunk{
        .{ .data = "aa", .hash = hashing.data("aa") },
        .{ .data = "bb", .hash = hashing.data("bb") },
        .{ .data = "cc", .hash = hashing.data("cc") },
    };
    var object = try xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]Term{.{
        .hash = object.hash,
        .unpacked_length = 2,
        .range = .{ .start = 1, .end = 2 },
    }};
    const locations = [_]Location{.{
        .hash = object.hash,
        .range = .{ .start = 1, .end = 2 },
        .url = "memory://whole",
        .byte_range = null,
    }};
    var plan = try Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);

    const Context = struct {
        bytes: []const u8,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            try std.testing.expect(request.byte_range == null);
            self.reader = .fixed(self.bytes);
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .bytes = object.bytes };
    const opener = Opener{ .context = &context, .open_fn = Context.open, .close_fn = Context.close };

    const result = try reconstruct(allocator, &plan, opener);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("bb", result);

    const expected = [_]ExpectedChunk{.{ .hash = hashing.data("bb"), .size = 2 }};
    var verified: std.Io.Writer.Allocating = .init(allocator);
    defer verified.deinit();
    const count = try consumeVerified(allocator, &plan, opener, &expected, &verified.writer);
    try std.testing.expectEqual(@as(u64, 2), count);
    try std.testing.expectEqualStrings("bb", verified.written());
}

test "reconstruction does not emit empty writes" {
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
}

test "shard validation reports a missing file" {
    const allocator = std.testing.allocator;
    const package = try @import("store.zig").pack(allocator, "data", .{});
    defer {
        var mutable = package;
        mutable.deinit(allocator);
    }
    try std.testing.expectError(error.NotFound, validateShardFile(allocator, package.shard_bytes, hashing.zero));
}

test "shard plan for an empty file contains no chunks" {
    const allocator = std.testing.allocator;
    const empty = try @import("store.zig").pack(allocator, "", .{});
    defer {
        var mutable = empty;
        mutable.deinit(allocator);
    }
    var empty_plan = try planFromShard(allocator, empty.shard_bytes, empty.file_hash);
    defer empty_plan.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), empty_plan.size);
    try std.testing.expectEqual(@as(usize, 0), empty_plan.chunks.len);
}

test "shard validation rejects a corrupted file Merkle root" {
    const allocator = std.testing.allocator;
    const empty = try @import("store.zig").pack(allocator, "", .{});
    defer {
        var mutable = empty;
        mutable.deinit(allocator);
    }
    @memset(empty.shard_bytes[shard.header_size..][0..hashing.zero.len], 1);
    try std.testing.expectError(error.HashMismatch, validateShardFile(allocator, empty.shard_bytes, null));
}

const PackOpener = struct {
    objects: []const xorb.Serialized,
    reader: std.Io.Reader = undefined,
    opens: usize = 0,

    fn opener(self: *PackOpener) Opener {
        return .{ .context = self, .open_fn = open, .close_fn = close };
    }

    fn open(raw: *anyopaque, request: Request) !*std.Io.Reader {
        const self: *PackOpener = @ptrCast(@alignCast(raw));
        for (self.objects) |object| {
            if (!hashing.eql(object.hash, request.hash)) continue;
            const range = request.byte_range orelse ByteRange{
                .start = 0,
                .end = @intCast(object.bytes.len - 1),
            };
            const start: usize = @intCast(range.start);
            const end: usize = @intCast(range.end + 1);
            if (start > end or end > object.bytes.len) return error.InvalidRange;
            self.opens += 1;
            self.reader = .fixed(object.bytes[start..end]);
            return &self.reader;
        }
        return error.NotFound;
    }

    fn close(_: *anyopaque, _: *std.Io.Reader) void {}
};

test "verified consumption round-trips fixed chunk boundaries" {
    const allocator = std.testing.allocator;
    var fixed = try chunker.Fixed.init(2);
    const package = try @import("store.zig").pack(allocator, "abcdef", .{
        .compression = .none,
        .strategy = fixed.strategy(),
    });
    defer {
        var mutable = package;
        mutable.deinit(allocator);
    }
    var manifest = try planFromShard(allocator, package.shard_bytes, package.file_hash);
    defer manifest.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), manifest.chunks.len);

    var source = PackOpener{ .objects = package.objects };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const count = try consumeVerified(allocator, &manifest.plan, source.opener(), manifest.chunks, &output.writer);
    try std.testing.expectEqual(@as(u64, 6), count);
    try std.testing.expectEqualStrings("abcdef", output.written());

    var silent = PackOpener{ .objects = package.objects };
    try std.testing.expectEqual(
        @as(u64, 6),
        try consumeVerified(allocator, &manifest.plan, silent.opener(), manifest.chunks, null),
    );
}

test "verified consumption rejects an incorrect file root" {
    const allocator = std.testing.allocator;
    var fixed = try chunker.Fixed.init(2);
    const package = try @import("store.zig").pack(allocator, "abcdef", .{
        .compression = .none,
        .strategy = fixed.strategy(),
    });
    defer {
        var mutable = package;
        mutable.deinit(allocator);
    }
    var manifest = try planFromShard(allocator, package.shard_bytes, package.file_hash);
    defer manifest.deinit(allocator);
    manifest.plan.file_hash = hashing.data("wrong root");

    var source = PackOpener{ .objects = package.objects };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.HashMismatch,
        consumeVerified(allocator, &manifest.plan, source.opener(), manifest.chunks, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), source.opens);
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "verified consumption accepts a canonical file" {
    const allocator = std.testing.allocator;
    const package = try @import("store.zig").pack(allocator, "abcdef", .{ .compression = .none });
    defer {
        var mutable = package;
        mutable.deinit(allocator);
    }
    var manifest = try planFromShard(allocator, package.shard_bytes, package.file_hash);
    defer manifest.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), manifest.chunks.len);

    var source = PackOpener{ .objects = package.objects };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const count = try consumeVerified(allocator, &manifest.plan, source.opener(), manifest.chunks, &output.writer);
    try std.testing.expectEqual(@as(u64, 6), count);
    try std.testing.expectEqualStrings("abcdef", output.written());
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

test "unverified consumption leaves the chunk index untouched without expected chunks" {
    const all = [_]ExpectedChunk{
        .{ .hash = hashing.data("ab"), .size = 2 },
        .{ .hash = hashing.data("c"), .size = 1 },
    };
    var next: usize = std.math.maxInt(usize) - 1;
    try std.testing.expect(takeTermChunks(null, &next, 2) == null);
    try std.testing.expectEqual(std.math.maxInt(usize) - 1, next);

    next = 0;
    try std.testing.expect(takeTermChunks(null, &next, 1) == null);
    try std.testing.expect(takeTermChunks(null, &next, 2) == null);
    try std.testing.expectEqual(@as(usize, 0), next);
    try std.testing.expectEqualSlices(ExpectedChunk, all[0..1], takeTermChunks(&all, &next, 1).?);
    try std.testing.expectEqualSlices(ExpectedChunk, all[1..2], takeTermChunks(&all, &next, 1).?);
    try std.testing.expectEqual(@as(usize, 2), next);
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

const OpenedTerm = struct {
    object: xorb.Serialized,
    plan: Plan,
    expected: []ExpectedChunk,
    reader: std.Io.Reader = undefined,

    fn init(allocator: std.mem.Allocator, inputs: []const []const u8) !OpenedTerm {
        const chunks = try allocator.alloc(xorb.Chunk, inputs.len);
        defer allocator.free(chunks);
        var nodes: hashing.Aggregator = .{};
        var size: u64 = 0;
        for (inputs, chunks) |input, *chunk| {
            chunk.* = .{ .data = input, .hash = hashing.data(input) };
            try nodes.add(.{ .hash = chunk.hash, .size = input.len });
            size += input.len;
        }
        var object = try xorb.serialize(allocator, chunks, .none);
        errdefer object.deinit(allocator);
        const expected = try allocator.alloc(ExpectedChunk, inputs.len);
        errdefer allocator.free(expected);
        for (inputs, expected) |input, *chunk| {
            chunk.* = .{ .hash = hashing.data(input), .size = @intCast(input.len) };
        }
        const terms = [_]Term{.{
            .hash = object.hash,
            .unpacked_length = @intCast(size),
            .range = .{ .start = 0, .end = @intCast(inputs.len) },
        }};
        const locations = [_]Location{.{
            .hash = object.hash,
            .range = .{ .start = 0, .end = @intCast(inputs.len) },
            .url = "memory://object",
            .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
        }};
        const plan = try Plan.init(allocator, &terms, &locations);
        return .{ .object = object, .plan = plan, .expected = expected };
    }

    fn deinit(self: *OpenedTerm, allocator: std.mem.Allocator) void {
        allocator.free(self.expected);
        self.plan.deinit(allocator);
        self.object.deinit(allocator);
    }

    fn source(self: *OpenedTerm) *std.Io.Reader {
        self.reader = .fixed(self.object.bytes);
        return &self.reader;
    }
};

test "opened term verification writes every selected chunk" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{ "abc", "def" });
    defer fixture.deinit(allocator);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const count = try decodeOpenedTermVerified(
        allocator,
        &fixture.plan,
        fixture.source(),
        fixture.expected,
        &output.writer,
    );
    try std.testing.expectEqual(@as(u64, 6), count);
    try std.testing.expectEqualStrings("abcdef", output.written());
}

test "opened term verification rejects empty and inverted term ranges before writing" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    fixture.plan.terms[0].range = .{ .start = 1, .end = 1 };
    try std.testing.expectError(
        error.InvalidRange,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), fixture.expected, &output.writer),
    );
    fixture.plan.terms[0].range = .{ .start = 2, .end = 1 };
    try std.testing.expectError(
        error.InvalidRange,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), fixture.expected, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "opened term verification rejects plan output ranges before writing" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    fixture.plan.output_length = 2;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.UnsupportedRange,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), fixture.expected, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "opened term verification rejects plan file hashes before writing" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    fixture.plan.file_hash = try hashing.file(allocator, &.{.{ .hash = hashing.data("abcdef"), .size = 6 }});
    try std.testing.expectError(
        error.UnsupportedFileHash,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), fixture.expected, &output.writer),
    );
    fixture.plan.file_hash = hashing.data("wrong file");
    try std.testing.expectError(
        error.UnsupportedFileHash,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), fixture.expected, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "opened term verification rejects a chunk count the term does not select" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    const split = [_]ExpectedChunk{
        .{ .hash = hashing.data("abc"), .size = 3 },
        .{ .hash = hashing.data("def"), .size = 3 },
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.SizeMismatch,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), &split, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "opened term verification rejects expected sizes that disagree with the term" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const short = [_]ExpectedChunk{.{ .hash = hashing.data("abcde"), .size = 5 }};
    try std.testing.expectError(
        error.SizeMismatch,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), &short, &output.writer),
    );
    const empty = [_]ExpectedChunk{.{ .hash = hashing.data(""), .size = 0 }};
    try std.testing.expectError(
        error.InvalidChunkSize,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), &empty, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "opened term verification rejects a same-size chunk with the wrong hash" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    var wrong = [_]ExpectedChunk{.{ .hash = hashing.data("abcdex"), .size = 6 }};
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.HashMismatch,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), &wrong, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "verified decoding rejects chunk splits the encoded records do not use" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{ "a", "bc" });
    defer fixture.deinit(allocator);
    fixture.expected[0] = .{ .hash = hashing.data("ab"), .size = 2 };
    fixture.expected[1] = .{ .hash = hashing.data("c"), .size = 1 };

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.SizeMismatch,
        decodeOpenedTermVerified(allocator, &fixture.plan, fixture.source(), fixture.expected, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);

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
    var context = Context{ .bytes = fixture.object.bytes };
    try std.testing.expectError(
        error.SizeMismatch,
        consumeVerified(allocator, &fixture.plan, .{
            .context = &context,
            .open_fn = Context.open,
            .close_fn = Context.close,
        }, fixture.expected, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "opened term verification streams one-byte reads and repeated writes" {
    const allocator = std.testing.allocator;
    const large = try allocator.alloc(u8, 10_000);
    defer allocator.free(large);
    for (large, 0..) |*byte, index| byte.* = @truncate(index *% 17);
    var fixture = try OpenedTerm.init(allocator, &.{ large, "tail" });
    defer fixture.deinit(allocator);
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
    var context = Context{ .bytes = fixture.object.bytes };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const count = try decodeOpenedTermVerified(
        allocator,
        &fixture.plan,
        &context.reader,
        fixture.expected,
        &output.writer,
    );
    try std.testing.expectEqual(@as(u64, large.len + 4), count);
    try std.testing.expectEqualSlices(u8, large, output.written()[0..large.len]);
    try std.testing.expectEqualStrings("tail", output.written()[large.len..]);
}

test "verified consumption rejects expected chunks the plan does not select" {
    const allocator = std.testing.allocator;
    var fixture = try OpenedTerm.init(allocator, &.{"abcdef"});
    defer fixture.deinit(allocator);
    var context = struct {
        opens: usize = 0,
        reader: std.Io.Reader = .fixed(""),
        fn open(raw: *anyopaque, _: Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.opens += 1;
            return &self.reader;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    }{};
    const opener = Opener{ .context = &context, .open_fn = @TypeOf(context).open, .close_fn = @TypeOf(context).close };
    const split = [_]ExpectedChunk{
        .{ .hash = hashing.data("abc"), .size = 3 },
        .{ .hash = hashing.data("def"), .size = 3 },
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.SizeMismatch,
        consumeVerified(allocator, &fixture.plan, opener, &split, &output.writer),
    );
    const short = [_]ExpectedChunk{.{ .hash = hashing.data("abcde"), .size = 5 }};
    try std.testing.expectError(
        error.SizeMismatch,
        consumeVerified(allocator, &fixture.plan, opener, &short, &output.writer),
    );
    try std.testing.expectEqual(@as(usize, 0), context.opens);
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}
