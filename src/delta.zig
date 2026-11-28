//! Source-independent chunk reuse and fetch planning

const module = @This();
const std = @import("std");
const constants = @import("constants.zig");
const hashing = @import("hash.zig");
const recon = @import("recon.zig");

pub const TargetChunk = struct {
    index: usize,
    offset: u64,
    hash: hashing.Hash,
    size: u32,
};

/// The handle can contain a memory slice, file range, or remote chunk reference
pub const BaseMatch = struct {
    context: *anyopaque,
    release_fn: ?*const fn (context: *anyopaque) void = null,

    pub fn release(self: *BaseMatch) void {
        if (self.release_fn) |release_fn| release_fn(self.context);
        self.* = undefined;
    }
};

/// Returned matches belong to the resulting Program
pub const Base = struct {
    context: *anyopaque,
    match_fn: *const fn (context: *anyopaque, target: TargetChunk) anyerror!?BaseMatch,

    pub fn match(self: Base, target: TargetChunk) !?BaseMatch {
        return self.match_fn(self.context, target);
    }
};

pub const Copy = struct {
    target: TargetChunk,
    source: BaseMatch,

    pub fn write(self: Copy, bytes: []const u8, sink: *std.Io.Writer) !void {
        if (bytes.len != self.target.size) return error.SizeMismatch;
        if (!hashing.eql(hashing.data(bytes), self.target.hash)) return error.HashMismatch;
        try sink.writeAll(bytes);
    }
};

pub const Fetch = struct {
    offset: u64,
    expected_chunks: []const recon.ExpectedChunk,
    terms: [1]recon.Term,
    locations: [1]recon.Location,

    /// Decode this operation and verify each chunk against the cursor's expected hashes.
    pub fn write(
        self: *Fetch,
        allocator: std.mem.Allocator,
        opener: recon.Opener,
        sink: *std.Io.Writer,
    ) !u64 {
        const target = self.plan();
        return recon.consumeVerified(allocator, &target, opener, self.expected_chunks, sink);
    }

    /// The returned plan borrows this Fetch and its target metadata
    pub fn plan(self: *Fetch) recon.Plan {
        return .{
            .terms = &self.terms,
            .locations = &self.locations,
        };
    }
};

pub const Operation = union(enum) {
    copy: Copy,
    fetch: Fetch,

    pub fn deinit(self: *Operation) void {
        switch (self.*) {
            .copy => |*copy| copy.source.release(),
            .fetch => {},
        }
        self.* = undefined;
    }
};

/// Borrows target metadata and owns every returned base match
pub const Program = struct {
    size: u64,
    operations: []Operation,

    pub fn deinit(self: *Program, allocator: std.mem.Allocator) void {
        for (self.operations) |*operation| operation.deinit();
        allocator.free(self.operations);
        self.* = undefined;
    }
};

/// Produces owned operations without collecting the complete plan
pub const Cursor = struct {
    pub const Operation = module.Operation;
    pub const Base = module.Base;
    pub const BaseMatch = module.BaseMatch;
    pub const TargetChunk = module.TargetChunk;
    pub const Plan = recon.Plan;
    pub const ExpectedChunk = recon.ExpectedChunk;
    pub const Term = recon.Term;
    pub const Location = recon.Location;
    pub const Opener = recon.Opener;
    pub const Request = recon.Request;
    pub const fromShard = recon.planFromShard;

    target: *const recon.Plan,
    expected_chunks: []const recon.ExpectedChunk,
    base: ?module.Base,
    size: u64,
    next_chunk: usize = 0,
    file_offset: u64 = 0,
    term_index: usize = 0,
    term_first_chunk: usize = 0,
    lookahead: ?Lookahead = null,
    locator: recon.Locator,

    const Lookahead = struct {
        chunk: module.TargetChunk,
        match: ?module.BaseMatch,
    };

    /// Target metadata must outlive the cursor and every operation it produces
    /// A location is needed only when next emits a fetch
    pub fn init(
        allocator: std.mem.Allocator,
        target: *const recon.Plan,
        expected_chunks: []const recon.ExpectedChunk,
        base: ?module.Base,
    ) !Cursor {
        if (target.offset_into_first_range != 0 or target.output_length != null)
            return error.UnsupportedRange;
        return .{
            .target = target,
            .expected_chunks = expected_chunks,
            .base = base,
            .size = try validateTarget(target, expected_chunks),
            .locator = recon.Locator.init(allocator, target.locations),
        };
    }

    pub fn deinit(self: *Cursor) void {
        self.releaseLookahead();
        self.locator.deinit();
        self.* = undefined;
    }

    /// Copy handles are independently owned; matcher errors leave the position retryable
    pub fn next(self: *Cursor) !?module.Operation {
        if (self.lookahead == null) {
            if (self.next_chunk == self.expected_chunks.len) return null;
            const match = try self.matchAt(self.next_chunk, self.file_offset);
            self.lookahead = .{
                .chunk = self.chunkAt(self.next_chunk, self.file_offset),
                .match = match,
            };
        }
        const found = self.lookahead.?;
        if (found.match) |match| {
            self.lookahead = null;
            self.advance();
            return .{ .copy = .{ .target = found.chunk, .source = match } };
        }

        const first = self.next_chunk;
        const first_term = self.termAt(first);
        const start_range = first_term.term.range.start + @as(
            u32,
            @intCast(first - first_term.first_chunk),
        );
        var end = first;
        var offset = self.file_offset;
        var size: u64 = 0;
        var pending: ?Lookahead = null;
        errdefer if (pending) |*lookahead| if (lookahead.match) |*match| match.release();
        while (end != first_term.first_chunk + first_term.count) {
            size += self.expected_chunks[end].size;
            offset += self.expected_chunks[end].size;
            end += 1;
            if (end == first_term.first_chunk + first_term.count) break;
            const match = try self.matchAt(end, offset);
            if (match != null) {
                pending = .{ .chunk = self.chunkAt(end, offset), .match = match };
                break;
            }
        }
        const term = recon.Term{
            .hash = first_term.term.hash,
            .unpacked_length = @intCast(size),
            .range = .{
                .start = start_range,
                .end = start_range + @as(u32, @intCast(end - first)),
            },
        };
        const location = try self.locator.find(term) orelse return error.MissingLocation;
        self.next_chunk = end;
        self.file_offset = offset;
        self.lookahead = pending;
        return .{ .fetch = .{
            .offset = found.chunk.offset,
            .expected_chunks = self.expected_chunks[first..end],
            .terms = .{term},
            .locations = .{location},
        } };
    }

    const TermAt = struct {
        term: recon.Term,
        first_chunk: usize,
        count: usize,
    };

    fn termAt(self: *Cursor, chunk_index: usize) TermAt {
        while (self.term_index < self.target.terms.len) {
            const term = self.target.terms[self.term_index];
            const count: usize = term.range.end - term.range.start;
            if (chunk_index < self.term_first_chunk + count)
                return .{ .term = term, .first_chunk = self.term_first_chunk, .count = count };
            self.term_index += 1;
            self.term_first_chunk += count;
        }
        unreachable;
    }

    fn chunkAt(self: *const Cursor, index: usize, offset: u64) module.TargetChunk {
        const expected = self.expected_chunks[index];
        return .{ .index = index, .offset = offset, .hash = expected.hash, .size = expected.size };
    }

    fn matchAt(self: *const Cursor, index: usize, offset: u64) !?module.BaseMatch {
        const base = self.base orelse return null;
        return base.match(self.chunkAt(index, offset));
    }

    fn advance(self: *Cursor) void {
        self.file_offset += self.expected_chunks[self.next_chunk].size;
        self.next_chunk += 1;
    }

    fn releaseLookahead(self: *Cursor) void {
        if (self.lookahead) |*lookahead| if (lookahead.match) |*match| match.release();
        self.lookahead = null;
    }
};

/// Matches are whole chunks; consecutive missing chunks become one Fetch per term
pub fn plan(
    allocator: std.mem.Allocator,
    target: *const recon.Plan,
    expected_chunks: []const recon.ExpectedChunk,
    base: ?Base,
) !Program {
    var cursor = try Cursor.init(allocator, target, expected_chunks, base);
    defer cursor.deinit();
    var operations: std.ArrayList(Operation) = .empty;
    errdefer {
        for (operations.items) |*operation| operation.deinit();
        operations.deinit(allocator);
    }
    while (try cursor.next()) |operation_value| {
        var operation = operation_value;
        errdefer operation.deinit();
        try operations.append(allocator, operation);
    }
    return .{ .size = cursor.size, .operations = try operations.toOwnedSlice(allocator) };
}

pub fn validateTarget(
    target: *const recon.Plan,
    expected_chunks: []const recon.ExpectedChunk,
) !u64 {
    var nodes: hashing.Aggregator = .{};
    var next: usize = 0;
    var total: u64 = 0;
    for (target.terms) |term| {
        if (term.range.start >= term.range.end) return error.InvalidRange;
        const count: usize = term.range.end - term.range.start;
        if (count > expected_chunks.len -| next) return error.SizeMismatch;
        var term_size: u64 = 0;
        for (expected_chunks[next..][0..count]) |chunk| {
            if (chunk.size == 0 or chunk.size > constants.max_chunk_size)
                return error.InvalidChunkSize;
            term_size = std.math.add(u64, term_size, chunk.size) catch return error.InvalidSize;
            total = std.math.add(u64, total, chunk.size) catch return error.InvalidSize;
            try nodes.add(.{ .hash = chunk.hash, .size = chunk.size });
        }
        if (term_size != term.unpacked_length) return error.SizeMismatch;
        next += count;
    }
    if (next != expected_chunks.len) return error.SizeMismatch;
    if (target.file_hash) |expected_hash| {
        if (!hashing.eql(expected_hash, try nodes.fileHash())) return error.HashMismatch;
    }
    return total;
}
