//! Storage-independent packaging and publishing

const std = @import("std");
const constants = @import("constants.zig");
const chunker = @import("chunker.zig");
const hashing = @import("hash.zig");
const xorb = @import("xorb.zig");
const shard = @import("shard.zig");
const dedup = @import("dedup.zig");

pub const DedupSource = dedup.Source;
pub const DedupMatch = dedup.Match;

pub const ObjectKind = enum { xorb, shard };

pub const Object = struct {
    kind: ObjectKind,
    hash: hashing.Hash,
    data: []const u8,
    raw_size: u64,
};

/// Object data is borrowed for each `put` call
pub const Store = struct {
    context: *anyopaque,
    put_fn: *const fn (context: *anyopaque, object: Object) anyerror!void,

    pub fn put(self: Store, object: Object) !void {
        return self.put_fn(self.context, object);
    }
};

pub const PackOptions = struct {
    compression: xorb.Compression = .lz4,
    max_xorb_size: u64 = constants.max_xorb_size,
    max_xorb_chunks: u32 = constants.max_xorb_chunks,

    pub fn validate(self: PackOptions) !void {
        if (self.max_xorb_size == 0 or self.max_xorb_size > constants.max_xorb_size or
            self.max_xorb_chunks == 0 or self.max_xorb_chunks > constants.max_xorb_chunks)
            return error.InvalidOptions;
    }
};

pub const NewXorbListener = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, object: shard.Xorb) anyerror!void,
};

pub const PublisherOptions = struct {
    compression: xorb.Compression = .lz4,
    max_xorb_size: u64 = constants.max_xorb_size,
    max_xorb_chunks: u32 = constants.max_xorb_chunks,
    dedup_source: ?DedupSource = null,
    new_xorb_listener: ?NewXorbListener = null,

    pub fn fromPackOptions(options: PackOptions) PublisherOptions {
        return .{
            .compression = options.compression,
            .max_xorb_size = options.max_xorb_size,
            .max_xorb_chunks = options.max_xorb_chunks,
        };
    }

    fn validate(self: PublisherOptions) !void {
        return PackOptions.validate(.{
            .compression = self.compression,
            .max_xorb_size = self.max_xorb_size,
            .max_xorb_chunks = self.max_xorb_chunks,
        });
    }
};

pub const Package = struct {
    file_hash: hashing.Hash,
    size: u64,
    objects: []xorb.Serialized,
    shard_bytes: []u8,

    pub fn deinit(self: *Package, allocator: std.mem.Allocator) void {
        for (self.objects) |*object| object.deinit(allocator);
        allocator.free(self.objects);
        allocator.free(self.shard_bytes);
        self.* = undefined;
    }
};

/// Empty inputs produce only a shard
pub fn pack(
    allocator: std.mem.Allocator,
    input: []const u8,
    options: PackOptions,
) !Package {
    try options.validate();
    const chunks = try chunker.chunkBuffer(allocator, input);
    defer allocator.free(chunks);
    const source_chunks = try allocator.alloc(xorb.Chunk, chunks.len);
    defer allocator.free(source_chunks);
    var file_nodes: hashing.Aggregator = .{};
    for (chunks, source_chunks) |chunk, *source| {
        source.* = .{ .data = chunk.data, .hash = chunk.hash };
        try file_nodes.add(.{ .hash = chunk.hash, .size = chunk.data.len });
    }
    const file_hash = try file_nodes.fileHash();
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &sha256, .{});

    var objects: std.ArrayList(xorb.Serialized) = .empty;
    errdefer {
        for (objects.items) |*object| object.deinit(allocator);
        objects.deinit(allocator);
    }
    var segments: std.ArrayList(shard.Segment) = .empty;
    defer segments.deinit(allocator);
    var checks: std.ArrayList(hashing.Hash) = .empty;
    defer checks.deinit(allocator);
    var shard_xorbs: std.ArrayList(shard.Xorb) = .empty;
    defer shard_xorbs.deinit(allocator);

    var first: usize = 0;
    while (first < source_chunks.len) {
        var end = first;
        var bytes: u64 = 0;
        while (end < source_chunks.len and end - first < options.max_xorb_chunks) {
            const next_size = bytes + source_chunks[end].data.len;
            if (end != first and next_size > options.max_xorb_size) break;
            bytes = next_size;
            end += 1;
        }
        const object = try xorb.serialize(allocator, source_chunks[first..end], options.compression);
        objects.append(allocator, object) catch |err| {
            var owned = object;
            owned.deinit(allocator);
            return err;
        };
        try segments.append(allocator, .{
            .xorb_hash = object.hash,
            .unpacked_segment_bytes = @intCast(bytes),
            .chunk_index_start = 0,
            .chunk_index_end = @intCast(end - first),
        });
        try checks.append(allocator, object.verificationHash());
        try shard_xorbs.append(allocator, .{
            .hash = object.hash,
            .chunks = object.chunks,
            .raw_size = @intCast(object.raw_size),
            .serialized_size = @intCast(object.body_length),
        });
        first = end;
    }

    const shard_bytes = try shard.serialize(allocator, &.{.{
        .hash = file_hash,
        .segments = segments.items,
        .verification = checks.items,
        .sha256 = hashing.fromStandard(sha256),
    }}, shard_xorbs.items);
    errdefer allocator.free(shard_bytes);

    return .{
        .file_hash = file_hash,
        .size = input.len,
        .objects = try objects.toOwnedSlice(allocator),
        .shard_bytes = shard_bytes,
    };
}

/// Uploads Xorbs before their shards
pub fn publish(allocator: std.mem.Allocator, package: *const Package, store: Store) !void {
    for (package.objects, 0..) |object, index| {
        const duplicate = for (package.objects[0..index]) |previous| {
            if (hashing.eql(previous.hash, object.hash)) break true;
        } else false;
        if (duplicate) continue;
        try store.put(.{
            .kind = .xorb,
            .hash = object.hash,
            .data = object.bytes,
            .raw_size = object.raw_size,
        });
    }
    try publishShard(allocator, package.shard_bytes, package.size, store);
}

pub const max_shard_size = 64 * 1024 * 1024;
const empty_shard_size = shard.header_size + 2 * shard.entry_size;

pub fn publishShard(allocator: std.mem.Allocator, bytes: []const u8, raw_size: u64, destination: Store) !void {
    return publishShardLimited(allocator, bytes, raw_size, destination, max_shard_size);
}

fn publishShardLimited(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    raw_size: u64,
    destination: Store,
    limit: usize,
) !void {
    if (limit < empty_shard_size) return error.ShardTooLarge;
    if (bytes.len <= limit) {
        return destination.put(.{
            .kind = .shard,
            .hash = hashing.data(bytes),
            .data = bytes,
            .raw_size = raw_size,
        });
    }

    const reader = try shard.Reader.init(bytes);
    var xorbs: std.ArrayList(shard.Xorb) = .empty;
    defer {
        for (xorbs.items) |object| allocator.free(object.chunks);
        xorbs.deinit(allocator);
    }
    var size: usize = empty_shard_size;
    var record_index: u32 = 0;
    for (0..reader.footer.xorb_count) |_| {
        const info = try reader.xorbAt(record_index);
        record_index += info.count + 1;
        const addition = (@as(usize, info.count) + 1) * shard.entry_size;
        if (xorbs.items.len != 0 and addition > limit - size) {
            try flushXorbs(allocator, &xorbs, destination);
            size = empty_shard_size;
        }
        if (addition > limit - empty_shard_size) return error.ShardTooLarge;
        var object = try info.decode(allocator);
        errdefer object.deinit(allocator);
        try xorbs.append(allocator, object.value);
        size += addition;
    }
    try flushXorbs(allocator, &xorbs, destination);

    var files: std.ArrayList(shard.File) = .empty;
    defer {
        for (files.items) |file| freeDecodedFile(allocator, file);
        files.deinit(allocator);
    }
    size = empty_shard_size;
    var file_index: u32 = 0;
    for (0..reader.footer.file_count) |_| {
        const info = try reader.fileAt(file_index);
        file_index = @intCast((info.end - shard.header_size) / shard.entry_size);
        const addition = info.end - info.offset;
        if (files.items.len != 0 and addition > limit - size) {
            try flushFiles(allocator, &files, raw_size, destination, limit);
            size = empty_shard_size;
        }
        if (addition > limit - empty_shard_size) return error.ShardTooLarge;
        var file = try info.decode(allocator);
        errdefer file.deinit(allocator);
        try files.append(allocator, file.value);
        size += addition;
    }
    try flushFiles(allocator, &files, raw_size, destination, limit);
}

pub fn wireShardSize(bytes: []const u8) !usize {
    const reader = try shard.Reader.init(bytes);
    return reader.footer.file_lookup_offset;
}

fn flushXorbs(allocator: std.mem.Allocator, xorbs: *std.ArrayList(shard.Xorb), destination: Store) !void {
    if (xorbs.items.len == 0) return;
    const bytes = try shard.serialize(allocator, &.{}, xorbs.items);
    defer allocator.free(bytes);
    if (try wireShardSize(bytes) > max_shard_size) return error.ShardTooLarge;
    try destination.put(.{
        .kind = .shard,
        .hash = hashing.data(bytes),
        .data = bytes,
        .raw_size = 0,
    });
    for (xorbs.items) |object| allocator.free(object.chunks);
    xorbs.clearRetainingCapacity();
}

fn flushFiles(
    allocator: std.mem.Allocator,
    files: *std.ArrayList(shard.File),
    raw_size: u64,
    destination: Store,
    limit: usize,
) !void {
    if (files.items.len == 0) return;
    const bytes = try shard.serialize(allocator, files.items, &.{});
    defer allocator.free(bytes);
    if (try wireShardSize(bytes) > limit) return error.ShardTooLarge;
    try destination.put(.{
        .kind = .shard,
        .hash = hashing.data(bytes),
        .data = bytes,
        .raw_size = raw_size,
    });
    for (files.items) |file| freeDecodedFile(allocator, file);
    files.clearRetainingCapacity();
}

fn freeDecodedFile(allocator: std.mem.Allocator, file: shard.File) void {
    allocator.free(file.segments);
    if (file.verification.len != 0) allocator.free(file.verification);
}

pub const PublishResult = struct {
    file_hash: hashing.Hash,
    size: u64,
    xorb_count: u64,
};

/// Owned reconstruction metadata for custom upload pipelines
pub const Plan = struct {
    file: shard.File = .{ .hash = hashing.zero, .segments = &.{} },
    new_xorbs: []shard.Xorb = &.{},
    size: u64 = 0,
    xorb_count: u64 = 0,

    pub fn fromFile(file: shard.File, new_xorbs: []shard.Xorb, size: u64) Plan {
        return .{
            .file = file,
            .new_xorbs = new_xorbs,
            .size = size,
            .xorb_count = file.segments.len,
        };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        freeDecodedFile(allocator, self.file);
        for (self.new_xorbs) |object| allocator.free(object.chunks);
        allocator.free(self.new_xorbs);
        self.* = undefined;
    }

    /// Consumes the plan's metadata, even on failure
    pub fn publish(self: *Plan, allocator: std.mem.Allocator, destination: Store) !PublishResult {
        const result = PublishResult{
            .file_hash = self.file.hash,
            .size = self.size,
            .xorb_count = self.xorb_count,
        };
        defer self.deinit(allocator);
        var batch = BatchPublisher.init(allocator, destination);
        defer batch.deinit();
        try batch.append(self);
        try batch.finish();
        return result;
    }
};

/// Aggregates file and new-Xorb metadata without batching Xorb payloads
pub const BatchPublisher = struct {
    allocator: std.mem.Allocator,
    destination: Store,
    plans: std.ArrayList(Plan) = .empty,
    finished: bool = false,

    pub fn init(allocator: std.mem.Allocator, destination: Store) BatchPublisher {
        return .{ .allocator = allocator, .destination = destination };
    }

    pub fn deinit(self: *BatchPublisher) void {
        for (self.plans.items) |*plan| plan.deinit(self.allocator);
        self.plans.deinit(self.allocator);
        self.* = undefined;
    }

    /// Success empties `plan`; failure preserves its batch-allocator-owned allocations
    pub fn append(self: *BatchPublisher, plan: *Plan) !void {
        if (self.finished) return error.AlreadyFinished;
        try self.plans.ensureUnusedCapacity(self.allocator, 1);
        self.plans.appendAssumeCapacity(plan.*);
        plan.* = .{};
    }

    /// Publishes all appended metadata, using the standard shard size limit
    pub fn finish(self: *BatchPublisher) !void {
        if (self.finished) return error.AlreadyFinished;
        self.finished = true;

        var files: std.ArrayList(shard.File) = .empty;
        defer files.deinit(self.allocator);
        var new_xorbs: std.ArrayList(shard.Xorb) = .empty;
        defer new_xorbs.deinit(self.allocator);
        var hashes: std.AutoHashMapUnmanaged(hashing.Hash, void) = .empty;
        defer hashes.deinit(self.allocator);
        var raw_size: u64 = 0;
        for (self.plans.items) |plan| {
            try new_xorbs.appendSlice(self.allocator, plan.new_xorbs);
            const entry = try hashes.getOrPut(self.allocator, plan.file.hash);
            if (entry.found_existing) continue;
            try files.append(self.allocator, plan.file);
            raw_size = std.math.add(u64, raw_size, plan.size) catch return error.FileTooLarge;
        }
        if (files.items.len == 0) return;
        const bytes = try shard.serialize(self.allocator, files.items, new_xorbs.items);
        defer self.allocator.free(bytes);
        try publishShard(self.allocator, bytes, raw_size, self.destination);
    }
};

pub const dedup_window = 64;

/// Buffers one Xorb, shard metadata, and up to 64 dedup chunks
pub const Publisher = struct {
    allocator: std.mem.Allocator,
    destination: Store,
    options: PublisherOptions,
    chunker: chunker.Chunker,
    serializer: xorb.Serializer,
    file_nodes: hashing.Aggregator = .{},
    file_sha256: std.crypto.hash.sha2.Sha256 = .init(.{}),
    segments: std.ArrayList(shard.Segment) = .empty,
    checks: std.ArrayList(hashing.Hash) = .empty,
    xorbs: std.ArrayList(shard.Xorb) = .empty,
    size: u64 = 0,
    xorb_count: u64 = 0,
    finished: bool = false,
    failed: bool = false,
    has_complete_sha256: bool = true,
    reused_xorb: ?hashing.Hash = null,
    reused_verification: std.crypto.hash.Blake3 = .init(.{ .key = constants.verification_key }),
    pending_chunks: [dedup_window]chunker.Chunk = undefined,
    pending_head: usize = 0,
    pending_len: usize = 0,

    /// Borrows the dedup source, listener, and callback metadata
    pub fn init(allocator: std.mem.Allocator, destination: Store, options: PublisherOptions) !Publisher {
        try options.validate();
        return .{
            .allocator = allocator,
            .destination = destination,
            .options = options,
            .chunker = chunker.Chunker.init(),
            .serializer = .init(options.compression),
        };
    }

    pub fn deinit(self: *Publisher) void {
        self.chunker.deinit(self.allocator);
        self.serializer.deinit(self.allocator);
        self.segments.deinit(self.allocator);
        self.checks.deinit(self.allocator);
        for (self.xorbs.items) |object| self.allocator.free(object.chunks);
        self.xorbs.deinit(self.allocator);
        self.dropPending(self.pending_len);
    }

    /// An operational failure consumes an unspecified input prefix and makes the publisher terminal
    pub fn write(self: *Publisher, input: []const u8) !void {
        if (self.failed) return error.WriteFailed;
        if (self.finished) return error.AlreadyFinished;
        self.writeFallible(input) catch |err| {
            self.failed = true;
            return err;
        };
    }

    fn writeFallible(self: *Publisher, input: []const u8) !void {
        self.file_sha256.update(input);
        var remaining = input;
        while (remaining.len != 0) {
            const result = try self.chunker.next(self.allocator, remaining, false);
            if (result.chunk) |chunk| try self.addChunk(chunk);
            remaining = remaining[result.consumed..];
        }
    }

    pub fn finish(self: *Publisher) !PublishResult {
        var plan = try self.finishPlan();
        return plan.publish(self.allocator, self.destination);
    }

    pub fn finishPlan(self: *Publisher) !Plan {
        if (self.failed) return error.WriteFailed;
        if (self.finished) return error.AlreadyFinished;
        self.finished = true;
        const final = try self.chunker.finish(self.allocator);
        if (final.chunk) |chunk| try self.addChunk(chunk);
        try self.processPending();
        try self.flushXorb();
        const file_hash = try self.file_nodes.fileHash();
        const sha256 = if (self.has_complete_sha256)
            hashing.fromStandard(self.file_sha256.finalResult())
        else
            null;
        const segments = try self.segments.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(segments);
        const checks = try self.checks.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(checks);
        const xorbs = try self.xorbs.toOwnedSlice(self.allocator);
        self.segments = .empty;
        self.checks = .empty;
        self.xorbs = .empty;
        return .{
            .file = .{
                .hash = file_hash,
                .segments = segments,
                .verification = checks,
                .sha256 = sha256,
            },
            .new_xorbs = xorbs,
            .size = self.size,
            .xorb_count = self.xorb_count,
        };
    }

    /// `nodes` must match the Xorb range because direct reuse omits SHA-256 metadata
    pub fn reuse(
        self: *Publisher,
        object_hash: hashing.Hash,
        chunk_index_start: u32,
        nodes: []const hashing.Node,
    ) !void {
        if (self.failed) return error.WriteFailed;
        if (self.finished) return error.AlreadyFinished;
        const byte_total = try validateReuse(nodes, chunk_index_start);
        var accepted = self.size;
        if (!self.chunker.returned_pending) {
            accepted = std.math.add(u64, accepted, self.chunker.pending.items.len) catch
                return error.FileTooLarge;
        }
        for (0..self.pending_len) |index| {
            const chunk = self.pending_chunks[(self.pending_head + index) % dedup_window];
            accepted = std.math.add(u64, accepted, chunk.data.len) catch return error.FileTooLarge;
        }
        accepted = std.math.add(u64, accepted, byte_total) catch return error.FileTooLarge;
        const continues = self.reuseContinues(object_hash, chunk_index_start);
        const buffered_new = self.serializer.chunks.items.len != 0 or self.chunker.pending.items.len != 0;
        const uninterrupted = self.pending_len == 0 and !buffered_new;
        if (continues and uninterrupted) {
            const last = self.segments.items[self.segments.items.len - 1];
            if (last.unpacked_segment_bytes > std.math.maxInt(u32) - byte_total) {
                return error.InvalidDedupMatch;
            }
        }
        if (self.pending_len == 0 and (!continues or buffered_new)) {
            try self.reserveReuseSegments(1 + @as(usize, @intFromBool(buffered_new)));
        }
        self.reuseFallible(object_hash, chunk_index_start, nodes) catch |err| {
            self.failed = true;
            return err;
        };
    }

    fn reuseFallible(
        self: *Publisher,
        object_hash: hashing.Hash,
        chunk_index_start: u32,
        nodes: []const hashing.Node,
    ) !void {
        const final = try self.chunker.finish(self.allocator);
        if (final.chunk) |chunk| try self.addChunk(chunk);
        try self.processPending();
        self.has_complete_sha256 = false;
        try self.appendReuse(object_hash, chunk_index_start, nodes);
    }

    fn reuseContinues(self: *const Publisher, object_hash: hashing.Hash, chunk_index_start: u32) bool {
        const hash = self.reused_xorb orelse return false;
        if (!hashing.eql(hash, object_hash)) return false;
        const last = self.segments.items[self.segments.items.len - 1];
        return last.chunk_index_end == chunk_index_start;
    }

    fn validateReuse(nodes: []const hashing.Node, chunk_index_start: u32) !u32 {
        if (nodes.len == 0 or nodes.len > std.math.maxInt(u32) - chunk_index_start) {
            return error.InvalidDedupMatch;
        }
        var total: u64 = 0;
        for (nodes) |node| {
            if (node.size == 0 or node.size > constants.max_chunk_size) return error.InvalidDedupMatch;
            total = std.math.add(u64, total, node.size) catch return error.FileTooLarge;
            if (total > std.math.maxInt(u32)) return error.InvalidDedupMatch;
        }
        return @intCast(total);
    }

    fn appendReuse(
        self: *Publisher,
        object_hash: hashing.Hash,
        chunk_index_start: u32,
        nodes: []const hashing.Node,
    ) !void {
        const byte_total = try validateReuse(nodes, chunk_index_start);
        if (self.size > std.math.maxInt(u64) - @as(u64, byte_total)) return error.FileTooLarge;
        const continues = self.reuseContinues(object_hash, chunk_index_start);
        if (!continues) {
            try self.flushXorb();
            try self.reserveReuseSegments(1);
            self.resetReuse();
            self.reused_xorb = object_hash;
            self.segments.appendAssumeCapacity(.{
                .xorb_hash = object_hash,
                .unpacked_segment_bytes = 0,
                .chunk_index_start = chunk_index_start,
                .chunk_index_end = chunk_index_start,
            });
            self.checks.appendAssumeCapacity(hashing.zero);
            self.xorb_count += 1;
        }
        const last = self.segments.items.len - 1;
        self.size += byte_total;
        for (nodes) |node| {
            self.reused_verification.update(&node.hash);
            self.segments.items[last].unpacked_segment_bytes += @intCast(node.size);
            self.segments.items[last].chunk_index_end += 1;
            try self.file_nodes.add(node);
        }
        self.checks.items[last] = self.reuseVerification();
    }

    fn reserveReuseSegments(self: *Publisher, count: usize) !void {
        try self.segments.ensureUnusedCapacity(self.allocator, count);
        try self.checks.ensureUnusedCapacity(self.allocator, count);
    }

    fn reuseVerification(self: *const Publisher) hashing.Hash {
        var state = self.reused_verification;
        var result: hashing.Hash = undefined;
        state.final(&result);
        return result;
    }

    fn resetReuse(self: *Publisher) void {
        self.reused_xorb = null;
        self.reused_verification = .init(.{ .key = constants.verification_key });
    }

    fn addChunk(self: *Publisher, chunk: chunker.Chunk) !void {
        if (self.options.dedup_source) |source| {
            if (self.pending_len == dedup_window) try self.processOne(source);
            try self.buffer(chunk);
            return;
        }
        try self.addNew(chunk);
    }

    fn buffer(self: *Publisher, chunk: chunker.Chunk) !void {
        const data = try self.allocator.dupe(u8, chunk.data);
        const index = (self.pending_head + self.pending_len) % dedup_window;
        self.pending_chunks[index] = .{ .data = data, .hash = chunk.hash };
        self.pending_len += 1;
    }

    fn dropPending(self: *Publisher, count: usize) void {
        for (0..count) |index| {
            const chunk = self.pending_chunks[(self.pending_head + index) % dedup_window];
            self.allocator.free(chunk.data);
        }
        self.pending_head = (self.pending_head + count) % dedup_window;
        self.pending_len -= count;
    }

    fn processPending(self: *Publisher) !void {
        const source = self.options.dedup_source orelse return;
        while (self.pending_len != 0) try self.processOne(source);
    }

    fn processOne(self: *Publisher, source: DedupSource) !void {
        var hashes: [dedup_window]hashing.Hash = undefined;
        for (0..self.pending_len) |index| {
            hashes[index] = self.pending_chunks[(self.pending_head + index) % dedup_window].hash;
        }
        if (try source.query(self.allocator, hashes[0..self.pending_len])) |found| {
            var match = found;
            defer match.deinit(self.allocator);
            try self.appendReuse(match.xorb_hash, match.chunk_index_start, match.nodes);
            self.dropPending(match.nodes.len);
            return;
        }
        const first = self.pending_chunks[self.pending_head];
        try self.addNew(first);
        self.dropPending(1);
    }

    fn addNew(self: *Publisher, chunk: chunker.Chunk) !void {
        self.resetReuse();
        const flush = self.serializer.chunks.items.len == self.options.max_xorb_chunks or
            (self.serializer.raw_size != 0 and
                self.serializer.raw_size + chunk.data.len > self.options.max_xorb_size);
        if (flush) {
            try self.flushXorb();
        }
        self.size = std.math.add(u64, self.size, chunk.data.len) catch return error.FileTooLarge;
        try self.serializer.add(self.allocator, .{ .data = chunk.data, .hash = chunk.hash });
        if (self.serializer.raw_size == self.options.max_xorb_size) try self.flushXorb();
    }

    fn flushXorb(self: *Publisher) !void {
        if (self.serializer.chunks.items.len == 0) return;
        var object = try self.serializer.finish(self.allocator);
        defer object.deinit(self.allocator);
        const chunk_count = object.chunks.len;
        const duplicate = for (self.xorbs.items) |item| {
            if (hashing.eql(item.hash, object.hash)) break true;
        } else false;
        if (!duplicate) {
            try self.destination.put(.{
                .kind = .xorb,
                .hash = object.hash,
                .data = object.bytes,
                .raw_size = object.raw_size,
            });
            const metadata = object.chunks;
            object.chunks = &.{};
            self.xorbs.append(self.allocator, .{
                .hash = object.hash,
                .chunks = metadata,
                .raw_size = @intCast(object.raw_size),
                .serialized_size = @intCast(object.body_length),
            }) catch |err| {
                self.allocator.free(metadata);
                return err;
            };
            if (self.options.new_xorb_listener) |listener|
                try listener.callback(listener.context, self.xorbs.items[self.xorbs.items.len - 1]);
        }
        try self.segments.append(self.allocator, .{
            .xorb_hash = object.hash,
            .unpacked_segment_bytes = @intCast(object.raw_size),
            .chunk_index_start = 0,
            .chunk_index_end = @intCast(chunk_count),
        });
        for (object.nodes) |node| try self.file_nodes.add(node);
        try self.checks.append(self.allocator, object.verificationHash());
        self.xorb_count += 1;
    }
};

const test_publisher_input = @as([128 * 1024]u8, @splat('x'));

fn testPublisherFailure(
    stage: enum { chunk, metadata, store },
    fail_at: ?usize,
) anyerror!struct { failed: bool, allocations: usize, store_allocations: ?usize } {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator, .fail_at = fail_at };
    defer tracker.deinit();
    var destination = support.MemoryStore{
        .allocator = std.testing.allocator,
        .allocation_count = &tracker.allocation_count,
    };
    defer destination.deinit();
    if (stage == .store) destination.fail_on_put = 0;
    const input = &test_publisher_input;
    var publisher = try Publisher.init(tracker.allocator(), destination.store(), .{ .compression = .none });
    var failed = false;
    switch (stage) {
        .chunk => {
            publisher.write(input) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
            };
        },
        .metadata => {
            publisher.write(input) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
            };
            if (!failed) {
                _ = publisher.finish() catch |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    failed = true;
                };
            }
        },
        .store => {
            publisher.write(input) catch |err| {
                publisher.deinit();
                return err;
            };
            _ = publisher.finish() catch |err| {
                try std.testing.expectEqual(error.InjectedStoreFailure, err);
                failed = true;
            };
        },
    }
    if (stage == .chunk and fail_at == null and !failed) {
        try std.testing.expectEqual(@as(usize, 1), publisher.serializer.chunks.items.len);
    }
    if (stage == .store) {
        try std.testing.expectEqual(@as(usize, 1), destination.puts);
        try std.testing.expectEqual(ObjectKind.xorb, destination.last_attempted_kind.?);
        try std.testing.expectEqual(@as(usize, 0), publisher.serializer.chunks.items.len);
    }
    publisher.deinit();
    if (stage != .store)
        try std.testing.expectEqual(fail_at != null and fail_at.? == tracker.allocation_count, failed);
    if (tracker.duplicate_frees != 0) return error.PublisherDuplicateFree;
    if (tracker.invalid_frees != 0) return error.PublisherInvalidFree;
    if (tracker.outstanding() != 0) return error.PublisherOutstandingAllocation;
    return .{
        .failed = failed,
        .allocations = tracker.allocation_count,
        .store_allocations = destination.put_allocation_count,
    };
}

fn testPublisherMetadataFailureAfterStore(offset: usize) !void {
    const baseline = try testPublisherFailure(.metadata, null);
    const store_allocations = baseline.store_allocations orelse return error.TestNeverReachedXorbStore;
    const fail_at = store_allocations + offset;
    const result = try testPublisherFailure(.metadata, fail_at);
    try std.testing.expect(result.failed);
    try std.testing.expectEqual(fail_at, result.allocations);
}

fn testRingFailure(fail_at: ?usize) !usize {
    const support = @import("test_support");
    const Context = struct {
        fn query(_: *anyopaque, _: std.mem.Allocator, _: []const hashing.Hash) !?dedup.Match {
            return null;
        }
    };
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator, .fail_at = fail_at };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    var dummy: u8 = 0;
    var failed = false;
    _ = blk: {
        var publisher = Publisher.init(tracker.allocator(), destination.store(), .{
            .compression = .none,
            .dedup_source = .{ .context = &dummy, .query_fn = Context.query },
        }) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        defer publisher.deinit();
        for (0..100) |index| {
            publisher.addChunk(.{
                .data = "x",
                .hash = support.syntheticHash(1, index),
            }) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
        }
        var plan = publisher.finishPlan() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        plan.deinit(tracker.allocator());
    };
    try std.testing.expectEqual(fail_at != null, failed);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    return tracker.allocation_count;
}

fn testBatchFailure(fail_at: ?usize) !usize {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator, .fail_at = fail_at };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    const allocator = tracker.allocator();
    var failed = false;
    _ = blk: {
        var batch = BatchPublisher.init(allocator, destination.store());
        defer batch.deinit();
        for ([_][]const u8{ "AAA", "BBB" }) |input| {
            var publisher = Publisher.init(allocator, destination.store(), .{ .compression = .none }) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
            defer publisher.deinit();
            publisher.write(input) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
            var plan = publisher.finishPlan() catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
            defer plan.deinit(allocator);
            batch.append(&plan) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
        }
        batch.finish() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    };
    if (fail_at != null) try std.testing.expect(failed);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    return tracker.allocation_count;
}

test "BatchPublisher rejects appends after completion" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.finish();

    const segments = try allocator.alloc(shard.Segment, 1);
    segments[0] = .{
        .xorb_hash = hashing.data("xorb"),
        .unpacked_segment_bytes = 0,
        .chunk_index_start = 0,
        .chunk_index_end = 0,
    };
    var plan = Plan{
        .file = .{
            .hash = hashing.data("file"),
            .segments = segments,
        },
        .new_xorbs = &.{},
    };
    defer plan.deinit(allocator);
    try std.testing.expectError(error.AlreadyFinished, batch.append(&plan));
    try std.testing.expectEqual(@as(usize, 1), plan.file.segments.len);
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

test "BatchPublisher allocation failures preserve ownership and clean up" {
    const allocations = try testBatchFailure(null);
    for (0..allocations) |fail_at| _ = try testBatchFailure(fail_at);
}

test "Publisher ring allocation failures are clean" {
    const allocations = try testRingFailure(null);
    for (0..allocations) |fail_at| _ = try testRingFailure(fail_at);
}

test "Publisher streaming serialization allocation failures are clean" {
    const baseline = try testPublisherFailure(.chunk, null);
    try std.testing.expect(!baseline.failed);
    for (0..baseline.allocations) |fail_at| {
        const result = try testPublisherFailure(.chunk, fail_at);
        try std.testing.expect(result.failed);
    }
}

test "Publisher metadata list append failure after xorb store is clean" {
    try testPublisherMetadataFailureAfterStore(0);
}

test "Publisher xorb metadata append failure after xorb store is clean" {
    try testPublisherMetadataFailureAfterStore(1);
}

test "Publisher deinit is clean after an immediate store failure" {
    const result = try testPublisherFailure(.store, null);
    try std.testing.expect(result.failed);
}

const ReuseAllocationFailure = enum { segment, verification };

fn exerciseReuseAllocationFailure(comptime failure: ReuseAllocationFailure) !void {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    {
        var publisher = try Publisher.init(tracker.allocator(), destination.store(), .{});
        defer publisher.deinit();
        const a_hash = hashing.data("xorb A");
        const b_hash = hashing.data("xorb B");
        const a_nodes = [_]hashing.Node{.{ .hash = hashing.data("A0"), .size = 3 }};
        const b_nodes = [_]hashing.Node{
            .{ .hash = hashing.data("B0"), .size = 3 },
            .{ .hash = hashing.data("B1"), .size = 3 },
        };
        try publisher.segments.ensureTotalCapacityPrecise(tracker.allocator(), 4);
        try publisher.checks.ensureTotalCapacityPrecise(tracker.allocator(), 4);
        try publisher.reuse(a_hash, 0, &a_nodes);
        while (publisher.segments.items.len < publisher.segments.capacity) {
            try publisher.reuse(a_hash, 0, &a_nodes);
        }
        try std.testing.expectEqual(publisher.segments.items.len, publisher.checks.items.len);
        try std.testing.expectEqual(publisher.segments.capacity, publisher.checks.capacity);
        if (failure == .verification) {
            try publisher.segments.ensureTotalCapacityPrecise(
                tracker.allocator(),
                publisher.segments.items.len + 1,
            );
        }
        const segment_count = publisher.segments.items.len;

        tracker.fail_at = tracker.allocation_count;
        try std.testing.expectError(error.OutOfMemory, publisher.reuse(b_hash, 1, b_nodes[1..]));
        tracker.fail_at = null;
        try publisher.reuse(b_hash, 1, b_nodes[1..]);

        var plan = try publisher.finishPlan();
        defer plan.deinit(tracker.allocator());
        try std.testing.expectEqual(segment_count + 1, plan.file.segments.len);
        try std.testing.expectEqual(plan.file.segments.len, plan.file.verification.len);
        for (plan.file.segments[0..segment_count], plan.file.verification[0..segment_count]) |segment, check| {
            try std.testing.expectEqual(a_hash, segment.xorb_hash);
            try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
            try std.testing.expectEqual(@as(u32, 1), segment.chunk_index_end);
            try std.testing.expectEqual(@as(u32, 3), segment.unpacked_segment_bytes);
            try std.testing.expectEqual(hashing.verificationNodes(&a_nodes), check);
        }
        const segment = plan.file.segments[segment_count];
        try std.testing.expectEqual(b_hash, segment.xorb_hash);
        try std.testing.expectEqual(@as(u32, 1), segment.chunk_index_start);
        try std.testing.expectEqual(@as(u32, 2), segment.chunk_index_end);
        try std.testing.expectEqual(@as(u32, 3), segment.unpacked_segment_bytes);
        try std.testing.expectEqual(hashing.verificationNodes(b_nodes[1..]), plan.file.verification[segment_count]);
        try std.testing.expectEqual(@as(u64, @intCast(segment_count + 1)) * 3, plan.size);
        try std.testing.expectEqual(@as(u64, segment_count + 1), plan.xorb_count);
        try std.testing.expectEqual(@as(usize, 0), plan.new_xorbs.len);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "reuse segment reservation failure preserves the active Xorb" {
    try exerciseReuseAllocationFailure(.segment);
}

test "reuse verification reservation failure preserves the active Xorb" {
    try exerciseReuseAllocationFailure(.verification);
}

test "reuse preflights a fresh segment before flushing pending input" {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    {
        var publisher = try Publisher.init(tracker.allocator(), destination.store(), .{});
        defer publisher.deinit();
        const object_hash = hashing.data("existing xorb");
        const node = hashing.Node{ .hash = hashing.data("AAA"), .size = 3 };
        try publisher.segments.ensureTotalCapacityPrecise(tracker.allocator(), 1);
        try publisher.checks.ensureTotalCapacityPrecise(tracker.allocator(), 1);
        try publisher.reuse(object_hash, 0, &.{node});
        try publisher.write("BBB");

        tracker.fail_at = tracker.allocation_count;
        try std.testing.expectError(error.OutOfMemory, publisher.reuse(object_hash, 1, &.{node}));
        tracker.fail_at = null;
        try publisher.reuse(object_hash, 1, &.{node});

        var plan = try publisher.finishPlan();
        defer plan.deinit(tracker.allocator());
        try std.testing.expectEqual(@as(usize, 3), plan.file.segments.len);
        try std.testing.expectEqual(object_hash, plan.file.segments[0].xorb_hash);
        try std.testing.expectEqual(@as(u32, 0), plan.file.segments[0].chunk_index_start);
        try std.testing.expectEqual(@as(u32, 1), plan.file.segments[0].chunk_index_end);
        try std.testing.expectEqual(object_hash, plan.file.segments[2].xorb_hash);
        try std.testing.expectEqual(@as(u32, 1), plan.file.segments[2].chunk_index_start);
        try std.testing.expectEqual(@as(u32, 2), plan.file.segments[2].chunk_index_end);
        try std.testing.expectEqual(hashing.verificationNodes(&.{node}), plan.file.verification[0]);
        try std.testing.expectEqual(hashing.verificationNodes(&.{node}), plan.file.verification[2]);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "continued reuse rejects segment byte overflow without mutation" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    const object_hash = hashing.data("existing xorb");
    const chunk_size = 128 * 1024;
    const node_count = std.math.maxInt(u32) / chunk_size;
    for (0..node_count) |index| {
        const node = hashing.Node{
            .hash = support.syntheticHash(7, index),
            .size = chunk_size,
        };
        try publisher.reuse(object_hash, @intCast(index), &.{node});
    }
    const extra = hashing.Node{
        .hash = support.syntheticHash(7, node_count),
        .size = chunk_size,
    };
    try std.testing.expectError(
        error.InvalidDedupMatch,
        publisher.reuse(object_hash, node_count, &.{extra}),
    );

    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), plan.file.segments.len);
    try std.testing.expectEqual(node_count * chunk_size, plan.file.segments[0].unpacked_segment_bytes);
    try std.testing.expectEqual(node_count, plan.file.segments[0].chunk_index_end);
    try std.testing.expectEqual(@as(u64, node_count) * chunk_size, plan.size);
}

test "reuse rejects file size overflow without mutation" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    const object_hash = hashing.data("existing xorb");
    const node = hashing.Node{ .hash = hashing.data("AAA"), .size = 3 };
    try publisher.reuse(object_hash, 0, &.{node});
    publisher.size = std.math.maxInt(u64) - 2;
    const before = publisher.segments.items[0];

    try std.testing.expectError(error.FileTooLarge, publisher.reuse(object_hash, 1, &.{node}));
    try std.testing.expectEqual(std.math.maxInt(u64) - 2, publisher.size);
    try std.testing.expectEqual(@as(u64, 1), publisher.xorb_count);
    try std.testing.expectEqual(@as(usize, 1), publisher.segments.items.len);
    try std.testing.expectEqual(before, publisher.segments.items[0]);
}

fn checkReusePendingOverflow(publisher: *Publisher, destination: *const @import("test_support").MemoryStore) !void {
    publisher.size = std.math.maxInt(u64) - 4;
    const size_before = publisher.size;
    const xorb_count_before = publisher.xorb_count;
    const puts_before = destination.puts;
    const segment_count_before = publisher.segments.items.len;
    const pending_len_before = publisher.pending_len;
    const pending_head_before = publisher.pending_head;
    const returned_before = publisher.chunker.returned_pending;
    const buffered_before = try std.testing.allocator.dupe(u8, publisher.chunker.pending.items);
    defer std.testing.allocator.free(buffered_before);
    const queued_before = try std.testing.allocator.alloc([]u8, pending_len_before);
    var initialized: usize = 0;
    defer {
        for (queued_before[0..initialized]) |bytes| std.testing.allocator.free(bytes);
        std.testing.allocator.free(queued_before);
    }
    for (queued_before, 0..) |*copy, index| {
        const chunk = publisher.pending_chunks[(pending_head_before + index) % dedup_window];
        copy.* = try std.testing.allocator.dupe(u8, chunk.data);
        initialized += 1;
    }
    const node = hashing.Node{ .hash = hashing.data("abc"), .size = 3 };

    try std.testing.expectError(error.FileTooLarge, publisher.reuse(
        hashing.data("existing xorb"),
        0,
        &.{node},
    ));
    try std.testing.expectEqual(size_before, publisher.size);
    try std.testing.expectEqual(xorb_count_before, publisher.xorb_count);
    try std.testing.expectEqual(puts_before, destination.puts);
    try std.testing.expectEqual(segment_count_before, publisher.segments.items.len);
    try std.testing.expectEqual(pending_len_before, publisher.pending_len);
    try std.testing.expectEqual(pending_head_before, publisher.pending_head);
    try std.testing.expectEqual(returned_before, publisher.chunker.returned_pending);
    try std.testing.expectEqualSlices(u8, buffered_before, publisher.chunker.pending.items);
    try std.testing.expect(publisher.has_complete_sha256);
    for (queued_before, 0..) |expected, index| {
        const chunk = publisher.pending_chunks[(pending_head_before + index) % dedup_window];
        try std.testing.expectEqualSlices(u8, expected, chunk.data);
    }
}

test "reuse preflight preserves a short buffered tail" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .max_xorb_size = 3,
    });
    defer publisher.deinit();
    try publisher.write("abc");
    try std.testing.expectEqualStrings("abc", publisher.chunker.pending.items);
    try checkReusePendingOverflow(&publisher, &destination);
}

test "reuse preflight excludes an already counted returned chunk view" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .max_xorb_size = 256 * 1024,
    });
    defer publisher.deinit();
    const block = @as([128 * 1024]u8, @splat('x'));
    try publisher.write(block[0 .. block.len - 1]);
    try publisher.write(block[block.len - 1 ..]);
    try std.testing.expect(publisher.chunker.returned_pending);
    try std.testing.expectEqual(block.len, publisher.chunker.pending.items.len);
    try std.testing.expectEqual(@as(u64, block.len), publisher.size);
    publisher.size = std.math.maxInt(u64) - 4;
    const node = hashing.Node{ .hash = hashing.data("abc"), .size = 3 };
    try publisher.reuse(hashing.data("existing xorb"), 0, &.{node});
    try std.testing.expectEqual(std.math.maxInt(u64) - 1, publisher.size);
    try std.testing.expect(!publisher.has_complete_sha256);
    try std.testing.expect(!publisher.chunker.returned_pending);
    try std.testing.expectEqual(@as(usize, 0), publisher.chunker.pending.items.len);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.file.segments.len);
    try std.testing.expectEqual(@as(u32, block.len), plan.file.segments[0].unpacked_segment_bytes);
    try std.testing.expectEqual(@as(u32, 3), plan.file.segments[1].unpacked_segment_bytes);
}

test "reuse preflight preserves pending dedup chunks" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    const Context = struct {
        fn query(_: *anyopaque, _: std.mem.Allocator, _: []const hashing.Hash) !?dedup.Match {
            return null;
        }
    };
    var dummy: u8 = 0;
    var publisher = try Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .max_xorb_size = 3,
        .dedup_source = .{ .context = &dummy, .query_fn = Context.query },
    });
    defer publisher.deinit();
    const block = @as([128 * 1024]u8, @splat('x'));
    try publisher.write(&block);
    try std.testing.expectEqual(@as(usize, 1), publisher.pending_len);
    try std.testing.expectEqualSlices(u8, &block, publisher.pending_chunks[publisher.pending_head].data);
    try checkReusePendingOverflow(&publisher, &destination);
}

test "Publisher write-time xorb flush failure has clean ownership" {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer tracker.deinit();
    var destination = support.MemoryStore{
        .allocator = std.testing.allocator,
        .fail_on_put = 0,
    };
    defer destination.deinit();
    const one_chunk = blk: {
        const input = @as([128 * 1024]u8, @splat('x'));
        const chunks = try chunker.chunkBuffer(std.testing.allocator, &input);
        defer std.testing.allocator.free(chunks);
        try std.testing.expectEqual(@as(usize, 1), chunks.len);
        break :blk chunks[0].data;
    };
    var publisher = try Publisher.init(tracker.allocator(), destination.store(), .{
        .compression = .none,
        .max_xorb_size = @intCast(one_chunk.len),
    });
    try std.testing.expectError(error.InjectedStoreFailure, publisher.write(one_chunk));
    try std.testing.expectEqual(@as(usize, 1), destination.puts);
    try std.testing.expectEqual(ObjectKind.xorb, destination.last_attempted_kind.?);
    publisher.deinit();
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "Publisher rejects every operation after a failed write" {
    const support = @import("test_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    {
        var publisher = try Publisher.init(tracker.allocator(), destination.store(), .{});
        defer publisher.deinit();
        tracker.fail_at = tracker.allocation_count;
        try std.testing.expectError(error.OutOfMemory, publisher.write("AAA"));
        tracker.fail_at = null;
        try std.testing.expectError(error.WriteFailed, publisher.write("AAA"));
        const node = hashing.Node{ .hash = hashing.data("AAA"), .size = 3 };
        try std.testing.expectError(error.WriteFailed, publisher.reuse(hashing.data("existing"), 0, &.{node}));
        try std.testing.expectError(error.WriteFailed, publisher.finishPlan());
        try std.testing.expectError(error.WriteFailed, publisher.finish());
        try std.testing.expectEqual(@as(usize, 0), destination.puts);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "direct reuse flushes pending input before the reused segment" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    const nodes = [_]hashing.Node{.{ .hash = hashing.data("AAA"), .size = 3 }};
    const file_hash = try hashing.file(allocator, &.{
        .{ .hash = hashing.data("BBB"), .size = 3 },
        nodes[0],
    });
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    try publisher.write("BBB");
    try publisher.reuse(hashing.data("existing xorb"), 0, &nodes);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(file_hash, plan.file.hash);
    try std.testing.expectEqual(@as(usize, 2), plan.file.segments.len);
    try std.testing.expectEqual(@as(u64, 6), plan.size);
    try std.testing.expectEqual(@as(usize, 1), plan.new_xorbs.len);
    try std.testing.expectEqual(hashing.data("BBB"), plan.new_xorbs[0].chunks[0].hash);
    try std.testing.expectEqual(@as(u32, 3), plan.new_xorbs[0].chunks[0].unpacked_segment_bytes);
}

test "adjacent reuse ranges continue from a nonzero chunk offset" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    const object_hash = hashing.data("existing xorb");
    const nodes = [_]hashing.Node{
        .{ .hash = hashing.data("CCC"), .size = 3 },
        .{ .hash = hashing.data("BBB"), .size = 3 },
    };
    try publisher.reuse(object_hash, 2, nodes[0..1]);
    try publisher.reuse(object_hash, 3, nodes[1..2]);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), plan.file.segments.len);
    try std.testing.expectEqual(@as(u32, 2), plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 4), plan.file.segments[0].chunk_index_end);
    try std.testing.expectEqual(@as(u32, 6), plan.file.segments[0].unpacked_segment_bytes);
    try std.testing.expectEqual(hashing.verificationNodes(&nodes), plan.file.verification[0]);
}

test "Publisher releases BG4 scratch after multiple successful xorbs" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var tracker: support.TrackingAllocator = .{ .backing = allocator };
    defer tracker.deinit();
    var destination: support.MemoryStore = .{ .allocator = allocator };
    defer destination.deinit();
    var data: [400_000]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% index / 97);

    _ = {
        var publisher = try Publisher.init(tracker.allocator(), destination.store(), .{
            .compression = .bg4_lz4,
            .max_xorb_size = 128 * 1024,
        });
        defer publisher.deinit();
        try publisher.write(&data);
        const result = try publisher.finish();
        try std.testing.expect(result.xorb_count > 1);
        try std.testing.expect(destination.count(.xorb) > 1);
    };
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
}

test "Publisher borrows chunk input only while compressing" {
    const allocator = std.testing.allocator;
    const input = @as([128 * 1024]u8, @splat('x'));
    const chunks = try chunker.chunkBuffer(allocator, &input);
    defer allocator.free(chunks);
    try std.testing.expectEqual(@as(usize, 1), chunks.len);
    var expected = try xorb.serialize(allocator, &.{.{
        .data = chunks[0].data,
        .hash = chunks[0].hash,
    }}, .none);
    defer expected.deinit(allocator);

    var destination = @import("test_support").MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .max_xorb_size = chunks[0].data.len,
    });
    defer publisher.deinit();
    const scratch = try allocator.dupe(u8, chunks[0].data);
    defer allocator.free(scratch);
    try publisher.write(scratch);
    @memset(scratch, 0);
    _ = try publisher.finish();
    for (destination.objects.items) |object| {
        if (object.kind == .xorb) {
            try std.testing.expectEqualSlices(u8, expected.bytes, object.data);
            return;
        }
    }
    return error.TestMissingPublishedXorb;
}

test "oversized shard publication uses the package allocator" {
    const support = @import("test_support");
    const files = [_]shard.File{
        .{ .hash = support.syntheticHash(0, 0), .segments = &.{} },
        .{ .hash = support.syntheticHash(0, 1), .segments = &.{} },
    };
    const chunk = shard.Chunk{
        .hash = support.syntheticHash(1, 0),
        .byte_range_start = 0,
        .unpacked_segment_bytes = 1,
    };
    const objects = [_]shard.Xorb{
        .{ .hash = support.syntheticHash(2, 0), .chunks = &.{chunk}, .raw_size = 1, .serialized_size = 9 },
        .{ .hash = support.syntheticHash(2, 1), .chunks = &.{chunk}, .raw_size = 1, .serialized_size = 9 },
    };
    const bytes = try shard.serialize(std.testing.allocator, &files, &objects);
    defer std.testing.allocator.free(bytes);

    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    try publishShardLimited(tracker.allocator(), bytes, 2, destination.store(), 240);
    try std.testing.expect(tracker.allocation_count != 0);
    try std.testing.expectEqual(@as(usize, 3), destination.count(.shard));
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}
