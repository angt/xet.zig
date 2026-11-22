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

    fn validate(self: PackOptions) !void {
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
        if (self.max_xorb_size == 0 or self.max_xorb_size > constants.max_xorb_size or
            self.max_xorb_chunks == 0 or self.max_xorb_chunks > constants.max_xorb_chunks)
            return error.InvalidOptions;
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
    const nodes = try allocator.alloc(hashing.Node, chunks.len);
    defer allocator.free(nodes);
    const source_chunks = try allocator.alloc(xorb.Chunk, chunks.len);
    defer allocator.free(source_chunks);
    for (chunks, nodes, source_chunks) |chunk, *node, *source| {
        node.* = .{ .hash = chunk.hash, .size = chunk.data.len };
        source.* = .{ .data = chunk.data, .hash = chunk.hash };
    }
    const file_hash = try hashing.file(allocator, nodes);
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
            var mutable = object;
            mutable.deinit(allocator);
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

fn publishShard(allocator: std.mem.Allocator, bytes: []const u8, raw_size: u64, destination: Store) !void {
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
    var file_record_index: u32 = 0;
    for (0..reader.footer.file_count) |_| {
        const info = try reader.fileAt(file_record_index);
        file_record_index = @intCast((info.end - shard.header_size) / shard.entry_size);
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
    file: shard.File,
    new_xorbs: []shard.Xorb,
    size: u64,
    xorb_count: u64,

    pub fn fromFile(file: shard.File, new_xorbs: []shard.Xorb, size: u64) Plan {
        return .{
            .file = file,
            .new_xorbs = new_xorbs,
            .size = size,
            .xorb_count = file.segments.len,
        };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.file.segments);
        if (self.file.verification.len != 0) allocator.free(self.file.verification);
        for (self.new_xorbs) |object| allocator.free(object.chunks);
        allocator.free(self.new_xorbs);
        self.* = undefined;
    }

    /// Consumes the plan's metadata, even on failure
    pub fn publish(self: *Plan, allocator: std.mem.Allocator, destination: Store) !PublishResult {
        defer self.deinit(allocator);
        const shard_bytes = try shard.serialize(allocator, &.{self.file}, self.new_xorbs);
        defer allocator.free(shard_bytes);
        try publishShard(allocator, shard_bytes, self.size, destination);
        return .{ .file_hash = self.file.hash, .size = self.size, .xorb_count = self.xorb_count };
    }
};

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
    chunk_index: u64 = 0,
    reused_xorb: ?hashing.Hash = null,
    reused_next_chunk: u32 = 0,
    reused_verification: std.crypto.hash.Blake3 = .init(.{ .key = constants.verification_key }),
    pending_chunks: std.ArrayList(chunker.Chunk) = .empty,
    pending_hashes: std.ArrayList(hashing.Hash) = .empty,
    pending_query: bool = false,

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
        for (self.pending_chunks.items) |chunk| self.allocator.free(chunk.data);
        self.pending_chunks.deinit(self.allocator);
        self.pending_hashes.deinit(self.allocator);
    }

    pub fn write(self: *Publisher, input: []const u8) !void {
        if (self.finished) return error.AlreadyFinished;
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

    /// Returns the reconstruction without publishing it
    pub fn finishPlan(self: *Publisher) !Plan {
        if (self.finished) return error.AlreadyFinished;
        self.finished = true;
        const final = try self.chunker.finish(self.allocator);
        if (final.chunk) |chunk| try self.addChunk(chunk);
        try self.processPending();
        try self.flushXorb();
        const file_hash = try self.file_nodes.fileHash();
        const sha256 = hashing.fromStandard(self.file_sha256.finalResult());
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

    /// References existing chunks. `nodes` must exactly match the Xorb range
    pub fn reuse(
        self: *Publisher,
        object_hash: hashing.Hash,
        chunk_index_start: u32,
        nodes: []const hashing.Node,
    ) !void {
        if (nodes.len == 0 or nodes.len > std.math.maxInt(u32) - chunk_index_start) {
            return error.InvalidDedupMatch;
        }
        const continues = if (self.reused_xorb) |hash|
            hashing.eql(hash, object_hash) and self.reused_next_chunk == chunk_index_start
        else
            false;
        if (!continues) {
            try self.flushXorb();
            self.resetReuse();
            self.reused_xorb = object_hash;
            try self.segments.append(self.allocator, .{
                .xorb_hash = object_hash,
                .unpacked_segment_bytes = 0,
                .chunk_index_start = chunk_index_start,
                .chunk_index_end = chunk_index_start,
            });
            try self.checks.append(self.allocator, hashing.zero);
            self.xorb_count += 1;
        }
        const last = self.segments.items.len - 1;
        for (nodes) |node| {
            if (node.size == 0 or node.size > constants.max_chunk_size) return error.InvalidDedupMatch;
            self.reused_verification.update(&node.hash);
            self.size = std.math.add(u64, self.size, node.size) catch return error.FileTooLarge;
            self.segments.items[last].unpacked_segment_bytes += @intCast(node.size);
            self.segments.items[last].chunk_index_end += 1;
            self.reused_next_chunk += 1;
            try self.file_nodes.add(node);
        }
        self.checks.items[last] = self.reuseVerification();
    }

    fn reuseVerification(self: *const Publisher) hashing.Hash {
        var state = self.reused_verification;
        var result: hashing.Hash = undefined;
        state.final(&result);
        return result;
    }

    fn resetReuse(self: *Publisher) void {
        self.reused_xorb = null;
        self.reused_next_chunk = 0;
        self.reused_verification = .init(.{ .key = constants.verification_key });
    }

    fn addChunk(self: *Publisher, chunk: chunker.Chunk) !void {
        if (self.options.dedup_source) |source| {
            if (self.pending_chunks.items.len == 0) {
                try self.buffer(chunk);
                return;
            }
            if (self.pending_chunks.items.len == 64 or dedup.eligible(chunk.hash)) {
                try self.processBatch(source);
            }
            try self.buffer(chunk);
            return;
        }
        try self.addNew(chunk);
    }

    fn buffer(self: *Publisher, chunk: chunker.Chunk) !void {
        const data = try self.allocator.dupe(u8, chunk.data);
        errdefer self.allocator.free(data);
        try self.pending_chunks.append(self.allocator, .{ .data = data, .hash = chunk.hash });
        errdefer self.pending_chunks.shrinkRetainingCapacity(self.pending_chunks.items.len - 1);
        try self.pending_hashes.append(self.allocator, chunk.hash);
        if (self.pending_chunks.items.len == 1) self.pending_query = self.chunk_index == 0 or dedup.eligible(chunk.hash);
        self.chunk_index += 1;
    }

    fn dropPending(self: *Publisher, count: usize) void {
        for (self.pending_chunks.items[0..count]) |chunk| self.allocator.free(chunk.data);
        for (self.pending_chunks.items[count..], self.pending_hashes.items[count..], 0..) |chunk, hash, index| {
            self.pending_chunks.items[index] = chunk;
            self.pending_hashes.items[index] = hash;
        }
        self.pending_chunks.shrinkRetainingCapacity(self.pending_chunks.items.len - count);
        self.pending_hashes.shrinkRetainingCapacity(self.pending_hashes.items.len - count);
        self.pending_query = self.pending_chunks.items.len != 0 and dedup.eligible(self.pending_hashes.items[0]);
    }

    fn processPending(self: *Publisher) !void {
        if (self.pending_chunks.items.len == 0) return;
        const source = self.options.dedup_source.?;
        if (self.pending_query) {
            try self.processBatch(source);
        } else {
            while (self.pending_chunks.items.len != 0) {
                try self.addNew(self.pending_chunks.items[0]);
                self.dropPending(1);
            }
        }
        std.debug.assert(self.pending_chunks.items.len == 0);
    }

    fn processBatch(self: *Publisher, source: DedupSource) !void {
        const found = try source.query(self.allocator, self.pending_hashes.items);
        const consumed = if (found) |located| blk: {
            var match = located;
            defer match.deinit(self.allocator);
            try self.reuse(match.xorb_hash, match.chunk_index_start, match.nodes);
            break :blk match.nodes.len;
        } else 0;
        if (consumed != 0) {
            self.dropPending(consumed);
            if (self.pending_chunks.items.len != 0) {
                if (self.pending_query) {
                    try self.processBatch(source);
                } else {
                    while (self.pending_chunks.items.len != 0) {
                        try self.addNew(self.pending_chunks.items[0]);
                        self.dropPending(1);
                    }
                }
            }
            return;
        }
        const first = self.pending_chunks.items[0];
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
        const existing = for (self.xorbs.items) |item| {
            if (hashing.eql(item.hash, object.hash)) break item;
        } else null;
        if (existing == null) {
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

const regression_publisher_input = @as([128 * 1024]u8, @splat('x'));

fn regressionPublisherInput() ![]const u8 {
    const chunks = try chunker.chunkBuffer(std.testing.allocator, &regression_publisher_input);
    defer std.testing.allocator.free(chunks);
    return chunks[0].data;
}

fn regressionPublisherFailure(
    stage: enum { chunk, metadata, store },
    fail_at: ?usize,
) anyerror!struct { failed: bool, allocations: usize, store_allocations: ?usize } {
    const support = @import("regression_support");
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator, .fail_at = fail_at };
    defer tracker.deinit();
    var destination = support.MemoryStore{
        .allocator = std.testing.allocator,
        .allocation_count = &tracker.allocation_count,
    };
    defer destination.deinit();
    if (stage == .store) destination.fail_on_put = 0;
    const input = try regressionPublisherInput();
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

fn regressionPublisherMetadataFailureAfterStore(offset: usize) !void {
    const baseline = try regressionPublisherFailure(.metadata, null);
    const store_allocations = baseline.store_allocations orelse return error.TestNeverReachedXorbStore;
    const fail_at = store_allocations + offset;
    const result = try regressionPublisherFailure(.metadata, fail_at);
    try std.testing.expect(result.failed);
    try std.testing.expectEqual(fail_at, result.allocations);
}

fn regressionPublisherStoreSweep() !void {
    const result = try regressionPublisherFailure(.store, null);
    try std.testing.expect(result.failed);
}

test "Publisher streaming serialization allocation failures are clean" {
    const baseline = try regressionPublisherFailure(.chunk, null);
    try std.testing.expect(!baseline.failed);
    for (0..baseline.allocations) |fail_at| {
        const result = try regressionPublisherFailure(.chunk, fail_at);
        try std.testing.expect(result.failed);
    }
}

test "Publisher metadata list append failure after xorb store is clean" {
    try regressionPublisherMetadataFailureAfterStore(0);
}

test "Publisher xorb metadata append failure after xorb store is clean" {
    try regressionPublisherMetadataFailureAfterStore(1);
}

test "Publisher deinit is clean after an immediate store failure" {
    try regressionPublisherStoreSweep();
}

test "streaming publisher matches contiguous hashes with tiny xorbs" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 400_000);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% index / 97);
    var package = try pack(allocator, data, .{ .max_xorb_size = 128 * 1024 });
    defer package.deinit(allocator);

    const Context = struct {
        xorbs: usize = 0,
        xorb_bytes: std.ArrayList([]u8) = .empty,
        shard_bytes: std.ArrayList(u8) = .empty,
        fn put(raw: *anyopaque, object: Object) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            switch (object.kind) {
                .xorb => {
                    self.xorbs += 1;
                    try self.xorb_bytes.append(std.testing.allocator, try std.testing.allocator.dupe(u8, object.data));
                },
                .shard => try self.shard_bytes.appendSlice(std.testing.allocator, object.data),
            }
        }
    };
    var context = Context{};
    defer {
        for (context.xorb_bytes.items) |bytes| allocator.free(bytes);
        context.xorb_bytes.deinit(allocator);
        context.shard_bytes.deinit(allocator);
    }
    var publisher = try Publisher.init(allocator, .{ .context = &context, .put_fn = Context.put }, .{
        .max_xorb_size = 128 * 1024,
    });
    defer publisher.deinit();
    for (data) |byte| try publisher.write(&.{byte});
    const result = try publisher.finish();
    try std.testing.expectEqual(package.file_hash, result.file_hash);
    try std.testing.expectEqual(package.objects.len, result.xorb_count);
    try std.testing.expectEqualSlices(u8, package.shard_bytes, context.shard_bytes.items);
    for (package.objects) |*object| {
        for (context.xorb_bytes.items) |uploaded| {
            if (std.mem.eql(u8, uploaded, object.bytes)) break;
        } else return error.TestMissingCanonicalXorb;
    }
}

test "Publisher releases BG4 scratch after multiple successful xorbs" {
    const support = @import("regression_support");
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

    var destination = @import("regression_support").MemoryStore{ .allocator = allocator };
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

test "repeated xorbs upload once and retain every file segment" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 0);

    const Context = struct {
        xorb_uploads: usize = 0,
        shard_bytes: std.ArrayList(u8) = .empty,
        fn put(raw: *anyopaque, object: Object) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            switch (object.kind) {
                .xorb => self.xorb_uploads += 1,
                .shard => try self.shard_bytes.appendSlice(std.testing.allocator, object.data),
            }
        }
    };
    var context = Context{};
    defer context.shard_bytes.deinit(allocator);
    var publisher = try Publisher.init(allocator, .{ .context = &context, .put_fn = Context.put }, .{
        .max_xorb_size = 1024 * 1024,
    });
    defer publisher.deinit();
    try publisher.write(data);
    const result = try publisher.finish();
    try std.testing.expectEqual(@as(usize, 1), context.xorb_uploads);
    try std.testing.expectEqual(@as(u64, 4), result.xorb_count);

    const reader = try shard.Reader.init(context.shard_bytes.items);
    const info = (try reader.findFile(result.file_hash)).?;
    try std.testing.expectEqual(@as(u32, 4), info.count);
    try std.testing.expectEqual(@as(usize, 1), reader.footer.xorb_count);
    for (0..info.count) |index| {
        const segment = try info.segment(@intCast(index));
        try std.testing.expectEqual(@as(u32, 1024 * 1024), segment.unpacked_segment_bytes);
        try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
        try std.testing.expectEqual(@as(u32, 8), segment.chunk_index_end);
    }

    var package = try pack(allocator, data, .{ .max_xorb_size = 1024 * 1024 });
    defer package.deinit(allocator);
    const packed_reader = try shard.Reader.init(package.shard_bytes);
    try std.testing.expectEqual(@as(usize, 1), packed_reader.footer.xorb_count);
    try std.testing.expectEqual(result.file_hash, package.file_hash);
}

test "oversized shard publication uses the package allocator" {
    const support = @import("regression_support");
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
    const package = Package{
        .file_hash = hashing.data("file"),
        .size = 2,
        .objects = &.{},
        .shard_bytes = bytes,
    };
    var destination = support.MemoryStore{ .allocator = std.testing.allocator };
    defer destination.deinit();
    try publishShardLimited(tracker.allocator(), bytes, package.size, destination.store(), 240);
    try std.testing.expect(tracker.allocation_count != 0);
    try std.testing.expectEqual(@as(usize, 3), destination.count(.shard));
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "pack and publish a multi-object package" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 2_000_000);
    defer allocator.free(data);
    for (data, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% i / 97);
    var package = try pack(allocator, data, .{ .max_xorb_size = 128 * 1024 });
    defer package.deinit(allocator);
    try std.testing.expect(package.objects.len >= 2);
    const reader = try shard.Reader.init(package.shard_bytes);
    const info = (try reader.findFile(package.file_hash)).?;
    try std.testing.expectEqual(@as(u32, @intCast(package.objects.len)), info.count);
    const Context = struct {
        objects: usize = 0,
        shards: usize = 0,
        fn put(raw: *anyopaque, object: Object) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            switch (object.kind) {
                .xorb => self.objects += 1,
                .shard => self.shards += 1,
            }
        }
    };
    var context = Context{};
    try publish(allocator, &package, .{ .context = &context, .put_fn = Context.put });
    try std.testing.expectEqual(package.objects.len, context.objects);
    try std.testing.expectEqual(@as(usize, 1), context.shards);
}
