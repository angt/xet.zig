//! Storage-independent packaging and publishing

const std = @import("std");
const constants = @import("constants.zig");
const chunker = @import("chunker.zig");
const batch_hash = @import("chunk_batch.zig");
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

pub const Store = struct {
    pub const Item = Object;

    context: *anyopaque,
    put_fn: *const fn (context: *anyopaque, object: Object) anyerror!void,

    /// `object.data` is borrowed for this call only
    pub fn put(self: Store, object: Object) !void {
        return self.put_fn(self.context, object);
    }
};

pub const PackOptions = struct {
    compression: xorb.Compression = .lz4,
    max_xorb_size: u64 = constants.target_xorb_size,
    max_xorb_chunks: u32 = constants.max_xorb_chunks,
    strategy: ?chunker.Strategy = null,

    pub fn validate(self: PackOptions) !void {
        if (self.max_xorb_size == 0 or self.max_xorb_size > constants.max_xorb_size or
            self.max_xorb_chunks == 0 or self.max_xorb_chunks > constants.max_xorb_chunks)
            return error.InvalidOptions;
    }
};

/// Drops Xorbs and rejects shards, for publishers that defer storage to a listener
pub fn noStore() Store {
    return .{ .context = undefined, .put_fn = discard };
}

fn discard(_: *anyopaque, object: Object) !void {
    if (object.kind == .shard) return error.InvalidOperation;
}

pub const NewXorbListener = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, object: shard.Xorb) anyerror!void,
};

pub const ReferenceOperation = struct {
    xorb_hash: hashing.Hash,
    chunk_index_start: u32,
    nodes: []const hashing.Node,
};

pub const Operation = union(enum) {
    reference: ReferenceOperation,
    store: struct { item: Object, allocator: std.mem.Allocator },
};

pub const OperationDisposition = enum { release, retain };

/// Announces every closed Xorb so segments with a placeholder hash can resolve
pub const FlushListener = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, hash: hashing.Hash) anyerror!void,
};

/// The listener frees a retained payload with the originating writer's allocator.
/// Reference nodes are borrowed and the reference disposition is ignored
pub const OperationListener = struct {
    context: *anyopaque,
    callback: *const fn (
        context: *anyopaque,
        operation: Operation,
    ) anyerror!OperationDisposition,
};

/// One open Xorb that outlives the files filling it
pub const XorbWriter = struct {
    allocator: std.mem.Allocator,
    /// Receives every Xorb this writer flushes, so a deduplicated hash stays stored here
    destination: Store,
    op_listener: ?OperationListener = null,
    /// Bumped by every install, so an older publisher cannot release a newer listener
    op_listener_gen: u64 = 0,
    new_xorb_listener: ?NewXorbListener = null,
    /// Runs after a flush resolves the open Xorb's hash
    flush_listener: ?FlushListener = null,
    serializer: xorb.Serializer,
    /// Completed Xorb metadata, owned here until taken or freed by deinit
    xorbs: std.ArrayList(shard.Xorb) = .empty,
    stored: std.AutoHashMapUnmanaged(hashing.Hash, usize) = .empty,
    /// Chunk positions in the open Xorb, so a repeat can reference the first copy
    open: std.AutoHashMapUnmanaged(hashing.Hash, u32) = .empty,
    marked: Checkpoint = .{},
    /// Whether the latest flush also carried committed chunks
    carries_committed: bool = false,
    /// A failed flush dropped chunks that committed file terms may reference
    lost: bool = false,
    /// Metadata count that survives abandonment because committed files need it
    retained: usize = 0,
    /// Identifies the one publisher allowed to fill the open Xorb
    active_publisher: ?u64 = null,
    publisher_gen: u64 = 0,
    discarding: bool = false,

    pub const Checkpoint = struct {
        output: usize = 0,
        chunks: usize = 0,
        nodes: usize = 0,
        boundaries: usize = 0,
        raw_size: u64 = 0,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        destination: Store,
        compression: xorb.Compression,
    ) XorbWriter {
        return .{
            .allocator = allocator,
            .destination = destination,
            .serializer = .init(compression),
        };
    }

    pub fn deinit(self: *XorbWriter) void {
        self.serializer.deinit(self.allocator);
        for (self.xorbs.items) |object| self.allocator.free(object.chunks);
        self.xorbs.deinit(self.allocator);
        self.stored.deinit(self.allocator);
        self.open.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const XorbWriter) u32 {
        return @intCast(self.serializer.chunks.items.len);
    }

    pub fn rawSize(self: *const XorbWriter) u64 {
        return self.serializer.raw_size;
    }

    /// Returns the position of a chunk already buffered in the open Xorb
    pub fn find(self: *const XorbWriter, hash: hashing.Hash) ?u32 {
        return self.open.get(hash);
    }

    fn checkpoint(self: *const XorbWriter) Checkpoint {
        return .{
            .output = self.serializer.output.items.len,
            .chunks = self.serializer.chunks.items.len,
            .nodes = self.serializer.nodes.items.len,
            .boundaries = self.serializer.packed_boundaries.items.len,
            .raw_size = self.serializer.raw_size,
        };
    }

    /// Remembers the buffer state a later rollback returns to; fails while a file owns the Xorb
    pub fn mark(self: *XorbWriter) !void {
        try self.requireIdle();
        self.advanceFloor();
    }

    /// Accepts one file's plan: moves the floor past its chunks and spends its claim
    fn acceptPlan(self: *XorbWriter, gen: u64) void {
        if (self.active_publisher != gen) return;
        self.advanceFloor();
        self.active_publisher = null;
    }

    fn advanceFloor(self: *XorbWriter) void {
        self.marked = self.checkpoint();
        self.retained = self.xorbs.items.len;
        self.carries_committed = false;
    }

    /// Drops the abandoned file's chunks; fails while a file owns the Xorb
    pub fn rollback(self: *XorbWriter) !void {
        try self.requireIdle();
        self.rollbackWith(false);
    }

    /// Keeps stored Xorbs reusable; fails while a file owns the Xorb
    pub fn discardBuffered(self: *XorbWriter) !void {
        try self.requireIdle();
        self.rollbackWith(true);
    }

    /// Owner cleanup for the claiming file, so it also spends that claim
    fn rollbackOwned(self: *XorbWriter, gen: u64, keep_stored: bool) void {
        if (self.active_publisher) |active| {
            if (active != gen) return;
            self.active_publisher = null;
        } else if (self.publisher_gen != gen) return;
        self.rollbackWith(keep_stored);
    }

    fn rollbackWith(self: *XorbWriter, keep_stored: bool) void {
        self.discarding = false;
        const point = self.marked;
        self.serializer.output.shrinkRetainingCapacity(point.output);
        self.serializer.chunks.shrinkRetainingCapacity(point.chunks);
        self.serializer.nodes.shrinkRetainingCapacity(point.nodes);
        self.serializer.packed_boundaries.shrinkRetainingCapacity(point.boundaries);
        self.serializer.raw_size = point.raw_size;
        if (!keep_stored) {
            for (self.xorbs.items[self.retained..]) |object| {
                _ = self.stored.remove(object.hash);
                self.allocator.free(object.chunks);
            }
            self.xorbs.shrinkRetainingCapacity(self.retained);
        }
        self.open.clearRetainingCapacity();
        for (self.serializer.chunks.items, 0..) |chunk, index| {
            self.open.putAssumeCapacity(chunk.hash, @intCast(index));
        }
    }

    /// Rejects mutation while a file owns the open Xorb
    fn requireIdle(self: *const XorbWriter) !void {
        if (self.active_publisher != null) return error.ActivePublisher;
    }

    /// Adds a chunk only while no publisher owns the open Xorb
    pub fn add(self: *XorbWriter, chunk: chunker.Chunk) !void {
        try self.requireIdle();
        return self.addActive(chunk);
    }

    /// The claiming publisher adds chunks its own segment covers
    fn addActive(self: *XorbWriter, chunk: chunker.Chunk) !void {
        const index = self.count();
        const entry = try self.open.getOrPut(self.allocator, chunk.hash);
        errdefer if (!entry.found_existing) self.open.removeByPtr(entry.key_ptr);
        try self.serializer.add(self.allocator, chunk);
        entry.value_ptr.* = index;
    }

    /// Closes the open Xorb; fails while a publisher owns it
    pub fn flush(self: *XorbWriter) !hashing.Hash {
        try self.requireIdle();
        return self.flushActive();
    }

    /// The claiming publisher closes the Xorb it is filling
    fn flushActive(self: *XorbWriter) !hashing.Hash {
        // A flush carrying committed chunks can no longer be rolled back
        const carries = self.marked.chunks != 0;
        var object = try self.serializer.finish(self.allocator);
        defer object.deinit(self.allocator);
        self.open.clearRetainingCapacity();
        self.carries_committed = carries;
        // The flush emptied the buffers, so the floor moves to empty
        self.marked = self.checkpoint();
        return self.deliver(&object) catch |err| {
            // The chunks are gone, so no plan referencing them can be published
            if (carries) self.lost = true;
            return err;
        };
    }

    fn deliver(self: *XorbWriter, object: *xorb.Serialized) !hashing.Hash {
        // The hash was delivered to this writer's only store, so a repeat stores nothing
        if (self.stored.get(object.hash)) |index| {
            if (self.carries_committed) self.retained = self.xorbs.items.len;
            // A rolled-back index may have lost this Xorb, so announce it again
            if (!self.discarding) {
                if (self.new_xorb_listener) |listener| try listener.callback(
                    listener.context,
                    self.xorbs.items[index],
                );
            }
            if (self.op_listener) |listener| _ = try listener.callback(listener.context, .{
                .reference = .{
                    .xorb_hash = object.hash,
                    .chunk_index_start = 0,
                    .nodes = object.nodes,
                },
            });
            if (self.flush_listener) |listener| try listener.callback(
                listener.context,
                object.hash,
            );
            return object.hash;
        }
        try self.stored.ensureUnusedCapacity(self.allocator, 1);
        // Reserve the hash index before giving the object to its destination.
        const item: Object = .{
            .kind = .xorb,
            .hash = object.hash,
            .data = object.bytes,
            .raw_size = object.raw_size,
        };
        try self.destination.put(item);
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
        if (self.carries_committed) self.retained = self.xorbs.items.len;
        // An aborting listener drops the Xorb it just saw, so never announce that
        const index = self.xorbs.items.len - 1;
        self.stored.putAssumeCapacity(object.hash, index);
        if (self.op_listener) |listener| {
            const disposition = try listener.callback(listener.context, .{ .store = .{
                .item = item,
                .allocator = self.allocator,
            } });
            if (disposition == .retain) object.bytes = &.{};
        }
        // A rollback only truncates the tail, so a survivor at `index` is this Xorb
        if (!self.discarding and index < self.xorbs.items.len) {
            if (self.new_xorb_listener) |listener|
                try listener.callback(listener.context, self.xorbs.items[index]);
        }
        if (self.flush_listener) |listener| try listener.callback(listener.context, object.hash);
        return object.hash;
    }

    /// Returns the token that releaseOperationListener needs to clear this install
    pub fn installOperationListener(self: *XorbWriter, listener: ?OperationListener) u64 {
        self.op_listener_gen +%= 1;
        self.op_listener = listener;
        return self.op_listener_gen;
    }

    /// A stale file must not disconnect the listener the next file installed
    pub fn releaseOperationListener(self: *XorbWriter, gen: u64) void {
        if (self.op_listener_gen != gen) return;
        self.op_listener = null;
    }

    /// Interleaved publishers would describe overlapping ranges of one Xorb
    /// Claiming checkpoints the buffers, so an abandoned file cannot reach past its start
    fn claimPublisher(self: *XorbWriter) !u64 {
        if (self.active_publisher != null) return error.ActivePublisher;
        self.publisher_gen +%= 1;
        self.active_publisher = self.publisher_gen;
        // The floor is this file's start, so its own chunks stay droppable
        self.advanceFloor();
        return self.publisher_gen;
    }

    /// A spent token cannot release the claim a later publisher owns
    fn releasePublisher(self: *XorbWriter, gen: u64) void {
        if (self.active_publisher != gen) return;
        self.active_publisher = null;
    }

    /// Hands over Xorb metadata; fails while a publisher owns the open Xorb
    pub fn takeXorbs(self: *XorbWriter) ![]shard.Xorb {
        try self.requireIdle();
        const owned = try self.xorbs.toOwnedSlice(self.allocator);
        // The metadata left this writer, so a rollback must not free it again
        self.retained = 0;
        self.stored.clearRetainingCapacity();
        return owned;
    }
};

pub const PublisherOptions = struct {
    /// Enables bounded parallel hashing for large contiguous writes.
    io: ?std.Io = null,
    compression: xorb.Compression = .lz4,
    max_xorb_size: u64 = constants.target_xorb_size,
    max_xorb_chunks: u32 = constants.max_xorb_chunks,
    strategy: ?chunker.Strategy = null,
    dedup_source: ?DedupSource = null,
    new_xorb_listener: ?NewXorbListener = null,
    operation_listener: ?OperationListener = null,
    /// Share one open Xorb across publishers instead of flushing per file
    /// `init` returns `ActivePublisher` while another publisher still claims it
    xorb_writer: ?*XorbWriter = null,

    pub fn fromPack(opts: PackOptions) PublisherOptions {
        return .{
            .compression = opts.compression,
            .max_xorb_size = opts.max_xorb_size,
            .max_xorb_chunks = opts.max_xorb_chunks,
            .strategy = opts.strategy,
        };
    }

    fn validate(self: PublisherOptions) !void {
        return PackOptions.validate(.{
            .compression = self.compression,
            .max_xorb_size = self.max_xorb_size,
            .max_xorb_chunks = self.max_xorb_chunks,
            .strategy = self.strategy,
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
    opts: PackOptions,
) !Package {
    try opts.validate();
    const chunks = try chunker.chunkWith(allocator, input, opts.strategy);
    defer allocator.free(chunks);
    var file_nodes: hashing.Aggregator = .{};
    for (chunks) |chunk| {
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
    while (first < chunks.len) {
        var end = first;
        var bytes: u64 = 0;
        while (end < chunks.len and end - first < opts.max_xorb_chunks) {
            const next_size = bytes + chunks[end].data.len;
            if (end != first and next_size > opts.max_xorb_size) break;
            bytes = next_size;
            end += 1;
        }
        const object = try xorb.serialize(allocator, chunks[first..end], opts.compression);
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
        if (hasHash(package.objects[0..index], object.hash)) continue;
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

pub fn publishShard(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    raw_size: u64,
    destination: Store,
) !void {
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
    if (bytes.len <= limit) return putShard(destination, bytes, raw_size);

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
        if (addition > limit - size) {
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
        if (addition > limit - size) {
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

fn putShard(destination: Store, bytes: []const u8, raw_size: u64) !void {
    return destination.put(.{
        .kind = .shard,
        .hash = hashing.data(bytes),
        .data = bytes,
        .raw_size = raw_size,
    });
}

fn flushXorbs(
    allocator: std.mem.Allocator,
    xorbs: *std.ArrayList(shard.Xorb),
    destination: Store,
) !void {
    if (xorbs.items.len == 0) return;
    const bytes = try shard.serialize(allocator, &.{}, xorbs.items);
    defer allocator.free(bytes);
    if (try wireShardSize(bytes) > max_shard_size) return error.ShardTooLarge;
    try putShard(destination, bytes, 0);
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
    try putShard(destination, bytes, raw_size);
    for (files.items) |file| freeDecodedFile(allocator, file);
    files.clearRetainingCapacity();
}

fn freeDecodedFile(allocator: std.mem.Allocator, file: shard.File) void {
    allocator.free(file.segments);
    allocator.free(file.verification);
}

fn hasHash(objects: anytype, hash: hashing.Hash) bool {
    for (objects) |object| if (hashing.eql(object.hash, hash)) return true;
    return false;
}

pub const PublishResult = struct {
    file_hash: hashing.Hash,
    size: u64,
    xorb_count: u64,
};

/// Owned recon metadata for custom upload pipelines
pub const Plan = struct {
    origin: ?*const XorbWriter = null,
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
    /// Terms awaiting the open Xorb, borrowed from plan-owned slices that never move
    waiting: std.ArrayList(*shard.Segment) = .empty,
    waiting_writer: ?*const XorbWriter = null,
    finished: bool = false,

    pub fn init(allocator: std.mem.Allocator, destination: Store) BatchPublisher {
        return .{ .allocator = allocator, .destination = destination };
    }

    pub fn deinit(self: *BatchPublisher) void {
        for (self.plans.items) |*plan| plan.deinit(self.allocator);
        self.plans.deinit(self.allocator);
        self.waiting.deinit(self.allocator);
        self.* = undefined;
    }

    /// Success empties `plan`, while failure leaves it owned by the caller
    /// `plan`'s allocations must come from the allocator passed to `init`
    pub fn append(self: *BatchPublisher, plan: *Plan) !void {
        if (self.finished) return error.AlreadyFinished;
        var count: usize = 0;
        for (plan.file.segments) |segment| {
            if (hashing.eql(segment.xorb_hash, hashing.zero)) count += 1;
        }
        if (count != 0 and self.waiting.items.len != 0 and self.waiting_writer != plan.origin)
            return error.WrongWriter;
        // Both reservations precede any move, so failure leaves `plan` with the caller
        try self.plans.ensureUnusedCapacity(self.allocator, 1);
        try self.waiting.ensureUnusedCapacity(self.allocator, count);
        if (count != 0) self.waiting_writer = plan.origin;
        for (@constCast(plan.file.segments)) |*segment| {
            if (hashing.eql(segment.xorb_hash, hashing.zero))
                self.waiting.appendAssumeCapacity(segment);
        }
        self.plans.appendAssumeCapacity(plan.*);
        plan.* = .{};
    }

    /// Replaces the placeholder hash of segments still awaiting their open Xorb
    pub fn resolveOpenXorb(
        self: *BatchPublisher,
        origin: ?*const XorbWriter,
        hash: hashing.Hash,
    ) void {
        if (origin != self.waiting_writer) return;
        for (self.waiting.items) |segment| segment.xorb_hash = hash;
        self.waiting.clearRetainingCapacity();
        self.waiting_writer = null;
    }

    /// Publishes all appended metadata, using the standard shard size limit
    pub fn finish(self: *BatchPublisher) !void {
        return self.finishWith(&.{});
    }

    /// Session-owned Xorb metadata joins the shard; the caller keeps ownership
    /// Fails with `XorbLeftOpen` while any segment still awaits its open Xorb
    pub fn finishWith(self: *BatchPublisher, extra_xorbs: []const shard.Xorb) !void {
        if (self.finished) return error.AlreadyFinished;
        if (self.waiting.items.len != 0) return error.XorbLeftOpen;
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
        try new_xorbs.appendSlice(self.allocator, extra_xorbs);
        if (files.items.len == 0) return;
        const bytes = try shard.serialize(self.allocator, files.items, new_xorbs.items);
        defer self.allocator.free(bytes);
        try publishShard(self.allocator, bytes, raw_size, self.destination);
    }
};

/// Both transport adapters bind file plans and their one open Xorb here.
/// The address must stay stable after begin until all file handles are released.
pub const Packing = struct {
    writer: XorbWriter,
    batch: BatchPublisher,
    files_in_tail: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        data: Store,
        metadata: Store,
        compression: xorb.Compression,
    ) Packing {
        return .{ .writer = .init(
            allocator,
            data,
            compression,
        ), .batch = .init(allocator, metadata) };
    }

    pub fn deinit(self: *Packing) void {
        self.batch.deinit();
        self.writer.deinit();
    }

    pub fn begin(self: *Packing, options: PublisherOptions, sealed: ?OperationListener) !Publisher {
        if (self.writer.active_publisher != null) return error.ActivePublisher;
        // Bound random-read amplification when many independent files share an object.
        if (self.files_in_tail >= 64 and self.writer.rawSize() >= 64 * 1024) {
            _ = self.writer.installOperationListener(sealed);
            try self.seal();
        }
        var opts = options;
        opts.xorb_writer = &self.writer;
        self.writer.flush_listener = .{ .context = self, .callback = resolve };
        return Publisher.init(self.batch.allocator, self.writer.destination, opts);
    }

    pub fn endFile(self: *Packing, file: *Publisher) !PublishResult {
        if (file.shared_writer != &self.writer) return error.WrongWriter;
        var plan = try file.finishPlan();
        errdefer plan.deinit(self.batch.allocator);
        const result = PublishResult{
            .file_hash = plan.file.hash,
            .size = plan.size,
            .xorb_count = plan.xorb_count,
        };
        try self.batch.append(&plan);
        try file.acceptPlan();
        if (file.awaiting.items.len != 0) self.files_in_tail += 1;
        return result;
    }

    pub fn seal(self: *Packing) !void {
        if (self.writer.count() != 0) _ = try self.writer.flush();
    }

    pub fn publish(self: *Packing) !void {
        if (self.writer.lost) return error.OperationFailed;
        return self.batch.finishWith(self.writer.xorbs.items);
    }

    fn resolve(raw: *anyopaque, hash: hashing.Hash) !void {
        const self: *Packing = @ptrCast(@alignCast(raw));
        self.batch.resolveOpenXorb(&self.writer, hash);
        self.files_in_tail = 0;
    }
};

pub const dedup_window = 64;

/// Buffers one file's metadata, its chunker, and up to 64 dedup chunks
pub const Publisher = struct {
    allocator: std.mem.Allocator,
    destination: Store,
    opts: PublisherOptions,
    chunker: chunker.Chunker,
    /// An owned open Xorb, flushed when this file completes
    writer: XorbWriter = undefined,
    /// A session-owned writer that outlives this file
    shared_writer: ?*XorbWriter = null,
    /// Identifies this file's install on a shared writer
    op_listener_gen: u64 = 0,
    /// Identifies this file's claim on a shared writer
    publisher_gen: u64 = 0,
    /// Whether this file still holds the shared writer's claim
    claimed: bool = false,
    /// Whether a plan exists for the claim to hand over
    plan_ready: bool = false,
    /// Abort cleanup runs once, even if several failure paths reach it
    dropped: bool = false,
    depth: u32 = 0,
    pending_drop: bool = false,
    keep_stored: bool = false,
    /// Index of the awaiting segment that newly added chunks still extend
    open_index: ?usize = null,
    /// Index of the awaiting segment that repeated chunks still extend
    held_index: ?usize = null,
    /// Segments whose Xorb hash stays unknown until the open Xorb closes
    awaiting: std.ArrayList(usize) = .empty,
    held_verification: std.crypto.hash.Blake3 = .init(.{ .key = constants.verification_key }),
    /// Segments inspected while closing an Xorb, so tests can assert constant time
    resolve_visits: usize = 0,
    open_verification: std.crypto.hash.Blake3 = .init(.{ .key = constants.verification_key }),
    file_nodes: hashing.Aggregator = .{},
    file_sha256: std.crypto.hash.sha2.Sha256 = .init(.{}),
    segments: std.ArrayList(shard.Segment) = .empty,
    checks: std.ArrayList(hashing.Hash) = .empty,
    size: u64 = 0,
    xorb_count: u64 = 0,
    finished: bool = false,
    failed: bool = false,
    has_complete_sha256: bool = true,
    reused_xorb: ?hashing.Hash = null,
    /// Segment that names a previously stored Xorb and can still be extended
    reuse_index: ?usize = null,
    reused_verification: std.crypto.hash.Blake3 = .init(.{ .key = constants.verification_key }),
    pending_chunks: [dedup_window]chunker.Chunk = undefined,
    pending_borrowed: [dedup_window]bool = @splat(false),
    pending_head: usize = 0,
    pending_len: usize = 0,

    /// Borrows the dedup source, listeners, shared writer, and callback metadata
    pub fn init(
        allocator: std.mem.Allocator,
        destination: Store,
        opts: PublisherOptions,
    ) !Publisher {
        try opts.validate();
        var publisher: Publisher = .{
            .allocator = allocator,
            .destination = destination,
            .opts = opts,
            .chunker = chunker.Chunker.init(),
        };
        if (opts.xorb_writer) |writer| {
            // Claiming precedes the listener install so a rejected publisher changes nothing
            publisher.publisher_gen = try writer.claimPublisher();
            publisher.claimed = true;
            // The active file owns the operation context until it is finalized
            publisher.op_listener_gen = writer.installOperationListener(opts.operation_listener);
            writer.serializer.compression = opts.compression;
            publisher.shared_writer = writer;
        } else {
            publisher.writer = .init(allocator, destination, opts.compression);
            publisher.writer.op_listener = opts.operation_listener;
            publisher.writer.new_xorb_listener = opts.new_xorb_listener;
        }
        // The strategy resets only after the claim, since it may belong to a live file
        if (opts.strategy) |strategy| publisher.chunker = chunker.Chunker.initWith(strategy);
        return publisher;
    }

    fn xorbWriter(self: *Publisher) *XorbWriter {
        return self.shared_writer orelse &self.writer;
    }

    pub fn deinit(self: *Publisher) void {
        self.chunker.deinit(self.allocator);
        if (self.shared_writer) |writer| {
            // A failed finish still owns its chunks, while an accepted plan owns none
            if (!self.dropped) self.abort();
            writer.releaseOperationListener(self.op_listener_gen);
            writer.releasePublisher(self.publisher_gen);
        } else {
            self.writer.deinit();
        }
        self.segments.deinit(self.allocator);
        self.checks.deinit(self.allocator);
        self.awaiting.deinit(self.allocator);
        self.dropPending(self.pending_len);
    }

    /// An operational failure consumes an unspecified input prefix and makes the publisher terminal
    pub fn write(self: *Publisher, input: []const u8) !void {
        if (self.failed) return error.WriteFailed;
        if (self.finished) return error.AlreadyFinished;
        self.enter();
        defer self.leave();
        self.writeFallible(input) catch |err| {
            self.abort();
            return err;
        };
    }

    /// Owner-only abort; a newer file's claim makes this a no-op
    pub fn abort(self: *Publisher) void {
        self.drop(false);
    }

    /// Owner-only abort that keeps stored Xorbs reusable for a later file
    pub fn discardBuffered(self: *Publisher) void {
        self.drop(true);
    }

    /// Callbacks run while this file still owns the writer, so they may cancel it
    fn enter(self: *Publisher) void {
        self.depth += 1;
    }

    /// Performs the rollback a cancelled call deferred until it stopped reading
    fn leave(self: *Publisher) void {
        self.depth -= 1;
        if (self.depth != 0 or !self.pending_drop) return;
        self.pending_drop = false;
        self.rollback(self.keep_stored);
    }

    /// Drops this file's buffered chunks and retires its claim
    fn drop(self: *Publisher, keep_stored: bool) void {
        if (self.dropped) return;
        self.dropped = true;
        // An accepted plan leaves this file owning no buffered chunk
        if (self.shared_writer != null and self.finished and !self.claimed) return;
        // The failed file is terminal from here, even before its chunks are gone
        self.failed = true;
        if (self.depth != 0) {
            self.pending_drop = true;
            self.keep_stored = keep_stored;
            // Only a discard frees the metadata a running flush may still read
            if (!keep_stored) self.xorbWriter().discarding = true;
            return;
        }
        self.rollback(keep_stored);
    }

    fn rollback(self: *Publisher, keep_stored: bool) void {
        if (self.shared_writer) |writer| {
            writer.rollbackOwned(self.publisher_gen, keep_stored);
        } else {
            self.writer.rollbackWith(keep_stored);
        }
    }

    /// A callback may abort this file, which must end the calling operation
    fn requireLive(self: *const Publisher) !void {
        if (self.failed) return error.WriteFailed;
    }

    /// Accepts this file's finished plan, which is the point its chunks become committed
    pub fn acceptPlan(self: *Publisher) !void {
        if (self.failed) return error.WriteFailed;
        // Finalization may still write, so the claim survives until the plan exists
        if (!self.plan_ready) return error.PlanNotFinished;
        self.claimed = false;
        if (self.shared_writer) |writer| writer.acceptPlan(self.publisher_gen);
    }

    fn writeFallible(self: *Publisher, input: []const u8) !void {
        if (self.opts.io) |io| {
            if (self.opts.strategy == null and batch_hash.canBatch(input.len)) {
                var next_sha = self.file_sha256;
                var sha = io.async(std.crypto.hash.sha2.Sha256.update, .{ &next_sha, input });
                defer {
                    sha.await(io);
                    self.file_sha256 = next_sha;
                }
                return self.writeChunks(input, io);
            }
        }
        self.file_sha256.update(input);
        return self.writeChunks(input, null);
    }

    fn writeChunks(self: *Publisher, input: []const u8, io: ?std.Io) !void {
        var it = batch_hash.Iterator{ .io = io, .input = input };
        while (try it.next(&self.chunker, self.allocator)) |chunk| {
            try self.requireLive();
            try self.queueChunk(chunk, io != null and it.from_input);
            try self.requireLive();
        }
        if (io != null) {
            // Only the tail still awaiting a dedup match outlives the caller's buffer.
            for (0..self.pending_len) |i| {
                const slot = (self.pending_head + i) % dedup_window;
                if (!self.pending_borrowed[slot]) continue;
                const chunk = &self.pending_chunks[slot];
                chunk.data = try self.allocator.dupe(u8, chunk.data);
                self.pending_borrowed[slot] = false;
            }
        }
        try self.requireLive();
    }

    /// A shared writer must be completed by its session, because this file's Xorb stays open
    pub fn finish(self: *Publisher) !PublishResult {
        if (self.shared_writer != null) return error.XorbLeftOpen;
        var plan = try self.finishPlan();
        return plan.publish(self.allocator, self.destination);
    }

    pub fn finishPlan(self: *Publisher) !Plan {
        if (self.failed) return error.WriteFailed;
        if (self.finished) return error.AlreadyFinished;
        self.finished = true;
        self.enter();
        defer self.leave();
        return self.finishOwned() catch |err| {
            // The owner still holds the claim so its abort can drop its chunks
            self.failed = true;
            return err;
        };
    }

    fn finishOwned(self: *Publisher) !Plan {
        const final = try self.chunker.finish(self.allocator);
        // The final boundary runs a callback, which may abort this file
        try self.requireLive();
        if (final.chunk) |chunk| try self.addChunk(chunk);
        try self.requireLive();
        try self.processPending();
        try self.requireLive();
        // A shared writer keeps its Xorb open until the session completes it
        if (self.shared_writer == null) {
            try self.flushXorb();
            // The flush listeners run callbacks, which may abort this file
            try self.requireLive();
        } else {
            self.open_index = null;
            self.held_index = null;
        }
        const file_hash = try self.file_nodes.fileHash();
        const sha256 = if (self.has_complete_sha256)
            hashing.fromStandard(self.file_sha256.finalResult())
        else
            null;
        const segments = try self.segments.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(segments);
        const checks = try self.checks.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(checks);
        const xorbs: []shard.Xorb = if (self.shared_writer == null) try self.writer.takeXorbs() else &.{};
        // A shared writer keeps the claim, so only an accepted plan commits these chunks
        const plan: Plan = .{
            .origin = self.shared_writer,
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
        self.plan_ready = true;
        return plan;
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
        const buffered_new = self.open_index != null or self.chunker.pending.items.len != 0;
        if (self.pending_len == 0) {
            if (continues and !buffered_new) {
                const last = self.segments.items[self.segments.items.len - 1];
                if (last.unpacked_segment_bytes > std.math.maxInt(u32) - byte_total) {
                    return error.InvalidDedupMatch;
                }
            } else {
                try self.reserveReuseSegments(1 + @as(usize, @intFromBool(buffered_new)));
            }
        }
        self.enter();
        defer self.leave();
        self.reuseFallible(object_hash, chunk_index_start, nodes) catch |err| {
            self.abort();
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
        try self.requireLive();
        if (final.chunk) |chunk| try self.addChunk(chunk);
        try self.requireLive();
        try self.processPending();
        try self.requireLive();
        self.has_complete_sha256 = false;
        try self.appendReuse(object_hash, chunk_index_start, nodes);
    }

    fn reuseContinues(
        self: *const Publisher,
        object_hash: hashing.Hash,
        chunk_index_start: u32,
    ) bool {
        const hash = self.reused_xorb orelse return false;
        if (!hashing.eql(hash, object_hash)) return false;
        const index = self.reuse_index orelse return false;
        return self.segments.items[index].chunk_index_end == chunk_index_start;
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
            // Only this file's pending chunks justify closing the shared Xorb
            if (self.open_index != null) try self.flushXorb();
            try self.reserveReuseSegments(1);
            self.resetReuse();
            self.held_index = null;
            self.reused_xorb = object_hash;
            self.segments.appendAssumeCapacity(.{
                .xorb_hash = object_hash,
                .unpacked_segment_bytes = 0,
                .chunk_index_start = chunk_index_start,
                .chunk_index_end = chunk_index_start,
            });
            self.checks.appendAssumeCapacity(hashing.zero);
            self.reuse_index = self.segments.items.len - 1;
            self.xorb_count += 1;
        }
        const last = self.reuse_index.?;
        self.size += byte_total;
        // Segments stay in file order, so this term ends any awaiting run
        self.held_index = null;
        self.open_index = null;
        for (nodes) |node| {
            self.reused_verification.update(&node.hash);
            self.segments.items[last].unpacked_segment_bytes += @intCast(node.size);
            self.segments.items[last].chunk_index_end += 1;
            try self.file_nodes.add(node);
        }
        self.checks.items[last] = self.reuseVerification();
        if (self.opts.operation_listener) |listener| {
            _ = try listener.callback(listener.context, .{ .reference = .{
                .xorb_hash = object_hash,
                .chunk_index_start = chunk_index_start,
                .nodes = nodes,
            } });
            // The queued reference belongs to an aborted file, which must not extend it
            try self.requireLive();
        }
    }

    fn reserveReuseSegments(self: *Publisher, count: usize) !void {
        try self.segments.ensureUnusedCapacity(self.allocator, count);
        try self.checks.ensureUnusedCapacity(self.allocator, count);
    }

    fn reuseVerification(self: *const Publisher) hashing.Hash {
        var result: hashing.Hash = undefined;
        self.reused_verification.final(&result);
        return result;
    }

    fn resetReuse(self: *Publisher) void {
        self.reused_xorb = null;
        self.reuse_index = null;
        self.reused_verification = .init(.{ .key = constants.verification_key });
    }

    fn addChunk(self: *Publisher, chunk: chunker.Chunk) !void {
        return self.queueChunk(chunk, false);
    }

    fn queueChunk(self: *Publisher, chunk: chunker.Chunk, borrow: bool) !void {
        const source = self.opts.dedup_source orelse return self.addNew(chunk);
        if (self.pending_len == dedup_window) try self.processOne(source);
        const index = (self.pending_head + self.pending_len) % dedup_window;
        self.pending_chunks[index] = .{
            .data = if (borrow) chunk.data else try self.allocator.dupe(u8, chunk.data),
            .hash = chunk.hash,
        };
        self.pending_borrowed[index] = borrow;
        self.pending_len += 1;
    }

    fn dropPending(self: *Publisher, count: usize) void {
        for (0..count) |index| {
            const slot = (self.pending_head + index) % dedup_window;
            if (!self.pending_borrowed[slot]) self.allocator.free(self.pending_chunks[slot].data);
        }
        self.pending_head = (self.pending_head + count) % dedup_window;
        self.pending_len -= count;
    }

    fn processPending(self: *Publisher) !void {
        const source = self.opts.dedup_source orelse return;
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
            // The query callback may have aborted this file
            try self.requireLive();
            try self.validatePendingSizes(match.nodes);
            try self.appendReuse(match.xorb_hash, match.chunk_index_start, match.nodes);
            self.dropPending(match.nodes.len);
            return;
        }
        try self.requireLive();
        const first = self.pending_chunks[self.pending_head];
        try self.addNew(first);
        self.dropPending(1);
    }

    /// Returned sizes must describe the buffered bytes they replace
    fn validatePendingSizes(self: *const Publisher, nodes: []const hashing.Node) !void {
        for (nodes, 0..) |node, index| {
            const chunk = self.pending_chunks[(self.pending_head + index) % dedup_window];
            if (node.size != chunk.data.len) return error.InvalidDedupMatch;
        }
    }

    fn addNew(self: *Publisher, chunk: chunker.Chunk) !void {
        const writer = self.xorbWriter();
        // A repeat of a chunk the open Xorb holds waits for that Xorb's hash
        if (self.opts.dedup_source != null) {
            if (writer.find(chunk.hash)) |position| return self.referenceOpen(chunk, position);
        }
        self.resetReuse();
        // A shared Xorb may already exceed this file's limit, so compare inclusively
        const flush = writer.count() >= self.opts.max_xorb_chunks or
            (writer.rawSize() != 0 and writer.rawSize() + chunk.data.len > self.opts.max_xorb_size);
        if (flush) {
            try self.flushXorb();
            // A flush listener or dedup query may abort this file
            try self.requireLive();
        }
        // A segment this file owns is separate from one that only names open chunks
        self.held_index = null;
        self.size = std.math.add(u64, self.size, chunk.data.len) catch return error.FileTooLarge;
        const start = writer.count();
        try writer.addActive(chunk);
        if (self.open_index) |index| {
            self.segments.items[index].unpacked_segment_bytes += @intCast(chunk.data.len);
            self.segments.items[index].chunk_index_end += 1;
            self.open_verification.update(&chunk.hash);
            self.checks.items[index] = self.openVerification();
        } else {
            // Reservations precede any move, so failure leaves the segment list intact
            try self.reserveReuseSegments(1);
            try self.awaiting.ensureUnusedCapacity(self.allocator, 1);
            self.open_verification = .init(.{ .key = constants.verification_key });
            self.open_verification.update(&chunk.hash);
            const index = self.segments.items.len;
            self.segments.appendAssumeCapacity(.{
                .xorb_hash = hashing.zero,
                .unpacked_segment_bytes = @intCast(chunk.data.len),
                .chunk_index_start = start,
                .chunk_index_end = start + 1,
            });
            self.checks.appendAssumeCapacity(self.openVerification());
            self.awaiting.appendAssumeCapacity(index);
            self.open_index = index;
            self.xorb_count += 1;
        }
        try self.file_nodes.add(.{ .hash = chunk.hash, .size = chunk.data.len });
        // A full Xorb cannot accept another chunk, so it closes right away
        if (writer.count() >= self.opts.max_xorb_chunks or
            writer.rawSize() >= self.opts.max_xorb_size)
        {
            try self.flushXorb();
            try self.requireLive();
        }
    }

    /// A segment naming chunks the open Xorb holds resolves when that Xorb closes
    fn referenceOpen(self: *Publisher, chunk: chunker.Chunk, position: u32) !void {
        if (self.held_index) |index| {
            if (self.segments.items[index].chunk_index_end == position)
                return self.referenceHold(index, chunk, position);
        }
        // Reservations precede any move, so failure leaves the segment list intact
        try self.reserveReuseSegments(1);
        try self.awaiting.ensureUnusedCapacity(self.allocator, 1);
        self.resetReuse();
        self.held_verification = .init(.{ .key = constants.verification_key });
        try self.referenceHold(self.segments.items.len, chunk, position);
        self.xorb_count += 1;
    }

    /// `index` is either the open segment or a segment about to be appended
    fn referenceHold(self: *Publisher, index: usize, chunk: chunker.Chunk, position: u32) !void {
        const node = hashing.Node{ .hash = chunk.hash, .size = chunk.data.len };
        const size = std.math.add(u64, self.size, chunk.data.len) catch return error.FileTooLarge;
        const bytes = if (index < self.segments.items.len)
            std.math.add(
                u64,
                self.segments.items[index].unpacked_segment_bytes,
                chunk.data.len,
            ) catch
                return error.FileTooLarge
        else
            chunk.data.len;
        if (bytes > std.math.maxInt(u32)) return error.FileTooLarge;
        if (index == self.segments.items.len) {
            self.segments.appendAssumeCapacity(.{
                .xorb_hash = hashing.zero,
                .unpacked_segment_bytes = 0,
                .chunk_index_start = position,
                .chunk_index_end = position,
            });
            self.checks.appendAssumeCapacity(hashing.zero);
            self.awaiting.appendAssumeCapacity(index);
            // Segments stay in file order, so a later new chunk opens its own term
            self.open_index = null;
        }
        self.size = size;
        self.held_verification.update(&node.hash);
        self.segments.items[index].unpacked_segment_bytes = @intCast(bytes);
        self.segments.items[index].chunk_index_end = position + 1;
        try self.file_nodes.add(node);
        self.checks.items[index] = self.heldVerification();
        self.held_index = index;
    }

    fn heldVerification(self: *const Publisher) hashing.Hash {
        var result: hashing.Hash = undefined;
        self.held_verification.final(&result);
        return result;
    }

    /// Closes the open Xorb and resolves every segment awaiting its hash
    fn flushXorb(self: *Publisher) !void {
        self.open_index = null;
        self.held_index = null;
        const writer = self.xorbWriter();
        if (writer.count() == 0) return;
        // This file owns the claim, so the public guard would reject the close
        const hash = try writer.flushActive();
        try self.requireLive();
        for (self.awaiting.items) |index| {
            self.resolve_visits += 1;
            self.segments.items[index].xorb_hash = hash;
        }
        self.awaiting.clearRetainingCapacity();
    }

    fn openVerification(self: *const Publisher) hashing.Hash {
        var result: hashing.Hash = undefined;
        self.open_verification.final(&result);
        return result;
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
    var publisher = try Publisher.init(
        tracker.allocator(),
        destination.store(),
        .{ .compression = .none },
    );
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
        try std.testing.expectEqual(@as(u32, 1), publisher.xorbWriter().count());
    }
    if (stage == .store) {
        try std.testing.expectEqual(@as(usize, 1), destination.puts);
        try std.testing.expectEqual(ObjectKind.xorb, destination.last_attempted_kind.?);
        try std.testing.expectEqual(@as(u32, 0), publisher.xorbWriter().count());
    }
    publisher.deinit();
    if (stage != .store)
        try std.testing.expectEqual(
            fail_at != null and fail_at.? == tracker.allocation_count,
            failed,
        );
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
            var publisher = Publisher.init(
                allocator,
                destination.store(),
                .{ .compression = .none },
            ) catch |err| {
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

test "XorbWriter rollback after a mid-file flush keeps committed chunks" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const first = chunker.Chunk{ .data = "shared", .hash = hashing.data("shared") };
    try writer.add(first);
    // Committing the first file leaves its chunk buffered in the open Xorb
    try writer.mark();
    // Reaching for that chunk flushes, so committed data is already on its way
    _ = try writer.flush();
    try std.testing.expect(writer.carries_committed);
    const second = chunker.Chunk{ .data = "later", .hash = hashing.data("later") };
    try writer.add(second);
    try std.testing.expectEqual(@as(u32, 1), writer.count());

    try writer.rollback();
    try std.testing.expectEqual(@as(u32, 0), writer.count());
    try std.testing.expectEqual(@as(u64, 0), writer.rawSize());
    try std.testing.expectEqual(@as(usize, 1), writer.xorbs.items.len);
    try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
}

test "XorbWriter discardBuffered keeps stored Xorbs for reuse" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    try writer.mark();
    try writer.add(.{ .data = "abandoned", .hash = hashing.data("abandoned") });
    _ = try writer.flush();
    try writer.add(.{ .data = "later", .hash = hashing.data("later") });

    try writer.discardBuffered();
    try std.testing.expectEqual(@as(u32, 0), writer.count());
    try std.testing.expectEqual(@as(u64, 0), writer.rawSize());
    // The stored Xorb stays available for the shard that committed files need
    try std.testing.expectEqual(@as(usize, 1), writer.xorbs.items.len);
    try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
}

test "Publisher flushes a shared Xorb that already exceeds its chunk limit" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    // Earlier files already buffered ten chunks in the shared Xorb
    for (0..10) |index| {
        const data = try std.fmt.allocPrint(allocator, "chunk {d}", .{index});
        defer allocator.free(data);
        try writer.add(.{ .data = data, .hash = hashing.data(data) });
    }
    var publisher = try Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .max_xorb_chunks = 4,
        .xorb_writer = &writer,
    });
    defer publisher.deinit();
    try publisher.write("overflow");
    // Short input stays buffered until the chunker is finished
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    // The limit applies to the whole Xorb, so ten buffered chunks force a close
    try std.testing.expectEqual(@as(u32, 1), writer.count());
    try std.testing.expectEqual(@as(usize, 1), writer.xorbs.items.len);
    try std.testing.expectEqual(@as(usize, 10), writer.xorbs.items[0].chunks.len);
}

test "Publisher refuses to publish a shared Xorb on its own" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var publisher = try Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .xorb_writer = &writer,
    });
    defer publisher.deinit();
    try publisher.write("payload");
    try std.testing.expectError(error.XorbLeftOpen, publisher.finish());
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
        for (
            plan.file.segments[0..segment_count],
            plan.file.verification[0..segment_count],
        ) |segment, check| {
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
        try std.testing.expectEqual(
            hashing.verificationNodes(b_nodes[1..]),
            plan.file.verification[segment_count],
        );
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
    try std.testing.expectEqual(
        node_count * chunk_size,
        plan.file.segments[0].unpacked_segment_bytes,
    );
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

fn checkReusePendingOverflow(
    publisher: *Publisher,
    destination: *const @import("test_support").MemoryStore,
) !void {
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
    try std.testing.expectEqualSlices(
        u8,
        &block,
        publisher.pending_chunks[publisher.pending_head].data,
    );
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
        try std.testing.expectError(error.WriteFailed, publisher.reuse(
            hashing.data("existing"),
            0,
            &.{node},
        ));
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
        .{
            .hash = support.syntheticHash(2, 0),
            .chunks = &.{chunk},
            .raw_size = 1,
            .serialized_size = 9,
        },
        .{
            .hash = support.syntheticHash(2, 1),
            .chunks = &.{chunk},
            .raw_size = 1,
            .serialized_size = 9,
        },
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

test "a batch cannot resolve two independent writers' outstanding file terms" {
    const gpa = std.testing.allocator;
    var left = Packing.init(gpa, noStore(), noStore(), .none);
    defer left.deinit();
    var right = Packing.init(gpa, noStore(), noStore(), .none);
    defer right.deinit();
    var a = try left.begin(.{}, null);
    defer a.deinit();
    var b = try right.begin(.{}, null);
    defer b.deinit();
    try a.write("alpha");
    try b.write("bravo");
    try std.testing.expectError(error.WrongWriter, left.endFile(&b));
    _ = try left.endFile(&a);
    var second = try b.finishPlan();
    defer second.deinit(gpa);
    try std.testing.expectError(error.WrongWriter, left.batch.append(&second));
    try right.batch.append(&second);
    try b.acceptPlan();
    try left.seal();
    try std.testing.expectEqual(
        hashing.zero,
        right.batch.plans.items[0].file.segments[0].xorb_hash,
    );
    try right.seal();
    try std.testing.expect(!hashing.eql(
        left.writer.xorbs.items[0].hash,
        right.writer.xorbs.items[0].hash,
    ));
    try std.testing.expectEqual(
        right.writer.xorbs.items[0].hash,
        right.batch.plans.items[0].file.segments[0].xorb_hash,
    );
}
