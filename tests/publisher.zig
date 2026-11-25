const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

test "streaming publisher matches contiguous hashes with tiny xorbs" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    var package = try xet.pack(allocator, data, .{ .max_xorb_size = 128 * 1024 });
    defer package.deinit(allocator);
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{
        .max_xorb_size = 128 * 1024,
    });
    defer publisher.deinit();
    for (data) |byte| try publisher.write(&.{byte});
    const result = try publisher.finish();
    try std.testing.expectEqual(package.file_hash, result.file_hash);
    try std.testing.expectEqual(package.objects.len, result.xorb_count);
    try std.testing.expectEqual(package.objects.len, destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    for (package.objects) |*object| {
        for (destination.objects.items) |uploaded| {
            if (uploaded.kind == .xorb and std.mem.eql(u8, uploaded.data, object.bytes)) break;
        } else return error.TestMissingCanonicalXorb;
    }
    for (destination.objects.items) |uploaded| {
        if (uploaded.kind == .shard)
            try std.testing.expectEqualSlices(u8, package.shard_bytes, uploaded.data);
    }
}

test "repeated xorbs upload once and retain every file segment" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 0);

    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{
        .max_xorb_size = 1024 * 1024,
    });
    defer publisher.deinit();
    try publisher.write(data);
    const result = try publisher.finish();
    try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    try std.testing.expectEqual(@as(u64, 4), result.xorb_count);

    const shard_bytes = for (destination.objects.items) |object| {
        if (object.kind == .shard) break object.data;
    } else return error.TestMissingPublishedShard;
    const reader = try xet.shard.Reader.init(shard_bytes);
    const info = (try reader.findFile(result.file_hash)).?;
    try std.testing.expectEqual(@as(u32, 4), info.count);
    try std.testing.expectEqual(@as(usize, 1), reader.footer.xorb_count);
    for (0..info.count) |index| {
        const segment = try info.segment(@intCast(index));
        try std.testing.expectEqual(@as(u32, 1024 * 1024), segment.unpacked_segment_bytes);
        try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
        try std.testing.expectEqual(@as(u32, 8), segment.chunk_index_end);
    }

    var package = try xet.pack(allocator, data, .{ .max_xorb_size = 1024 * 1024 });
    defer package.deinit(allocator);
    const packed_reader = try xet.shard.Reader.init(package.shard_bytes);
    try std.testing.expectEqual(@as(usize, 1), packed_reader.footer.xorb_count);
    try std.testing.expectEqual(result.file_hash, package.file_hash);
}

test "low-level reuse publishes an owned UploadPlan" {
    const allocator = std.testing.allocator;
    const nodes = [_]xet.Node{
        .{ .hash = xet.hash.data("AAA"), .size = 3 },
        .{ .hash = xet.hash.data("BBB"), .size = 3 },
    };
    const file_hash = try xet.hash.file(allocator, &nodes);
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    try publisher.reuse(xet.hash.data("existing xorb"), 4, &nodes);
    var plan = try publisher.finishPlan();
    try std.testing.expect(plan.file.sha256 == null);
    const result = try plan.publish(allocator, destination.store());
    try std.testing.expectEqual(file_hash, result.file_hash);
    try std.testing.expectEqual(@as(u64, 6), result.size);
    try std.testing.expectEqual(@as(usize, 0), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    const reader = try xet.shard.Reader.init(destination.objects.items[0].data);
    const file = (try reader.findFile(file_hash)).?;
    try std.testing.expect((try file.sha256()) == null);
    const segment = try file.segment(0);
    try std.testing.expectEqual(@as(u32, 4), segment.chunk_index_start);
    try std.testing.expectEqual(@as(u32, 6), segment.chunk_index_end);
    try std.testing.expectEqual(xet.hash.verification(&.{ nodes[0].hash, nodes[1].hash }), try file.verification(0));
    try std.testing.expectError(error.AlreadyFinished, publisher.reuse(nodes[0].hash, 0, nodes[0..1]));
}

test "BatchPublisher takes plans and publishes combined metadata through any Store" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = xet.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();

    const inputs = [_][]const u8{ "AAA", "BBB" };
    var hashes: [inputs.len]xet.Hash = undefined;
    for (inputs, &hashes, 0..) |input, *file_hash, index| {
        var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{ .compression = .none });
        defer publisher.deinit();
        try publisher.write(input);
        var plan = try publisher.finishPlan();
        defer plan.deinit(allocator);
        file_hash.* = plan.file.hash;
        const segments = plan.file.segments.ptr;
        try batch.append(&plan);
        try std.testing.expectEqual(@as(usize, 0), plan.file.segments.len);
        try std.testing.expectEqual(@as(usize, 0), plan.new_xorbs.len);
        try std.testing.expectEqual(index + 1, batch.plans.items.len);
        try std.testing.expectEqual(segments, batch.plans.items[index].file.segments.ptr);
        try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
    }

    try batch.finish();
    try std.testing.expectEqual(@as(usize, 2), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    try std.testing.expectError(error.AlreadyFinished, batch.finish());

    for (destination.objects.items) |object| {
        if (object.kind != .shard) continue;
        const reader = try xet.shard.Reader.init(object.data);
        try std.testing.expectEqual(@as(u32, 2), reader.footer.file_count);
        try std.testing.expectEqual(@as(u32, 2), reader.footer.xorb_count);
        try std.testing.expectEqual(@as(u64, 6), object.raw_size);
        for (hashes) |file_hash| try std.testing.expect((try reader.findFile(file_hash)) != null);
    }
}

test "BatchPublisher publishes each unique file once" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = xet.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();

    for ([_][]const u8{ "AAA", "AAA" }) |input| {
        var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{ .compression = .none });
        defer publisher.deinit();
        try publisher.write(input);
        var plan = try publisher.finishPlan();
        defer plan.deinit(allocator);
        try batch.append(&plan);
    }

    try batch.finish();
    const shard_object = for (destination.objects.items) |object| {
        if (object.kind == .shard) break object;
    } else return error.TestExpectedShard;
    try std.testing.expectEqual(@as(u64, 3), shard_object.raw_size);
    const reader = try xet.shard.Reader.init(shard_object.data);
    try std.testing.expectEqual(@as(u32, 1), reader.footer.file_count);
    try std.testing.expectEqual(@as(u32, 1), reader.footer.xorb_count);
}

test "global match survives one-byte streaming writes" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const chunked = try xet.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    const source_chunks = try allocator.alloc(xet.xorb.Chunk, chunked.len);
    defer allocator.free(source_chunks);
    for (source_chunks, chunked) |*destination, source| destination.* = .{
        .data = source.data,
        .hash = source.hash,
    };
    var object = try xet.xorb.serialize(allocator, source_chunks, .none);
    defer object.deinit(allocator);
    const shard_bytes = try support.makeGlobalDedupShard(allocator, &object, null);
    var index: xet.DedupShardIndex = .{};
    defer index.deinit(allocator);
    _ = try index.addOwned(allocator, shard_bytes, 0);
    const SourceContext = struct {
        index: *xet.DedupShardIndex,
        fn query(raw: *anyopaque, query_allocator: std.mem.Allocator, hashes: []const xet.Hash) !?xet.DedupMatch {
            const self: *@This() = @ptrCast(@alignCast(raw));
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = SourceContext{ .index = &index };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{
        .compression = .none,
        .dedup_source = .{
            .context = &context,
            .query_fn = SourceContext.query,
        },
    });
    defer publisher.deinit();
    for (data) |byte| try publisher.write(&.{byte});
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), plan.new_xorbs.len);
    try std.testing.expectEqual(@as(usize, 1), plan.file.segments.len);
    try std.testing.expectEqual(@as(u32, @intCast(chunked.len)), plan.file.segments[0].chunk_index_end);
}

test "Publisher sliding window matches across the old batch boundary" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 9 * 1024 * 1024);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% index / 131);
    const chunked = try xet.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    try std.testing.expect(chunked.len > 68);

    var source_chunks: [4]xet.xorb.Chunk = undefined;
    for (&source_chunks, chunked[62..66]) |*destination, source| destination.* = .{
        .data = source.data,
        .hash = source.hash,
    };
    var object = try xet.xorb.serialize(allocator, &source_chunks, .none);
    defer object.deinit(allocator);
    var index: xet.DedupShardIndex = .{};
    defer index.deinit(allocator);
    _ = try index.addOwned(allocator, try support.makeGlobalDedupShard(allocator, &object, null), 0);

    const Context = struct {
        index: *xet.DedupShardIndex,
        longest_query: usize = 0,
        fn query(raw: *anyopaque, query_allocator: std.mem.Allocator, hashes: []const xet.Hash) !?xet.DedupMatch {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.longest_query = @max(self.longest_query, hashes.len);
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = Context{ .index = &index };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{
        .compression = .none,
        .dedup_source = .{ .context = &context, .query_fn = Context.query },
    });
    defer publisher.deinit();
    try publisher.write(data);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);

    try std.testing.expectEqual(@as(usize, xet.dedup_window), context.longest_query);
    const found = for (plan.file.segments, 0..) |segment, segment_index| {
        if (xet.hash.eql(segment.xorb_hash, object.hash)) break segment_index;
    } else return error.TestMissingBoundaryMatch;
    const segment = plan.file.segments[found];
    try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
    try std.testing.expectEqual(@as(u32, 4), segment.chunk_index_end);
    try std.testing.expectEqual(xet.hash.verificationNodes(object.nodes), plan.file.verification[found]);
}

test "Publisher checks every remaining prefix after a dedup match" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const chunked = try xet.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    try std.testing.expect(chunked.len > 4);

    var original_xorbs: std.ArrayList(xet.xorb.Serialized) = .empty;
    defer {
        for (original_xorbs.items) |*object| object.deinit(allocator);
        original_xorbs.deinit(allocator);
    }
    var first: usize = 0;
    while (first < chunked.len) {
        const end = @min(first + 2, chunked.len);
        const source_chunks = try allocator.alloc(xet.xorb.Chunk, end - first);
        defer allocator.free(source_chunks);
        for (source_chunks, chunked[first..end]) |*destination, source| destination.* = .{
            .data = source.data,
            .hash = source.hash,
        };
        try original_xorbs.append(allocator, try xet.xorb.serialize(allocator, source_chunks, .none));
        first = end;
    }

    var shards: std.ArrayList([]u8) = .empty;
    errdefer {
        for (shards.items) |bytes| allocator.free(bytes);
    }
    defer shards.deinit(allocator);
    for (original_xorbs.items) |*object| {
        const bytes = try support.makeGlobalDedupShard(allocator, object, null);
        errdefer allocator.free(bytes);
        try shards.append(allocator, bytes);
    }
    const Context = struct {
        index: xet.DedupShardIndex = .{},
        fn query(raw: *anyopaque, query_allocator: std.mem.Allocator, hashes: []const xet.Hash) !?xet.DedupMatch {
            const self: *@This() = @ptrCast(@alignCast(raw));
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = Context{};
    defer context.index.deinit(allocator);
    for (shards.items) |bytes| _ = try context.index.addOwned(allocator, bytes, 0);

    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{
        .compression = .none,
        .dedup_source = .{ .context = &context, .query_fn = Context.query },
    });
    defer publisher.deinit();
    try publisher.write(data);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), plan.new_xorbs.len);
    try std.testing.expectEqual(original_xorbs.items.len, plan.file.segments.len);
    for (plan.file.segments, original_xorbs.items) |segment, object| {
        try std.testing.expectEqual(object.hash, segment.xorb_hash);
        try std.testing.expectEqual(@as(u32, @intCast(object.chunks.len)), segment.chunk_index_end);
    }
    try std.testing.expect(plan.file.sha256 != null);
}

fn checkSingleChunkXorbs(allocator: std.mem.Allocator, objects: []const support.CapturedObject) !void {
    var count: usize = 0;
    for (objects) |object| {
        if (object.kind != .xorb) continue;
        const chunks = try support.readUncompressedXorb(allocator, object.data);
        defer allocator.free(chunks);
        try std.testing.expectEqual(@as(usize, 1), chunks.len);
        count += 1;
    }
    try std.testing.expect(count >= 3);
}

fn reconstructCapturedPackage(allocator: std.mem.Allocator, destination: *support.MemoryStore, file_hash: xet.Hash, expected: []const u8) !void {
    const shard_bytes = for (destination.objects.items) |object| {
        if (object.kind == .shard) break object.data;
    } else return error.TestMissingPublishedShard;
    var manifest = try xet.reconstruction.planFromShard(allocator, shard_bytes, file_hash);
    defer manifest.deinit(allocator);
    const Context = struct {
        store: *support.MemoryStore,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: xet.reconstruction.Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            for (self.store.objects.items) |object| {
                if (object.kind == .xorb and xet.hash.eql(object.hash, request.hash)) {
                    self.reader = .fixed(object.data);
                    return &self.reader;
                }
            }
            return error.TestMissingXorb;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .store = destination };
    const bytes = try xet.reconstruction.reconstruct(allocator, &manifest.plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    });
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, expected, bytes);
}

const MaxChunkComparison = struct {
    package: xet.Package,
    result: xet.store.PublishResult,
    packed_store: support.MemoryStore,
    streamed: support.MemoryStore,

    fn deinit(self: *MaxChunkComparison, allocator: std.mem.Allocator) void {
        self.packed_store.deinit();
        self.streamed.deinit();
        self.package.deinit(allocator);
    }
};

fn compareMaxChunkEntryPoints(allocator: std.mem.Allocator) !MaxChunkComparison {
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const opts = xet.PackOptions{ .compression = .none, .max_xorb_size = 64 * 1024 * 1024, .max_xorb_chunks = 1 };
    var result: MaxChunkComparison = .{
        .package = try xet.pack(allocator, data, opts),
        .result = undefined,
        .packed_store = .{ .allocator = allocator },
        .streamed = .{ .allocator = allocator },
    };
    errdefer result.deinit(allocator);
    try xet.publish(allocator, &result.package, result.packed_store.store());
    var publisher = try xet.StorePublisher.init(
        allocator,
        result.streamed.store(),
        xet.PublisherOptions.fromPack(opts),
    );
    defer publisher.deinit();
    try publisher.write(data);
    result.result = try publisher.finish();
    try std.testing.expectEqual(result.package.file_hash, result.result.file_hash);
    try reconstructCapturedPackage(allocator, &result.packed_store, result.package.file_hash, data);
    try reconstructCapturedPackage(allocator, &result.streamed, result.result.file_hash, data);
    return result;
}

test "pack and Publisher honor max_xorb_chunks with matching hashes and reconstruction" {
    const allocator = std.testing.allocator;
    var comparison = try compareMaxChunkEntryPoints(allocator);
    defer comparison.deinit(allocator);
    try checkSingleChunkXorbs(allocator, comparison.packed_store.objects.items);
    try checkSingleChunkXorbs(allocator, comparison.streamed.objects.items);
}
