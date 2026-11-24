const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

fn exerciseGlobalAllocationFailure(fail_at: ?usize) !usize {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const chunked = try xet.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    const chunks = try allocator.alloc(xet.xorb.Chunk, chunked.len);
    defer allocator.free(chunks);
    for (chunks, chunked) |*destination, source| destination.* = .{
        .data = source.data,
        .hash = source.hash,
    };
    var object = try xet.xorb.serialize(allocator, chunks, .none);
    defer object.deinit(allocator);
    const shard_bytes = try support.makeGlobalDedupShard(allocator, &object, null);
    var index: xet.DedupShardIndex = .{};
    defer index.deinit(allocator);
    _ = try index.addOwned(allocator, shard_bytes, 0);
    const Context = struct {
        index: *xet.DedupShardIndex,
        fn query(raw: *anyopaque, query_allocator: std.mem.Allocator, hashes: []const xet.Hash) !?xet.DedupMatch {
            const self: *@This() = @ptrCast(@alignCast(raw));
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = Context{ .index = &index };
    var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = fail_at };
    defer tracker.deinit();
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    _ = {
        var publisher = try xet.StorePublisher.init(tracker.allocator(), destination.store(), .{
            .compression = .none,
            .dedup_source = .{
                .context = &context,
                .query_fn = Context.query,
            },
        });
        defer publisher.deinit();
        try publisher.write(data);
        var plan = try publisher.finishPlan();
        plan.deinit(tracker.allocator());
    };
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    return tracker.allocation_count;
}

test "global dedup allocation failures clean up pending matches and chunks" {
    const allocations = try exerciseGlobalAllocationFailure(null);
    for (0..allocations) |fail_at| {
        try std.testing.expectError(error.OutOfMemory, exerciseGlobalAllocationFailure(fail_at));
    }
}

test "Client.upload reuses a server-provided global chunk match" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const hmac_key = xet.hash.data("global shard key");
    var responses = [_]support.HttpResponse{
        .{ .body = try support.makeGlobalDedupShard(allocator, &object, hmac_key) },
        .{ .status = .not_found },
        .{ .body = support.result_json },
    };
    defer allocator.free(@constCast(responses[0].body));
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(responses[0].body);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const result = try client.upload(allocator, "AAA", .{ .compression = .none });
    try server.finish();
    try std.testing.expectEqual(@as(usize, 2), server.exchanges.items.len);
    const expected_target = try std.fmt.allocPrint(allocator, "/v1/chunks/default-merkledb/{s}", .{xet.hash.toHex(chunks[0].hash)});
    defer allocator.free(expected_target);
    try std.testing.expectEqualStrings(expected_target, server.exchanges.items[0].target);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[server.exchanges.items.len - 1].target);
    const reader = try xet.shard.Reader.init(server.exchanges.items[server.exchanges.items.len - 1].body);
    try std.testing.expectEqual(@as(usize, 0), reader.footer.xorb_count);
    const file = (try reader.findFile(result.file_hash)).?;
    const segment = try file.segment(0);
    try std.testing.expectEqual(object.hash, segment.xorb_hash);
    try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
    try std.testing.expectEqual(@as(u32, 1), segment.chunk_index_end);
    try std.testing.expectEqual(xet.hash.verification(&.{chunks[0].hash}), try file.verification(0));
}

fn uploadRepeatedAbc(client: *xet.http.Client, allocator: std.mem.Allocator, comptime streaming: bool) !xet.store.PublishResult {
    if (!streaming) return client.upload(allocator, "AAA", .{ .compression = .none });
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    var file = try session.beginFile();
    defer file.deinit();
    for ("AAA") |byte| try file.write(&.{byte});
    const result = try file.finish();
    try session.finish();
    return result;
}

fn exerciseFreshClientDedup(comptime streaming: bool) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{
        .data = "AAA",
        .hash = xet.hash.data("AAA"),
    }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const global_shard = try support.makeGlobalDedupShard(allocator, &object, null);
    defer allocator.free(global_shard);
    const responses = [_]support.HttpResponse{
        .{ .status = .not_found },
        .{},
        .{ .body = support.result_json },
        .{ .body = global_shard },
        .{ .body = support.result_json },
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();

    var first = try xet.http.Client.init(allocator, io, server.origin, "");
    defer first.deinit();
    const first_result = try uploadRepeatedAbc(&first, allocator, streaming);
    var second = try xet.http.Client.init(allocator, io, server.origin, "");
    defer second.deinit();
    const second_result = try uploadRepeatedAbc(&second, allocator, streaming);
    try server.finish();
    try std.testing.expectEqual(@as(usize, 5), server.exchanges.items.len);

    try std.testing.expectEqual(first_result, second_result);
    try std.testing.expectEqualStrings("/v1/xorbs/default/" ++ xet.hash.toHex(object.hash), server.exchanges.items[1].target);
    try std.testing.expectEqual(@as(usize, object.body_length), server.exchanges.items[1].body.len);
    try std.testing.expectEqualStrings("/v1/chunks/default-merkledb/" ++ xet.hash.toHex(chunks[0].hash), server.exchanges.items[3].target);
    try std.testing.expectEqual(@as(usize, 0), server.exchanges.items[3].body.len);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[2].target);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[4].target);
    const first_bytes = server.exchanges.items[1].body.len + server.exchanges.items[2].body.len;
    try std.testing.expectEqual(@as(u64, @intCast(first_bytes)), first.uploadedBytes());
    try std.testing.expectEqual(@as(u64, @intCast(server.exchanges.items[4].body.len)), second.uploadedBytes());
    var uploads: usize = 0;
    for (server.exchanges.items) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/xorbs/default/")) uploads += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), uploads);
    const reader = try xet.shard.Reader.init(server.exchanges.items[4].body);
    try std.testing.expectEqual(@as(usize, 0), reader.footer.xorb_count);
    try std.testing.expect((try reader.findFile(second_result.file_hash)) != null);
}

test "fresh clients deduplicate repeated HTTP xorb uploads" {
    try exerciseFreshClientDedup(false);
}

test "incremental uploads through fresh clients retain global dedup" {
    try exerciseFreshClientDedup(true);
}

test "global lookup failures and expired shards fall back to normal uploads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const expired = try support.makeGlobalDedupShard(allocator, &object, null);
    defer allocator.free(expired);
    std.mem.writeInt(u64, expired[expired.len - xet.shard.footer_size + 112 ..][0..8], 1, .little);
    var responses = [_]support.HttpResponse{
        .{ .status = .internal_server_error },
        .{},
        .{ .body = support.result_json },
        .{ .body = expired },
        .{},
        .{ .body = support.result_json },
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
    try server.finish();
    try std.testing.expectEqual(@as(usize, 6), server.exchanges.items.len);
    try support.checkXorbBody(server.exchanges.items[1].body);
    try support.checkXorbBody(server.exchanges.items[4].body);
}

test "Client.upload reuses a contiguous run from one global lookup" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const chunked = try xet.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    try std.testing.expect(chunked.len >= 2);
    const source_chunks = try allocator.alloc(xet.xorb.Chunk, chunked.len);
    defer allocator.free(source_chunks);
    for (source_chunks, chunked) |*destination, source| destination.* = .{
        .data = source.data,
        .hash = source.hash,
    };
    var object = try xet.xorb.serialize(allocator, source_chunks, .none);
    defer object.deinit(allocator);
    var responses = [_]support.HttpResponse{
        .{ .body = try support.makeGlobalDedupShard(allocator, &object, null) },
        .{ .status = .not_found },
        .{ .status = .not_found },
        .{},
        .{ .body = support.result_json },
    };
    defer allocator.free(@constCast(responses[0].body));
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(responses[0].body);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const result = try client.upload(allocator, data, .{ .compression = .none });
    try server.finish();
    try std.testing.expectEqual(@as(usize, 2), server.exchanges.items.len);
    const reader = try xet.shard.Reader.init(server.exchanges.items[server.exchanges.items.len - 1].body);
    try std.testing.expectEqual(@as(usize, 0), reader.footer.xorb_count);
    const file = (try reader.findFile(result.file_hash)).?;
    try std.testing.expectEqual(@as(u32, 1), file.count);
    const segment = try file.segment(0);
    try std.testing.expectEqual(@as(u32, @intCast(chunked.len)), segment.chunk_index_end);
    try std.testing.expectEqual(@as(u32, @intCast(data.len)), segment.unpacked_segment_bytes);
}

test "Client.upload mixes global matches with new chunks" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const original_chunks = try xet.chunkBuffer(allocator, data);
    defer allocator.free(original_chunks);
    var original_xorbs: std.ArrayList(xet.xorb.Serialized) = .empty;
    defer {
        for (original_xorbs.items) |*object| object.deinit(allocator);
        original_xorbs.deinit(allocator);
    }
    var first: usize = 0;
    while (first < original_chunks.len) {
        const end = @min(first + 2, original_chunks.len);
        const source_chunks = try allocator.alloc(xet.xorb.Chunk, end - first);
        defer allocator.free(source_chunks);
        for (source_chunks, original_chunks[first..end]) |*destination, source| destination.* = .{
            .data = source.data,
            .hash = source.hash,
        };
        const object = try xet.xorb.serialize(allocator, source_chunks, .none);
        try original_xorbs.append(allocator, object);
        first = end;
    }
    data[287_345] ^= 0x5a;
    var responses = [_]support.HttpResponse{
        .{ .body = try support.makeGlobalDedupShard(allocator, &original_xorbs.items[0], null) },
        .{ .status = .not_found },
        .{ .status = .not_found },
        .{},
        .{},
        .{},
        .{ .body = support.result_json },
    };
    defer allocator.free(@constCast(responses[0].body));
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(responses[0].body);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const result = try client.upload(allocator, data, .{ .compression = .none, .max_xorb_size = 128 * 1024 });
    try server.finish();
    try std.testing.expectEqual(@as(usize, 5), server.exchanges.items.len);
    var lookups: usize = 0;
    var uploads: usize = 0;
    for (server.exchanges.items[0 .. server.exchanges.items.len - 1]) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/chunks/default-merkledb/")) lookups += 1;
        if (std.mem.startsWith(u8, exchange.target, "/v1/xorbs/default/")) uploads += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), lookups);
    try std.testing.expectEqual(@as(usize, 3), uploads);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[server.exchanges.items.len - 1].target);
    const reader = try xet.shard.Reader.init(server.exchanges.items[server.exchanges.items.len - 1].body);
    try std.testing.expectEqual(@as(usize, 3), reader.footer.xorb_count);
    const file = (try reader.findFile(result.file_hash)).?;
    try std.testing.expect(file.count >= 2);
}

test "Client.upload gates remote misses after the first chunk" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const data = try allocator.alloc(u8, 9 * 1024 * 1024);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% index / 131);
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    _ = try client.upload(allocator, data, .{ .compression = .none });
    try server.finish();
    var lookups: usize = 0;
    for (server.exchanges.items) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/chunks/default-merkledb/")) lookups += 1;
    }
    try std.testing.expect(lookups >= 1);
    try std.testing.expect(lookups <= 4);
}
