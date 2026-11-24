const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

fn checkCapturedHttpObjects(exchanges: []const support.HttpExchange, comptime streaming: bool) !void {
    try std.testing.expectEqual(@as(usize, 3), exchanges.len);
    const offset: usize = if (streaming) 1 else 0;
    if (streaming) {
        try std.testing.expect(std.mem.startsWith(u8, exchanges[0].target, "/v1/chunks/default-merkledb/"));
        try std.testing.expectEqualStrings("/v2/shards", exchanges[2].target);
    } else {
        try std.testing.expectEqualStrings("/v2/shards", exchanges[1].target);
        try std.testing.expectEqualStrings("/v1/shards", exchanges[2].target);
    }
    try support.checkShardBody(exchanges[2].body);
    try std.testing.expect(std.mem.startsWith(u8, exchanges[offset].target, "/v1/xorbs/default/"));
    try support.checkXorbBody(exchanges[offset].body);
}

test "CAS upload bytes are canonical for pack publish" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{ .{}, .{ .status = .not_found }, .{} };
    // Pack publication deliberately performs no global lookup
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    try xet.publish(allocator, &package, client.store());
    try server.finish();
    try checkCapturedHttpObjects(server.exchanges.items, false);
}

test "CAS upload bytes are canonical for streaming Publisher" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{ .status = .not_found } };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try checkCapturedHttpObjects(server.exchanges.items, true);
}

test "HTTP upload byte counts match transmitted xorb and shard bodies" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{
        .{ .status = .not_found },
        .{},
        .{ .body = support.result_json },
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    try std.testing.expectEqual(@as(u64, 0), client.uploadedBytes());
    const before = client.uploadedBytes();
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
    try server.finish();
    var expected: u64 = 0;
    for (server.exchanges.items) |exchange| {
        if (!std.mem.startsWith(u8, exchange.target, "/v1/chunks/")) expected += exchange.body.len;
    }
    try std.testing.expectEqual(expected, client.uploadedBytes() - before);
}

fn captureUpload(
    allocator: std.mem.Allocator,
    data: []const u8,
    streaming: bool,
) !struct { result: xet.store.PublishResult, shard: []u8 } {
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    if (streaming) {
        var file = try session.beginFile();
        defer file.deinit();
        const splits = [_]usize{ 1, 3, 4093, 17, 65_535, 2 };
        var offset: usize = 0;
        var index: usize = 0;
        while (offset < data.len) : (index += 1) {
            const end = @min(offset + splits[index % splits.len], data.len);
            try file.write(data[offset..end]);
            offset = end;
        }
        _ = try file.finish();
    } else {
        try session.addFile(data);
    }
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    const published = session.results()[0];
    const shard_bytes = try capturedHttpShard(server.exchanges.items);
    return .{ .result = published, .shard = try allocator.dupe(u8, shard_bytes) };
}

test "UploadSession incremental writes match whole-buffer file and reconstruction metadata" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const whole = try captureUpload(allocator, data, false);
    defer allocator.free(whole.shard);
    const incremental = try captureUpload(allocator, data, true);
    defer allocator.free(incremental.shard);

    try std.testing.expectEqual(whole.result, incremental.result);
    try std.testing.expectEqualSlices(u8, whole.shard, incremental.shard);
    const reader = try xet.shard.Reader.init(incremental.shard);
    const file = (try reader.findFile(incremental.result.file_hash)).?;
    try std.testing.expectEqual(@as(u64, data.len), incremental.result.size);
    try std.testing.expect(file.count > 0);
    try std.testing.expect((try file.sha256()) != null);
}

test "multiple incremental files preserve result order and combined shard publication" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    const inputs = [_][]const u8{ "AAA", "BBB" };
    var returned: [inputs.len]xet.store.PublishResult = undefined;
    for (inputs, &returned) |input, *result| {
        var file = try session.beginFile();
        defer file.deinit();
        for (input) |byte| try file.write(&.{byte});
        result.* = try file.finish();
    }
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 5), server.exchanges.items.len);

    try std.testing.expectEqual(inputs.len, session.results().len);
    for (session.results(), returned, inputs) |result, direct, input| {
        try std.testing.expectEqual(direct, result);
        const expected_hash = try xet.hash.file(allocator, &.{.{
            .hash = xet.hash.data(input),
            .size = input.len,
        }});
        try std.testing.expectEqual(expected_hash, result.file_hash);
        try std.testing.expectEqual(@as(u64, input.len), result.size);
    }
    var shard_count: usize = 0;
    for (server.exchanges.items) |exchange| {
        if (!std.mem.endsWith(u8, exchange.target, "/shards")) continue;
        shard_count += 1;
        const reader = try xet.shard.Reader.init(exchange.body);
        try std.testing.expectEqual(@as(usize, 2), reader.footer.file_count);
        try std.testing.expectEqual(@as(usize, 2), reader.footer.xorb_count);
        for (session.results(), inputs) |result, input| {
            const file = (try reader.findFile(result.file_hash)).?;
            try std.testing.expectEqual(@as(u32, 1), file.count);
            try std.testing.expectEqual(xet.hash.verification(&.{xet.hash.data(input)}), try file.verification(0));
        }
    }
    try std.testing.expectEqual(@as(usize, 1), shard_count);
}

test "UploadSession discards an unfinished file before accepting another" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();

    var unfinished = try session.beginFile();
    try unfinished.write("discarded");
    try std.testing.expectError(error.FileAlreadyActive, session.beginFile());
    try std.testing.expectError(error.FileAlreadyActive, session.finish());
    unfinished.deinit();

    try session.addFile("AAA");
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expectEqual(@as(usize, 1), session.results().len);
    try std.testing.expectEqual(@as(u64, 3), session.results()[0].size);
}

test "UploadFile rejects writes and finalization after completion" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    var file = try session.beginFile();
    defer file.deinit();
    try file.write("AAA");
    const result = try file.finish();
    try std.testing.expectError(error.AlreadyFinished, file.write("more"));
    try std.testing.expectError(error.AlreadyFinished, file.finish());
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expectEqual(@as(usize, 1), session.results().len);
    try std.testing.expectEqual(result, session.results()[0]);
}

test "UploadSession rejects new files and repeated completion after finishing" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    try session.addFile("AAA");
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expectError(error.AlreadyFinished, session.beginFile());
    try std.testing.expectError(error.AlreadyFinished, session.finish());
}

fn exerciseSessionAllocFailure(fail_at: ?usize) !usize {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = fail_at };
    defer tracker.deinit();
    const operation = tracker.allocator();
    var failed = false;
    _ = blk: {
        var session = client.uploadSession(operation, .{ .compression = .none }) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        defer session.deinit();
        var first_file = session.beginFile() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        _ = {
            defer first_file.deinit();
            first_file.write("A") catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
            first_file.write("AA") catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
            _ = first_file.finish() catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
        };
        var second_file = session.beginFile() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        _ = {
            defer second_file.deinit();
            for ("BBB") |byte| second_file.write(&.{byte}) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
            _ = second_file.finish() catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failed = true;
                break :blk;
            };
        };
        session.finish() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failed = true;
            break :blk;
        };
        try std.testing.expectEqual(@as(usize, 2), session.results().len);
    };
    if (fail_at != null) try std.testing.expect(failed);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    return tracker.allocation_count;
}

test "UploadSession operation allocation failures are clean" {
    const allocations = try exerciseSessionAllocFailure(null);
    for (0..allocations) |fail_at| {
        _ = try exerciseSessionAllocFailure(fail_at);
    }
}

test "UploadSession uploads only unmatched chunks and publishes one combined shard" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const global_chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var global_object = try xet.xorb.serialize(allocator, &global_chunks, .none);
    defer global_object.deinit(allocator);
    const global_shard = try support.makeGlobalDedupShard(allocator, &global_object, null);
    defer allocator.free(global_shard);
    const new_chunks = [_]xet.xorb.Chunk{.{ .data = "BBB", .hash = xet.hash.data("BBB") }};
    var new_object = try xet.xorb.serialize(allocator, &new_chunks, .none);
    defer new_object.deinit(allocator);

    var responses = [_]support.HttpResponse{
        .{ .body = global_shard },
        .{ .status = .not_found },
        .{},
        .{ .body = support.result_json },
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    try session.addFile("AAA");
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    try session.addFile("BBB");
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expectEqualStrings(new_object.bytes[0..new_object.body_length], server.exchanges.items[2].body);
    const uploaded_chunks = try support.readUncompressedXorb(allocator, server.exchanges.items[2].body);
    defer allocator.free(uploaded_chunks);
    try std.testing.expectEqual(@as(usize, 1), uploaded_chunks.len);
    try std.testing.expectEqualStrings("BBB", uploaded_chunks[0].bytes);
    try session.finish();
    try server.finish();

    try std.testing.expectEqual(@as(usize, 2), session.results().len);
    const inputs = [_][]const u8{ "AAA", "BBB" };
    const objects = [_]*const xet.xorb.Serialized{ &global_object, &new_object };
    const uploaded_shard = server.exchanges.items[3].body;
    const reader = try xet.shard.Reader.init(uploaded_shard);
    try std.testing.expectEqual(@as(usize, 2), reader.footer.file_count);
    try std.testing.expectEqual(@as(usize, 1), reader.footer.xorb_count);
    try std.testing.expect((try reader.findXorb(global_object.hash)) == null);
    const uploaded_info = (try reader.findXorb(new_object.hash)).?;
    try std.testing.expectEqual(@as(u32, 1), uploaded_info.count);
    try std.testing.expectEqual(xet.hash.data("BBB"), (try uploaded_info.chunk(0)).hash);
    for (session.results(), inputs, objects) |result, input, object| {
        const info = (try reader.findFile(result.file_hash)).?;
        try std.testing.expectEqual(@as(u32, 1), info.count);
        const segment = try info.segment(0);
        try std.testing.expectEqual(object.hash, segment.xorb_hash);
        try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
        try std.testing.expectEqual(@as(u32, 1), segment.chunk_index_end);
        try std.testing.expectEqual(xet.hash.verification(&.{xet.hash.data(input)}), try info.verification(0));
    }

    const metadata = [_]xet.shard.Xorb{
        .{
            .hash = global_object.hash,
            .chunks = global_object.chunks,
            .raw_size = @intCast(global_object.raw_size),
            .serialized_size = @intCast(global_object.body_length),
        },
        .{
            .hash = new_object.hash,
            .chunks = new_object.chunks,
            .raw_size = @intCast(new_object.raw_size),
            .serialized_size = @intCast(new_object.body_length),
        },
    };
    var files: [2]xet.shard.OwnedFile = undefined;
    var count: usize = 0;
    defer for (files[0..count]) |*file| file.deinit(allocator);
    for (session.results(), &files) |result, *file| {
        file.* = try (try reader.findFile(result.file_hash)).?.decode(allocator);
        count += 1;
    }
    const full_shard = try xet.shard.serialize(allocator, &.{
        files[0].value,
        files[1].value,
    }, &metadata);
    defer allocator.free(full_shard);
    for (session.results(), inputs) |result, input| {
        _ = try xet.reconstruction.validateShardFile(allocator, full_shard, result.file_hash);
        try reconstructHttpShard(allocator, full_shard, result.file_hash, input, &objects);
    }
}

test "UploadSession joins reordered reused ranges at their actual offsets" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{
        .compression = .none,
        .max_xorb_size = 3 * 128 * 1024,
    });
    defer session.deinit();
    var data: [3 * 128 * 1024]u8 = undefined;
    @memset(data[0 .. 128 * 1024], 'A');
    @memset(data[128 * 1024 .. 2 * 128 * 1024], 'B');
    @memset(data[2 * 128 * 1024 ..], 'C');
    try session.addFile(&data);
    var reordered: [2 * 128 * 1024]u8 = undefined;
    @memcpy(reordered[0 .. 128 * 1024], data[2 * 128 * 1024 ..]);
    @memcpy(reordered[128 * 1024 ..], data[128 * 1024 .. 2 * 128 * 1024]);
    try session.addFile(&reordered);
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);

    const shard_bytes = try capturedHttpShard(server.exchanges.items);
    _ = try xet.reconstruction.validateShardFile(allocator, shard_bytes, session.results()[1].file_hash);
    const reader = try xet.shard.Reader.init(shard_bytes);
    const info = (try reader.findFile(session.results()[1].file_hash)).?;
    try std.testing.expectEqual(@as(u32, 2), info.count);
    const expected = [_]xet.reconstruction.Range{
        .{ .start = 2, .end = 3 },
        .{ .start = 1, .end = 2 },
    };
    for (expected, 0..) |range, index| {
        const segment = try info.segment(@intCast(index));
        try std.testing.expectEqual(range.start, segment.chunk_index_start);
        try std.testing.expectEqual(range.end, segment.chunk_index_end);
    }
    try reconstructCapturedHttp(allocator, server.exchanges.items, session.results()[1].file_hash, &reordered);
}

fn exerciseRemoteMisses(status: std.http.Status, inputs: []const []const u8, expected_lookups: usize, expected_xorbs: usize) !void {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{
        .{ .status = status },
        .{ .status = status },
    };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    server.stop_after_shard = true;
    server.lookup_status = status;
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var session = try client.uploadSession(allocator, .{ .compression = .none });
    defer session.deinit();
    for (inputs) |input| try session.addFile(input);
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(expected_lookups + expected_xorbs + 1, server.exchanges.items.len);
    try std.testing.expectEqual(inputs.len, session.results().len);
    var lookups: usize = 0;
    for (server.exchanges.items) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/chunks/default-merkledb/")) lookups += 1;
    }
    try std.testing.expectEqual(expected_lookups, lookups);
}

test "UploadSession caches remote misses but retries failed lookups" {
    const repeated = [_][]const u8{ "AAA", "AAA" };
    try exerciseRemoteMisses(.not_found, &repeated, 1, 1);
    const distinct = [_][]const u8{ "AAA", "BBB" };
    try exerciseRemoteMisses(.internal_server_error, &distinct, 2, 2);
}

fn exerciseRetainedXorbAfterFailedFile(comptime fail_finish: bool) !void {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var session = try client.uploadSession(tracker.allocator(), .{
        .compression = .none,
        .max_xorb_size = 128 * 1024,
    });
    defer session.deinit();
    const block = @as([128 * 1024]u8, @splat(0));
    var first = try session.beginFile();
    var retain_first = true;
    defer if (retain_first) first.deinit();
    for (0..65) |_| try first.write(&block);
    if (fail_finish) {
        tracker.fail_at = tracker.allocation_count;
        try std.testing.expectError(error.OutOfMemory, first.finish());
        tracker.fail_at = null;
    }
    first.deinit();
    retain_first = false;

    var second = try session.beginFile();
    defer second.deinit();
    try second.write(&block);
    const result = try second.finish();
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 4), server.exchanges.items.len);
    try std.testing.expectEqual(@as(usize, 1), session.results().len);
    try std.testing.expectEqual(result, session.results()[0]);
    const shard_bytes = try capturedHttpShard(server.exchanges.items);
    const reader = try xet.shard.Reader.init(shard_bytes);
    try std.testing.expectEqual(@as(u32, 1), reader.footer.file_count);
    try std.testing.expectEqual(@as(u32, 1), reader.footer.xorb_count);
    const segment = try (try reader.findFile(result.file_hash)).?.segment(0);
    const info = (try reader.findXorb(segment.xorb_hash)).?;
    try std.testing.expectEqual(@as(u32, 1), info.count);
    try std.testing.expectEqual(@as(u32, block.len), (try info.chunk(0)).unpacked_segment_bytes);
    try reconstructCapturedHttp(allocator, server.exchanges.items, result.file_hash, &block);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
}

test "UploadSession publishes valid Xorb metadata retained from an abandoned file" {
    try exerciseRetainedXorbAfterFailedFile(false);
}

test "UploadSession publishes valid Xorb metadata retained after a failed finish" {
    try exerciseRetainedXorbAfterFailedFile(true);
}

test "UploadSession allows a replacement after a failed file write" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var session = try client.uploadSession(tracker.allocator(), .{ .compression = .none });
    defer session.deinit();

    var failed = try session.beginFile();
    defer failed.deinit();
    tracker.fail_at = tracker.allocation_count;
    try std.testing.expectError(error.OutOfMemory, failed.write("AAA"));
    tracker.fail_at = null;
    try std.testing.expectError(error.WriteFailed, failed.write("AAA"));
    try std.testing.expectError(error.WriteFailed, failed.finish());

    var replacement = try session.beginFile();
    defer replacement.deinit();
    try replacement.write("BBBCCC");
    const result = try replacement.finish();
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);

    try std.testing.expectEqual(@as(usize, 1), session.results().len);
    try std.testing.expectEqual(result, session.results()[0]);
    try reconstructCapturedHttp(allocator, server.exchanges.items, result.file_hash, "BBBCCC");
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
}

test "deinitializing a stale failed handle preserves the replacement file" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var session = try client.uploadSession(tracker.allocator(), .{ .compression = .none });
    defer session.deinit();

    var failed = try session.beginFile();
    var retain_failed = true;
    defer if (retain_failed) failed.deinit();
    tracker.fail_at = tracker.allocation_count;
    try std.testing.expectError(error.OutOfMemory, failed.write("AAA"));
    tracker.fail_at = null;

    var replacement = try session.beginFile();
    defer replacement.deinit();
    try replacement.write("BBB");
    failed.deinit();
    retain_failed = false;
    try replacement.write("CCC");
    const result = try replacement.finish();
    try session.finish();
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);

    const shard_bytes = try capturedHttpShard(server.exchanges.items);
    const reader = try xet.shard.Reader.init(shard_bytes);
    const info = (try reader.findFile(result.file_hash)).?;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("BBBCCC", &digest, .{});
    try std.testing.expectEqual(xet.hash.fromStandard(digest), (try info.sha256()).?);
    try reconstructCapturedHttp(allocator, server.exchanges.items, result.file_hash, "BBBCCC");
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
}

test "UploadSession failed file finalization retries as WriteFailed" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var session = try client.uploadSession(tracker.allocator(), .{ .compression = .none });
    defer session.deinit();
    var file = try session.beginFile();
    defer file.deinit();
    try file.write("AAA");

    tracker.fail_at = tracker.allocation_count;
    try std.testing.expectError(error.OutOfMemory, file.finish());
    tracker.fail_at = null;
    try std.testing.expectError(error.WriteFailed, file.finish());
    try std.testing.expectError(error.WriteFailed, file.write("BBB"));
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
}

fn reconstructHttpShard(
    allocator: std.mem.Allocator,
    shard_bytes: []const u8,
    file_hash: xet.Hash,
    expected: []const u8,
    objects: []const *const xet.xorb.Serialized,
) !void {
    var manifest = try xet.reconstruction.planFromShard(allocator, shard_bytes, file_hash);
    defer manifest.deinit(allocator);
    const Context = struct {
        objects: []const *const xet.xorb.Serialized,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: xet.reconstruction.Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            for (self.objects) |object| {
                if (xet.hash.eql(object.hash, request.hash)) {
                    self.reader = .fixed(object.bytes);
                    return &self.reader;
                }
            }
            return error.TestMissingCapturedXorb;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .objects = objects };
    const output = try xet.reconstruction.reconstruct(allocator, &manifest.plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    });
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, expected, output);
}

fn capturedHttpShard(exchanges: []const support.HttpExchange) ![]const u8 {
    for (exchanges) |exchange| {
        if (std.mem.endsWith(u8, exchange.target, "/shards")) return exchange.body;
    }
    return error.TestMissingPublishedShard;
}

fn reconstructCapturedHttp(
    allocator: std.mem.Allocator,
    exchanges: []const support.HttpExchange,
    file_hash: xet.Hash,
    expected: []const u8,
) !void {
    var manifest = try xet.reconstruction.planFromShard(
        allocator,
        try capturedHttpShard(exchanges),
        file_hash,
    );
    defer manifest.deinit(allocator);
    const Context = struct {
        exchanges: []const support.HttpExchange,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: xet.reconstruction.Request) !*std.Io.Reader {
            const self: *@This() = @ptrCast(@alignCast(raw));
            var target: ["/v1/xorbs/default/".len + 64]u8 = undefined;
            const expected_target = try std.fmt.bufPrint(
                &target,
                "/v1/xorbs/default/{s}",
                .{xet.hash.toHex(request.hash)},
            );
            for (self.exchanges) |exchange| {
                if (std.mem.eql(u8, exchange.target, expected_target)) {
                    self.reader = .fixed(exchange.body);
                    return &self.reader;
                }
            }
            return error.TestMissingCapturedXorb;
        }
        fn close(_: *anyopaque, _: *std.Io.Reader) void {}
    };
    var context = Context{ .exchanges = exchanges };
    const output = try xet.reconstruction.reconstruct(allocator, &manifest.plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    });
    defer allocator.free(output);
    try std.testing.expectEqualSlices(u8, expected, output);
}
