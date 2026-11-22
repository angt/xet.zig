const std = @import("std");
const xet = @import("xet");
const support = @import("regression_support");

const result_json =
    \\{"type":"result"}
;
const validating_frame =
    \\{"type":"validating","verified":1,"total":1}
;
const upload_error_frame =
    \\{"type":"error","message":"rejected","retryable":false}
;

const expected_abc_sha256 = blk: {
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(
        &digest,
        "eacf018fbf1678ba2322ae5dde4041419c7a1796a36103b0ad1500f261ff10b4",
    ) catch unreachable;
    break :blk digest;
};

fn checkUploadedAbcSha256(bytes: []const u8) !void {
    try std.testing.expect(bytes.len >= 144);
    const flags = std.mem.readInt(u32, bytes[80..84], .little);
    try std.testing.expect(flags & xet.shard.metadata_extension_flag != 0);
    const count = std.mem.readInt(u32, bytes[84..88], .little);
    const verified: usize = @intFromBool(flags & xet.shard.verification_flag != 0);
    const metadata: usize = @intFromBool(flags & xet.shard.metadata_extension_flag != 0);
    const sha_offset = 48 + 48 * (1 + @as(usize, count) * (1 + verified) + metadata) - 48;
    try std.testing.expect(sha_offset + 48 <= bytes.len);
    try std.testing.expectEqualSlices(u8, &expected_abc_sha256, bytes[sha_offset..][0..32]);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), bytes[sha_offset + 32 .. sha_offset + 48]);
}

fn exerciseUploadedSha256(comptime streaming: bool) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{ .{}, .{ .body = result_json } };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    if (streaming) {
        var publisher = try xet.StorePublisher.init(allocator, client.store(), .{ .compression = .none });
        defer publisher.deinit();
        try publisher.write("a");
        try publisher.write("b");
        try publisher.write("c");
        _ = try publisher.finish();
    } else {
        var package = try xet.pack(allocator, "abc", .{ .compression = .none });
        defer package.deinit(allocator);
        try xet.publish(allocator, &package, client.store());
    }
    try server.finish(2);
    try std.testing.expectEqual(@as(usize, 2), server.exchanges.items.len);
    try checkUploadedAbcSha256(server.exchanges.items[1].body);
}

test "pack publish uploads Git SHA-256 in Xet word order" {
    try exerciseUploadedSha256(false);
}

test "streaming Publisher uploads Git SHA-256 in Xet word order" {
    try exerciseUploadedSha256(true);
}

const raw_records = "\x00\x03\x00\x00\x00\x03\x00\x00AAA" ++
    "\x00\x03\x00\x00\x00\x03\x00\x00BBB";

test "decoded Git SHA-256 survives shard reserialization" {
    const allocator = std.testing.allocator;
    var package = try xet.pack(allocator, "abc", .{ .compression = .none });
    defer package.deinit(allocator);
    const reader = try xet.shard.Reader.init(package.shard_bytes);
    const info = (try reader.findFile(package.file_hash)) orelse return error.TestMissingFile;
    var decoded = try info.decode(allocator);
    defer decoded.deinit(allocator);
    decoded.value.sha256 = expected_abc_sha256;
    const bytes = try xet.shard.serialize(allocator, &.{decoded.value}, &.{});
    defer allocator.free(bytes);
    try checkUploadedAbcSha256(bytes);
}

test "Publisher write-time xorb flush failure has clean ownership" {
    var tracker = support.TrackingAllocator{ .backing = std.testing.allocator };
    defer tracker.deinit();
    var destination = support.MemoryStore{
        .allocator = std.testing.allocator,
        .fail_on_put = 0,
    };
    defer destination.deinit();
    const one_chunk = blk: {
        const input = @as([128 * 1024]u8, @splat('x'));
        const chunks = try xet.chunkBuffer(std.testing.allocator, &input);
        defer std.testing.allocator.free(chunks);
        try std.testing.expectEqual(@as(usize, 1), chunks.len);
        break :blk chunks[0].data;
    };
    var publisher = try xet.StorePublisher.init(tracker.allocator(), destination.store(), .{
        .compression = .none,
        .max_xorb_size = @intCast(one_chunk.len),
    });
    try std.testing.expectError(error.InjectedStoreFailure, publisher.write(one_chunk));
    try std.testing.expectEqual(@as(usize, 1), destination.puts);
    try std.testing.expectEqual(xet.ObjectKind.xorb, destination.last_attempted_kind.?);
    publisher.deinit();
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

const second_record_range = xet.reconstruction.ByteRange{ .start = 11, .end = 21 };
const deterministic_gzip_records = [_]u8{
    31, 139, 8, 0,  0,   0,   0,   0, 2, 3,   99, 96,  102, 96, 96, 0, 98, 71,
    71, 71,  6, 40, 211, 201, 201, 9, 0, 137, 80, 230, 211, 22, 0,  0, 0,
};

fn exerciseRawRecordHttp() !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{.{
        .body = &deterministic_gzip_records,
        .content_encoding = "gzip",
    }};
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const request = xet.reconstruction.Request{
        .hash = xet.hash.zero,
        .url = url,
        .byte_range = second_record_range,
    };
    var output: support.SinkBuffer = .init(allocator);
    defer output.deinit();
    var rejected = false;
    const opener = client.opener();
    const maybe_source: ?*std.Io.Reader = opener.open(request) catch |err| blk: {
        try std.testing.expect(err == error.HttpContentEncodingUnsupported or err == error.InvalidResponse);
        rejected = true;
        break :blk null;
    };
    if (maybe_source) |source| {
        defer opener.close(source);
        var buffer: [32]u8 = undefined;
        while (true) {
            const count = try source.readSliceShort(&buffer);
            if (count == 0) break;
            try output.writer.writeAll(buffer[0..count]);
        }
    }
    if (rejected) {
        try std.testing.expectEqual(@as(usize, 0), output.written().len);
    } else {
        try std.testing.expectEqualStrings(raw_records[11..22], output.written());
    }
    try server.finish(1);
    try std.testing.expectEqualStrings("bytes=11-21", server.exchanges.items[0].range.?);
    const accept_encoding = server.exchanges.items[0].accept_encoding orelse "identity";
    try std.testing.expect(std.mem.indexOf(u8, accept_encoding, "identity") != null);
    try std.testing.expect(std.mem.indexOf(u8, accept_encoding, "gzip") == null);
}

test "streaming raw xorb range handles gzip 200 without wrong bytes" {
    try exerciseRawRecordHttp();
}

test "compressed reconstruction JSON still negotiates gzip" {
    const allocator = std.testing.allocator;
    const compressed = [_]u8{
        31, 139, 8,   0,   0,   0,   0,  0,   2,   3,  171, 86, 42, 73,  45,  202,
        45, 86,  178, 138, 142, 213, 81, 170, 200, 47, 74,  2,  50, 171, 107, 107,
        1,  187, 174, 49,  186, 23,  0,  0,   0,
    };
    const responses = [_]support.HttpResponse{.{ .body = &compressed, .content_encoding = "gzip" }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(xet.hash.data("file"), null);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), plan.terms.len);
    try server.finish(1);
    const accepted = server.exchanges.items[0].accept_encoding orelse return error.TestMissingAcceptEncoding;
    try std.testing.expect(std.mem.indexOf(u8, accepted, "gzip") != null);
}

test "V2 shard upload requests identity and rejects encoded responses" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{
        .{ .body = result_json },
        .{ .body = result_json, .content_encoding = "gzip" },
    };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try client.putShard("shard");
    if (client.putShard("shard")) |_| {
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expect(err == error.InvalidResponse or err == error.HttpContentEncodingUnsupported);
    }
    try server.finish(2);
    for (server.exchanges.items) |exchange| {
        const accepted = exchange.accept_encoding orelse return error.TestMissingAcceptEncoding;
        try std.testing.expect(std.mem.indexOf(u8, accepted, "identity") != null);
        try std.testing.expect(std.mem.indexOf(u8, accepted, "gzip") == null);
    }
}

fn exerciseWholeObjectHttp() !void {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{.{ .body = raw_records }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    const request = xet.reconstruction.Request{
        .hash = xet.hash.zero,
        .url = url,
        .byte_range = null,
    };
    var output: support.SinkBuffer = .init(allocator);
    defer output.deinit();
    const opener = client.opener();
    const source = try opener.open(request);
    defer opener.close(source);
    var buffer: [7]u8 = undefined;
    while (true) {
        const count = try source.readSliceShort(&buffer);
        if (count == 0) break;
        try output.writer.writeAll(buffer[0..count]);
    }
    try std.testing.expectEqualStrings(raw_records, output.written());
    try server.finish(1);
    try std.testing.expect(server.exchanges.items[0].range == null);
    try std.testing.expectEqualStrings("identity", server.exchanges.items[0].accept_encoding.?);
}

test "streaming transport opens full object for unknown encoded length" {
    try exerciseWholeObjectHttp();
}

fn makeLargeFileTerms(
    allocator: std.mem.Allocator,
    count: usize,
    object: xet.shard.Xorb,
    with_sha256: bool,
) !struct { file: xet.shard.File, segments: []xet.shard.Segment, checks: []xet.Hash } {
    const segments = try allocator.alloc(xet.shard.Segment, count);
    errdefer allocator.free(segments);
    const checks = try allocator.alloc(xet.Hash, count);
    errdefer allocator.free(checks);
    for (segments, checks, 0..) |*segment, *check, index| {
        segment.* = .{
            .xorb_hash = object.hash,
            .unpacked_segment_bytes = 1,
            .chunk_index_start = 0,
            .chunk_index_end = 1,
        };
        check.* = support.syntheticHash(9, index);
    }
    return .{
        .file = .{
            .hash = support.syntheticHash(8, count),
            .segments = segments,
            .verification = checks,
            .sha256 = if (with_sha256) support.syntheticHash(10, count) else null,
        },
        .segments = segments,
        .checks = checks,
    };
}

test "exact 64 MiB footerless shard body publishes successfully" {
    const allocator = std.testing.allocator;
    const count = 699_048;
    const chunk = xet.shard.Chunk{
        .hash = support.syntheticHash(7, 0),
        .byte_range_start = 0,
        .unpacked_segment_bytes = 1,
    };
    const object = xet.shard.Xorb{
        .hash = support.syntheticHash(6, 0),
        .chunks = &.{chunk},
        .raw_size = 1,
        .serialized_size = 9,
    };
    const terms = try makeLargeFileTerms(allocator, count, object, false);
    defer {
        allocator.free(terms.segments);
        allocator.free(terms.checks);
    }
    const bytes = try xet.shard.serialize(allocator, &.{terms.file}, &.{});
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 67_109_012), bytes.len);
    var package = xet.Package{
        .file_hash = terms.file.hash,
        .size = count,
        .objects = &.{},
        .shard_bytes = bytes,
    };
    const responses = [_]support.HttpResponse{.{ .body = result_json }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try xet.publish(allocator, &package, client.store());
    try server.finish(1);
    const body = server.exchanges.items[0].body;
    try std.testing.expectEqual(@as(usize, 67_108_800), body.len);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, body[40..48], .little));
    for (0..count) |index| {
        const offset = 96 + index * 48;
        try std.testing.expectEqualSlices(u8, &object.hash, body[offset..][0..32]);
        try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, body[offset + 36 ..][0..4], .little));
    }
}

test "footerless and empty-lookup shards validate and plan with unknown encoded lengths" {
    const allocator = std.testing.allocator;
    const chunk_hash = xet.hash.data("hello");
    const xorb_hash = try xet.hash.xorb(allocator, &.{.{ .hash = chunk_hash, .size = 5 }});
    const file_hash = try xet.hash.file(allocator, &.{.{ .hash = chunk_hash, .size = 5 }});
    const checks = [_]xet.Hash{xet.hash.verification(&.{chunk_hash})};

    const full = try xet.shard.serialize(allocator, &.{.{
        .hash = file_hash,
        .segments = &.{.{
            .xorb_hash = xorb_hash,
            .unpacked_segment_bytes = 5,
            .chunk_index_start = 0,
            .chunk_index_end = 1,
        }},
        .verification = &checks,
    }}, &.{.{
        .hash = xorb_hash,
        .chunks = &.{.{
            .hash = chunk_hash,
            .byte_range_start = 0,
            .unpacked_segment_bytes = 5,
        }},
        .raw_size = 5,
        .serialized_size = 0, // Unknown encoded length
    }});
    defer allocator.free(full);

    const full_reader = try xet.shard.Reader.init(full);
    const body_len = full_reader.footer.file_lookup_offset;

    const footerless = try allocator.dupe(u8, full[0..body_len]);
    defer allocator.free(footerless);
    std.mem.writeInt(u64, footerless[40..48], 0, .little);

    const empty_lookup = try allocator.alloc(u8, body_len + xet.shard.footer_size);
    defer allocator.free(empty_lookup);
    @memcpy(empty_lookup[0..body_len], full[0..body_len]);
    @memcpy(empty_lookup[body_len..], full[full.len - xet.shard.footer_size ..]);
    const footer = empty_lookup[body_len..];
    std.mem.writeInt(u64, footer[32..40], 0, .little); // file_count
    std.mem.writeInt(u64, footer[40..48], body_len, .little); // xorb_lookup_offset
    std.mem.writeInt(u64, footer[48..56], 0, .little); // xorb_count
    std.mem.writeInt(u64, footer[56..64], body_len, .little); // chunk_lookup_offset
    std.mem.writeInt(u64, footer[64..72], 0, .little); // chunk_count
    std.mem.writeInt(u64, footer[192..200], body_len, .little); // footer_offset

    for ([_][]const u8{ footerless, empty_lookup }) |bytes| {
        const reader = try xet.shard.Reader.init(bytes);
        try std.testing.expect(!reader.footer.has_file_lookup);
        try std.testing.expect(!reader.footer.has_xorb_lookup);
        try std.testing.expectEqual(@as(usize, 1), reader.footer.file_count);
        try std.testing.expectEqual(@as(usize, 1), reader.footer.xorb_count);
        try std.testing.expectEqual(body_len, try xet.store.wireShardSize(bytes));
        try std.testing.expectEqual(file_hash, try xet.reconstruction.validateShardFile(allocator, bytes, file_hash));
        var manifest = try xet.reconstruction.planFromShard(allocator, bytes, file_hash);
        defer manifest.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), manifest.plan.terms.len);
        try std.testing.expect(manifest.plan.locations[0].byte_range == null);
    }
}

test "unknown encoded length uses transport and verifies nonzero chunk start" {
    const allocator = std.testing.allocator;
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "AAA", .hash = xet.hash.data("AAA") },
        .{ .data = "BBB", .hash = xet.hash.data("BBB") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const file_hash = try xet.hash.file(allocator, &.{.{ .hash = xet.hash.data("BBB"), .size = 3 }});
    const checks = [_]xet.Hash{xet.hash.verification(&.{xet.hash.data("BBB")})};
    const bytes = try xet.shard.serialize(allocator, &.{.{
        .hash = file_hash,
        .segments = &.{.{
            .xorb_hash = object.hash,
            .unpacked_segment_bytes = 3,
            .chunk_index_start = 1,
            .chunk_index_end = 2,
        }},
        .verification = &checks,
    }}, &.{.{
        .hash = object.hash,
        .chunks = object.chunks,
        .raw_size = @intCast(object.raw_size),
        .serialized_size = 0,
    }});
    defer allocator.free(bytes);
    var manifest = try xet.reconstruction.planFromShard(allocator, bytes, file_hash);
    defer manifest.deinit(allocator);
    try std.testing.expect(manifest.plan.locations[0].byte_range == null);
    var fetch_context = support.SliceOpener{ .bytes = object.bytes };
    const output = try xet.reconstruction.reconstruct(allocator, &manifest.plan, fetch_context.opener());
    defer allocator.free(output);
    try std.testing.expectEqualStrings("BBB", output);
    try std.testing.expectEqual(@as(@TypeOf(fetch_context.last_range), null), fetch_context.last_range);
    var open_context = support.SliceOpener{ .bytes = object.bytes };
    var sink = support.SinkBuffer.init(allocator);
    defer sink.deinit();
    const count = try xet.reconstruction.consumeVerified(
        allocator,
        &manifest.plan,
        open_context.opener(),
        manifest.chunks,
        &sink.writer,
    );
    try std.testing.expectEqual(@as(u64, 3), count);
    try std.testing.expectEqualStrings("BBB", sink.written());
    try std.testing.expectEqual(@as(@TypeOf(open_context.last_range), null), open_context.last_range);
    try std.testing.expectEqual(open_context.requests, open_context.closes);
}

fn checkXorbBody(body: []const u8) !void {
    const golden = [_]u8{ 0, 3, 0, 0, 0, 3, 0, 0, 'A', 'A', 'A' };
    try std.testing.expectEqualSlices(u8, &golden, body);
}

fn checkShardBody(shard_bytes: []const u8) !void {
    const cas_bookend = @as([32]u8, @splat(0xff)) ++ @as([16]u8, @splat(0));
    const cas_end = std.mem.lastIndexOf(u8, shard_bytes, &cas_bookend) orelse
        return error.TestMissingCasBookend;
    const footer_offset = std.mem.readInt(u64, shard_bytes[40..48], .little);
    try std.testing.expectEqual(@as(u64, 0), footer_offset);
    try std.testing.expectEqual(cas_end + cas_bookend.len, shard_bytes.len);
    if (cas_end < 96) return error.TestTruncatedCasSection;
    const xorb_record = cas_end - 96;
    try std.testing.expectEqual(@as(u32, 11), std.mem.readInt(u32, shard_bytes[xorb_record + 44 ..][0..4], .little));
}

fn capturePackHttp(allocator: std.mem.Allocator, io: std.Io, origin: []const u8) !void {
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    var client = try xet.http.Client.init(allocator, io, origin, "");
    defer client.deinit();
    try xet.publish(allocator, &package, client.store());
}

fn captureStreamingHttp(allocator: std.mem.Allocator, io: std.Io, origin: []const u8) !void {
    var client = try xet.http.Client.init(allocator, io, origin, "");
    defer client.deinit();
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
}

fn checkCapturedHttpObjects(exchanges: []const support.HttpExchange, comptime streaming: bool) !void {
    try std.testing.expectEqual(@as(usize, 3), exchanges.len);
    const offset: usize = if (streaming) 1 else 0;
    if (streaming) {
        try std.testing.expect(std.mem.startsWith(u8, exchanges[0].target, "/v1/chunks/default-merkledb/"));
        try std.testing.expectEqualStrings("/v2/shards", exchanges[2].target);
        try checkShardBody(exchanges[2].body);
    } else {
        try std.testing.expectEqualStrings("/v2/shards", exchanges[1].target);
        try std.testing.expectEqualStrings("/v1/shards", exchanges[2].target);
        try checkShardBody(exchanges[2].body);
    }
    try std.testing.expect(std.mem.startsWith(u8, exchanges[offset].target, "/v1/xorbs/default/"));
    try checkXorbBody(exchanges[offset].body);
}

test "CAS upload bytes are canonical for pack publish" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{ .{}, .{ .status = .not_found }, .{} };
    // Pack publication deliberately performs no global lookup
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    try capturePackHttp(allocator, io, server.origin);
    try server.finish(3);
    try checkCapturedHttpObjects(server.exchanges.items, false);
}

test "CAS upload bytes are canonical for streaming Publisher" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{ .status = .not_found } };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(null);
    try captureStreamingHttp(allocator, io, server.origin);
    try server.finish(server.exchanges.items.len);
    try checkCapturedHttpObjects(server.exchanges.items, true);
}

test "simple HTTP upload and download keep client and operation allocators separate" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var responses = [_]support.HttpResponse{
        .{ .status = .not_found },
        .{},
        .{ .status = .not_found },
        .{ .body = result_json },
        .{ .status = .not_found },
        .{},
        .{},
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconstructionJson(allocator, url, &object, 3, 0);
    defer allocator.free(body);
    responses[5].body = body;
    responses[6].body = object.bytes;
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    const operation_allocator = tracker.allocator();

    const published = try client.upload(operation_allocator, "AAA", .{ .compression = .none });
    const output = try client.download(operation_allocator, published.file_hash);
    defer operation_allocator.free(output);
    try std.testing.expectEqualStrings("AAA", output);
    try server.finish(7);
    try checkXorbBody(server.exchanges.items[1].body);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
}

fn makeGlobalDedupShard(
    allocator: std.mem.Allocator,
    object: *const xet.xorb.Serialized,
    key: ?xet.Hash,
) ![]u8 {
    const chunks = try allocator.dupe(xet.shard.Chunk, object.chunks);
    defer allocator.free(chunks);
    if (key) |hmac_key| {
        for (chunks) |*chunk| chunk.hash = xet.hash.keyed(hmac_key, &chunk.hash);
    }
    const metadata = xet.shard.Xorb{
        .hash = object.hash,
        .chunks = chunks,
        .raw_size = @intCast(object.raw_size),
        .serialized_size = @intCast(object.body_length),
    };
    const bytes = try xet.shard.serialize(allocator, &.{}, &.{metadata});
    if (key) |hmac_key| @memcpy(bytes[bytes.len - xet.shard.footer_size + 72 ..][0..32], &hmac_key);
    return bytes;
}

test "Client.upload reuses a server-provided global chunk match" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const hmac_key = xet.hash.data("global shard key");
    var responses = [_]support.HttpResponse{
        .{ .body = try makeGlobalDedupShard(allocator, &object, hmac_key) },
        .{ .status = .not_found },
        .{ .body = result_json },
    };
    defer allocator.free(@constCast(responses[0].body));
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(responses[0].body);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const result = try client.upload(allocator, "AAA", .{ .compression = .none });
    try server.finish(server.exchanges.items.len);
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

test "Client.upload reuses a contiguous run from one global lookup" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const data = try deterministicChunks(allocator);
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
        .{ .body = try makeGlobalDedupShard(allocator, &object, null) },
        .{ .status = .not_found },
        .{ .status = .not_found },
        .{},
        .{ .body = result_json },
    };
    defer allocator.free(@constCast(responses[0].body));
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(responses[0].body);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const result = try client.upload(allocator, data, .{ .compression = .none });
    try server.finish(server.exchanges.items.len);
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
    const data = try deterministicChunks(allocator);
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
        .{ .body = try makeGlobalDedupShard(allocator, &original_xorbs.items[0], null) },
        .{ .status = .not_found },
        .{ .status = .not_found },
        .{},
        .{},
        .{},
        .{ .body = result_json },
    };
    defer allocator.free(@constCast(responses[0].body));
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.startGlobalDedup(responses[0].body);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const result = try client.upload(allocator, data, .{ .compression = .none, .max_xorb_size = 128 * 1024 });
    try server.finish(server.exchanges.items.len);
    var lookups: usize = 0;
    var uploads: usize = 0;
    for (server.exchanges.items[0 .. server.exchanges.items.len - 1]) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/chunks/default-merkledb/")) lookups += 1;
        if (std.mem.startsWith(u8, exchange.target, "/v1/xorbs/default/")) uploads += 1;
    }
    try std.testing.expect(lookups >= 1);
    try std.testing.expect(uploads >= 1);
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
    try server.finish(server.exchanges.items.len);
    var lookups: usize = 0;
    for (server.exchanges.items) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/chunks/default-merkledb/")) lookups += 1;
    }
    try std.testing.expect(lookups <= 4);
}

test "global match survives one-byte streaming writes" {
    const allocator = std.testing.allocator;
    const data = try deterministicChunks(allocator);
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
    const shard_bytes = try makeGlobalDedupShard(allocator, &object, null);
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
    _ = try index.addOwned(allocator, try makeGlobalDedupShard(allocator, &object, null), 0);

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
    const data = try deterministicChunks(allocator);
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
        const bytes = try makeGlobalDedupShard(allocator, object, null);
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

test "invalid dedup source matches are rejected and released" {
    const allocator = std.testing.allocator;
    const Context = struct {
        fn query(_: *anyopaque, query_allocator: std.mem.Allocator, _: []const xet.Hash) !?xet.DedupMatch {
            const nodes = try query_allocator.alloc(xet.Node, 1);
            nodes[0] = .{ .hash = xet.hash.data("wrong"), .size = 3 };
            return .{ .nodes = nodes, .xorb_hash = xet.hash.zero, .chunk_index_start = 0 };
        }
    };
    var dummy: u8 = 0;
    const source = xet.DedupSource{ .context = &dummy, .query_fn = Context.query };
    try std.testing.expectError(error.InvalidDedupMatch, source.query(allocator, &.{xet.hash.data("AAA")}));
}

fn exerciseGlobalAllocationFailure(fail_at: ?usize) !usize {
    const allocator = std.testing.allocator;
    const data = try deterministicChunks(allocator);
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
    const shard_bytes = try makeGlobalDedupShard(allocator, &object, null);
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

test "BatchPublisher rejects appends after completion" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = xet.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.finish();

    const segments = try allocator.alloc(xet.shard.Segment, 1);
    segments[0] = .{
        .xorb_hash = xet.hash.data("xorb"),
        .unpacked_segment_bytes = 0,
        .chunk_index_start = 0,
        .chunk_index_end = 0,
    };
    var plan = xet.UploadPlan{
        .file = .{
            .hash = xet.hash.data("file"),
            .segments = segments,
        },
        .new_xorbs = &.{},
    };
    defer plan.deinit(allocator);
    try std.testing.expectError(error.AlreadyFinished, batch.append(&plan));
    try std.testing.expectEqual(@as(usize, 1), plan.file.segments.len);
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

test "direct reuse flushes pending input before the reused segment" {
    const allocator = std.testing.allocator;
    const nodes = [_]xet.Node{.{ .hash = xet.hash.data("AAA"), .size = 3 }};
    const file_hash = try xet.hash.file(allocator, &.{
        .{ .hash = xet.hash.data("BBB"), .size = 3 },
        nodes[0],
    });
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    try publisher.write("BBB");
    try publisher.reuse(xet.hash.data("existing xorb"), 0, &nodes);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(file_hash, plan.file.hash);
    try std.testing.expectEqual(@as(usize, 2), plan.file.segments.len);
    try std.testing.expectEqual(@as(u64, 6), plan.size);
    try std.testing.expectEqual(@as(usize, 1), plan.new_xorbs.len);
    try std.testing.expectEqual(xet.hash.data("BBB"), plan.new_xorbs[0].chunks[0].hash);
    try std.testing.expectEqual(@as(u32, 3), plan.new_xorbs[0].chunks[0].unpacked_segment_bytes);
}

test "continued reuse rejects segment byte overflow without mutation" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{ .compression = .none });
    defer publisher.deinit();
    const object_hash = xet.hash.data("existing xorb");
    const chunk_size = 128 * 1024;
    const node_count = std.math.maxInt(u32) / chunk_size;
    for (0..node_count) |index| {
        const node = xet.Node{
            .hash = support.syntheticHash(7, index),
            .size = chunk_size,
        };
        try publisher.reuse(object_hash, @intCast(index), &.{node});
    }
    const extra = xet.Node{
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

fn freeTestShardFile(allocator: std.mem.Allocator, file: xet.shard.File) void {
    allocator.free(file.segments);
    if (file.verification.len != 0) allocator.free(file.verification);
}

fn decodeTestShardFile(allocator: std.mem.Allocator, info: xet.shard.FileInfo) !xet.shard.File {
    var decoded = try info.decode(allocator);
    const file = decoded.value;
    decoded.value.segments = &.{};
    decoded.value.verification = &.{};
    return file;
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

test "UploadSession uploads only unmatched chunks and publishes one combined shard" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const global_chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var global_object = try xet.xorb.serialize(allocator, &global_chunks, .none);
    defer global_object.deinit(allocator);
    const global_shard = try makeGlobalDedupShard(allocator, &global_object, null);
    defer allocator.free(global_shard);
    const new_chunks = [_]xet.xorb.Chunk{.{ .data = "BBB", .hash = xet.hash.data("BBB") }};
    var new_object = try xet.xorb.serialize(allocator, &new_chunks, .none);
    defer new_object.deinit(allocator);

    var responses = [_]support.HttpResponse{
        .{ .body = global_shard },
        .{ .status = .not_found },
        .{},
        .{ .body = result_json },
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
    try server.finish(4);

    try std.testing.expectEqual(@as(usize, 2), session.results().len);
    const inputs = [_][]const u8{ "AAA", "BBB" };
    const expected_objects = [_]*const xet.xorb.Serialized{ &global_object, &new_object };
    const uploaded_shard = server.exchanges.items[3].body;
    const reader = try xet.shard.Reader.init(uploaded_shard);
    try std.testing.expectEqual(@as(usize, 2), reader.footer.file_count);
    try std.testing.expectEqual(@as(usize, 1), reader.footer.xorb_count);
    try std.testing.expect((try reader.findXorb(global_object.hash)) == null);
    const uploaded_info = (try reader.findXorb(new_object.hash)).?;
    try std.testing.expectEqual(@as(u32, 1), uploaded_info.count);
    try std.testing.expectEqual(xet.hash.data("BBB"), (try uploaded_info.chunk(0)).hash);
    for (session.results(), inputs, expected_objects) |result, input, object| {
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
    var decoded_files: [2]xet.shard.File = undefined;
    for (session.results(), &decoded_files) |result, *file| {
        file.* = try decodeTestShardFile(allocator, (try reader.findFile(result.file_hash)).?);
    }
    defer for (&decoded_files) |file| freeTestShardFile(allocator, file);
    const full_shard = try xet.shard.serialize(allocator, &decoded_files, &metadata);
    defer allocator.free(full_shard);
    for (session.results(), inputs) |result, input| {
        _ = try xet.reconstruction.validateShardFile(allocator, full_shard, result.file_hash);
        try reconstructHttpShard(allocator, full_shard, result.file_hash, input, &expected_objects);
    }
}

fn exerciseRemoteMisses(status: std.http.Status, inputs: []const []const u8, expected_lookups: usize) !void {
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
    try server.finish(server.exchanges.items.len);
    try std.testing.expectEqual(inputs.len, session.results().len);
    var lookups: usize = 0;
    for (server.exchanges.items) |exchange| {
        if (std.mem.startsWith(u8, exchange.target, "/v1/chunks/default-merkledb/")) lookups += 1;
    }
    try std.testing.expectEqual(expected_lookups, lookups);
}

fn exerciseUploadSessionAllocationFailure(fail_at: ?usize) !usize {
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
    var expected_failure = false;
    _ = blk: {
        var session = client.uploadSession(operation, .{ .compression = .none }) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            expected_failure = true;
            break :blk;
        };
        defer session.deinit();
        session.addFile("AAA") catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            expected_failure = true;
            break :blk;
        };
        session.addFile("BBB") catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            expected_failure = true;
            break :blk;
        };
        session.finish() catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            expected_failure = true;
            break :blk;
        };
        try std.testing.expectEqual(@as(usize, 2), session.results().len);
    };
    if (fail_at != null) try std.testing.expect(expected_failure);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    return tracker.allocation_count;
}

test "UploadSession operation allocation failures are clean" {
    const allocations = try exerciseUploadSessionAllocationFailure(null);
    for (0..allocations) |fail_at| _ = try exerciseUploadSessionAllocationFailure(fail_at);
}

test "UploadSession avoids repeat remote lookups and retries failed files" {
    const repeated = [_][]const u8{ "AAA", "AAA" };
    try exerciseRemoteMisses(.not_found, &repeated, 1);
    const distinct = [_][]const u8{ "AAA", "BBB" };
    try exerciseRemoteMisses(.internal_server_error, &distinct, 2);
}

test "global lookup failure and expired shard fall back to normal upload" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const expired = try makeGlobalDedupShard(allocator, &object, null);
    defer allocator.free(expired);
    std.mem.writeInt(u64, expired[expired.len - xet.shard.footer_size + 112 ..][0..8], 1, .little);
    var responses = [_]support.HttpResponse{
        .{ .status = .internal_server_error },
        .{},
        .{ .body = result_json },
        .{ .body = expired },
        .{},
        .{ .body = result_json },
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
    _ = try client.upload(allocator, "AAA", .{ .compression = .none });
    try server.finish(6);
    try checkXorbBody(server.exchanges.items[1].body);
    try checkXorbBody(server.exchanges.items[4].body);
}

test "simple HTTP download releases output after a hash mismatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    responses[1].body = try makeReconstructionJson(allocator, url, &object, 3, 0);
    defer allocator.free(@constCast(responses[1].body));
    responses[2].body = object.bytes;
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();

    try std.testing.expectError(error.HashMismatch, client.download(allocator, xet.hash.zero));
    try server.finish(3);
}

fn makePartialShard(allocator: std.mem.Allocator, object: *const xet.xorb.Serialized) !struct {
    bytes: []u8,
    file_hash: xet.Hash,
} {
    const file_hash = try xet.hash.file(allocator, &.{.{ .hash = xet.hash.data("BBB"), .size = 3 }});
    const checks = [_]xet.Hash{xet.hash.verification(&.{xet.hash.data("BBB")})};
    return .{
        .file_hash = file_hash,
        .bytes = try xet.shard.serialize(allocator, &.{.{
            .hash = file_hash,
            .segments = &.{.{
                .xorb_hash = object.hash,
                .unpacked_segment_bytes = 3,
                .chunk_index_start = 1,
                .chunk_index_end = 2,
            }},
            .verification = &checks,
        }}, &.{.{
            .hash = object.hash,
            .chunks = object.chunks,
            .raw_size = @intCast(object.raw_size),
            .serialized_size = @intCast(object.bytes.len),
        }}),
    };
}

fn initPartialFixture(allocator: std.mem.Allocator) !struct {
    object: xet.xorb.Serialized,
    shard_bytes: []u8,
    file_hash: xet.Hash,
} {
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "AAA", .hash = xet.hash.data("AAA") },
        .{ .data = "BBB", .hash = xet.hash.data("BBB") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    errdefer object.deinit(allocator);
    const generated = try makePartialShard(allocator, &object);
    return .{ .object = object, .shard_bytes = generated.bytes, .file_hash = generated.file_hash };
}

fn exercisePartialShard(allocator: std.mem.Allocator, comptime streaming: bool) !void {
    var fixture = try initPartialFixture(allocator);
    defer fixture.object.deinit(allocator);
    defer allocator.free(fixture.shard_bytes);
    var manifest = try xet.reconstruction.planFromShard(allocator, fixture.shard_bytes, fixture.file_hash);
    defer manifest.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), manifest.size);
    try std.testing.expectEqual(@as(usize, 1), manifest.chunks.len);
    try std.testing.expectEqual(xet.hash.data("BBB"), manifest.chunks[0].hash);
    try std.testing.expectEqual(@as(u32, 1), manifest.plan.terms[0].range.start);
    try std.testing.expectEqual(@as(u32, 2), manifest.plan.terms[0].range.end);
    const expected_range = xet.reconstruction.ByteRange{ .start = 0, .end = @intCast(fixture.object.bytes.len - 1) };
    if (!streaming) {
        var fetch_context = support.SliceOpener{ .bytes = fixture.object.bytes };
        const output = try xet.reconstruction.reconstruct(allocator, &manifest.plan, fetch_context.opener());
        defer allocator.free(output);
        try std.testing.expectEqualStrings("BBB", output);
        try std.testing.expectEqual(@as(?xet.reconstruction.ByteRange, expected_range), fetch_context.last_range);
        return;
    }
    var open_context = support.SliceOpener{ .bytes = fixture.object.bytes };
    var sink = support.SinkBuffer.init(allocator);
    defer sink.deinit();
    const count = try xet.reconstruction.consumeVerified(
        allocator,
        &manifest.plan,
        open_context.opener(),
        manifest.chunks,
        &sink.writer,
    );
    try std.testing.expectEqual(@as(u64, 3), count);
    try std.testing.expectEqualStrings("BBB", sink.written());
    try std.testing.expectEqual(@as(?xet.reconstruction.ByteRange, expected_range), open_context.last_range);
    try std.testing.expectEqual(open_context.requests, open_context.closes);
}

test "buffered shard segment starting inside a xorb reconstructs BBB" {
    try exercisePartialShard(std.testing.allocator, false);
}

test "verified streaming shard segment starting inside a xorb reconstructs BBB" {
    try exercisePartialShard(std.testing.allocator, true);
}

fn makeHttpRangePlan(allocator: std.mem.Allocator, object: *const xet.xorb.Serialized, url: []const u8) !xet.reconstruction.Plan {
    return xet.reconstruction.Plan.init(allocator, &.{.{
        .hash = object.hash,
        .unpacked_length = 3,
        .range = .{ .start = 1, .end = 2 },
    }}, &.{.{
        .hash = object.hash,
        .range = .{ .start = 1, .end = 2 },
        .url = url,
        .byte_range = .{ .start = 11, .end = 21 },
    }});
}

const RangeScenario = enum { matching, ignored, wrong };

fn exerciseHttpRanges(allocator: std.mem.Allocator, io: std.Io, scenario: RangeScenario) !void {
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "AAA", .hash = xet.hash.data("AAA") },
        .{ .data = "BBB", .hash = xet.hash.data("BBB") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var content_range_buffer: [80]u8 = undefined;
    const content_range = if (scenario == .wrong)
        try std.fmt.bufPrint(&content_range_buffer, "bytes 0-10/{d}", .{object.bytes.len})
    else
        try std.fmt.bufPrint(&content_range_buffer, "bytes 11-21/{d}", .{object.bytes.len});
    const response = switch (scenario) {
        .matching => support.HttpResponse{
            .status = .partial_content,
            .body = object.bytes[11..22],
            .content_range = content_range,
        },
        .ignored => support.HttpResponse{ .status = .ok, .body = object.bytes },
        .wrong => support.HttpResponse{
            .status = .partial_content,
            .body = object.bytes[0..11],
            .content_range = content_range,
        },
    };
    const responses = [_]support.HttpResponse{response};
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    var plan = try makeHttpRangePlan(allocator, &object, url);
    defer plan.deinit(allocator);
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var sink = support.SinkBuffer.init(allocator);
    defer sink.deinit();
    const result = xet.reconstruction.consume(allocator, &plan, client.opener(), &sink.writer);
    switch (scenario) {
        .matching => {
            const count = try result;
            try std.testing.expectEqual(@as(u64, 3), count);
            try std.testing.expectEqualStrings("BBB", sink.written());
        },
        .ignored => {
            if (result) |count| {
                try std.testing.expectEqual(@as(u64, 3), count);
                try std.testing.expectEqualStrings("BBB", sink.written());
            } else |_| {
                try std.testing.expectEqual(@as(usize, 0), sink.written().len);
            }
        },
        .wrong => {
            try std.testing.expectError(error.InvalidResponse, result);
            try std.testing.expectEqual(@as(usize, 0), sink.written().len);
        },
    }
    try server.finish(1);
    try std.testing.expectEqualStrings("bytes=11-21", server.exchanges.items[0].range.?);
}

test "streaming HTTP matching xorb range returns BBB" {
    try exerciseHttpRanges(std.testing.allocator, std.testing.io, .matching);
}

test "streaming HTTP ignored nonzero range never returns wrong bytes" {
    try exerciseHttpRanges(std.testing.allocator, std.testing.io, .ignored);
}

test "streaming HTTP wrong Content-Range is rejected" {
    try exerciseHttpRanges(std.testing.allocator, std.testing.io, .wrong);
}

test "streaming HTTP zero-start range trims an oversized full-object response" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{.{ .body = "0123456789extra" }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    const source = try client.opener().open(.{
        .hash = xet.hash.zero,
        .url = url,
        .byte_range = .{ .start = 0, .end = 9 },
    });
    defer client.opener().close(source);
    var output: support.SinkBuffer = .init(allocator);
    defer output.deinit();
    var buffer: [16]u8 = undefined;
    while (true) {
        const count = try source.readSliceShort(&buffer);
        if (count == 0) break;
        try output.writer.writeAll(buffer[0..count]);
    }
    try std.testing.expectEqual(@as(usize, 10), output.written().len);
    try std.testing.expectEqualStrings("0123456789", output.written());
    try server.finish(1);
    try std.testing.expectEqualStrings("bytes=0-9", server.exchanges.items[0].range.?);
}

const TestReconstructionTerm = struct {
    hash: []const u8,
    unpacked_length: u32,
    range: xet.reconstruction.Range,
};

fn writeReconstructionJson(
    allocator: std.mem.Allocator,
    offset: u64,
    terms: anytype,
    locations_name: []const u8,
    hash: []const u8,
    locations: anytype,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();

    var json: std.json.Stringify = .{ .writer = &out.writer };
    try json.beginObject();
    try json.objectField("offset_into_first_range");
    try json.write(offset);
    try json.objectField("terms");
    try json.write(terms);
    try json.objectField(locations_name);
    try json.beginObject();
    try json.objectField(hash);
    try json.write(locations);
    try json.endObject();
    try json.endObject();

    return out.toOwnedSlice();
}

fn makeReconstructionJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    object: *const xet.xorb.Serialized,
    declared_length: u32,
    offset: u64,
) ![]u8 {
    const hash = xet.hash.toHex(object.hash);
    const terms = [_]TestReconstructionTerm{.{
        .hash = &hash,
        .unpacked_length = declared_length,
        .range = .{ .start = 0, .end = 1 },
    }};
    const FetchInfo = struct {
        range: xet.reconstruction.Range,
        url: []const u8,
        url_range: xet.reconstruction.ByteRange,
    };
    const locations = [_]FetchInfo{.{
        .range = .{ .start = 0, .end = 1 },
        .url = url,
        .url_range = .{ .start = 0, .end = object.bytes.len - 1 },
    }};
    return writeReconstructionJson(allocator, offset, terms, "fetch_info", &hash, locations);
}

fn makeV2ReconstructionJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    object: *const xet.xorb.Serialized,
) ![]u8 {
    const hash = xet.hash.toHex(object.hash);
    const terms = [_]TestReconstructionTerm{
        .{
            .hash = &hash,
            .unpacked_length = 3,
            .range = .{ .start = 0, .end = 1 },
        },
        .{
            .hash = &hash,
            .unpacked_length = 3,
            .range = .{ .start = 1, .end = 2 },
        },
    };
    const Descriptor = struct {
        chunks: xet.reconstruction.Range,
        bytes: xet.reconstruction.ByteRange,
    };
    const Xorb = struct {
        url: []const u8,
        ranges: [2]Descriptor,
    };
    const locations = [_]Xorb{.{
        .url = url,
        .ranges = .{
            .{
                .chunks = .{ .start = 0, .end = 1 },
                .bytes = .{ .start = 0, .end = 10 },
            },
            .{
                .chunks = .{ .start = 1, .end = 2 },
                .bytes = .{ .start = 11, .end = 21 },
            },
        },
    }};
    return writeReconstructionJson(allocator, 0, terms, "xorbs", &hash, locations);
}

fn exerciseFileRange(allocator: std.mem.Allocator, io: std.Io, range: xet.reconstruction.ByteRange, expected: []const u8) !void {
    const chunks = [_]xet.xorb.Chunk{.{ .data = "abc", .hash = xet.hash.data("abc") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var content_range_buffer: [80]u8 = undefined;
    const content_range = try std.fmt.bufPrint(&content_range_buffer, "bytes 0-{d}/{d}", .{ object.bytes.len - 1, object.bytes.len });
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconstructionJson(allocator, url, &object, @intCast(object.raw_size), range.start);
    defer allocator.free(body);
    responses[1].body = body;
    responses[2].status = .partial_content;
    responses[2].body = object.bytes;
    responses[2].content_range = content_range;
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(xet.hash.data("file"), range);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(range.start, plan.offset_into_first_range);
    try std.testing.expectEqual(@as(u32, @intCast(object.raw_size)), plan.terms[0].unpacked_length);
    const output = try xet.reconstruction.reconstruct(allocator, &plan, client.opener());
    defer allocator.free(output);
    try server.finish(3);
    try std.testing.expect(std.mem.startsWith(u8, server.exchanges.items[0].target, "/v2/reconstructions/"));
    try std.testing.expect(std.mem.startsWith(u8, server.exchanges.items[1].target, "/v1/reconstructions/"));
    try std.testing.expectEqualStrings(expected, output);
    try std.testing.expectEqual(@as(?u64, expected.len), plan.output_length);
}

test "file range crossing EOF returns the available suffix" {
    try exerciseFileRange(std.testing.allocator, std.testing.io, .{ .start = 1, .end = 9 }, "bc");
}

test "file range in-bounds control returns the requested bytes" {
    try exerciseFileRange(std.testing.allocator, std.testing.io, .{ .start = 0, .end = 2 }, "abc");
}

test "short decoded term fails independently of EOF clipping" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "ab", .hash = xet.hash.data("ab") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var content_range_buffer: [80]u8 = undefined;
    const content_range = try std.fmt.bufPrint(&content_range_buffer, "bytes 0-{d}/{d}", .{ object.bytes.len - 1, object.bytes.len });
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconstructionJson(allocator, url, &object, 3, 0);
    defer allocator.free(body);
    responses[1].body = body;
    responses[2].status = .partial_content;
    responses[2].body = object.bytes;
    responses[2].content_range = content_range;
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(xet.hash.data("file"), .{ .start = 0, .end = 1 });
    defer plan.deinit(allocator);
    try std.testing.expectError(error.SizeMismatch, xet.reconstruction.reconstruct(allocator, &plan, client.opener()));
    try server.finish(3);
}

fn deterministicChunks(allocator: std.mem.Allocator) ![]u8 {
    const data = try allocator.alloc(u8, 600_000);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% index / 131);
    return data;
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
    const data = try deterministicChunks(allocator);
    defer allocator.free(data);
    const options = xet.PackOptions{ .compression = .none, .max_xorb_size = 64 * 1024 * 1024, .max_xorb_chunks = 1 };
    var result: MaxChunkComparison = .{
        .package = try xet.pack(allocator, data, options),
        .result = undefined,
        .packed_store = .{ .allocator = allocator },
        .streamed = .{ .allocator = allocator },
    };
    errdefer result.deinit(allocator);
    try xet.publish(allocator, &result.package, result.packed_store.store());
    var publisher = try xet.StorePublisher.init(
        allocator,
        result.streamed.store(),
        xet.PublisherOptions.fromPackOptions(options),
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

fn checkSha256Extension(shard_bytes: []const u8, file_hash: xet.Hash, expected: *const [32]u8) !void {
    const reader = try xet.shard.Reader.init(shard_bytes);
    const file = (try reader.findFile(file_hash)) orelse return error.TestMissingFile;
    try std.testing.expect(file.flags & xet.shard.metadata_extension_flag != 0);
    const actual = (try file.sha256()) orelse return error.TestMissingSha256;
    const converted = xet.hash.fromStandard(expected.*);
    try std.testing.expectEqualSlices(u8, &converted, &actual);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), shard_bytes[file.end - 16 .. file.end]);
}

test "empty pack includes the standard SHA-256 metadata digest" {
    const allocator = std.testing.allocator;
    var package = try xet.pack(allocator, "", .{});
    defer package.deinit(allocator);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &expected, .{});
    try checkSha256Extension(package.shard_bytes, package.file_hash, &expected);
}

test "pack includes independent SHA-256 file metadata" {
    const allocator = std.testing.allocator;
    const payload = "known nonempty payload for Git-backed Hub uploads";
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &expected, .{});
    var package = try xet.pack(allocator, payload, .{});
    defer package.deinit(allocator);
    try checkSha256Extension(package.shard_bytes, package.file_hash, &expected);
}

test "Publisher includes independent SHA-256 file metadata" {
    const allocator = std.testing.allocator;
    const payload = "known nonempty payload for Git-backed Hub uploads";
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &expected, .{});
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.StorePublisher.init(allocator, destination.store(), .{});
    defer publisher.deinit();
    try publisher.write(payload[0..7]);
    try publisher.write(payload[7..23]);
    try publisher.write(payload[23..]);
    const result = try publisher.finish();
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    for (destination.objects.items) |object| {
        if (object.kind == .shard) try checkSha256Extension(object.data, result.file_hash, &expected);
    }
}

test "publication splits wire shards at 64 MiB without losing metadata or order" {
    const allocator = std.testing.allocator;
    const count = 420_000;
    const xorbs = try allocator.alloc(xet.shard.Xorb, count);
    defer allocator.free(xorbs);
    const chunks = try allocator.alloc(xet.shard.Chunk, count);
    defer allocator.free(chunks);
    const segments = try allocator.alloc(xet.shard.Segment, count);
    defer allocator.free(segments);
    const expected_hashes = try allocator.alloc(xet.Hash, count);
    defer allocator.free(expected_hashes);
    const checks = try allocator.alloc(xet.Hash, count);
    defer allocator.free(checks);
    for (xorbs, chunks, segments, expected_hashes, checks, 0..) |*object, *chunk, *segment, *expected_hash, *check, index| {
        const chunk_hash = support.syntheticHash(1, index);
        expected_hash.* = chunk_hash;
        check.* = support.syntheticHash(4, index);
        chunk.* = .{ .hash = chunk_hash, .byte_range_start = 0, .unpacked_segment_bytes = 1 };
        var object_hash = support.syntheticHash(2, index);
        std.mem.writeInt(u64, object_hash[0..8], index + 1, .little);
        object.* = .{
            .hash = object_hash,
            .chunks = chunks[index .. index + 1],
            .raw_size = 1,
            .serialized_size = 9,
        };
        segment.* = .{
            .xorb_hash = object.hash,
            .unpacked_segment_bytes = 1,
            .chunk_index_start = 0,
            .chunk_index_end = 1,
        };
    }
    for (xorbs[1..], xorbs[0 .. xorbs.len - 1]) |current, previous| {
        if (xet.hash.eql(current.hash, previous.hash)) return error.TestDuplicateInputXorb;
    }
    const file_count = 3;
    const file_lengths = [file_count]usize{ count / 3, count / 3, count - 2 * (count / 3) };
    var files: [file_count]xet.shard.File = undefined;
    var file_start: usize = 0;
    for (&files, file_lengths, 0..) |*file, length, file_index| {
        file.* = .{
            .hash = support.syntheticHash(3, file_index),
            .segments = segments[file_start..][0..length],
            .verification = checks[file_start..][0..length],
            .sha256 = support.syntheticHash(5, file_index),
        };
        file_start += length;
    }
    const shard_bytes = try xet.shard.serialize(allocator, &files, xorbs);
    defer allocator.free(shard_bytes);
    try std.testing.expect(shard_bytes.len > 64 * 1024 * 1024);
    const empty_objects = try allocator.alloc(xet.xorb.Serialized, 0);
    defer allocator.free(empty_objects);
    const package = xet.Package{
        .file_hash = files[0].hash,
        .size = count,
        .objects = empty_objects,
        .shard_bytes = shard_bytes,
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    try xet.publish(allocator, &package, destination.store());

    var lookup: std.ArrayList(xet.shard.XorbInfo) = .empty;
    defer lookup.deinit(allocator);
    for (destination.objects.items) |object| {
        if (object.kind != .shard) continue;
        const reader = try xet.shard.Reader.init(object.data);
        var offset = reader.footer.xorb_info_offset;
        for (0..reader.footer.xorb_count) |_| {
            const chunk_count = std.mem.readInt(u32, object.data[offset + 36 ..][0..4], .little);
            const info = xet.shard.XorbInfo{
                .reader = reader,
                .offset = offset,
                .hash = object.data[offset..][0..32].*,
                .count = chunk_count,
                .raw_size = std.mem.readInt(u32, object.data[offset + 40 ..][0..4], .little),
                .serialized_size = std.mem.readInt(u32, object.data[offset + 44 ..][0..4], .little),
            };
            try lookup.append(allocator, info);
            offset += 48 * (@as(usize, chunk_count) + 1);
        }
    }
    try std.testing.expectEqual(count, lookup.items.len);
    std.mem.sort(xet.shard.XorbInfo, lookup.items, {}, struct {
        fn less(_: void, left: xet.shard.XorbInfo, right: xet.shard.XorbInfo) bool {
            return xet.hash.order(left.hash, right.hash) == .lt;
        }
    }.less);
    for (lookup.items[1..], lookup.items[0 .. lookup.items.len - 1]) |current, previous| {
        if (xet.hash.eql(current.hash, previous.hash)) return error.TestDuplicateSyntheticXorb;
    }
    const reconstructed = try allocator.alloc(xet.Hash, count);
    defer allocator.free(reconstructed);
    var found_files: [file_count]usize = @splat(0);
    var total_file_records: usize = 0;
    for (destination.objects.items) |object| {
        if (object.kind != .shard) continue;
        const reader = try xet.shard.Reader.init(object.data);
        total_file_records += reader.footer.file_count;
        var output_index: usize = 0;
        for (files, 0..) |expected_file, file_index| {
            const file = (try reader.findFile(expected_file.hash)) orelse {
                output_index += expected_file.segments.len;
                continue;
            };
            found_files[file_index] += 1;
            try std.testing.expectEqual(@as(u32, @intCast(expected_file.segments.len)), file.count);
            try std.testing.expectEqual(expected_file.sha256, try file.sha256());
            for (0..file.count) |index| {
                const segment = try file.segment(@intCast(index));
                try std.testing.expectEqual(expected_file.verification[index], try file.verification(@intCast(index)));
                var low: usize = 0;
                var high = lookup.items.len;
                while (low < high) {
                    const middle = low + (high - low) / 2;
                    switch (xet.hash.order(lookup.items[middle].hash, segment.xorb_hash)) {
                        .lt => low = middle + 1,
                        .gt => high = middle,
                        .eq => {
                            low = middle;
                            high = middle;
                        },
                    }
                }
                if (low == lookup.items.len or !xet.hash.eql(lookup.items[low].hash, segment.xorb_hash))
                    return error.TestMissingPublishedXorb;
                const info = lookup.items[low];
                for (segment.chunk_index_start..segment.chunk_index_end) |chunk_index| {
                    const chunk = try info.chunk(@intCast(chunk_index));
                    try std.testing.expectEqual(@as(u32, 1), chunk.unpacked_segment_bytes);
                    reconstructed[output_index] = chunk.hash;
                    output_index += 1;
                }
            }
        }
        try std.testing.expectEqual(count, output_index);
    }
    try std.testing.expectEqual(file_count, total_file_records);
    try std.testing.expectEqualSlices(usize, &[_]usize{ 1, 1, 1 }, &found_files);
    try std.testing.expectEqualSlices(xet.Hash, expected_hashes, reconstructed);
    for (destination.objects.items) |object| {
        if (object.kind == .shard) {
            const local_reader = try xet.shard.Reader.init(object.data);
            try std.testing.expect(local_reader.footer.has_file_lookup and local_reader.footer.has_xorb_lookup);
            try std.testing.expect(try xet.store.wireShardSize(object.data) <= 64 * 1024 * 1024);
        }
    }
    try std.testing.expect(destination.count(.shard) > 1);
}

fn twoChunkFixture(allocator: std.mem.Allocator) !struct {
    object: xet.xorb.Serialized,
    file_hash: xet.Hash,
} {
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "AAA", .hash = xet.hash.data("AAA") },
        .{ .data = "BBB", .hash = xet.hash.data("BBB") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    errdefer object.deinit(allocator);
    const file_hash = try xet.hash.file(allocator, &.{.{
        .hash = xet.hash.data("AAABBB"),
        .size = 6,
    }});
    return .{ .object = object, .file_hash = file_hash };
}

test "V2 reconstruction splits multi-range descriptors and reconstructs in order" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try twoChunkFixture(allocator);
    defer fixture.object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{}, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    responses[0].body = try makeV2ReconstructionJson(allocator, url, &fixture.object);
    defer allocator.free(@constCast(responses[0].body));
    responses[1].status = .partial_content;
    responses[1].body = fixture.object.bytes[0..11];
    responses[1].content_range = "bytes 0-10/22";
    responses[2].status = .partial_content;
    responses[2].body = fixture.object.bytes[11..22];
    responses[2].content_range = "bytes 11-21/22";
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(fixture.file_hash, null);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.locations.len);
    const output = try xet.reconstruction.reconstruct(allocator, &plan, client.opener());
    defer allocator.free(output);
    try std.testing.expectEqualStrings("AAABBB", output);
    try server.finish(3);
    try std.testing.expectEqualStrings("bytes=0-10", server.exchanges.items[1].range.?);
    try std.testing.expectEqualStrings("bytes=11-21", server.exchanges.items[2].range.?);
}

test "V1 reconstruction fallback is cached across plans" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try twoChunkFixture(allocator);
    defer fixture.object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconstructionJson(allocator, url, &fixture.object, 3, 0);
    defer allocator.free(body);
    responses[1].body = body;
    responses[2].body = body;
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var first = try client.getPlan(fixture.file_hash, null);
    defer first.deinit(allocator);
    var second = try client.getPlan(fixture.file_hash, null);
    defer second.deinit(allocator);
    try server.finish(3);
    try std.testing.expect(std.mem.startsWith(u8, server.exchanges.items[0].target, "/v2/reconstructions/"));
    try std.testing.expect(std.mem.startsWith(u8, server.exchanges.items[1].target, "/v1/reconstructions/"));
    try std.testing.expect(std.mem.startsWith(u8, server.exchanges.items[2].target, "/v1/reconstructions/"));
}

test "V2 shard upload requires a terminal result frame" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{.{
        .body =
        \\{"type":"validating","verified":1,"total":1}
        \\{"type":"committing","stage":"syncing"}
        \\{"type":"result"}
        ,
    }};
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    try client.putShard(package.shard_bytes);
    try server.finish(1);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[0].target);
    try checkShardBody(server.exchanges.items[0].body);
}

test "V2 shard upload accepts trailing newline-free result and ignores later frames" {
    const allocator = std.testing.allocator;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{
        .{
            .body = result_json,
        },
        .{
            .body =
            \\{"type":"result"}
            \\{"type":"validating","verified":1,"total":1}
            \\
            ,
        },
    };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try client.putShard(package.shard_bytes);
    try client.putShard(package.shard_bytes);
    try server.finish(2);
}

test "V2 shard upload rejects terminal errors and missing results" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{
        .{ .body = upload_error_frame },
        .{ .body = validating_frame },
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    try std.testing.expectError(error.ShardUploadFailed, client.putShard(package.shard_bytes));
    try std.testing.expectError(error.InvalidResponse, client.putShard(package.shard_bytes));
    try server.finish(2);
}

test "V2 shard upload falls back to V1 and caches the choice" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    try client.putShard(package.shard_bytes);
    try client.putShard(package.shard_bytes);
    try server.finish(3);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[0].target);
    try std.testing.expectEqualStrings("/v1/shards", server.exchanges.items[1].target);
    try std.testing.expectEqualStrings("/v1/shards", server.exchanges.items[2].target);
}
