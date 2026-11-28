const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

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
        .{ .body = support.result_json },
        .{ .status = .not_found },
        .{},
        .{},
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconJson(allocator, url, &object, 3, 0);
    defer allocator.free(body);
    responses[5].body = body;
    responses[6].body = object.bytes;
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    const operation_allocator = tracker.allocator();

    const published = try support.uploadBytes(&client, "AAA", .{ .compression = .none });
    var output: std.Io.Writer.Allocating = .init(operation_allocator);
    defer output.deinit();
    _ = try client.download(published.file_hash, &output.writer, .{});
    try std.testing.expectEqualStrings("AAA", output.written());
    try server.finish();
    try std.testing.expectEqual(@as(usize, 7), server.exchanges.items.len);
    try support.checkXorbBody(server.exchanges.items[1].body);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
}

test "HTTP upload and download support fixed chunk boundaries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    var fixed = try xet.chunker.Fixed.init(16 * 1024);
    const fixed_chunks = try xet.chunker.chunkWith(allocator, data, fixed.strategy());
    defer allocator.free(fixed_chunks);
    try std.testing.expect(fixed_chunks.len > 1);
    const nodes = try allocator.alloc(xet.hash.Node, fixed_chunks.len);
    defer allocator.free(nodes);
    for (fixed_chunks, nodes) |chunk, *node| {
        node.* = .{ .hash = chunk.hash, .size = @intCast(chunk.data.len) };
    }
    const expected_hash = try xet.hash.file(allocator, nodes);
    var object = try xet.xorb.serialize(allocator, fixed_chunks, .none);
    defer object.deinit(allocator);
    var responses = [_]support.HttpResponse{
        .{ .status = .not_found },
        .{},
        .{ .status = .not_found },
        .{ .body = support.result_json },
        .{},
        .{},
        .{},
        .{},
    };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const hash_hex = xet.hash.toHex(object.hash);
    const terms = [_]ReconTerm{.{
        .hash = &hash_hex,
        .unpacked_length = @intCast(data.len),
        .range = .{ .start = 0, .end = @intCast(fixed_chunks.len) },
    }};
    const FetchInfo = struct {
        range: xet.recon.Range,
        url: []const u8,
        url_range: xet.recon.ByteRange,
    };
    const locations = [_]FetchInfo{.{
        .range = .{ .start = 0, .end = @intCast(fixed_chunks.len) },
        .url = url,
        .url_range = .{ .start = 0, .end = object.bytes.len - 1 },
    }};
    const Descriptor = struct {
        chunks: xet.recon.Range,
        bytes: xet.recon.ByteRange,
    };
    const Xorb = struct {
        url: []const u8,
        ranges: [1]Descriptor,
    };
    const v2_locations = [_]Xorb{.{
        .url = url,
        .ranges = .{.{
            .chunks = locations[0].range,
            .bytes = locations[0].url_range,
        }},
    }};
    const body = try writeReconJson(allocator, 0, &terms, "xorbs", &hash_hex, &v2_locations);
    defer allocator.free(body);
    responses[4].body = body;
    responses[5].body = object.bytes;
    responses[6].body = body;
    responses[7].body = object.bytes;
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();

    const published = try support.uploadBytes(&client, data, .{
        .compression = .none,
        .strategy = fixed.strategy(),
    });
    try std.testing.expect(xet.hash.eql(published.file_hash, expected_hash));
    // Canonical boundaries must disagree with the fixed-boundary upload
    const canonical_chunks = try xet.chunker.chunkBuffer(allocator, data);
    defer allocator.free(canonical_chunks);
    try std.testing.expect(canonical_chunks.len > 1);
    const rebuilt_nodes = try allocator.alloc(xet.hash.Node, canonical_chunks.len);
    defer allocator.free(rebuilt_nodes);
    for (canonical_chunks, rebuilt_nodes) |chunk, *node| {
        node.* = .{ .hash = chunk.hash, .size = @intCast(chunk.data.len) };
    }
    try std.testing.expect(!xet.hash.eql(
        try xet.hash.file(allocator, rebuilt_nodes),
        expected_hash,
    ));
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(error.HashMismatch, client.download(
        published.file_hash,
        &output.writer,
        .{},
    ));
    output.clearRetainingCapacity();
    _ = try client.download(published.file_hash, &output.writer, .{ .strategy = fixed.strategy() });
    try std.testing.expectEqualSlices(u8, data, output.written());
    try server.finish();
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
    responses[1].body = try makeReconJson(allocator, url, &object, 3, 0);
    defer allocator.free(@constCast(responses[1].body));
    responses[2].body = object.bytes;
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();

    var sink: std.Io.Writer.Discarding = .init(&.{});
    try std.testing.expectError(error.HashMismatch, client.download(
        xet.hash.zero,
        &sink.writer,
        .{},
    ));
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
}

test "canceled object body read preserves the cancel error" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 128 * 1024);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index);
    const chunks = [_]xet.xorb.Chunk{.{ .data = data, .hash = xet.hash.data(data) }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    responses[1].body = try makeReconJson(allocator, url, &object, @intCast(data.len), 0);
    defer allocator.free(@constCast(responses[1].body));
    responses[2].body = object.bytes;
    try server.start();
    // All headers and the plan fit before this offset in the 128 KiB object.
    const io = support.cancelAfterReadBytes(16 * 1024);
    defer support.stopCanceling();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var sink: std.Io.Writer.Discarding = .init(&.{});
    try std.testing.expectError(error.Canceled, client.download(xet.hash.zero, &sink.writer, .{}));
}

test "canceled object read propagates through recon" {
    const allocator = std.testing.allocator;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "AAA", .hash = xet.hash.data("AAA") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    responses[1].body = try makeReconJson(allocator, url, &object, 3, 0);
    defer allocator.free(@constCast(responses[1].body));
    responses[2].body = object.bytes;
    try server.start();
    const io = support.cancelAtRead(2);
    defer support.stopCanceling();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var sink: std.Io.Writer.Discarding = .init(&.{});
    try std.testing.expectError(error.Canceled, client.download(xet.hash.zero, &sink.writer, .{}));
}

fn exerciseFileRange(
    allocator: std.mem.Allocator,
    io: std.Io,
    range: xet.recon.ByteRange,
    expected: []const u8,
) !void {
    const chunks = [_]xet.xorb.Chunk{.{ .data = "abc", .hash = xet.hash.data("abc") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var content_range_buffer: [80]u8 = undefined;
    const content_range = try std.fmt.bufPrint(
        &content_range_buffer,
        "bytes 0-{d}/{d}",
        .{ object.bytes.len - 1, object.bytes.len },
    );
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconJson(allocator, url, &object, @intCast(object.raw_size), range.start);
    defer allocator.free(body);
    responses[1].body = body;
    responses[2].status = .partial_content;
    responses[2].body = object.bytes;
    responses[2].content_range = content_range;
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(xet.hash.data("file"), range);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(range.start, plan.offset_into_first_range);
    try std.testing.expectEqual(@as(u32, @intCast(object.raw_size)), plan.terms[0].unpacked_length);
    const output = try xet.recon.reconstruct(allocator, &plan, client.opener());
    defer allocator.free(output);
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expect(std.mem.startsWith(
        u8,
        server.exchanges.items[0].target,
        "/v2/reconstructions/",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        server.exchanges.items[1].target,
        "/v1/reconstructions/",
    ));
    try std.testing.expectEqualStrings(expected, output);
    try std.testing.expectEqual(@as(?u64, expected.len), plan.output_length);
}

test "file range crossing EOF returns the available suffix" {
    try exerciseFileRange(std.testing.allocator, std.testing.io, .{ .start = 1, .end = 9 }, "bc");
}

test "file range in-bounds returns the requested bytes" {
    try exerciseFileRange(std.testing.allocator, std.testing.io, .{ .start = 0, .end = 2 }, "abc");
}

test "short decoded term fails independently of EOF clipping" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const chunks = [_]xet.xorb.Chunk{.{ .data = "ab", .hash = xet.hash.data("ab") }};
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    var content_range_buffer: [80]u8 = undefined;
    const content_range = try std.fmt.bufPrint(
        &content_range_buffer,
        "bytes 0-{d}/{d}",
        .{ object.bytes.len - 1, object.bytes.len },
    );
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconJson(allocator, url, &object, 3, 0);
    defer allocator.free(body);
    responses[1].body = body;
    responses[2].status = .partial_content;
    responses[2].body = object.bytes;
    responses[2].content_range = content_range;
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(xet.hash.data("file"), .{ .start = 0, .end = 1 });
    defer plan.deinit(allocator);
    try std.testing.expectError(error.SizeMismatch, xet.recon.reconstruct(
        allocator,
        &plan,
        client.opener(),
    ));
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
}

fn makeHttpRangePlan(
    allocator: std.mem.Allocator,
    object: *const xet.xorb.Serialized,
    url: []const u8,
) !xet.recon.Plan {
    return xet.recon.Plan.init(allocator, &.{.{
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

const RangeScenario = enum { matching, ignored, wrong, missing };

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
        .matching, .missing => support.HttpResponse{
            .status = .partial_content,
            .body = object.bytes[11..22],
            .content_range = if (scenario == .matching) content_range else null,
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
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var sink = std.Io.Writer.Allocating.init(allocator);
    defer sink.deinit();
    const result = xet.recon.consume(allocator, &plan, client.opener(), &sink.writer);
    switch (scenario) {
        .matching, .ignored => {
            try std.testing.expectEqual(@as(u64, 3), try result);
            try std.testing.expectEqualStrings("BBB", sink.written());
        },
        .wrong, .missing => {
            try std.testing.expectError(error.InvalidResponse, result);
            try std.testing.expectEqual(@as(usize, 0), sink.written().len);
        },
    }
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    try std.testing.expectEqualStrings("bytes=11-21", server.exchanges.items[0].range.?);
}

test "object opener checks the offset of partial and full responses" {
    for (std.enums.values(RangeScenario)) |scenario|
        try exerciseHttpRanges(std.testing.allocator, std.testing.io, scenario);
}

test "streaming HTTP zero-start range trims an oversized full-object response" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{.{ .body = "0123456789extra" }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    var client = try xet.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    const source = try client.opener().open(.{
        .hash = xet.hash.zero,
        .url = url,
        .byte_range = .{ .start = 0, .end = 9 },
    });
    defer client.opener().close(source);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var buffer: [16]u8 = undefined;
    while (true) {
        const count = try source.readSliceShort(&buffer);
        if (count == 0) break;
        try output.writer.writeAll(buffer[0..count]);
    }
    try std.testing.expectEqual(@as(usize, 10), output.written().len);
    try std.testing.expectEqualStrings("0123456789", output.written());
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    try std.testing.expectEqualStrings("bytes=0-9", server.exchanges.items[0].range.?);
}

const raw_records = "\x00\x03\x00\x00\x00\x03\x00\x00AAA" ++
    "\x00\x03\x00\x00\x00\x03\x00\x00BBB";

const second_record_range = xet.recon.ByteRange{ .start = 11, .end = 21 };
const deterministic_gzip_records = [_]u8{
    31, 139, 8, 0,  0,   0,   0,   0, 2, 3,   99, 96,  102, 96, 96, 0, 98, 71,
    71, 71,  6, 40, 211, 201, 201, 9, 0, 137, 80, 230, 211, 22, 0,  0, 0,
};

test "streaming raw xorb range rejects a gzip response" {
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
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    const request = xet.recon.Request{
        .hash = xet.hash.zero,
        .url = url,
        .byte_range = second_record_range,
    };
    const opener = client.opener();
    try std.testing.expectError(error.HttpContentEncodingUnsupported, opener.open(request));
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    try std.testing.expectEqualStrings("bytes=11-21", server.exchanges.items[0].range.?);
    const accept_encoding = server.exchanges.items[0].accept_encoding orelse return error.TestMissingAcceptEncoding;
    try std.testing.expectEqualStrings("identity", accept_encoding);
}

test "compressed recon JSON still negotiates gzip" {
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
    var client = try xet.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(xet.hash.data("file"), null);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), plan.terms.len);
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    const accepted = server.exchanges.items[0].accept_encoding orelse return error.TestMissingAcceptEncoding;
    try std.testing.expect(std.mem.indexOf(u8, accepted, "gzip") != null);
}

test "streaming transport opens full object for unknown encoded length" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{.{ .body = raw_records }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    var client = try xet.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    const request = xet.recon.Request{
        .hash = xet.hash.zero,
        .url = url,
        .byte_range = null,
    };
    var output: std.Io.Writer.Allocating = .init(allocator);
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
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    try std.testing.expect(server.exchanges.items[0].range == null);
    try std.testing.expectEqualStrings("identity", server.exchanges.items[0].accept_encoding.?);
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

test "V2 recon splits multi-range descriptors and reconstructs in order" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try twoChunkFixture(allocator);
    defer fixture.object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{}, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    responses[0].body = try makeV2ReconJson(allocator, url, &fixture.object);
    defer allocator.free(@constCast(responses[0].body));
    responses[1].status = .partial_content;
    responses[1].body = fixture.object.bytes[0..11];
    responses[1].content_range = "bytes 0-10/22";
    responses[2].status = .partial_content;
    responses[2].body = fixture.object.bytes[11..22];
    responses[2].content_range = "bytes 11-21/22";
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var plan = try client.getPlan(fixture.file_hash, null);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.locations.len);
    const output = try xet.recon.reconstruct(allocator, &plan, client.opener());
    defer allocator.free(output);
    try std.testing.expectEqualStrings("AAABBB", output);
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expectEqualStrings("bytes=0-10", server.exchanges.items[1].range.?);
    try std.testing.expectEqualStrings("bytes=11-21", server.exchanges.items[2].range.?);
}

test "V1 recon fallback is cached across plans" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try twoChunkFixture(allocator);
    defer fixture.object.deinit(allocator);
    var responses = [_]support.HttpResponse{ .{ .status = .not_found }, .{}, .{} };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    const url = try server.objectUrl(allocator);
    defer allocator.free(url);
    const body = try makeReconJson(allocator, url, &fixture.object, 3, 0);
    defer allocator.free(body);
    responses[1].body = body;
    responses[2].body = body;
    try server.start();
    var client = try xet.Client.init(allocator, io, server.origin, "");
    defer client.deinit();
    var first = try client.getPlan(fixture.file_hash, null);
    defer first.deinit(allocator);
    var second = try client.getPlan(fixture.file_hash, null);
    defer second.deinit(allocator);
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expect(std.mem.startsWith(
        u8,
        server.exchanges.items[0].target,
        "/v2/reconstructions/",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        server.exchanges.items[1].target,
        "/v1/reconstructions/",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        server.exchanges.items[2].target,
        "/v1/reconstructions/",
    ));
}

const ReconTerm = struct {
    hash: []const u8,
    unpacked_length: u32,
    range: xet.recon.Range,
};

fn writeReconJson(
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

fn makeReconJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    object: *const xet.xorb.Serialized,
    declared_length: u32,
    offset: u64,
) ![]u8 {
    const hash = xet.hash.toHex(object.hash);
    const terms = [_]ReconTerm{.{
        .hash = &hash,
        .unpacked_length = declared_length,
        .range = .{ .start = 0, .end = 1 },
    }};
    const FetchInfo = struct {
        range: xet.recon.Range,
        url: []const u8,
        url_range: xet.recon.ByteRange,
    };
    const locations = [_]FetchInfo{.{
        .range = .{ .start = 0, .end = 1 },
        .url = url,
        .url_range = .{ .start = 0, .end = object.bytes.len - 1 },
    }};
    return writeReconJson(allocator, offset, terms, "fetch_info", &hash, locations);
}

fn makeV2ReconJson(
    allocator: std.mem.Allocator,
    url: []const u8,
    object: *const xet.xorb.Serialized,
) ![]u8 {
    const hash = xet.hash.toHex(object.hash);
    const terms = [_]ReconTerm{
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
        chunks: xet.recon.Range,
        bytes: xet.recon.ByteRange,
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
    return writeReconJson(allocator, 0, terms, "xorbs", &hash, locations);
}
