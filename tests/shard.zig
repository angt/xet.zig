const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

const SliceOpener = struct {
    bytes: []const u8,
    requests: usize = 0,
    closes: usize = 0,
    last_range: ?xet.reconstruction.ByteRange = .{ .start = 0, .end = 0 },
    reader: std.Io.Reader = undefined,

    fn opener(self: *SliceOpener) xet.stream.Opener {
        return .{ .context = self, .open_fn = open, .close_fn = close };
    }

    fn open(raw: *anyopaque, request: xet.reconstruction.Request) !*std.Io.Reader {
        const self: *SliceOpener = @ptrCast(@alignCast(raw));
        self.requests += 1;
        self.last_range = request.byte_range;
        const range = request.byte_range orelse xet.reconstruction.ByteRange{
            .start = 0,
            .end = @intCast(self.bytes.len - 1),
        };
        const start: usize = @intCast(range.start);
        const end: usize = @intCast(range.end + 1);
        if (start > end or end > self.bytes.len) return error.TestRangeOutsideFixture;
        self.reader = .fixed(self.bytes[start..end]);
        return &self.reader;
    }

    fn close(raw: *anyopaque, _: *std.Io.Reader) void {
        const self: *SliceOpener = @ptrCast(@alignCast(raw));
        self.closes += 1;
    }
};

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
    const responses = [_]support.HttpResponse{.{ .body = support.result_json }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try xet.publish(allocator, &package, client.store());
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
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
    var fetch_context = SliceOpener{ .bytes = object.bytes };
    const output = try xet.reconstruction.reconstruct(allocator, &manifest.plan, fetch_context.opener());
    defer allocator.free(output);
    try std.testing.expectEqualStrings("BBB", output);
    try std.testing.expectEqual(@as(@TypeOf(fetch_context.last_range), null), fetch_context.last_range);
    var open_context = SliceOpener{ .bytes = object.bytes };
    var sink = std.Io.Writer.Allocating.init(allocator);
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

test "V2 shard upload accepts progress frames before the result" {
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
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[0].target);
    try support.checkShardBody(server.exchanges.items[0].body);
}

test "V2 shard upload accepts a result without a trailing newline" {
    const allocator = std.testing.allocator;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{.{ .body = support.result_json }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try client.putShard(package.shard_bytes);
    try server.finish();
}

test "V2 shard upload ignores frames after the result" {
    const allocator = std.testing.allocator;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{.{
        .body =
        \\{"type":"result"}
        \\{"type":"validating","verified":1,"total":1}
        \\
        ,
    }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try client.putShard(package.shard_bytes);
    try server.finish();
}

fn expectShardUploadError(response_body: []const u8, expected: anyerror) !void {
    const allocator = std.testing.allocator;
    var package = try xet.pack(allocator, "AAA", .{ .compression = .none });
    defer package.deinit(allocator);
    const responses = [_]support.HttpResponse{.{ .body = response_body }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try std.testing.expectError(expected, client.putShard(package.shard_bytes));
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
}

test "V2 shard upload reports a terminal server error" {
    try expectShardUploadError(support.upload_error_frame, error.ShardUploadFailed);
}

test "V2 shard upload rejects a response without a result" {
    try expectShardUploadError(support.validating_frame, error.InvalidResponse);
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
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[0].target);
    try std.testing.expectEqualStrings("/v1/shards", server.exchanges.items[1].target);
    try std.testing.expectEqualStrings("/v1/shards", server.exchanges.items[2].target);
    var expected: u64 = 0;
    for (server.exchanges.items) |exchange| expected += exchange.body.len;
    try std.testing.expectEqual(expected, client.uploadedBytes());
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
        var fetch_context = SliceOpener{ .bytes = fixture.object.bytes };
        const output = try xet.reconstruction.reconstruct(allocator, &manifest.plan, fetch_context.opener());
        defer allocator.free(output);
        try std.testing.expectEqualStrings("BBB", output);
        try std.testing.expectEqual(@as(?xet.reconstruction.ByteRange, expected_range), fetch_context.last_range);
        return;
    }
    var open_context = SliceOpener{ .bytes = fixture.object.bytes };
    var sink = std.Io.Writer.Allocating.init(allocator);
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
    const responses = [_]support.HttpResponse{ .{}, .{ .body = support.result_json } };
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
    try server.finish();
    try std.testing.expectEqual(@as(usize, 2), server.exchanges.items.len);
    try checkUploadedAbcSha256(server.exchanges.items[1].body);
}

test "pack publish uploads Git SHA-256 in Xet word order" {
    try exerciseUploadedSha256(false);
}

test "streaming Publisher uploads Git SHA-256 in Xet word order" {
    try exerciseUploadedSha256(true);
}

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

test "V2 shard upload requests identity and rejects encoded responses" {
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{
        .{ .body = support.result_json },
        .{ .body = support.result_json, .content_encoding = "gzip" },
    };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try xet.http.Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try client.putShard("shard");
    try std.testing.expectError(error.HttpContentEncodingUnsupported, client.putShard("shard"));
    try server.finish();
    try std.testing.expectEqual(@as(usize, 2), server.exchanges.items.len);
    for (server.exchanges.items) |exchange| {
        const accepted = exchange.accept_encoding orelse return error.TestMissingAcceptEncoding;
        try std.testing.expectEqualStrings("identity", accepted);
    }
}
