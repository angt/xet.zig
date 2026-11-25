const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

const StoreOpener = struct {
    store: *const support.MemoryStore,
    reader: std.Io.Reader = undefined,

    fn opener(self: *StoreOpener) xet.stream.Opener {
        return .{ .context = self, .open_fn = open, .close_fn = close };
    }

    fn close(_: *anyopaque, _: *std.Io.Reader) void {}

    fn open(raw: *anyopaque, request: xet.stream.Request) !*std.Io.Reader {
        const self: *StoreOpener = @ptrCast(@alignCast(raw));
        for (self.store.objects.items) |object| {
            if (object.kind == .xorb and xet.hash.eql(object.hash, request.hash)) {
                self.reader = .fixed(object.data);
                return &self.reader;
            }
        }
        return error.NotFound;
    }
};

fn discardUpload(session: *xet.upload.Session) !void {
    while (try session.next()) |operation_value| {
        var operation = operation_value;
        operation.deinit();
    }
}

/// Keeps an issued operation owned until the test completes it
const Issued = struct {
    operation: xet.upload.Operation,
    done: bool = false,

    fn complete(self: *Issued) void {
        self.operation.complete();
        self.done = true;
    }

    fn release(self: *Issued) void {
        if (self.done) return;
        self.operation.deinit();
        self.done = true;
    }
};

/// Runs queued upload work, releasing the issued operation on failure
fn uploadAll(session: *xet.upload.Session, destination: *support.MemoryStore) !void {
    while (try session.next()) |operation_value| {
        var issued = Issued{ .operation = operation_value };
        defer issued.release();
        switch (issued.operation) {
            .store => |value| try destination.store().put(value.value),
            .reference => {},
        }
        issued.complete();
    }
}

test "upload operations own deferred payloads and deduplicate multiple files" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = xet.upload.Session.init(allocator, destination.store(), .{});
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    const data = "a moderately sized shared payload";
    try session.addFile(10, data, .{ .compression = .none });
    var second: xet.upload.File = undefined;
    try session.beginFile(&second, 20, .{ .compression = .none });
    for (data) |byte| try second.write(&.{byte});
    try second.finish();
    second.deinit();
    try session.addFile(30, "an independent file", .{ .compression = .none });

    var remaining: [4]xet.upload.Operation = undefined;
    var remaining_count: usize = 0;
    defer for (remaining[0..remaining_count]) |*operation| operation.deinit();
    var references: usize = 0;
    while (try session.next()) |operation| {
        if (operation == .reference) references += 1;
        remaining[remaining_count] = operation;
        remaining_count += 1;
    }
    try std.testing.expect((try session.next()) == null);
    try std.testing.expectError(error.PendingOperations, session.finish());
    try std.testing.expectEqual(@as(usize, 3), remaining_count);
    try std.testing.expectEqual(@as(usize, 1), references);
    var index = remaining_count;
    while (index != 0) {
        index -= 1;
        switch (remaining[index]) {
            .reference => |value| try std.testing.expectEqual(@as(xet.upload.FileId, 20), value.file_id),
            .store => |value| try destination.store().put(value.value),
        }
        remaining[index].complete();
        remaining_count = index;
    }
    try session.finish();
    try std.testing.expectEqual(@as(usize, 2), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    try std.testing.expectEqual(@as(usize, 3), session.plans().len);

    const shard_bytes = destination.objects.items[destination.objects.items.len - 1].data;
    const reader = try xet.shard.Reader.init(shard_bytes);
    try std.testing.expectEqual(@as(usize, 2), reader.footer.file_count);
    var opener = StoreOpener{ .store = &destination };
    var manifest = try xet.reconstruction.planFromShard(
        allocator,
        shard_bytes,
        session.plans()[1].file.hash,
    );
    defer manifest.deinit(allocator);
    const reconstructed = try xet.reconstruction.reconstruct(allocator, &manifest.plan, opener.opener());
    defer allocator.free(reconstructed);
    try std.testing.expectEqualStrings(data, reconstructed);
}

test "upload queue allocation failures release retained operations" {
    const allocator = std.testing.allocator;
    const data = "queued upload allocation coverage";
    var baseline_tracker = support.TrackingAllocator{ .backing = allocator };
    var baseline = support.MemoryStore{ .allocator = baseline_tracker.allocator() };
    var session = xet.upload.Session.init(baseline_tracker.allocator(), baseline.store(), .{});
    try session.addFile(1, data, .{ .compression = .none });
    try discardUpload(&session);
    session.deinit();
    baseline.deinit();
    const allocations = baseline_tracker.allocation_count;
    baseline_tracker.deinit();

    var fail_at: usize = 0;
    while (fail_at < allocations) : (fail_at += 1) {
        var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = fail_at };
        {
            var destination = support.MemoryStore{ .allocator = tracker.allocator() };
            defer destination.deinit();
            var current = xet.upload.Session.init(tracker.allocator(), destination.store(), .{});
            defer current.deinit();
            try std.testing.expectError(error.OutOfMemory, current.addFile(1, data, .{ .compression = .none }));
            try discardUpload(&current);
        }
        try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
        try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
        try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
        tracker.deinit();
    }
}

test "upload supports fixed chunks and canonical defaults simultaneously" {
    const allocator = std.testing.allocator;
    const data = "abcdefghij";
    const expected_nodes = [_]xet.hash.Node{
        .{ .hash = xet.hash.data("abcd"), .size = 4 },
        .{ .hash = xet.hash.data("efgh"), .size = 4 },
        .{ .hash = xet.hash.data("ij"), .size = 2 },
    };
    const expected_hash = try xet.hash.file(allocator, &expected_nodes);
    var fixed = try xet.Fixed.init(4);
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = xet.upload.Session.init(allocator, destination.store(), .{});
    defer session.deinit();
    errdefer discardUpload(&session) catch {};

    try session.addFile(1, data, .{ .compression = .none });
    try session.addFile(2, data, .{ .compression = .none, .strategy = fixed.strategy() });
    while (try session.next()) |operation_value| {
        var issued = Issued{ .operation = operation_value };
        defer issued.release();
        switch (issued.operation) {
            .reference => |value| try std.testing.expectEqual(@as(xet.upload.FileId, 2), value.file_id),
            .store => |value| try destination.store().put(value.value),
        }
        issued.complete();
    }
    try session.finish();
    try std.testing.expect(!xet.hash.eql(session.plans()[0].file.hash, expected_hash));
    try std.testing.expect(xet.hash.eql(session.plans()[1].file.hash, expected_hash));
    try std.testing.expectEqual(@as(usize, 3), session.plans()[1].file.segments[0].chunk_index_end);
    var package = try xet.pack(allocator, data, .{ .compression = .none, .strategy = fixed.strategy() });
    defer package.deinit(allocator);
    try std.testing.expect(xet.hash.eql(package.file_hash, expected_hash));

    const shard_bytes = destination.objects.items[destination.objects.items.len - 1].data;
    var manifest = try xet.reconstruction.planFromShard(allocator, shard_bytes, expected_hash);
    defer manifest.deinit(allocator);
    var opener = StoreOpener{ .store = &destination };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    _ = try xet.consumeWith(allocator, &manifest.plan, opener.opener(), &output.writer, fixed.strategy());
    try std.testing.expectEqualStrings(data, output.written());

    output.clearRetainingCapacity();
    _ = try xet.reconstruction.consumeVerified(allocator, &manifest.plan, opener.opener(), manifest.chunks, &output.writer);
    try std.testing.expectEqualStrings(data, output.written());
}

const ExternalSource = struct {
    object: *const xet.xorb.Serialized,

    fn query(raw: *anyopaque, query_allocator: std.mem.Allocator, hashes: []const xet.Hash) !?xet.DedupMatch {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (hashes.len == 0 or !xet.hash.eql(hashes[0], self.object.nodes[0].hash)) return null;
        const nodes = try query_allocator.dupe(xet.hash.Node, self.object.nodes);
        return .{ .nodes = nodes, .xorb_hash = self.object.hash, .chunk_index_start = 0 };
    }
};

test "upload reference queue allocation failures release cloned metadata" {
    const allocator = std.testing.allocator;
    const data = "external reference allocation coverage";
    var fixture = try Fixture.init(allocator, &.{data});
    defer fixture.deinit(allocator);
    var source = ExternalSource{ .object = &fixture.object };
    var baseline_tracker = support.TrackingAllocator{ .backing = allocator };
    var baseline = support.MemoryStore{ .allocator = baseline_tracker.allocator() };
    var session = xet.upload.Session.init(baseline_tracker.allocator(), baseline.store(), .{
        .dedup_source = .{ .context = &source, .query_fn = ExternalSource.query },
    });
    try session.addFile(1, data, .{ .compression = .none });
    try discardUpload(&session);
    session.deinit();
    baseline.deinit();
    const allocations = baseline_tracker.allocation_count;
    baseline_tracker.deinit();

    var fail_at: usize = 0;
    while (fail_at < allocations) : (fail_at += 1) {
        var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = fail_at };
        {
            var destination = support.MemoryStore{ .allocator = tracker.allocator() };
            defer destination.deinit();
            var current = xet.upload.Session.init(tracker.allocator(), destination.store(), .{
                .dedup_source = .{ .context = &source, .query_fn = ExternalSource.query },
            });
            defer current.deinit();
            try std.testing.expectError(error.OutOfMemory, current.addFile(1, data, .{ .compression = .none }));
            try discardUpload(&current);
        }
        try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
        try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
        try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
        tracker.deinit();
    }
}

test "upload accepts an external deduplication source" {
    const allocator = std.testing.allocator;
    const data = "external database chunk";
    var fixture = try Fixture.init(allocator, &.{data});
    defer fixture.deinit(allocator);
    var source = ExternalSource{ .object = &fixture.object };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = xet.upload.Session.init(allocator, destination.store(), .{
        .dedup_source = .{ .context = &source, .query_fn = ExternalSource.query },
    });
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    try session.addFile(1, data, .{ .compression = .none });
    var issued = Issued{ .operation = (try session.next()).? };
    defer issued.release();
    try std.testing.expect(issued.operation == .reference);
    issued.complete();
    try std.testing.expect((try session.next()) == null);
    try session.finish();
    try std.testing.expectEqual(@as(usize, 0), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
}

/// Returns the queried hash with a size unrelated to the buffered input
const MismatchedSizeSource = struct {
    fn query(_: *anyopaque, query_allocator: std.mem.Allocator, hashes: []const xet.Hash) !?xet.DedupMatch {
        const nodes = try query_allocator.alloc(xet.hash.Node, 1);
        nodes[0] = .{ .hash = hashes[0], .size = 42 };
        return .{ .nodes = nodes, .xorb_hash = xet.hash.data("external xorb"), .chunk_index_start = 0 };
    }
};

test "upload rejects external dedup matches whose sizes disagree with input" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var dummy: u8 = 0;
    var session = xet.upload.Session.init(allocator, destination.store(), .{
        .dedup_source = .{ .context = &dummy, .query_fn = MismatchedSizeSource.query },
    });
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    try std.testing.expectError(
        error.InvalidDedupMatch,
        session.addFile(1, "A", .{ .compression = .none }),
    );
    try std.testing.expectEqual(@as(usize, 0), session.pending());
    try std.testing.expectEqual(@as(usize, 0), session.plans().len);
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

test "upload references a duplicate xorb instead of silently dropping it" {
    const allocator = std.testing.allocator;
    var fixed = try xet.Fixed.init(1);
    const opts = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = xet.upload.Session.init(allocator, destination.store(), .{});
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    try session.addFile(1, "aa", opts);

    var stores: usize = 0;
    var references: usize = 0;
    while (try session.next()) |operation_value| {
        var issued = Issued{ .operation = operation_value };
        defer issued.release();
        switch (issued.operation) {
            .store => |value| {
                try destination.store().put(value.value);
                stores += 1;
            },
            .reference => references += 1,
        }
        issued.complete();
    }
    try std.testing.expectEqual(@as(usize, 1), stores);
    try std.testing.expectEqual(@as(usize, 1), references);
    try session.finish();
    try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    try std.testing.expectEqual(@as(usize, 2), session.plans()[0].file.segments.len);

    const shard_bytes = destination.objects.items[destination.objects.items.len - 1].data;
    var manifest = try xet.reconstruction.planFromShard(
        allocator,
        shard_bytes,
        session.plans()[0].file.hash,
    );
    defer manifest.deinit(allocator);
    var opener = StoreOpener{ .store = &destination };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    _ = try xet.consumeWith(allocator, &manifest.plan, opener.opener(), &output.writer, fixed.strategy());
    try std.testing.expectEqualStrings("aa", output.written());
}

test "upload store failure survives cleanup with zero outstanding operations" {
    const allocator = std.testing.allocator;
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var fixed = try xet.Fixed.init(1);
    const opts = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    };
    {
        var destination = support.MemoryStore{ .allocator = tracker.allocator(), .fail_on_put = 0 };
        defer destination.deinit();
        var session = xet.upload.Session.init(tracker.allocator(), destination.store(), .{});
        defer session.deinit();
        try session.addFile(1, "aa", opts);

        // The issued operation is released before the session can assert
        try std.testing.expectError(error.InjectedStoreFailure, uploadAll(&session, &destination));
        try std.testing.expectEqual(@as(usize, 1), destination.puts);
        try discardUpload(&session);
        try std.testing.expectEqual(@as(usize, 0), session.pending());
        try std.testing.expectError(error.OperationFailed, session.finish());
        try std.testing.expectEqual(@as(usize, 0), destination.count(.xorb));
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
}

/// Re-enters the session from the dedup query issued during plan finalization
const ReentrantSource = struct {
    session: ?*xet.upload.Session = null,
    queries: usize = 0,
    nested_finish: ?anyerror = null,
    nested_begin: ?anyerror = null,

    fn source(self: *ReentrantSource) xet.DedupSource {
        return .{ .context = self, .query_fn = query };
    }

    fn query(raw: *anyopaque, _: std.mem.Allocator, _: []const xet.Hash) !?xet.DedupMatch {
        const self: *ReentrantSource = @ptrCast(@alignCast(raw));
        self.queries += 1;
        const session = self.session orelse return null;
        self.nested_finish = null;
        session.finish() catch |err| {
            self.nested_finish = err;
        };
        var nested: xet.upload.File = undefined;
        if (session.beginFile(&nested, 2, .{ .compression = .none })) |_| {
            nested.deinit();
        } else |err| {
            self.nested_begin = err;
        }
        return null;
    }
};

test "upload keeps the active file guard through plan finalization" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var source = ReentrantSource{};
    var session = xet.upload.Session.init(allocator, destination.store(), .{
        .dedup_source = source.source(),
    });
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    var file: xet.upload.File = undefined;
    try session.beginFile(&file, 1, .{ .compression = .none });
    source.session = &session;
    try file.write("payload re-entering the upload session");
    try file.finish();
    file.deinit();
    source.session = null;

    try std.testing.expect(source.queries > 0);
    try std.testing.expectEqual(@as(?anyerror, error.ActiveFile), source.nested_finish);
    try std.testing.expectEqual(@as(?anyerror, error.ActiveFile), source.nested_begin);
    var probe: xet.upload.File = undefined;
    try session.beginFile(&probe, 2, .{ .compression = .none });
    probe.deinit();
    try uploadAll(&session, &destination);
    try session.finish();
    try std.testing.expectEqual(@as(usize, 1), session.plans().len);
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
}

test "upload cancelled operations prevent metadata publication" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = xet.upload.Session.init(allocator, destination.store(), .{});
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    try session.addFile(1, "new payload", .{ .compression = .none });
    var operation = (try session.next()).?;
    operation.deinit();
    try std.testing.expectError(error.OperationFailed, session.finish());
    var rejected: xet.upload.File = undefined;
    try std.testing.expectError(error.OperationFailed, session.beginFile(&rejected, 2, .{}));
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

/// The dedup window holds 64 chunks, so 70 emit six operations
const chunks_per_file = 70;
const operations_per_file = chunks_per_file - 64;

test "upload discards queued work when a file is abandoned" {
    const allocator = std.testing.allocator;
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var fixed = try xet.Fixed.init(2);
    const opts = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    };
    const abandoned = @as([2 * chunks_per_file]u8, @splat('b'));
    var package = try xet.pack(allocator, "aa", opts);
    defer package.deinit(allocator);
    {
        var destination = support.MemoryStore{ .allocator = tracker.allocator() };
        defer destination.deinit();
        var session = xet.upload.Session.init(tracker.allocator(), destination.store(), .{});
        defer session.deinit();
        try session.addFile(1, "aa", opts);

        var file: xet.upload.File = undefined;
        try session.beginFile(&file, 2, opts);
        try file.write(&abandoned);
        try std.testing.expectEqual(@as(usize, 1 + operations_per_file), session.pending());
        file.deinit();
        try std.testing.expectEqual(@as(usize, 1), session.pending());

        var issued = Issued{ .operation = (try session.next()).? };
        defer issued.release();
        try std.testing.expect(issued.operation == .store);
        try std.testing.expectEqual(@as(xet.upload.FileId, 1), issued.operation.store.file_id);
        try destination.store().put(issued.operation.store.value);
        issued.complete();
        try std.testing.expect((try session.next()) == null);
        try session.finish();

        try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
        const shard_bytes = destination.objects.items[destination.objects.items.len - 1].data;
        const reader = try xet.shard.Reader.init(shard_bytes);
        try std.testing.expectEqual(@as(u32, 1), reader.footer.file_count);
        try std.testing.expectEqual(@as(u32, 1), reader.footer.xorb_count);
        try std.testing.expect((try reader.findFile(package.file_hash)) != null);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
}

const FaultyChunks = struct {
    size: u32,
    fail_at: usize,
    calls: usize = 0,
    session: ?*xet.upload.Session = null,
    queued: usize = 0,

    fn strategy(self: *FaultyChunks) xet.Strategy {
        return .{ .context = self, .next_fn = next };
    }

    fn next(raw: *anyopaque, previous: []const u8, input: []const u8) !?usize {
        const self: *FaultyChunks = @ptrCast(@alignCast(raw));
        const remaining = self.size -| previous.len;
        if (remaining == 0) return error.InvalidChunkBoundary;
        if (input.len < remaining) return null;
        self.calls += 1;
        if (self.calls == self.fail_at) {
            if (self.session) |session| self.queued = session.pending();
            return error.InjectedChunkFailure;
        }
        return remaining;
    }
};

test "upload discards queued work when a write fails after enqueue" {
    const allocator = std.testing.allocator;
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var fixed = try xet.Fixed.init(2);
    const good = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    };
    var faulty = FaultyChunks{ .size = 2, .fail_at = chunks_per_file };
    const bad = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = faulty.strategy(),
    };
    const input = @as([2 * chunks_per_file]u8, @splat('c'));
    {
        var destination = support.MemoryStore{ .allocator = tracker.allocator() };
        defer destination.deinit();
        var session = xet.upload.Session.init(tracker.allocator(), destination.store(), .{});
        defer session.deinit();
        try session.addFile(1, "aa", good);

        faulty.session = &session;
        var file: xet.upload.File = undefined;
        try session.beginFile(&file, 2, bad);
        try std.testing.expectError(error.InjectedChunkFailure, file.write(&input));
        try std.testing.expect(faulty.queued > 1);
        try std.testing.expectError(error.WriteFailed, file.write(&input));
        try std.testing.expectEqual(@as(usize, 1), session.pending());
        file.deinit();
        try std.testing.expectEqual(@as(usize, 1), session.pending());

        var issued = Issued{ .operation = (try session.next()).? };
        defer issued.release();
        try std.testing.expect(issued.operation == .store);
        try std.testing.expectEqual(@as(xet.upload.FileId, 1), issued.operation.store.file_id);
        try destination.store().put(issued.operation.store.value);
        issued.complete();
        try std.testing.expect((try session.next()) == null);
        try session.finish();
        try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
        try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
}

test "upload queue storage follows outstanding work" {
    const allocator = std.testing.allocator;
    var fixed = try xet.Fixed.init(1);
    const opts = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var session = xet.upload.Session.init(allocator, destination.store(), .{});
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    var file: xet.upload.File = undefined;
    try session.beginFile(&file, 1, opts);
    defer file.deinit();

    var emitted: usize = 0;
    var peak_len: usize = 0;
    var peak_capacity: usize = 0;
    var input: [8]u8 = undefined;
    for (0..256) |i| {
        for (&input, 0..) |*byte, offset| byte.* = @truncate('a' + (i + offset) % 26);
        try file.write(&input);
        while (session.pending() > 1) {
            var issued = Issued{ .operation = (try session.next()).? };
            defer issued.release();
            if (issued.operation == .store) try destination.store().put(issued.operation.store.value);
            issued.complete();
            emitted += 1;
        }
        peak_len = @max(peak_len, session.queue.items.len);
        peak_capacity = @max(peak_capacity, session.queue.capacity);
    }
    try std.testing.expectEqual(@as(usize, 1), session.pending());
    try std.testing.expect(emitted > 200);
    try std.testing.expect(peak_len <= 8);
    try std.testing.expect(peak_capacity <= 32);

    try file.finish();
    while (try session.next()) |operation_value| {
        var issued = Issued{ .operation = operation_value };
        defer issued.release();
        if (issued.operation == .store) try destination.store().put(issued.operation.store.value);
        issued.complete();
    }
    try session.finish();
}

test "upload rollback keeps an issued operation usable" {
    const allocator = std.testing.allocator;
    var tracker = support.TrackingAllocator{ .backing = allocator };
    defer tracker.deinit();
    var fixed = try xet.Fixed.init(2);
    const opts = xet.PackOptions{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    };
    const abandoned = @as([2 * chunks_per_file]u8, @splat('d'));
    {
        var destination = support.MemoryStore{ .allocator = tracker.allocator() };
        defer destination.deinit();
        var session = xet.upload.Session.init(tracker.allocator(), destination.store(), .{});
        defer session.deinit();
        try session.addFile(1, "aa", opts);
        var early = Issued{ .operation = (try session.next()).? };
        defer early.release();
        try std.testing.expectEqual(@as(xet.upload.FileId, 1), early.operation.store.file_id);

        var file: xet.upload.File = undefined;
        try session.beginFile(&file, 2, opts);
        try file.write(&abandoned);
        var late = Issued{ .operation = (try session.next()).? };
        defer late.release();
        try std.testing.expectEqual(@as(xet.upload.FileId, 2), late.operation.store.file_id);
        file.deinit();
        try std.testing.expectEqual(@as(usize, 2), session.pending());

        try destination.store().put(late.operation.store.value);
        late.complete();
        try destination.store().put(early.operation.store.value);
        early.complete();
        try std.testing.expect((try session.next()) == null);
        try session.finish();

        try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
        const shard_bytes = destination.objects.items[destination.objects.items.len - 1].data;
        const reader = try xet.shard.Reader.init(shard_bytes);
        try std.testing.expectEqual(@as(u32, 1), reader.footer.file_count);
        try std.testing.expectEqual(@as(u32, 1), reader.footer.xorb_count);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
    try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
    try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
}

test "upload completions can run concurrently after file finalization" {
    const allocator = std.testing.allocator;
    const Destination = struct {
        store: support.MemoryStore,
        mutex: std.Io.Mutex = .init,
        ready: std.atomic.Value(usize) = .init(0),
        release: std.atomic.Value(bool) = .init(false),

        fn put(raw: *anyopaque, object: xet.store.Object) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            _ = self.ready.fetchAdd(1, .acq_rel);
            while (!self.release.load(.acquire)) {
                std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake) catch {};
            }
            self.mutex.lockUncancelable(std.testing.io);
            defer self.mutex.unlock(std.testing.io);
            try self.store.store().put(object);
        }
    };
    const Task = struct {
        fn run(destination: *Destination, operation: *xet.upload.Operation) void {
            std.debug.assert(operation.* == .store);
            Destination.put(destination, operation.store.value) catch {
                operation.deinit();
                return;
            };
            operation.complete();
        }
    };
    var destination = Destination{ .store = .{ .allocator = allocator } };
    defer destination.store.deinit();
    var session = xet.upload.Session.init(allocator, destination.store.store(), .{});
    defer session.deinit();
    errdefer discardUpload(&session) catch {};
    try session.addFile(1, "first independent payload", .{ .compression = .none });
    try session.addFile(2, "second independent payload", .{ .compression = .none });
    var first = (try session.next()).?;
    var second = (try session.next()).?;
    var first_pending = true;
    var second_pending = true;
    defer if (first_pending) first.deinit();
    defer if (second_pending) second.deinit();
    var first_future: std.Io.Future(void) = undefined;
    var second_future: std.Io.Future(void) = undefined;
    var first_running = false;
    var second_running = false;
    defer if (second_running) {
        destination.release.store(true, .release);
        second_future.await(std.testing.io);
        second_pending = false;
    };
    defer if (first_running) {
        destination.release.store(true, .release);
        first_future.await(std.testing.io);
        first_pending = false;
    };
    first_future = try std.testing.io.concurrent(Task.run, .{ &destination, &first });
    first_running = true;
    second_future = try std.testing.io.concurrent(Task.run, .{ &destination, &second });
    second_running = true;

    var reached: usize = 0;
    for (0..1000) |_| {
        reached = destination.ready.load(.acquire);
        if (reached == 2) break;
        std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expectEqual(@as(usize, 2), reached);
    destination.release.store(true, .release);
    first_future.await(std.testing.io);
    second_future.await(std.testing.io);
    first_running = false;
    second_running = false;
    first_pending = false;
    second_pending = false;
    try session.finish();
    try std.testing.expectEqual(@as(usize, 2), destination.store.count(.xorb));
    try std.testing.expectEqual(@as(usize, 0), session.pending());
}

const Fixture = struct {
    object: xet.xorb.Serialized,
    manifest: xet.reconstruction.ShardPlan,

    fn init(allocator: std.mem.Allocator, inputs: []const []const u8) !Fixture {
        const chunks = try allocator.alloc(xet.xorb.Chunk, inputs.len);
        defer allocator.free(chunks);
        var nodes: xet.hash.Aggregator = .{};
        var size: u64 = 0;
        for (inputs, chunks) |input, *chunk| {
            chunk.* = .{ .data = input, .hash = xet.hash.data(input) };
            try nodes.add(.{ .hash = chunk.hash, .size = input.len });
            size += input.len;
        }
        var object = try xet.xorb.serialize(allocator, chunks, .none);
        errdefer object.deinit(allocator);
        const file_hash = try nodes.fileHash();
        const bytes = try xet.shard.serialize(allocator, &.{.{
            .hash = file_hash,
            .segments = &.{.{
                .xorb_hash = object.hash,
                .unpacked_segment_bytes = @intCast(size),
                .chunk_index_start = 0,
                .chunk_index_end = @intCast(inputs.len),
            }},
            .verification = &.{object.verificationHash()},
        }}, &.{.{
            .hash = object.hash,
            .chunks = object.chunks,
            .raw_size = @intCast(object.raw_size),
            .serialized_size = @intCast(object.body_length),
        }});
        defer allocator.free(bytes);
        return .{
            .object = object,
            .manifest = try xet.reconstruction.planFromShard(allocator, bytes, file_hash),
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.object.deinit(allocator);
        self.manifest.deinit(allocator);
    }
};

const MemoryBase = struct {
    bytes: []const u8,

    fn match(raw: *anyopaque, target: xet.delta.TargetChunk) !?xet.delta.BaseMatch {
        const self: *MemoryBase = @ptrCast(@alignCast(raw));
        if (target.offset + target.size > self.bytes.len) return null;
        const bytes = self.bytes[@intCast(target.offset)..][0..target.size];
        if (!xet.hash.eql(xet.hash.data(bytes), target.hash)) return null;
        return .{ .context = @constCast(bytes.ptr) };
    }
};

fn decodeFetch(allocator: std.mem.Allocator, fixture: *const Fixture, fetch: *xet.delta.Fetch, output: *std.Io.Writer) !void {
    var reader: std.Io.Reader = .fixed(fixture.object.bytes);
    var plan = fetch.plan();
    _ = try xet.reconstruction.decodeOpenedTermVerified(
        allocator,
        &plan,
        &reader,
        fetch.expected_chunks,
        output,
    );
}

test "download cursor mixes memory copies and verified fetched ranges" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "alpha", "beta", "gamma" });
    defer fixture.deinit(allocator);
    var base = MemoryBase{ .bytes = "alphabetaXXXXX" };
    var cursor = try xet.delta.Cursor.init(
        allocator,
        &fixture.manifest.plan,
        fixture.manifest.chunks,
        .{ .context = &base, .match_fn = MemoryBase.match },
    );
    defer cursor.deinit();
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var copies: usize = 0;
    var fetches: usize = 0;
    while (try cursor.next()) |operation_value| {
        var operation = operation_value;
        defer operation.deinit();
        switch (operation) {
            .copy => |copy| {
                const bytes: [*]const u8 = @ptrCast(copy.source.context);
                try output.writer.writeAll(bytes[0..copy.target.size]);
                copies += 1;
            },
            .fetch => |*fetch| {
                try decodeFetch(allocator, &fixture, fetch, &output.writer);
                fetches += 1;
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 2), copies);
    try std.testing.expectEqual(@as(usize, 1), fetches);
    try std.testing.expectEqualStrings("alphabetagamma", output.written());
}

/// Serves exactly the requested inclusive byte range of a serialized xorb
const RangeOpener = struct {
    bytes: []const u8,
    opens: usize = 0,
    reader: std.Io.Reader = undefined,

    fn opener(self: *RangeOpener) xet.stream.Opener {
        return .{ .context = self, .open_fn = open, .close_fn = close };
    }

    fn close(_: *anyopaque, _: *std.Io.Reader) void {}

    fn open(raw: *anyopaque, request: xet.stream.Request) !*std.Io.Reader {
        const self: *RangeOpener = @ptrCast(@alignCast(raw));
        const range = request.byte_range orelse xet.stream.ByteRange{ .start = 0, .end = self.bytes.len - 1 };
        if (range.start > range.end or range.end >= self.bytes.len) return error.InvalidRange;
        self.opens += 1;
        const start: usize = @intCast(range.start);
        self.reader = .fixed(self.bytes[start..][0..@intCast(range.end - range.start + 1)]);
        return &self.reader;
    }
};

fn fetchWith(allocator: std.mem.Allocator, fetch: *xet.delta.Fetch, sources: *RangeOpener, output: *std.Io.Writer) !void {
    const location = fetch.locations[0];
    const source = try sources.opener().open(.{
        .hash = location.hash,
        .url = location.url,
        .byte_range = location.byte_range,
    });
    defer sources.opener().close(source);
    var plan = fetch.plan();
    _ = try xet.reconstruction.decodeOpenedTermVerified(
        allocator,
        &plan,
        source,
        fetch.expected_chunks,
        output,
    );
}

test "download cursor narrows the term before selecting a transport location" {
    const allocator = std.testing.allocator;
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "aa", .hash = xet.hash.data("aa") },
        .{ .data = "bb", .hash = xet.hash.data("bb") },
        .{ .data = "cc", .hash = xet.hash.data("cc") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]xet.reconstruction.Term{.{
        .hash = object.hash,
        .unpacked_length = 6,
        .range = .{ .start = 0, .end = 3 },
    }};
    // Each uncompressed record is an 8-byte header plus its payload
    const locations = [_]xet.reconstruction.Location{
        .{
            .hash = object.hash,
            .range = .{ .start = 0, .end = 3 },
            .url = "memory://broad",
            .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
        },
        .{
            .hash = object.hash,
            .range = .{ .start = 1, .end = 2 },
            .url = "memory://tight",
            .byte_range = .{ .start = 10, .end = 19 },
        },
    };
    var plan = try xet.reconstruction.Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    const expected = [_]xet.reconstruction.ExpectedChunk{
        .{ .hash = xet.hash.data("aa"), .size = 2 },
        .{ .hash = xet.hash.data("bb"), .size = 2 },
        .{ .hash = xet.hash.data("cc"), .size = 2 },
    };
    var base = MemoryBase{ .bytes = "aaxxcc" };
    var cursor = try xet.delta.Cursor.init(
        allocator,
        &plan,
        &expected,
        .{ .context = &base, .match_fn = MemoryBase.match },
    );
    defer cursor.deinit();
    var sources = RangeOpener{ .bytes = object.bytes };
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var copies: usize = 0;
    var fetches: usize = 0;
    while (try cursor.next()) |operation_value| {
        var operation = operation_value;
        defer operation.deinit();
        switch (operation) {
            .copy => |copy| {
                const bytes: [*]const u8 = @ptrCast(copy.source.context);
                try output.writer.writeAll(bytes[0..copy.target.size]);
                copies += 1;
            },
            .fetch => |*fetch| {
                try std.testing.expectEqualStrings("memory://tight", fetch.locations[0].url);
                try std.testing.expectEqual(@as(u64, 10), fetch.locations[0].byte_range.?.start);
                try std.testing.expectEqual(@as(u32, 1), fetch.terms[0].range.start);
                try std.testing.expectEqual(@as(u32, 2), fetch.terms[0].range.end);
                try fetchWith(allocator, fetch, &sources, &output.writer);
                fetches += 1;
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 2), copies);
    try std.testing.expectEqual(@as(usize, 1), fetches);
    try std.testing.expectEqual(@as(usize, 1), sources.opens);
    try std.testing.expectEqualStrings("aabbcc", output.written());
}

test "download cursor picks a packed range over a whole-object fallback" {
    const allocator = std.testing.allocator;
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "aa", .hash = xet.hash.data("aa") },
        .{ .data = "bb", .hash = xet.hash.data("bb") },
        .{ .data = "cc", .hash = xet.hash.data("cc") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]xet.reconstruction.Term{.{
        .hash = object.hash,
        .unpacked_length = 6,
        .range = .{ .start = 0, .end = 3 },
    }};
    const whole = xet.reconstruction.Location{
        .hash = object.hash,
        .range = .{ .start = 1, .end = 2 },
        .url = "memory://whole",
        .byte_range = null,
    };
    const bounded = xet.reconstruction.Location{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 3 },
        .url = "memory://broad",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    };
    const orders = [_][2]xet.reconstruction.Location{
        .{ bounded, whole },
        .{ whole, bounded },
    };
    for (orders) |locations| {
        var plan = try xet.reconstruction.Plan.init(allocator, &terms, &locations);
        defer plan.deinit(allocator);
        const expected = [_]xet.reconstruction.ExpectedChunk{
            .{ .hash = xet.hash.data("aa"), .size = 2 },
            .{ .hash = xet.hash.data("bb"), .size = 2 },
            .{ .hash = xet.hash.data("cc"), .size = 2 },
        };
        var base = MemoryBase{ .bytes = "aaxxcc" };
        var cursor = try xet.delta.Cursor.init(
            allocator,
            &plan,
            &expected,
            .{ .context = &base, .match_fn = MemoryBase.match },
        );
        defer cursor.deinit();
        var sources = RangeOpener{ .bytes = object.bytes };
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        var copies: usize = 0;
        var fetches: usize = 0;
        while (try cursor.next()) |operation_value| {
            var operation = operation_value;
            defer operation.deinit();
            switch (operation) {
                .copy => |copy| {
                    const bytes: [*]const u8 = @ptrCast(copy.source.context);
                    try output.writer.writeAll(bytes[0..copy.target.size]);
                    copies += 1;
                },
                .fetch => |*fetch| {
                    try std.testing.expectEqualStrings("memory://broad", fetch.locations[0].url);
                    try std.testing.expectEqual(@as(u32, 1), fetch.terms[0].range.start);
                    try std.testing.expectEqual(@as(u32, 2), fetch.terms[0].range.end);
                    try fetchWith(allocator, fetch, &sources, &output.writer);
                    fetches += 1;
                },
            }
        }
        try std.testing.expectEqual(@as(usize, 2), copies);
        try std.testing.expectEqual(@as(usize, 1), fetches);
        try std.testing.expectEqual(@as(usize, 1), sources.opens);
        try std.testing.expectEqualStrings("aabbcc", output.written());
    }
}

test "download cursor tracks the term as it advances through later terms" {
    const allocator = std.testing.allocator;
    const chunks = [_]xet.xorb.Chunk{
        .{ .data = "aa", .hash = xet.hash.data("aa") },
        .{ .data = "bb", .hash = xet.hash.data("bb") },
        .{ .data = "cc", .hash = xet.hash.data("cc") },
        .{ .data = "dd", .hash = xet.hash.data("dd") },
    };
    var object = try xet.xorb.serialize(allocator, &chunks, .none);
    defer object.deinit(allocator);
    const terms = [_]xet.reconstruction.Term{
        .{ .hash = object.hash, .unpacked_length = 2, .range = .{ .start = 0, .end = 1 } },
        .{ .hash = object.hash, .unpacked_length = 6, .range = .{ .start = 1, .end = 4 } },
    };
    const locations = [_]xet.reconstruction.Location{.{
        .hash = object.hash,
        .range = .{ .start = 0, .end = 4 },
        .url = "memory://object",
        .byte_range = .{ .start = 0, .end = @intCast(object.bytes.len - 1) },
    }};
    var plan = try xet.reconstruction.Plan.init(allocator, &terms, &locations);
    defer plan.deinit(allocator);
    const expected = [_]xet.reconstruction.ExpectedChunk{
        .{ .hash = xet.hash.data("aa"), .size = 2 },
        .{ .hash = xet.hash.data("bb"), .size = 2 },
        .{ .hash = xet.hash.data("cc"), .size = 2 },
        .{ .hash = xet.hash.data("dd"), .size = 2 },
    };
    var base = MemoryBase{ .bytes = "aaxxccyy" };
    var cursor = try xet.delta.Cursor.init(
        allocator,
        &plan,
        &expected,
        .{ .context = &base, .match_fn = MemoryBase.match },
    );
    defer cursor.deinit();
    var ranges: [2]xet.reconstruction.Range = undefined;
    var fetches: usize = 0;
    while (try cursor.next()) |operation_value| {
        var operation = operation_value;
        defer operation.deinit();
        if (operation != .fetch) continue;
        ranges[fetches] = operation.fetch.terms[0].range;
        fetches += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), fetches);
    try std.testing.expectEqual(@as(u32, 1), ranges[0].start);
    try std.testing.expectEqual(@as(u32, 2), ranges[0].end);
    try std.testing.expectEqual(@as(u32, 3), ranges[1].start);
    try std.testing.expectEqual(@as(u32, 4), ranges[1].end);
}

test "download fetch operations can write a positional file" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "first", "-second", "-third" });
    defer fixture.deinit(allocator);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile(std.testing.io, "output", .{ .read = true });
    defer file.close(std.testing.io);
    var cursor = try xet.delta.Cursor.init(allocator, &fixture.manifest.plan, fixture.manifest.chunks, null);
    defer cursor.deinit();
    while (try cursor.next()) |operation_value| {
        var operation = operation_value;
        defer operation.deinit();
        try std.testing.expect(operation == .fetch);
        var bytes: std.Io.Writer.Allocating = .init(allocator);
        defer bytes.deinit();
        try decodeFetch(allocator, &fixture, &operation.fetch, &bytes.writer);
        try file.writePositionalAll(std.testing.io, bytes.written(), operation.fetch.offset);
    }
    try file.setLength(std.testing.io, fixture.manifest.size);
    var bytes: [64]u8 = undefined;
    const count = try file.readPositional(std.testing.io, &.{&bytes}, 0);
    try std.testing.expectEqualStrings("first-second-third", bytes[0..count]);
}

const Handle = struct {
    released: *usize,
};

const OwnedBase = struct {
    matches: []const bool,
    created: usize = 0,
    releases: usize = 0,

    fn base(self: *OwnedBase) xet.delta.Base {
        return .{ .context = self, .match_fn = match };
    }

    fn match(raw: *anyopaque, target: xet.delta.TargetChunk) !?xet.delta.BaseMatch {
        const self: *OwnedBase = @ptrCast(@alignCast(raw));
        if (!self.matches[target.index]) return null;
        const handle = try std.testing.allocator.create(Handle);
        handle.* = .{ .released = &self.releases };
        self.created += 1;
        return .{ .context = handle, .release_fn = release };
    }

    fn release(raw: *anyopaque) void {
        const handle: *Handle = @ptrCast(@alignCast(raw));
        handle.released.* += 1;
        std.testing.allocator.destroy(handle);
    }
};

test "download operations retain base handles after cursor destruction" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "aa", "bbb", "cc" });
    defer fixture.deinit(allocator);
    var base = OwnedBase{ .matches = &.{ true, false, true } };
    var cursor = try xet.delta.Cursor.init(allocator, &fixture.manifest.plan, fixture.manifest.chunks, base.base());
    var issued = (try cursor.next()).?;
    var pending = true;
    defer if (pending) issued.deinit();
    try std.testing.expect(issued == .copy);
    var fetch = (try cursor.next()).?;
    try std.testing.expect(fetch == .fetch);
    // The copy matched past the fetch stays in the cursor's lookahead
    try std.testing.expectEqual(@as(usize, 2), base.created);

    cursor.deinit();
    // Only the cursor's lookahead handle dies with it
    try std.testing.expectEqual(@as(usize, 1), base.releases);
    issued.deinit();
    pending = false;
    try std.testing.expectEqual(@as(usize, 2), base.releases);
    fetch.deinit();
    try std.testing.expectEqual(@as(usize, 2), base.releases);
}

/// Fails the first lookup of chunk 1, optionally matching chunk 0
const FlakyBase = struct {
    fail: bool = true,
    match_zero: bool = false,
    created: usize = 0,
    released: usize = 0,

    fn base(self: *FlakyBase) xet.delta.Base {
        return .{ .context = self, .match_fn = match };
    }

    fn match(raw: *anyopaque, target: xet.delta.TargetChunk) !?xet.delta.BaseMatch {
        const self: *FlakyBase = @ptrCast(@alignCast(raw));
        if (target.index == 0 and !self.match_zero) return null;
        if (self.fail and target.index == 1) {
            self.fail = false;
            return error.InjectedFailure;
        }
        const handle = try std.testing.allocator.create(Handle);
        handle.* = .{ .released = &self.released };
        self.created += 1;
        return .{ .context = handle, .release_fn = release };
    }

    fn release(raw: *anyopaque) void {
        const handle: *Handle = @ptrCast(@alignCast(raw));
        handle.released.* += 1;
        std.testing.allocator.destroy(handle);
    }
};

test "cursor retries a failed lookahead without skipping chunks" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "aa", "bb", "cc" });
    defer fixture.deinit(allocator);
    var base = FlakyBase{};
    var cursor = try xet.delta.Cursor.init(allocator, &fixture.manifest.plan, fixture.manifest.chunks, base.base());
    defer cursor.deinit();
    var covered: u64 = 0;
    var copies: usize = 0;
    var fetches: usize = 0;
    var failed = false;
    while (true) {
        const value = cursor.next() catch |err| {
            try std.testing.expect(!failed);
            try std.testing.expectEqual(error.InjectedFailure, err);
            failed = true;
            continue;
        };
        const operation = value orelse break;
        var owned = operation;
        defer owned.deinit();
        switch (owned) {
            .copy => |copy| {
                try std.testing.expectEqual(covered, copy.target.offset);
                try std.testing.expect(copy.source.release_fn != null);
                covered += copy.target.size;
                copies += 1;
            },
            .fetch => |fetch| {
                try std.testing.expectEqual(covered, fetch.offset);
                var len: u64 = 0;
                for (fetch.expected_chunks) |chunk| len += chunk.size;
                try std.testing.expectEqual(len, fetch.terms[0].unpacked_length);
                covered += len;
                fetches += 1;
            },
        }
    }
    try std.testing.expect(failed);
    try std.testing.expectEqual(fixture.manifest.size, covered);
    try std.testing.expectEqual(@as(usize, 1), fetches);
    try std.testing.expectEqual(@as(usize, 2), copies);
    try std.testing.expectEqual(@as(usize, 2), base.created);
    try std.testing.expectEqual(@as(usize, 2), base.released);
}

test "cursor deinit after a failed lookahead keeps handles single-owner" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "aa", "bb", "cc" });
    defer fixture.deinit(allocator);
    var base = FlakyBase{ .match_zero = true };
    var cursor = try xet.delta.Cursor.init(allocator, &fixture.manifest.plan, fixture.manifest.chunks, base.base());
    var operation = (try cursor.next()).?;
    try std.testing.expect(operation == .copy);
    try std.testing.expectEqual(@as(u64, 0), operation.copy.target.offset);
    try std.testing.expectEqual(@as(u32, 2), operation.copy.target.size);
    try std.testing.expectError(error.InjectedFailure, cursor.next());
    cursor.deinit();
    try std.testing.expectEqual(@as(usize, 1), base.created);
    try std.testing.expectEqual(@as(usize, 0), base.released);
    operation.deinit();
    try std.testing.expectEqual(@as(usize, 1), base.released);
}

test "cursor deinit after a failed first probe releases nothing" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "aa", "bb" });
    defer fixture.deinit(allocator);
    var base = FlakyBase{};
    var cursor = try xet.delta.Cursor.init(allocator, &fixture.manifest.plan, fixture.manifest.chunks, base.base());
    try std.testing.expectError(error.InjectedFailure, cursor.next());
    cursor.deinit();
    try std.testing.expectEqual(@as(usize, 0), base.created);
    try std.testing.expectEqual(@as(usize, 0), base.released);
}

/// One term of two one-byte chunks with a whole-object location
const TwoChunkPlan = struct {
    plan: xet.reconstruction.Plan,
    chunks: [2]xet.reconstruction.ExpectedChunk,

    fn init(allocator: std.mem.Allocator) !TwoChunkPlan {
        const hash = xet.hash.data("object");
        const terms = [_]xet.reconstruction.Term{.{
            .hash = hash,
            .unpacked_length = 2,
            .range = .{ .start = 0, .end = 2 },
        }};
        const locations = [_]xet.reconstruction.Location{.{
            .hash = hash,
            .range = .{ .start = 0, .end = 2 },
            .url = "memory://object",
            .byte_range = null,
        }};
        return .{
            .plan = try xet.reconstruction.Plan.init(allocator, &terms, &locations),
            .chunks = .{
                .{ .hash = xet.hash.data("a"), .size = 1 },
                .{ .hash = xet.hash.data("b"), .size = 1 },
            },
        };
    }

    fn deinit(self: *TwoChunkPlan, allocator: std.mem.Allocator) void {
        self.plan.deinit(allocator);
    }
};

test "cursor deinit releases a pending match when the locator allocation fails" {
    const allocator = std.testing.allocator;
    var fixture = try TwoChunkPlan.init(allocator);
    defer fixture.deinit(allocator);
    var base = OwnedBase{ .matches = &.{ false, true } };
    var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = 0 };
    defer tracker.deinit();
    var cursor = try xet.delta.Cursor.init(
        tracker.allocator(),
        &fixture.plan,
        &fixture.chunks,
        base.base(),
    );
    try std.testing.expectError(error.OutOfMemory, cursor.next());
    try std.testing.expectEqual(@as(usize, 1), base.created);
    try std.testing.expectEqual(@as(usize, 1), base.releases);
    cursor.deinit();
    try std.testing.expectEqual(@as(usize, 1), base.releases);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "cursor retries after a locator allocation failure and releases each handle once" {
    const allocator = std.testing.allocator;
    var fixture = try TwoChunkPlan.init(allocator);
    defer fixture.deinit(allocator);
    var base = OwnedBase{ .matches = &.{ false, true } };
    var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = 0 };
    defer tracker.deinit();
    var cursor = try xet.delta.Cursor.init(
        tracker.allocator(),
        &fixture.plan,
        &fixture.chunks,
        base.base(),
    );
    try std.testing.expectError(error.OutOfMemory, cursor.next());
    try std.testing.expectEqual(@as(usize, 1), base.created);
    try std.testing.expectEqual(@as(usize, 1), base.releases);

    tracker.fail_at = null;
    var covered: u64 = 0;
    var operations: usize = 0;
    while (try cursor.next()) |operation_value| {
        var operation = operation_value;
        defer operation.deinit();
        switch (operation) {
            .fetch => |fetch| {
                try std.testing.expectEqual(@as(u64, 0), fetch.offset);
                try std.testing.expectEqual(covered, fetch.offset);
                try std.testing.expectEqual(@as(u32, 0), fetch.terms[0].range.start);
                try std.testing.expectEqual(@as(u32, 1), fetch.terms[0].range.end);
                covered += fetch.terms[0].unpacked_length;
            },
            .copy => |copy| {
                try std.testing.expectEqual(@as(u64, 1), copy.target.offset);
                try std.testing.expectEqual(covered, copy.target.offset);
                try std.testing.expectEqual(@as(u32, 1), copy.target.size);
                covered += copy.target.size;
            },
        }
        operations += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), operations);
    try std.testing.expectEqual(@as(u64, 2), covered);
    cursor.deinit();
    try std.testing.expectEqual(@as(usize, 2), base.created);
    try std.testing.expectEqual(@as(usize, 2), base.releases);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}

test "delta target validation rejects inverted term ranges" {
    var terms = [_]xet.reconstruction.Term{.{
        .hash = xet.hash.zero,
        .unpacked_length = 2,
        .range = .{ .start = 2, .end = 1 },
    }};
    var plan = xet.reconstruction.Plan{ .terms = &terms, .locations = &.{} };
    const chunks = [_]xet.reconstruction.ExpectedChunk{.{
        .hash = xet.hash.data("AA"),
        .size = 2,
    }};
    try std.testing.expectError(error.InvalidRange, xet.delta.validateTarget(&plan, &chunks));
}

test "download collected plan releases matches on allocation failure" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator, &.{ "aa", "bb" });
    defer fixture.deinit(allocator);
    var base = OwnedBase{ .matches = &.{ true, true } };
    var tracker = support.TrackingAllocator{ .backing = allocator, .fail_at = 0 };
    defer tracker.deinit();
    try std.testing.expectError(error.OutOfMemory, xet.delta.plan(
        tracker.allocator(),
        &fixture.manifest.plan,
        fixture.manifest.chunks,
        base.base(),
    ));
    try std.testing.expectEqual(@as(usize, 1), base.releases);
    try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
}
