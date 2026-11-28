const std = @import("std");
const xet = @import("xet");
const support = @import("test_support");

test "streaming publisher matches contiguous hashes with tiny xorbs" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    var package = try xet.store.pack(allocator, data, .{ .max_xorb_size = 128 * 1024 });
    defer package.deinit(allocator);
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
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

test "a releasing operation listener still stores xorbs" {
    const allocator = std.testing.allocator;
    const Observer = struct {
        fn callback(_: *anyopaque, _: xet.store.Operation) !xet.store.OperationDisposition {
            return .release;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .operation_listener = .{ .context = undefined, .callback = Observer.callback },
    });
    defer publisher.deinit();
    try publisher.write("AAA");
    _ = try publisher.finish();
    try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 1), destination.count(.shard));
}

test "a retained payload is freed through its owning allocator" {
    const allocator = std.testing.allocator;
    const Retainer = struct {
        payload: []const u8 = &.{},
        owner: ?std.mem.Allocator = null,
        fn callback(
            raw: *anyopaque,
            operation: xet.store.Operation,
        ) !xet.store.OperationDisposition {
            const self: *@This() = @ptrCast(@alignCast(raw));
            switch (operation) {
                .store => |value| {
                    self.payload = value.item.data;
                    self.owner = value.allocator;
                },
                .reference => {},
            }
            return .retain;
        }
    };
    var retain = Retainer{};
    // The shared writer allocates the payload, not the publisher that installed the listener
    var publisher_tracker = support.TrackingAllocator{ .backing = allocator };
    defer publisher_tracker.deinit();
    var writer_tracker = support.TrackingAllocator{ .backing = allocator };
    defer writer_tracker.deinit();
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(writer_tracker.allocator(), destination.store(), .none);
    defer writer.deinit();
    var publisher = try xet.store.Publisher.init(
        publisher_tracker.allocator(),
        destination.store(),
        .{
            .compression = .none,
            .max_xorb_chunks = 1,
            .operation_listener = .{ .context = &retain, .callback = Retainer.callback },
            .xorb_writer = &writer,
        },
    );
    defer publisher.deinit();
    try publisher.write("retained payload");
    var plan = try publisher.finishPlan();
    defer plan.deinit(publisher_tracker.allocator());

    try std.testing.expect(retain.payload.len != 0);
    const owner = retain.owner orelse return error.TestMissingOwnerAllocator;
    owner.free(retain.payload);
    try std.testing.expectEqual(@as(usize, 0), publisher_tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), writer_tracker.invalid_frees);
    try std.testing.expectEqual(@as(usize, 0), writer_tracker.duplicate_frees);
}

test "repeated xorbs upload once and retain every file segment" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(data);
    @memset(data, 0);

    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
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

    var package = try xet.store.pack(allocator, data, .{ .max_xorb_size = 1024 * 1024 });
    defer package.deinit(allocator);
    const packed_reader = try xet.shard.Reader.init(package.shard_bytes);
    try std.testing.expectEqual(@as(usize, 1), packed_reader.footer.xorb_count);
    try std.testing.expectEqual(result.file_hash, package.file_hash);
}

test "low-level reuse publishes an owned UploadPlan" {
    const allocator = std.testing.allocator;
    const nodes = [_]xet.hash.Node{
        .{ .hash = xet.hash.data("AAA"), .size = 3 },
        .{ .hash = xet.hash.data("BBB"), .size = 3 },
    };
    const file_hash = try xet.hash.file(allocator, &nodes);
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(
        allocator,
        destination.store(),
        .{ .compression = .none },
    );
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
    try std.testing.expectEqual(
        xet.hash.verification(&.{ nodes[0].hash, nodes[1].hash }),
        try file.verification(0),
    );
    try std.testing.expectError(error.AlreadyFinished, publisher.reuse(
        nodes[0].hash,
        0,
        nodes[0..1],
    ));
}

test "BatchPublisher takes plans and publishes combined metadata through any Store" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();

    const inputs = [_][]const u8{ "AAA", "BBB" };
    var hashes: [inputs.len]xet.Hash = undefined;
    for (inputs, &hashes, 0..) |input, *file_hash, index| {
        var publisher = try xet.store.Publisher.init(
            allocator,
            destination.store(),
            .{ .compression = .none },
        );
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
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();

    for ([_][]const u8{ "AAA", "AAA" }) |input| {
        var publisher = try xet.store.Publisher.init(
            allocator,
            destination.store(),
            .{ .compression = .none },
        );
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

/// A resolved term followed by the trailing term the open Xorb still owns
fn openXorbPlan(allocator: std.mem.Allocator, tag: []const u8) !xet.store.Plan {
    const segments = try allocator.alloc(xet.shard.Segment, 2);
    errdefer allocator.free(segments);
    segments[0] = .{
        .xorb_hash = xet.hash.data(tag),
        .unpacked_segment_bytes = 3,
        .chunk_index_start = 0,
        .chunk_index_end = 1,
    };
    segments[1] = .{
        .xorb_hash = xet.hash.zero,
        .unpacked_segment_bytes = 3,
        .chunk_index_start = 1,
        .chunk_index_end = 2,
    };
    const checks = try allocator.alloc(xet.Hash, 2);
    errdefer allocator.free(checks);
    checks[0] = xet.hash.verification(&.{xet.hash.data(tag)});
    checks[1] = checks[0];
    return .{
        .file = .{ .hash = xet.hash.data(tag), .segments = segments, .verification = checks },
        .size = 6,
        .xorb_count = 2,
    };
}

test "BatchPublisher patches only the segments awaiting the open Xorb" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();

    var first = try openXorbPlan(allocator, "first");
    try batch.append(&first);
    var second = try openXorbPlan(allocator, "second");
    try batch.append(&second);
    try std.testing.expectEqual(@as(usize, 2), batch.waiting.items.len);

    const open_hash = xet.hash.data("open xorb");
    batch.resolveOpenXorb(null, open_hash);
    try std.testing.expectEqual(@as(usize, 0), batch.waiting.items.len);
    for (batch.plans.items) |plan| {
        try std.testing.expectEqual(open_hash, plan.file.segments[1].xorb_hash);
    }
    try std.testing.expectEqual(
        xet.hash.data("first"),
        batch.plans.items[0].file.segments[0].xorb_hash,
    );

    // A later Xorb must not rewrite terms that are already resolved
    batch.resolveOpenXorb(null, xet.hash.data("other"));
    try std.testing.expectEqual(open_hash, batch.plans.items[0].file.segments[1].xorb_hash);

    // One flush per file leaves exactly the newest term waiting
    for (0..64) |_| {
        var next = try openXorbPlan(allocator, "many");
        try batch.append(&next);
        try std.testing.expectEqual(@as(usize, 1), batch.waiting.items.len);
        batch.resolveOpenXorb(null, open_hash);
        try std.testing.expectEqual(@as(usize, 0), batch.waiting.items.len);
    }

    try batch.finish();
    const shard_object = for (destination.objects.items) |object| {
        if (object.kind == .shard) break object;
    } else return error.TestExpectedShard;
    const reader = try xet.shard.Reader.init(shard_object.data);
    const file = (try reader.findFile(xet.hash.data("first"))).?;
    try std.testing.expectEqual(xet.hash.data("first"), (try file.segment(0)).xorb_hash);
    try std.testing.expectEqual(open_hash, (try file.segment(1)).xorb_hash);
}

test "Plan.publish rejects a segment awaiting the shared Xorb" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .xorb_writer = &writer,
    });
    defer publisher.deinit();
    try publisher.write("alpha");
    var plan = try publisher.finishPlan();
    try std.testing.expectEqual(xet.hash.zero, plan.file.segments[0].xorb_hash);
    try std.testing.expectError(error.XorbLeftOpen, plan.publish(allocator, destination.store()));
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

test "a spent shared publisher keeps the next publisher's listener" {
    const allocator = std.testing.allocator;
    const Observer = struct {
        calls: usize = 0,
        fn callback(raw: *anyopaque, _: xet.store.Operation) !xet.store.OperationDisposition {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            return .release;
        }
    };
    var observer = Observer{};
    const listener: xet.store.OperationListener = .{
        .context = &observer,
        .callback = Observer.callback,
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const opts: xet.store.PublisherOptions = .{
        .compression = .none,
        .max_xorb_chunks = 1,
        .operation_listener = listener,
        .xorb_writer = &writer,
    };

    var first = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try first.write("alpha");
    var first_plan = try first.finishPlan();
    defer first_plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try first.acceptPlan();

    // The same observer context is reused, but only the newer install is current
    var second = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try second.write("bravo");
    first.deinit();
    var second_plan = try second.finishPlan();
    defer second_plan.deinit(allocator);
    second.deinit();

    try std.testing.expectEqual(@as(usize, 2), observer.calls);
    try std.testing.expectEqual(@as(usize, 2), destination.count(.xorb));
}

test "a shared writer allows one active publisher at a time" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const opts: xet.store.PublisherOptions = .{ .compression = .none, .xorb_writer = &writer };

    var first = try xet.store.Publisher.init(allocator, destination.store(), opts);
    var retain_first = true;
    defer if (retain_first) first.deinit();
    try first.write("a");

    // A second publisher would let first's segment span b at [0, 2)
    try std.testing.expectError(
        error.ActivePublisher,
        xet.store.Publisher.init(allocator, destination.store(), opts),
    );

    // A finished plan keeps the claim until its batch accepts it
    var first_plan = try first.finishPlan();
    defer first_plan.deinit(allocator);
    try std.testing.expectError(
        error.ActivePublisher,
        xet.store.Publisher.init(allocator, destination.store(), opts),
    );
    // Accepting hands the writer on while the earlier handle stays alive
    try first.acceptPlan();
    var second = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer second.deinit();
    try second.write("b");
    first.deinit();
    retain_first = false;

    // The spent handle must not release the claim the newer file now owns
    try std.testing.expectError(
        error.ActivePublisher,
        xet.store.Publisher.init(allocator, destination.store(), opts),
    );
    var second_plan = try second.finishPlan();
    defer second_plan.deinit(allocator);
    try second.acceptPlan();

    // Each file owns only the Xorb range its own chunks produced
    try std.testing.expectEqual(@as(u32, 0), first_plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 1), first_plan.file.segments[0].chunk_index_end);
    try std.testing.expectEqual(@as(u32, 1), second_plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 2), second_plan.file.segments[0].chunk_index_end);

    // Recon is the check the interleaved ranges failed
    const first_hash = first_plan.file.hash;
    const second_hash = second_plan.file.hash;
    const open_hash = try writer.flush();
    @constCast(first_plan.file.segments)[0].xorb_hash = open_hash;
    @constCast(second_plan.file.segments)[0].xorb_hash = open_hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&first_plan);
    try batch.append(&second_plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackage(allocator, &destination, first_hash, "a");
    try reconstructCapturedPackage(allocator, &destination, second_hash, "b");

    // Abandoning a publisher also releases the writer
    var abandoned = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try abandoned.write("c");
    abandoned.deinit();
    var third = try xet.store.Publisher.init(allocator, destination.store(), opts);
    third.deinit();
}

test "a rejected publisher leaves the active file's chunking strategy alone" {
    const allocator = std.testing.allocator;
    const Counting = struct {
        seen: usize = 0,
        resets: usize = 0,

        fn strategy(self: *@This()) xet.chunker.Strategy {
            return .{ .context = self, .next_fn = next, .reset_fn = reset };
        }

        fn next(raw: *anyopaque, _: []const u8, input: []const u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const need = 2 -| self.seen;
            if (input.len < need) {
                self.seen += input.len;
                return null;
            }
            return need;
        }

        fn reset(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.seen = 0;
            self.resets += 1;
        }
    };
    var context = Counting{};
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const opts: xet.store.PublisherOptions = .{
        .compression = .none,
        .strategy = context.strategy(),
        .xorb_writer = &writer,
    };

    var publisher = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer publisher.deinit();
    try publisher.write("a");

    // Resetting the borrowed strategy here would rewrite the chunk already in flight
    const resets = context.resets;
    try std.testing.expectError(
        error.ActivePublisher,
        xet.store.Publisher.init(allocator, destination.store(), opts),
    );
    try std.testing.expectEqual(resets, context.resets);
    try publisher.write("bc");

    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 2), plan.file.segments[0].chunk_index_end);

    // The same input without an interleaved init chunks and hashes identically
    var control_destination = support.MemoryStore{ .allocator = allocator };
    defer control_destination.deinit();
    var control = try xet.store.Publisher.init(allocator, control_destination.store(), .{
        .compression = .none,
        .strategy = context.strategy(),
    });
    defer control.deinit();
    try control.write("a");
    try control.write("bc");
    var control_plan = try control.finishPlan();
    defer control_plan.deinit(allocator);
    try std.testing.expectEqual(control_plan.file.hash, plan.file.hash);
}

test "a finished plan keeps its claim until the batch accepts it" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var fixed = try xet.chunker.Fixed.init(1);
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = fixed.strategy(),
        .xorb_writer = &writer,
    });
    var retain = true;
    defer if (retain) publisher.deinit();
    try publisher.write("ab");
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);

    // The windows between finishPlan and append still own the chunks
    try std.testing.expectError(error.ActivePublisher, writer.rollback());
    try std.testing.expectError(error.ActivePublisher, writer.discardBuffered());
    try std.testing.expectError(error.ActivePublisher, writer.flush());
    try std.testing.expectError(error.ActivePublisher, writer.add(.{
        .data = "z",
        .hash = xet.hash.data("z"),
    }));
    try std.testing.expectEqual(@as(u32, 2), writer.count());

    const file_hash = plan.file.hash;
    try publisher.acceptPlan();
    publisher.deinit();
    retain = false;
    const open_hash = try writer.flush();
    @constCast(plan.file.segments)[0].xorb_hash = open_hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackageWith(allocator, &destination, file_hash, "ab", fixed.strategy());
}

test "an abandoned plan releases the claim a later file needs" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const opts: xet.store.PublisherOptions = .{ .compression = .none, .xorb_writer = &writer };

    // A caller that builds a plan and never appends must not wedge the writer
    var abandoned = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try abandoned.write("abandoned");
    var plan = try abandoned.finishPlan();
    plan.deinit(allocator);
    abandoned.abort();
    abandoned.deinit();
    try std.testing.expectEqual(@as(u32, 0), writer.count());

    var next = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer next.deinit();
    try next.write("c");
    var next_plan = try next.finishPlan();
    defer next_plan.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 1), writer.count());
}

test "an active publisher rejects direct writer mutations" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var fixed = try xet.chunker.Fixed.init(1);
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = fixed.strategy(),
        .xorb_writer = &writer,
    });
    defer publisher.deinit();
    try publisher.write("a");

    // Closing, filling or re-marking the Xorb here would leave the file's segment stale
    try std.testing.expectError(error.ActivePublisher, writer.mark());
    try std.testing.expectError(error.ActivePublisher, writer.flush());
    try std.testing.expectError(error.ActivePublisher, writer.takeXorbs());
    try std.testing.expectError(error.ActivePublisher, writer.add(.{
        .data = "z",
        .hash = xet.hash.data("z"),
    }));
    try std.testing.expectEqual(@as(u32, 1), writer.count());

    try publisher.write("b");
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0), plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 2), plan.file.segments[0].chunk_index_end);

    // Only the publisher's own close may empty the Xorb it filled
    try publisher.acceptPlan();
    const open_hash = try writer.flush();
    @constCast(plan.file.segments)[0].xorb_hash = open_hash;
    try std.testing.expectEqual(@as(usize, 1), writer.xorbs.items.len);
    try std.testing.expectEqual(@as(usize, 2), writer.xorbs.items[0].chunks.len);
    try std.testing.expectEqual(open_hash, writer.xorbs.items[0].hash);
}

test "an active publisher rejects direct writer rollback and discard" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var fixed = try xet.chunker.Fixed.init(1);
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = fixed.strategy(),
        .xorb_writer = &writer,
    });
    defer publisher.deinit();
    try publisher.write("a");

    // Dropping the open segment would leave the file's term naming a missing chunk
    try std.testing.expectError(error.ActivePublisher, writer.rollback());
    try std.testing.expectError(error.ActivePublisher, writer.discardBuffered());
    try std.testing.expectEqual(@as(u32, 1), writer.count());

    try publisher.write("b");
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    const file_hash = plan.file.hash;
    try std.testing.expectEqual(@as(u32, 0), plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 2), plan.file.segments[0].chunk_index_end);

    try publisher.acceptPlan();
    const open_hash = try writer.flush();
    @constCast(plan.file.segments)[0].xorb_hash = open_hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackageWith(allocator, &destination, file_hash, "ab", fixed.strategy());
}

test "a raw rollback leaves the chunks an accepted plan committed" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var fixed = try xet.chunker.Fixed.init(1);
    const opts: xet.store.PublisherOptions = .{
        .compression = .none,
        .strategy = fixed.strategy(),
        .xorb_writer = &writer,
    };

    var first = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try first.write("a");
    var first_plan = try first.finishPlan();
    defer first_plan.deinit(allocator);
    // Accepting the plan commits its chunks, so a later raw cleanup stops below them
    try first.acceptPlan();
    first.deinit();
    try writer.rollback();
    try writer.discardBuffered();
    try std.testing.expectEqual(@as(u32, 1), writer.count());

    const first_hash = first_plan.file.hash;
    const open_hash = try writer.flush();
    @constCast(first_plan.file.segments)[0].xorb_hash = open_hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&first_plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackageWith(allocator, &destination, first_hash, "a", fixed.strategy());
}

test "the owning publisher's abort retires its claim and keeps committed chunks" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const opts: xet.store.PublisherOptions = .{ .compression = .none, .xorb_writer = &writer };

    var first = try xet.store.Publisher.init(allocator, destination.store(), opts);
    var retain_first = true;
    defer if (retain_first) first.deinit();
    try first.write("a");
    var first_plan = try first.finishPlan();
    defer first_plan.deinit(allocator);
    try first.acceptPlan();

    // The abandoned file drops only its own chunks, leaving the first file's alone
    var abandoned = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try abandoned.write("bb");
    abandoned.abort();
    try std.testing.expectEqual(@as(u32, 1), writer.count());
    // The abort released the claim, so a stale deinit cannot disturb the next file
    abandoned.deinit();

    var second = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer second.deinit();
    try second.write("c");
    var second_plan = try second.finishPlan();
    defer second_plan.deinit(allocator);
    try second.acceptPlan();
    first.deinit();
    retain_first = false;

    const first_hash = first_plan.file.hash;
    const second_hash = second_plan.file.hash;
    const open_hash = try writer.flush();
    @constCast(first_plan.file.segments)[0].xorb_hash = open_hash;
    @constCast(second_plan.file.segments)[0].xorb_hash = open_hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&first_plan);
    try batch.append(&second_plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackage(allocator, &destination, first_hash, "a");
    try reconstructCapturedPackage(allocator, &destination, second_hash, "c");
}

test "an abandoned empty publisher keeps the previous file's chunks" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var fixed = try xet.chunker.Fixed.init(1);
    const opts: xet.store.PublisherOptions = .{
        .compression = .none,
        .strategy = fixed.strategy(),
        .xorb_writer = &writer,
    };

    var first = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try first.write("ab");
    var first_plan = try first.finishPlan();
    defer first_plan.deinit(allocator);
    try first.acceptPlan();
    first.deinit();

    // An empty file owns no chunks, so its cleanup must stop at the previous file
    var empty = try xet.store.Publisher.init(allocator, destination.store(), opts);
    empty.deinit();

    var last = try xet.store.Publisher.init(allocator, destination.store(), opts);
    try last.write("c");
    var last_plan = try last.finishPlan();
    defer last_plan.deinit(allocator);
    try last.acceptPlan();
    last.deinit();

    const open_hash = try writer.flush();
    for (@constCast(first_plan.file.segments)) |*segment| segment.xorb_hash = open_hash;
    for (@constCast(last_plan.file.segments)) |*segment| segment.xorb_hash = open_hash;
    const first_hash = first_plan.file.hash;
    const last_hash = last_plan.file.hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&first_plan);
    try batch.append(&last_plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackageWith(allocator, &destination, first_hash, "ab", fixed.strategy());
    try reconstructCapturedPackageWith(allocator, &destination, last_hash, "c", fixed.strategy());
}

test "deinit rolls back a shared writer after a failed finish plan" {
    const allocator = std.testing.allocator;
    const baseline_allocations = blk: {
        var tracker = support.TrackingAllocator{ .backing = allocator };
        defer tracker.deinit();
        var destination = support.MemoryStore{ .allocator = tracker.allocator() };
        defer destination.deinit();
        var writer = xet.store.XorbWriter.init(tracker.allocator(), destination.store(), .none);
        defer writer.deinit();
        var publisher = try xet.store.Publisher.init(tracker.allocator(), destination.store(), .{
            .compression = .none,
            .xorb_writer = &writer,
        });
        try publisher.write("abandoned");
        const start = tracker.allocation_count;
        var plan = try publisher.finishPlan();
        plan.deinit(tracker.allocator());
        publisher.deinit();
        break :blk tracker.allocation_count - start;
    };
    try std.testing.expect(baseline_allocations > 0);

    for (0..baseline_allocations) |offset| {
        var tracker = support.TrackingAllocator{ .backing = allocator };
        defer tracker.deinit();
        {
            var destination = support.MemoryStore{ .allocator = tracker.allocator() };
            defer destination.deinit();
            var writer = xet.store.XorbWriter.init(tracker.allocator(), destination.store(), .none);
            defer writer.deinit();
            var publisher = try xet.store.Publisher.init(
                tracker.allocator(),
                destination.store(),
                .{
                    .compression = .none,
                    .xorb_writer = &writer,
                },
            );
            try publisher.write("abandoned");
            tracker.fail_at = tracker.allocation_count + offset;
            const outcome = publisher.finishPlan();
            tracker.fail_at = null;
            if (outcome) |plan_value| {
                var plan = plan_value;
                plan.deinit(tracker.allocator());
                publisher.deinit();
                return error.TestUnexpectedFinishPlanSuccess;
            } else |_| {}

            // A failed plan leaves the file's bytes in the shared writer
            publisher.deinit();
            try std.testing.expectEqual(@as(u32, 0), writer.count());
            try std.testing.expectEqual(@as(u64, 0), writer.rawSize());
        }
        try std.testing.expectEqual(@as(usize, 0), tracker.outstanding());
        try std.testing.expectEqual(@as(usize, 0), tracker.duplicate_frees);
        try std.testing.expectEqual(@as(usize, 0), tracker.invalid_frees);
    }
}

test "BatchPublisher refuses to publish unresolved Xorb hashes" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();

    var plan = try openXorbPlan(allocator, "open");
    try batch.append(&plan);
    try std.testing.expectError(error.XorbLeftOpen, batch.finish());
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
    try std.testing.expectEqual(@as(usize, 1), batch.waiting.items.len);
    try std.testing.expect(!batch.finished);
}

test "chunker and xorb chunks share one type" {
    try std.testing.expect(xet.chunker.Chunk == xet.xorb.Chunk);
    const chunk: xet.chunker.Chunk = .{ .data = "abc", .hash = xet.hash.data("abc") };
    const object_chunk: xet.xorb.Chunk = chunk;
    try std.testing.expectEqualSlices(u8, "abc", object_chunk.data);
    try std.testing.expectEqual(chunk.hash, object_chunk.hash);
}

test "global match survives one-byte streaming writes" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const chunked = try xet.chunker.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    var object = try xet.xorb.serialize(allocator, chunked, .none);
    defer object.deinit(allocator);
    const shard_bytes = try support.makeGlobalDedupShard(allocator, &object, null);
    var index: xet.dedup.ShardIndex = .{};
    defer index.deinit(allocator);
    _ = try index.addOwned(allocator, shard_bytes, 0);
    const SourceContext = struct {
        index: *xet.dedup.ShardIndex,
        fn query(
            raw: *anyopaque,
            query_allocator: std.mem.Allocator,
            hashes: []const xet.Hash,
        ) !?xet.dedup.Match {
            const self: *@This() = @ptrCast(@alignCast(raw));
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = SourceContext{ .index = &index };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
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
    try std.testing.expectEqual(
        @as(u32, @intCast(chunked.len)),
        plan.file.segments[0].chunk_index_end,
    );
}

test "Publisher sliding window matches across the old batch boundary" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, 9 * 1024 * 1024);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% index / 131);
    const chunked = try xet.chunker.chunkBuffer(allocator, data);
    defer allocator.free(chunked);
    try std.testing.expect(chunked.len > 68);

    var object = try xet.xorb.serialize(allocator, chunked[62..66], .none);
    defer object.deinit(allocator);
    var index: xet.dedup.ShardIndex = .{};
    defer index.deinit(allocator);
    _ = try index.addOwned(
        allocator,
        try support.makeGlobalDedupShard(allocator, &object, null),
        0,
    );

    const Context = struct {
        index: *xet.dedup.ShardIndex,
        longest_query: usize = 0,
        fn query(
            raw: *anyopaque,
            query_allocator: std.mem.Allocator,
            hashes: []const xet.Hash,
        ) !?xet.dedup.Match {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.longest_query = @max(self.longest_query, hashes.len);
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = Context{ .index = &index };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .dedup_source = .{ .context = &context, .query_fn = Context.query },
    });
    defer publisher.deinit();
    try publisher.write(data);
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);

    try std.testing.expectEqual(@as(usize, xet.store.dedup_window), context.longest_query);
    const found = for (plan.file.segments, 0..) |segment, segment_index| {
        if (xet.hash.eql(segment.xorb_hash, object.hash)) break segment_index;
    } else return error.TestMissingBoundaryMatch;
    const segment = plan.file.segments[found];
    try std.testing.expectEqual(@as(u32, 0), segment.chunk_index_start);
    try std.testing.expectEqual(@as(u32, 4), segment.chunk_index_end);
    try std.testing.expectEqual(
        xet.hash.verificationNodes(object.nodes),
        plan.file.verification[found],
    );
}

test "Publisher checks every remaining prefix after a dedup match" {
    const allocator = std.testing.allocator;
    const data = try support.deterministicData(allocator);
    defer allocator.free(data);
    const chunked = try xet.chunker.chunkBuffer(allocator, data);
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
        try original_xorbs.append(allocator, try xet.xorb.serialize(
            allocator,
            chunked[first..end],
            .none,
        ));
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
        index: xet.dedup.ShardIndex = .{},
        fn query(
            raw: *anyopaque,
            query_allocator: std.mem.Allocator,
            hashes: []const xet.Hash,
        ) !?xet.dedup.Match {
            const self: *@This() = @ptrCast(@alignCast(raw));
            return self.index.find(query_allocator, hashes);
        }
    };
    var context = Context{};
    defer context.index.deinit(allocator);
    for (shards.items) |bytes| _ = try context.index.addOwned(allocator, bytes, 0);

    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
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

fn checkSingleChunkXorbs(
    allocator: std.mem.Allocator,
    objects: []const support.CapturedObject,
) !void {
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

fn reconstructCapturedPackage(
    allocator: std.mem.Allocator,
    destination: *support.MemoryStore,
    file_hash: xet.Hash,
    expected: []const u8,
) !void {
    return reconstructCapturedPackageWith(allocator, destination, file_hash, expected, null);
}

/// Custom chunking only verifies when the reader uses the same strategy
fn reconstructCapturedPackageWith(
    allocator: std.mem.Allocator,
    destination: *support.MemoryStore,
    file_hash: xet.Hash,
    expected: []const u8,
    strategy: ?xet.chunker.Strategy,
) !void {
    const shard_bytes = for (destination.objects.items) |object| {
        if (object.kind == .shard) break object.data;
    } else return error.TestMissingPublishedShard;
    var manifest = try xet.recon.planFromShard(allocator, shard_bytes, file_hash);
    defer manifest.deinit(allocator);
    const Context = struct {
        store: *support.MemoryStore,
        reader: std.Io.Reader = undefined,
        fn open(raw: *anyopaque, request: xet.recon.Request) !*std.Io.Reader {
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
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    _ = try xet.recon.consumeWith(allocator, &manifest.plan, .{
        .context = &context,
        .open_fn = Context.open,
        .close_fn = Context.close,
    }, &output.writer, strategy);
    try std.testing.expectEqualSlices(u8, expected, output.written());
}

const MaxChunkComparison = struct {
    package: xet.store.Package,
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
    const opts = xet.store.PackOptions{
        .compression = .none,
        .max_xorb_size = 64 * 1024 * 1024,
        .max_xorb_chunks = 1,
    };
    var result: MaxChunkComparison = .{
        .package = try xet.store.pack(allocator, data, opts),
        .result = undefined,
        .packed_store = .{ .allocator = allocator },
        .streamed = .{ .allocator = allocator },
    };
    errdefer result.deinit(allocator);
    try xet.store.publish(allocator, &result.package, result.packed_store.store());
    var publisher = try xet.store.Publisher.init(
        allocator,
        result.streamed.store(),
        xet.store.PublisherOptions.fromPack(opts),
    );
    defer publisher.deinit();
    try publisher.write(data);
    result.result = try publisher.finish();
    try std.testing.expectEqual(result.package.file_hash, result.result.file_hash);
    try reconstructCapturedPackage(allocator, &result.packed_store, result.package.file_hash, data);
    try reconstructCapturedPackage(allocator, &result.streamed, result.result.file_hash, data);
    return result;
}

test "a flush resolves only the segment the open Xorb owns" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    // One Xorb per chunk makes every added chunk close the open Xorb
    var fixed = try xet.chunker.Fixed.init(1);
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .max_xorb_chunks = 1,
        .strategy = fixed.strategy(),
    });
    defer publisher.deinit();
    try publisher.write("abcdefgh");
    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 8), plan.file.segments.len);
    try std.testing.expectEqual(plan.file.segments.len, publisher.resolve_visits);
}

test "takeXorbs resets the rollback floor to the empty writer" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();

    // A closed Xorb leaves one metadata entry, and marking keeps it
    try writer.add(.{ .data = "a", .hash = xet.hash.data("a") });
    _ = try writer.flush();
    try writer.mark();
    const taken = try writer.takeXorbs();
    defer {
        for (taken) |object| allocator.free(object.chunks);
        allocator.free(taken);
    }
    try std.testing.expectEqual(@as(usize, 1), taken.len);

    try writer.add(.{ .data = "b", .hash = xet.hash.data("b") });
    // The metadata was handed over, so the floor must now sit at empty
    try writer.rollback();
    try std.testing.expectEqual(@as(usize, 0), writer.xorbs.items.len);
    try std.testing.expectEqual(@as(u32, 0), writer.count());
}

test "acceptPlan before finishPlan is refused" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const opts: xet.store.PublisherOptions = .{ .compression = .none, .xorb_writer = &writer };

    var first = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer first.deinit();
    try first.write("a");

    // Accepting here would release the claim while this file can still write
    try std.testing.expectError(error.PlanNotFinished, first.acceptPlan());
    try std.testing.expectError(
        error.ActivePublisher,
        xet.store.Publisher.init(allocator, destination.store(), opts),
    );

    var first_plan = try first.finishPlan();
    defer first_plan.deinit(allocator);
    try first.acceptPlan();

    var second = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer second.deinit();
    try second.write("b");
    var second_plan = try second.finishPlan();
    defer second_plan.deinit(allocator);
    try second.acceptPlan();

    // Each file keeps the Xorb range its own chunks produced
    try std.testing.expectEqual(@as(u32, 0), first_plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 1), first_plan.file.segments[0].chunk_index_end);
    try std.testing.expectEqual(@as(u32, 1), second_plan.file.segments[0].chunk_index_start);
    try std.testing.expectEqual(@as(u32, 2), second_plan.file.segments[0].chunk_index_end);

    const first_hash = first_plan.file.hash;
    const second_hash = second_plan.file.hash;
    const open_hash = try writer.flush();
    @constCast(first_plan.file.segments)[0].xorb_hash = open_hash;
    @constCast(second_plan.file.segments)[0].xorb_hash = open_hash;
    var batch = xet.store.BatchPublisher.init(allocator, destination.store());
    defer batch.deinit();
    try batch.append(&first_plan);
    try batch.append(&second_plan);
    try batch.finishWith(writer.xorbs.items);
    try reconstructCapturedPackage(allocator, &destination, first_hash, "a");
    try reconstructCapturedPackage(allocator, &destination, second_hash, "b");
}

test "pack and Publisher honor max_xorb_chunks with matching hashes and recon" {
    const allocator = std.testing.allocator;
    var comparison = try compareMaxChunkEntryPoints(allocator);
    defer comparison.deinit(allocator);
    try checkSingleChunkXorbs(allocator, comparison.packed_store.objects.items);
    try checkSingleChunkXorbs(allocator, comparison.streamed.objects.items);
}

test "a writer cannot redirect a flush to another store" {
    // Delivery is bound at init, so no store can be skipped by a later flush
    try std.testing.expect(!@hasDecl(xet.store.XorbWriter, "flushTo"));
    try std.testing.expect(!@hasDecl(xet.store.XorbWriter, "flushCommitted"));
}

test "a duplicate chunk flushed again stays stored in the writer's one store" {
    const allocator = std.testing.allocator;
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    const chunk = xet.chunker.Chunk{ .data = "a", .hash = xet.hash.data("a") };

    try writer.add(chunk);
    const hash = try writer.flush();
    try writer.add(chunk);
    // The repeat resolves to the same Xorb, which the bound store already holds
    try std.testing.expectEqual(hash, try writer.flush());
    try std.testing.expectEqual(@as(usize, 1), destination.count(.xorb));
}

test "a duplicate chunk flushed through a second writer reaches that writer's store" {
    const allocator = std.testing.allocator;
    var first = support.MemoryStore{ .allocator = allocator };
    defer first.deinit();
    var second = support.MemoryStore{ .allocator = allocator };
    defer second.deinit();
    const chunk = xet.chunker.Chunk{ .data = "a", .hash = xet.hash.data("a") };

    var writer = xet.store.XorbWriter.init(allocator, first.store(), .none);
    defer writer.deinit();
    try writer.add(chunk);
    const hash = try writer.flush();
    try std.testing.expectEqual(@as(usize, 1), first.count(.xorb));

    // The second writer has never stored this Xorb, so its own store must receive it
    var other = xet.store.XorbWriter.init(allocator, second.store(), .none);
    defer other.deinit();
    try other.add(chunk);
    try std.testing.expectEqual(hash, try other.flush());
    try std.testing.expectEqual(@as(usize, 1), second.count(.xorb));
}

test "the shared writer claim survives finalization until the plan is accepted" {
    const allocator = std.testing.allocator;
    const Reenter = struct {
        destination: *support.MemoryStore = undefined,
        opts: xet.store.PublisherOptions = undefined,
        owner: ?*xet.store.Publisher = null,
        accept: ?anyerror = null,
        during: ?anyerror = null,

        fn strategy(self: *@This()) xet.chunker.Strategy {
            return .{ .context = self, .next_fn = next };
        }

        fn next(raw: *anyopaque, _: []const u8, input: []const u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (input.len != 0) return input.len;
            // Accepting here would hand the claim over before a plan exists
            if (self.owner) |owner| {
                self.accept = if (owner.acceptPlan()) |_| null else |err| err;
            }
            // A competing file must be refused for as long as this one finalizes
            if (xet.store.Publisher.init(
                self.destination.allocator,
                self.destination.store(),
                self.opts,
            )) |publisher| {
                var claimed = publisher;
                claimed.deinit();
                self.during = null;
            } else |err| self.during = err;
            return null;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var state = Reenter{ .destination = &destination };
    const opts: xet.store.PublisherOptions = .{
        .compression = .none,
        .strategy = state.strategy(),
        .xorb_writer = &writer,
    };
    state.opts = opts;
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer publisher.deinit();
    state.owner = &publisher;
    try publisher.write("kept");

    var plan = try publisher.finishPlan();
    defer plan.deinit(allocator);
    // The callback saw a live claim and no plan, so it could not spend either
    try std.testing.expectEqual(@as(?anyerror, error.PlanNotFinished), state.accept);
    try std.testing.expectEqual(@as(?anyerror, error.ActivePublisher), state.during);
    try std.testing.expectError(
        error.ActivePublisher,
        xet.store.Publisher.init(allocator, destination.store(), opts),
    );

    try publisher.acceptPlan();
    var second = try xet.store.Publisher.init(allocator, destination.store(), opts);
    second.deinit();
}

test "acceptPlan from a finalization callback neither commits nor leaks chunks" {
    const allocator = std.testing.allocator;
    const Reenter = struct {
        publisher: ?*xet.store.Publisher = null,
        outcome: ?anyerror = null,

        fn strategy(self: *@This()) xet.chunker.Strategy {
            return .{ .context = self, .next_fn = next };
        }

        fn next(raw: *anyopaque, _: []const u8, input: []const u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (input.len != 0) return input.len;
            // The final boundary runs inside finishPlan, before a plan exists
            if (self.publisher) |publisher| {
                self.outcome = if (publisher.acceptPlan()) |_| null else |err| err;
            }
            return error.InjectedStrategyFailure;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var state = Reenter{};
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = state.strategy(),
        .xorb_writer = &writer,
    });
    state.publisher = &publisher;
    try publisher.write("abandoned");

    try std.testing.expectError(error.InjectedStrategyFailure, publisher.finishPlan());
    // Accepting mid-finalization would release the claim while the plan is unbuilt
    try std.testing.expectEqual(
        @as(?anyerror, error.PlanNotFinished),
        state.outcome,
    );

    // The abandoned file owns its chunks, so none may survive in the shared writer
    publisher.deinit();
    try std.testing.expectEqual(@as(u32, 0), writer.count());
    try std.testing.expectEqual(@as(usize, 0), writer.xorbs.items.len);
}

test "abort from the final boundary callback refuses to build a plan" {
    const allocator = std.testing.allocator;
    const Aborting = struct {
        publisher: ?*xet.store.Publisher = null,
        aborted: bool = false,

        fn strategy(self: *@This()) xet.chunker.Strategy {
            return .{ .context = self, .next_fn = next };
        }

        fn next(raw: *anyopaque, _: []const u8, input: []const u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (input.len != 0) return input.len;
            // This is the final boundary, which runs inside finishPlan
            if (!self.aborted) {
                self.aborted = true;
                self.publisher.?.abort();
            }
            return null;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var state = Aborting{};
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = state.strategy(),
        .xorb_writer = &writer,
    });
    state.publisher = &publisher;
    try publisher.write("abandoned");

    try std.testing.expectError(error.WriteFailed, publisher.finishPlan());
    // A cancelled file owns no chunk, so the shared writer must stay empty
    publisher.deinit();
    try std.testing.expectEqual(@as(u32, 0), writer.count());
    try std.testing.expectEqual(@as(usize, 0), writer.xorbs.items.len);
}

test "an unshared publisher cancelled by its final callback keeps no plan" {
    const allocator = std.testing.allocator;
    const Aborting = struct {
        publisher: ?*xet.store.Publisher = null,
        aborted: bool = false,

        fn strategy(self: *@This()) xet.chunker.Strategy {
            return .{ .context = self, .next_fn = next };
        }

        fn next(raw: *anyopaque, _: []const u8, input: []const u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (input.len != 0) return input.len;
            if (!self.aborted) {
                self.aborted = true;
                self.publisher.?.abort();
            }
            return null;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var state = Aborting{};
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = state.strategy(),
    });
    defer publisher.deinit();
    state.publisher = &publisher;
    try publisher.write("abandoned");

    // Nothing may be published, since the file cancelled its own finalization
    try std.testing.expectError(error.WriteFailed, publisher.finish());
    try std.testing.expectEqual(@as(usize, 0), destination.count(.xorb));
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

test "abort from a boundary callback fails the write that triggered it" {
    const allocator = std.testing.allocator;
    const Aborting = struct {
        publisher: ?*xet.store.Publisher = null,

        fn strategy(self: *@This()) xet.chunker.Strategy {
            return .{ .context = self, .next_fn = next };
        }

        fn next(raw: *anyopaque, _: []const u8, input: []const u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.publisher == null) return if (input.len != 0) input.len else null;
            const owner = self.publisher.?;
            self.publisher = null;
            owner.abort();
            return if (input.len != 0) input.len else null;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var state = Aborting{};
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .strategy = state.strategy(),
        .xorb_writer = &writer,
    });
    state.publisher = &publisher;

    // The boundary hands back a chunk after cancelling, which must not be kept
    try std.testing.expectError(error.WriteFailed, publisher.write("abc"));
    try std.testing.expectEqual(@as(u32, 0), writer.count());
    try std.testing.expectError(error.WriteFailed, publisher.finishPlan());
    publisher.deinit();
    try std.testing.expectEqual(@as(u32, 0), writer.count());
}

test "abort from a store listener refuses the finish that emitted it" {
    const allocator = std.testing.allocator;
    const Aborting = struct {
        publisher: ?*xet.store.Publisher = null,
        announced: usize = 0,

        fn callback(
            raw: *anyopaque,
            operation: xet.store.Operation,
        ) !xet.store.OperationDisposition {
            const self: *@This() = @ptrCast(@alignCast(raw));
            // The Xorb is announced after its stored operation, exactly as a session does
            if (operation == .store and self.publisher != null) {
                const owner = self.publisher.?;
                self.publisher = null;
                owner.abort();
            }
            return .release;
        }

        fn newXorb(raw: *anyopaque, _: xet.shard.Xorb) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.announced += 1;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var state = Aborting{};
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), .{
        .compression = .none,
        .operation_listener = .{ .context = &state, .callback = Aborting.callback },
        .new_xorb_listener = .{ .context = &state, .callback = Aborting.newXorb },
    });
    defer publisher.deinit();
    state.publisher = &publisher;
    try publisher.write("abandoned");

    // The listener dropped the Xorb whose announcement follows its own delivery
    try std.testing.expectError(error.WriteFailed, publisher.finish());
    try std.testing.expectEqual(@as(usize, 0), state.announced);
    try std.testing.expectEqual(@as(usize, 0), destination.count(.shard));
}

test "a store listener's abort keeps the claim until its callback returns" {
    const allocator = std.testing.allocator;
    const Aborting = struct {
        destination: *support.MemoryStore = undefined,
        opts: xet.store.PublisherOptions = undefined,
        owner: ?*xet.store.Publisher = null,
        during: ?anyerror = null,

        fn callback(
            raw: *anyopaque,
            operation: xet.store.Operation,
        ) !xet.store.OperationDisposition {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (operation == .store) {
                if (self.owner) |owner| {
                    self.owner = null;
                    owner.abort();
                    // The cancelled file still owns the writer while it finalizes
                    if (xet.store.Publisher.init(
                        self.destination.allocator,
                        self.destination.store(),
                        self.opts,
                    )) |value| {
                        var other = value;
                        other.deinit();
                        self.during = null;
                    } else |err| self.during = err;
                }
            }
            return .release;
        }
    };
    var destination = support.MemoryStore{ .allocator = allocator };
    defer destination.deinit();
    var writer = xet.store.XorbWriter.init(allocator, destination.store(), .none);
    defer writer.deinit();
    var state = Aborting{ .destination = &destination };
    const opts: xet.store.PublisherOptions = .{
        .compression = .none,
        .max_xorb_chunks = 1,
        .operation_listener = .{ .context = &state, .callback = Aborting.callback },
        .xorb_writer = &writer,
    };
    state.opts = opts;
    var publisher = try xet.store.Publisher.init(allocator, destination.store(), opts);
    defer publisher.deinit();
    state.owner = &publisher;
    try publisher.write("abandoned");

    try std.testing.expectError(error.WriteFailed, publisher.finishPlan());
    try std.testing.expectEqual(@as(?anyerror, error.ActivePublisher), state.during);
    try std.testing.expectEqual(@as(u32, 0), writer.count());
    try std.testing.expectEqual(@as(usize, 0), writer.xorbs.items.len);
}
