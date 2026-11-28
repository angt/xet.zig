//! Optional hints for subsequent uploads to the same CAS origin.
//! Each slot is an atomically replaced digest followed by the original MDB shard.
const std = @import("std");
const dedup = @import("dedup.zig");
const hashing = @import("hash.zig");
const shard = @import("shard.zig");
const storage = @import("store.zig");

const slots = 4;

fn name(origin: [64]u8, slot: usize) [70]u8 {
    return (origin ++ "-" ++ [1]u8{'0' + @as(u8, @intCast(slot))} ++ ".mdb").*;
}

pub fn load(dir: std.Io.Dir, io: std.Io, endpoint: []const u8, index: *dedup.SessionIndex) !void {
    const origin = hashing.toHex(hashing.data(endpoint));
    const now = @divFloor(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    for (0..slots) |slot| {
        readSlot(dir, io, &name(origin, slot), index, @intCast(now)) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => return err,
            else => continue,
        };
    }
}

fn readSlot(
    dir: std.Io.Dir,
    io: std.Io,
    path: []const u8,
    index: *dedup.SessionIndex,
    now: i64,
) !void {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buffer);
    var digest: hashing.Hash = undefined;
    reader.interface.readSliceAll(&digest) catch |err| return reader.err orelse err;
    const bytes = reader.interface.allocRemaining(
        index.allocator,
        .limited(storage.max_shard_size),
    ) catch |err|
        return reader.err orelse err;
    if (!hashing.eql(digest, hashing.data(bytes))) {
        index.allocator.free(bytes);
        return;
    }
    _ = try index.addGlobalOwned(bytes, now);
}

pub fn save(dir: std.Io.Dir, io: std.Io, endpoint: []const u8, object: storage.Object) !void {
    if (object.data.len > storage.max_shard_size) return;
    const reader = try shard.Reader.init(object.data);
    if (reader.footer.xorb_count == 0) return;
    const origin = hashing.toHex(hashing.data(endpoint));
    const path = name(origin, object.hash[0] % slots);
    var tmp = try dir.createFileAtomic(io, &path, .{ .replace = true });
    defer tmp.deinit(io);
    try tmp.file.writeStreamingAll(io, &object.hash);
    try tmp.file.writeStreamingAll(io, object.data);
    try tmp.replace(io);
}

test "cached shards are scoped to an origin and corrupt hints are skipped" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const chunk = hashing.data("a");
    const bytes = try shard.serialize(allocator, &.{}, &.{.{
        .hash = chunk,
        .raw_size = 1,
        .serialized_size = 9,
        .chunks = &.{.{ .hash = chunk, .byte_range_start = 0, .unpacked_segment_bytes = 1 }},
    }});
    defer allocator.free(bytes);
    const object: storage.Object = .{
        .kind = .shard,
        .hash = hashing.data(bytes),
        .data = bytes,
        .raw_size = 1,
    };
    try save(tmp.dir, io, "cas-a", object);
    var index = dedup.SessionIndex.init(allocator);
    defer index.deinit();
    try load(tmp.dir, io, "cas-b", &index);
    try std.testing.expect(index.global.shards.items.len == 0);
    try load(tmp.dir, io, "cas-a", &index);
    try std.testing.expectEqual(@as(usize, 1), index.global.shards.items.len);
    const path = name(hashing.toHex(hashing.data("cas-a")), object.hash[0] % slots);
    try tmp.dir.writeFile(io, .{ .sub_path = &path, .data = &hashing.zero });
    try load(tmp.dir, io, "cas-a", &index);
    try std.testing.expectEqual(@as(usize, 1), index.global.shards.items.len);
}
