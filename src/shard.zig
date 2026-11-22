//! MDB shard V2 files: reconstruction records and lookup tables

const std = @import("std");
const hashing = @import("hash.zig");

pub const entry_size = 48;
pub const header_size = 48;
pub const footer_size = 200;
pub const verification_flag: u32 = 1 << 31;
pub const metadata_extension_flag: u32 = 1 << 30;

const magic = [32]u8{
    'H', 'F', 'R', 'e', 'p', 'o', 'M', 'e', 't', 'a', 'D', 'a', 't', 'a', 0,  85,
    105, 103, 69,  106, 123, 129, 87,  131, 165, 189, 217, 92,  205, 209, 74, 169,
};
const bookend = @as([32]u8, @splat(0xff)) ++ @as([16]u8, @splat(0));

pub const Segment = struct {
    xorb_hash: hashing.Hash,
    xorb_flags: u32 = 0,
    unpacked_segment_bytes: u32,
    chunk_index_start: u32,
    chunk_index_end: u32,
};

pub const File = struct {
    hash: hashing.Hash,
    segments: []const Segment,
    verification: []const hashing.Hash = &.{},
    sha256: ?hashing.Hash = null,
};

pub const Xorb = struct {
    hash: hashing.Hash,
    flags: u32 = 0,
    chunks: []const Chunk,
    raw_size: u32,
    serialized_size: u32,
};

pub const Chunk = struct {
    hash: hashing.Hash,
    byte_range_start: u32,
    unpacked_segment_bytes: u32,
    flags: u32 = 0,
};

pub const Error = error{
    InvalidShard,
    UnsupportedVersion,
    InvalidCounts,
    InvalidOffset,
    InvalidRange,
    NotFound,
};

fn putU32(output: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try output.appendSlice(allocator, &bytes);
}

fn putU64(output: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    try output.appendSlice(allocator, &bytes);
}

fn readU32(input: []const u8, offset: usize) !u32 {
    if (offset > input.len or input.len - offset < 4) return error.InvalidOffset;
    return std.mem.readInt(u32, input[offset..][0..4], .little);
}

fn readU64(input: []const u8, offset: usize) !u64 {
    if (offset > input.len or input.len - offset < 8) return error.InvalidOffset;
    return std.mem.readInt(u64, input[offset..][0..8], .little);
}

fn readHash(input: []const u8, offset: usize) !hashing.Hash {
    if (offset > input.len or input.len - offset < 32) return error.InvalidOffset;
    return input[offset..][0..32].*;
}

fn appendFile(output: *std.ArrayList(u8), allocator: std.mem.Allocator, file: File) !void {
    const count: u32 = @intCast(file.segments.len);
    if (file.verification.len != 0 and file.verification.len != file.segments.len)
        return error.InvalidCounts;
    var flags: u32 = 0;
    if (file.verification.len != 0) flags |= verification_flag;
    if (file.sha256 != null) flags |= metadata_extension_flag;
    try output.appendSlice(allocator, &file.hash);
    try putU32(output, allocator, flags);
    try putU32(output, allocator, count);
    try putU64(output, allocator, 0);
    for (file.segments) |segment| {
        if (segment.chunk_index_start >= segment.chunk_index_end) return error.InvalidRange;
        try output.appendSlice(allocator, &segment.xorb_hash);
        try putU32(output, allocator, segment.xorb_flags);
        try putU32(output, allocator, segment.unpacked_segment_bytes);
        try putU32(output, allocator, segment.chunk_index_start);
        try putU32(output, allocator, segment.chunk_index_end);
    }
    for (file.verification) |item| {
        try output.appendSlice(allocator, &item);
        try output.appendNTimes(allocator, 0, 16);
    }
    if (file.sha256) |item| {
        try output.appendSlice(allocator, &item);
        try output.appendNTimes(allocator, 0, 16);
    }
}

fn appendXorb(output: *std.ArrayList(u8), allocator: std.mem.Allocator, object: Xorb) !void {
    try output.appendSlice(allocator, &object.hash);
    try putU32(output, allocator, object.flags);
    try putU32(output, allocator, @intCast(object.chunks.len));
    try putU32(output, allocator, object.raw_size);
    try putU32(output, allocator, object.serialized_size);
    var expected_start: u32 = 0;
    var total: u64 = 0;
    for (object.chunks) |chunk| {
        if (chunk.byte_range_start != expected_start or chunk.unpacked_segment_bytes == 0)
            return error.InvalidRange;
        try output.appendSlice(allocator, &chunk.hash);
        try putU32(output, allocator, chunk.byte_range_start);
        try putU32(output, allocator, chunk.unpacked_segment_bytes);
        try putU32(output, allocator, chunk.flags);
        try putU32(output, allocator, 0);
        total += chunk.unpacked_segment_bytes;
        expected_start += chunk.unpacked_segment_bytes;
    }
    if (total != object.raw_size) return error.InvalidCounts;
}

const FileLocation = struct { hash: hashing.Hash, index: u32 };
const XorbLocation = struct { hash: hashing.Hash, index: u32 };
const ChunkLocation = struct { hash: hashing.Hash, xorb_index: u32, chunk_index: u32 };

fn hashLess(_: void, a: hashing.Hash, b: hashing.Hash) bool {
    return hashing.order(a, b) == .lt;
}

fn fileLess(_: void, a: File, b: File) bool {
    return hashLess({}, a.hash, b.hash);
}

fn xorbLess(_: void, a: Xorb, b: Xorb) bool {
    return hashLess({}, a.hash, b.hash);
}

fn sameXorb(a: Xorb, b: Xorb) bool {
    if (a.flags != b.flags or a.raw_size != b.raw_size or a.serialized_size != b.serialized_size or
        a.chunks.len != b.chunks.len) return false;
    for (a.chunks, b.chunks) |left, right| {
        if (!std.meta.eql(left, right)) return false;
    }
    return true;
}

fn chunkLess(_: void, a: ChunkLocation, b: ChunkLocation) bool {
    return hashing.truncated(a.hash) < hashing.truncated(b.hash);
}

/// Serialize a deterministic, unkeyed shard. Inputs are sorted internally
pub fn serialize(
    allocator: std.mem.Allocator,
    files_input: []const File,
    xorbs_input: []const Xorb,
) ![]u8 {
    const files = try allocator.dupe(File, files_input);
    defer allocator.free(files);
    const owned_xorbs = try allocator.dupe(Xorb, xorbs_input);
    defer allocator.free(owned_xorbs);
    var xorbs = owned_xorbs;
    std.mem.sort(File, files, {}, fileLess);
    std.mem.sort(Xorb, xorbs, {}, xorbLess);
    if (files.len > 1) for (files[1..], files[0 .. files.len - 1]) |current, previous| {
        if (hashing.eql(current.hash, previous.hash)) return error.InvalidCounts;
    };
    var unique: usize = 0;
    for (xorbs) |current| {
        if (unique != 0 and hashing.eql(current.hash, xorbs[unique - 1].hash)) {
            if (!sameXorb(current, xorbs[unique - 1])) return error.InvalidCounts;
            continue;
        }
        xorbs[unique] = current;
        unique += 1;
    }
    xorbs = xorbs[0..unique];

    const file_locations = try allocator.alloc(FileLocation, files.len);
    defer allocator.free(file_locations);
    const xorb_locations = try allocator.alloc(XorbLocation, xorbs.len);
    defer allocator.free(xorb_locations);
    var chunk_count: usize = 0;
    for (xorbs) |object| chunk_count = std.math.add(usize, chunk_count, object.chunks.len) catch
        return error.InvalidCounts;
    const chunk_locations = try allocator.alloc(ChunkLocation, chunk_count);
    defer allocator.free(chunk_locations);

    var file_section: std.ArrayList(u8) = .empty;
    defer file_section.deinit(allocator);
    for (files, file_locations) |file, *location| {
        location.* = .{ .hash = file.hash, .index = @intCast(file_section.items.len / entry_size) };
        try appendFile(&file_section, allocator, file);
    }
    try file_section.appendSlice(allocator, &bookend);

    var xorb_section: std.ArrayList(u8) = .empty;
    defer xorb_section.deinit(allocator);
    var chunk_position: usize = 0;
    for (xorbs, xorb_locations) |object, *location| {
        location.* = .{ .hash = object.hash, .index = @intCast(xorb_section.items.len / entry_size) };
        for (object.chunks, 0..) |chunk, index| {
            chunk_locations[chunk_position] = .{
                .hash = chunk.hash,
                .xorb_index = location.index,
                .chunk_index = @intCast(index),
            };
            chunk_position += 1;
        }
        try appendXorb(&xorb_section, allocator, object);
    }
    try xorb_section.appendSlice(allocator, &bookend);
    std.mem.sort(ChunkLocation, chunk_locations, {}, chunkLess);

    const xorb_info_offset = try offsetAfter(header_size, file_section.items.len, 1);
    const file_lookup_offset = try offsetAfter(xorb_info_offset, xorb_section.items.len, 1);
    const xorb_lookup_offset = try offsetAfter(file_lookup_offset, files.len, 12);
    const chunk_lookup_offset = try offsetAfter(xorb_lookup_offset, xorbs.len, 12);
    const footer_offset = try offsetAfter(chunk_lookup_offset, chunk_locations.len, 16);
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.ensureTotalCapacity(allocator, footer_offset + footer_size);
    try output.appendSlice(allocator, &magic);
    try putU64(&output, allocator, 2);
    try putU64(&output, allocator, footer_size);
    try output.appendSlice(allocator, file_section.items);
    try output.appendSlice(allocator, xorb_section.items);
    for (file_locations) |location| {
        try putU64(&output, allocator, hashing.truncated(location.hash));
        try putU32(&output, allocator, location.index);
    }
    for (xorb_locations) |location| {
        try putU64(&output, allocator, hashing.truncated(location.hash));
        try putU32(&output, allocator, location.index);
    }
    for (chunk_locations) |location| {
        try putU64(&output, allocator, hashing.truncated(location.hash));
        try putU32(&output, allocator, location.xorb_index);
        try putU32(&output, allocator, location.chunk_index);
    }

    var stored_on_disk: u64 = 0;
    var stored: u64 = 0;
    var materialized: u64 = 0;
    for (xorbs) |object| {
        stored_on_disk += object.serialized_size;
        stored += object.raw_size;
    }
    for (files) |file| {
        for (file.segments) |segment| materialized += segment.unpacked_segment_bytes;
    }

    // Write footer fields explicitly to avoid host-layout dependencies
    try putU64(&output, allocator, 1);
    try putU64(&output, allocator, header_size);
    try putU64(&output, allocator, xorb_info_offset);
    try putU64(&output, allocator, file_lookup_offset);
    try putU64(&output, allocator, files.len);
    try putU64(&output, allocator, xorb_lookup_offset);
    try putU64(&output, allocator, xorbs.len);
    try putU64(&output, allocator, chunk_lookup_offset);
    try putU64(&output, allocator, chunk_locations.len);
    try output.appendNTimes(allocator, 0, 32); // No HMAC key
    try putU64(&output, allocator, 0); // Creation timestamp
    try putU64(&output, allocator, std.math.maxInt(u64)); // No expiry
    try output.appendNTimes(allocator, 0, 48);
    try putU64(&output, allocator, stored_on_disk);
    try putU64(&output, allocator, materialized);
    try putU64(&output, allocator, stored);
    try putU64(&output, allocator, footer_offset);
    if (output.items.len != footer_offset + footer_size) return error.InvalidOffset;
    return output.toOwnedSlice(allocator);
}

pub const Footer = struct {
    has_file_lookup: bool = true,
    has_xorb_lookup: bool = true,
    file_info_offset: usize,
    xorb_info_offset: usize,
    file_lookup_offset: usize,
    file_count: usize,
    xorb_lookup_offset: usize,
    xorb_count: usize,
    chunk_lookup_offset: usize,
    chunk_count: usize,
    chunk_hash_key: hashing.Hash,
    creation_timestamp: u64,
    expiry: u64,
    footer_offset: usize,
};

pub const Reader = struct {
    data: []const u8,
    footer: Footer,

    pub fn init(data: []const u8) !Reader {
        if (data.len < header_size + 2 * entry_size) return error.InvalidShard;
        if (!std.mem.eql(u8, data[0..32], &magic)) return error.InvalidShard;
        if (try readU64(data, 32) != 2) return error.UnsupportedVersion;
        const stored_footer_size = try readU64(data, 40);
        if (stored_footer_size == 0) return initSequential(data, .{
            .has_file_lookup = false,
            .has_xorb_lookup = false,
            .file_info_offset = header_size,
            .xorb_info_offset = data.len,
            .file_lookup_offset = data.len,
            .file_count = 0,
            .xorb_lookup_offset = data.len,
            .xorb_count = 0,
            .chunk_lookup_offset = data.len,
            .chunk_count = 0,
            .chunk_hash_key = @splat(0),
            .creation_timestamp = 0,
            .expiry = 0,
            .footer_offset = data.len,
        });
        if (stored_footer_size != footer_size) return error.UnsupportedVersion;
        if (data.len < header_size + footer_size) return error.InvalidShard;
        const start = data.len - footer_size;
        if (try readU64(data, start) != 1) return error.UnsupportedVersion;
        const footer = Footer{
            .file_info_offset = try castUsize(try readU64(data, start + 8)),
            .xorb_info_offset = try castUsize(try readU64(data, start + 16)),
            .file_lookup_offset = try castUsize(try readU64(data, start + 24)),
            .file_count = try castUsize(try readU64(data, start + 32)),
            .xorb_lookup_offset = try castUsize(try readU64(data, start + 40)),
            .xorb_count = try castUsize(try readU64(data, start + 48)),
            .chunk_lookup_offset = try castUsize(try readU64(data, start + 56)),
            .chunk_count = try castUsize(try readU64(data, start + 64)),
            .chunk_hash_key = try readHash(data, start + 72),
            .creation_timestamp = try readU64(data, start + 104),
            .expiry = try readU64(data, start + 112),
            .footer_offset = try castUsize(try readU64(data, start + 192)),
        };
        if (footer.file_info_offset != header_size or footer.footer_offset != start or
            footer.xorb_info_offset < footer.file_info_offset or
            footer.file_lookup_offset < footer.xorb_info_offset or
            footer.xorb_lookup_offset < footer.file_lookup_offset or
            footer.chunk_lookup_offset < footer.xorb_lookup_offset or
            footer.footer_offset < footer.chunk_lookup_offset) return error.InvalidOffset;
        if (footer.xorb_info_offset - footer.file_info_offset < 48 or
            (footer.xorb_info_offset - footer.file_info_offset) % 48 != 0 or
            footer.file_lookup_offset - footer.xorb_info_offset < 48 or
            (footer.file_lookup_offset - footer.xorb_info_offset) % 48 != 0 or
            (footer.xorb_lookup_offset - footer.file_lookup_offset) !=
                (offsetAfter(0, footer.file_count, 12) catch return error.InvalidCounts) or
            (footer.chunk_lookup_offset - footer.xorb_lookup_offset) !=
                (offsetAfter(0, footer.xorb_count, 12) catch return error.InvalidCounts) or
            (footer.footer_offset - footer.chunk_lookup_offset) !=
                (offsetAfter(0, footer.chunk_count, 16) catch return error.InvalidCounts))
            return error.InvalidCounts;
        if (footer.file_count == 0 and footer.xorb_count == 0 and footer.chunk_count == 0) {
            var sequential = footer;
            sequential.has_file_lookup = false;
            sequential.has_xorb_lookup = false;
            return initSequential(data, sequential);
        }
        try validateLookupOrder(data, footer.file_lookup_offset, footer.file_count, 12);
        try validateLookupOrder(data, footer.xorb_lookup_offset, footer.xorb_count, 12);
        try validateLookupOrder(data, footer.chunk_lookup_offset, footer.chunk_count, 16);
        return .{ .data = data, .footer = footer };
    }

    pub fn findFile(self: Reader, hash: hashing.Hash) !?FileInfo {
        if (!self.footer.has_file_lookup) {
            var file_index: u32 = 0;
            for (0..self.footer.file_count) |_| {
                const info = try self.fileAt(file_index);
                file_index = @intCast((info.end - header_size) / entry_size);
                if (hashing.eql(info.hash, hash)) return info;
            }
            return null;
        }
        var low: usize = 0;
        var high = self.footer.file_count;
        const needle = hashing.truncated(hash);
        while (low < high) {
            const middle = low + (high - low) / 2;
            const key = try readU64(self.data, self.footer.file_lookup_offset + 12 * middle);
            if (key < needle) low = middle + 1 else high = middle;
        }
        var index = low;
        while (index < self.footer.file_count) : (index += 1) {
            const offset = self.footer.file_lookup_offset + 12 * index;
            if (try readU64(self.data, offset) != needle) break;
            const file_index = try readU32(self.data, offset + 8);
            const info = try self.fileAt(file_index);
            if (hashing.eql(info.hash, hash)) return info;
        }
        return null;
    }

    pub fn findXorb(self: Reader, hash: hashing.Hash) !?XorbInfo {
        if (!self.footer.has_xorb_lookup) {
            var xorb_index: u32 = 0;
            for (0..self.footer.xorb_count) |_| {
                const info = try self.xorbAt(xorb_index);
                xorb_index += info.count + 1;
                if (hashing.eql(info.hash, hash)) return info;
            }
            return null;
        }
        var low: usize = 0;
        var high = self.footer.xorb_count;
        const needle = hashing.truncated(hash);
        while (low < high) {
            const middle = low + (high - low) / 2;
            const offset = self.footer.xorb_lookup_offset + 12 * middle;
            if (try readU64(self.data, offset) < needle) low = middle + 1 else high = middle;
        }
        var index = low;
        while (index < self.footer.xorb_count) : (index += 1) {
            const offset = self.footer.xorb_lookup_offset + 12 * index;
            if (try readU64(self.data, offset) != needle) break;
            const record_index = try readU32(self.data, offset + 8);
            const info = try self.xorbAt(record_index);
            if (hashing.eql(info.hash, hash)) return info;
        }
        return null;
    }

    pub fn findChunks(self: Reader, hash: hashing.Hash) !ChunkLookup {
        var low: usize = 0;
        var high = self.footer.chunk_count;
        const needle = hashing.truncated(hash);
        while (low < high) {
            const middle = low + (high - low) / 2;
            const offset = self.footer.chunk_lookup_offset + 16 * middle;
            if (try readU64(self.data, offset) < needle) low = middle + 1 else high = middle;
        }
        return .{ .reader = self, .hash = hash, .index = low };
    }

    pub fn fileAt(self: Reader, index: u32) !FileInfo {
        const offset = try offsetAfter(self.footer.file_info_offset, index, entry_size);
        if (offset >= self.footer.xorb_info_offset) return error.InvalidOffset;
        const hash = try readHash(self.data, offset);
        if (hashing.eql(hash, @splat(0xff))) return error.InvalidRange;
        const flags = try readU32(self.data, offset + 32);
        const count = try readU32(self.data, offset + 36);
        const has_verification: u64 = @intFromBool(flags & verification_flag != 0);
        const has_metadata: u64 = @intFromBool(flags & metadata_extension_flag != 0);
        const entry_count = @as(u64, count) * (1 + has_verification) + has_metadata;
        const end = try offsetAfter(offset + entry_size, try castUsize(entry_count), entry_size);
        if (end > self.footer.xorb_info_offset) return error.InvalidCounts;
        return .{ .reader = self, .offset = offset, .end = end, .hash = hash, .flags = flags, .count = count };
    }

    pub fn xorbAt(self: Reader, index: u32) !XorbInfo {
        const offset = try offsetAfter(self.footer.xorb_info_offset, index, entry_size);
        if (offset >= self.footer.file_lookup_offset) return error.InvalidOffset;
        const hash = try readHash(self.data, offset);
        if (hashing.eql(hash, @splat(0xff))) return error.InvalidRange;
        const count = try readU32(self.data, offset + 36);
        const end = try offsetAfter(offset, try castUsize(@as(u64, count) + 1), entry_size);
        if (end > self.footer.file_lookup_offset) return error.InvalidCounts;
        return .{
            .reader = self,
            .offset = offset,
            .hash = hash,
            .count = count,
            .raw_size = try readU32(self.data, offset + 40),
            .serialized_size = try readU32(self.data, offset + 44),
        };
    }
};

fn initSequential(data: []const u8, initial_footer: Footer) !Reader {
    var footer = initial_footer;
    var file_entries: u64 = 0;
    var offset: usize = header_size;
    while (true) {
        const header_end = try offsetAfter(offset, 1, entry_size);
        if (header_end > footer.xorb_info_offset) return error.InvalidOffset;
        const hash = try readHash(data, offset);
        if (hashing.eql(hash, @splat(0xff))) {
            if (!std.mem.eql(u8, data[offset..header_end], &bookend)) return error.InvalidShard;
            footer.xorb_info_offset = header_end;
            break;
        }
        const flags = try readU32(data, offset + 32);
        const count = try readU32(data, offset + 36);
        const has_verification: u64 = @intFromBool(flags & verification_flag != 0);
        const has_metadata: u64 = @intFromBool(flags & metadata_extension_flag != 0);
        const following = @as(u64, count) * (1 + has_verification) + has_metadata;
        const end = try offsetAfter(header_end, try castUsize(following), entry_size);
        if (end > footer.xorb_info_offset) return error.InvalidCounts;
        file_entries += following + 1;
        footer.file_count += 1;
        offset = end;
    }

    var xorb_entries: u64 = 0;
    offset = footer.xorb_info_offset;
    while (true) {
        const header_end = try offsetAfter(offset, 1, entry_size);
        if (header_end > footer.file_lookup_offset) return error.InvalidOffset;
        const hash = try readHash(data, offset);
        if (hashing.eql(hash, @splat(0xff))) {
            if (!std.mem.eql(u8, data[offset..header_end], &bookend) or
                header_end != footer.file_lookup_offset) return error.InvalidShard;
            break;
        }
        const count = try readU32(data, offset + 36);
        const end = try offsetAfter(header_end, count, entry_size);
        if (end > footer.file_lookup_offset) return error.InvalidCounts;
        xorb_entries += @as(u64, count) + 1;
        footer.xorb_count += 1;
        footer.chunk_count += count;
        offset = end;
    }
    if (file_entries > std.math.maxInt(u32) or xorb_entries > std.math.maxInt(u32))
        return error.InvalidCounts;
    return .{ .data = data, .footer = footer };
}

fn castUsize(value: u64) !usize {
    return std.math.cast(usize, value) orelse error.InvalidOffset;
}

fn offsetAfter(start: usize, count: usize, stride: usize) !usize {
    const length = std.math.mul(usize, count, stride) catch return error.InvalidOffset;
    return std.math.add(usize, start, length) catch return error.InvalidOffset;
}

fn validateLookupOrder(data: []const u8, start: usize, count: usize, stride: usize) !void {
    if (count < 2) return;
    var previous = try readU64(data, start);
    for (1..count) |index| {
        const current = try readU64(data, start + index * stride);
        if (current < previous) return error.InvalidShard;
        previous = current;
    }
}

pub const OwnedFile = struct {
    value: File,

    pub fn deinit(self: *OwnedFile, allocator: std.mem.Allocator) void {
        allocator.free(self.value.segments);
        if (self.value.verification.len != 0) allocator.free(self.value.verification);
        self.* = undefined;
    }
};

pub const OwnedXorb = struct {
    value: Xorb,

    pub fn deinit(self: *OwnedXorb, allocator: std.mem.Allocator) void {
        allocator.free(self.value.chunks);
        self.* = undefined;
    }
};

pub const FileInfo = struct {
    reader: Reader,
    offset: usize,
    end: usize,
    hash: hashing.Hash,
    flags: u32,
    count: u32,

    pub fn segment(self: FileInfo, index: u32) !Segment {
        if (index >= self.count) return error.InvalidRange;
        const offset = self.offset + entry_size * (@as(usize, index) + 1);
        return .{
            .xorb_hash = try readHash(self.reader.data, offset),
            .xorb_flags = try readU32(self.reader.data, offset + 32),
            .unpacked_segment_bytes = try readU32(self.reader.data, offset + 36),
            .chunk_index_start = try readU32(self.reader.data, offset + 40),
            .chunk_index_end = try readU32(self.reader.data, offset + 44),
        };
    }

    pub fn verification(self: FileInfo, index: u32) !hashing.Hash {
        if (self.flags & verification_flag == 0 or index >= self.count) return error.InvalidRange;
        return readHash(self.reader.data, self.offset + entry_size * (@as(usize, self.count + index) + 1));
    }

    pub fn sha256(self: FileInfo) !?hashing.Hash {
        if (self.flags & metadata_extension_flag == 0) return null;
        return try readHash(self.reader.data, self.end - entry_size);
    }

    pub fn decode(self: FileInfo, allocator: std.mem.Allocator) !OwnedFile {
        const segments = try allocator.alloc(Segment, self.count);
        errdefer allocator.free(segments);
        for (segments, 0..) |*item, index| item.* = try self.segment(@intCast(index));
        var checks: []const hashing.Hash = &.{};
        errdefer if (checks.len != 0) allocator.free(checks);
        if (self.flags & verification_flag != 0) {
            const values = try allocator.alloc(hashing.Hash, self.count);
            checks = values;
            for (values, 0..) |*value, index| value.* = try self.verification(@intCast(index));
        }
        return .{
            .value = .{
                .hash = self.hash,
                .segments = segments,
                .verification = checks,
                .sha256 = try self.sha256(),
            },
        };
    }
};

pub const ChunkLookup = struct {
    reader: Reader,
    hash: hashing.Hash,
    index: usize,

    pub fn next(self: *ChunkLookup) !?ChunkInfo {
        while (self.index < self.reader.footer.chunk_count) : (self.index += 1) {
            const offset = self.reader.footer.chunk_lookup_offset + 16 * self.index;
            if (try readU64(self.reader.data, offset) != hashing.truncated(self.hash)) return null;
            const xorb_index = try readU32(self.reader.data, offset + 8);
            const chunk_index = try readU32(self.reader.data, offset + 12);
            const object = try self.reader.xorbAt(xorb_index);
            const chunk = try object.chunk(chunk_index);
            if (hashing.eql(chunk.hash, self.hash)) {
                self.index += 1;
                return .{
                    .object = object,
                    .index = chunk_index,
                };
            }
        }
        return null;
    }
};

pub const ChunkInfo = struct {
    object: XorbInfo,
    index: u32,
};

pub const XorbInfo = struct {
    reader: Reader,
    offset: usize,
    hash: hashing.Hash,
    count: u32,
    raw_size: u32,
    serialized_size: u32,

    pub fn chunk(self: XorbInfo, index: u32) !Chunk {
        if (index >= self.count) return error.InvalidRange;
        const offset = self.offset + entry_size * (@as(usize, index) + 1);
        return .{
            .hash = try readHash(self.reader.data, offset),
            .byte_range_start = try readU32(self.reader.data, offset + 32),
            .unpacked_segment_bytes = try readU32(self.reader.data, offset + 36),
            .flags = try readU32(self.reader.data, offset + 40),
        };
    }

    pub fn decode(self: XorbInfo, allocator: std.mem.Allocator) !OwnedXorb {
        const chunks = try allocator.alloc(Chunk, self.count);
        errdefer allocator.free(chunks);
        for (chunks, 0..) |*item, index| item.* = try self.chunk(@intCast(index));
        const flags = try readU32(self.reader.data, self.offset + 32);
        return .{
            .value = .{
                .hash = self.hash,
                .flags = flags,
                .chunks = chunks,
                .raw_size = self.raw_size,
                .serialized_size = self.serialized_size,
            },
        };
    }
};

test "complete shard round trip with sorted lookups" {
    const allocator = std.testing.allocator;
    const chunk_hash = hashing.data("chunk");
    const object_hash = hashing.data("object");
    const file_hash = hashing.data("file");
    const chunks = [_]Chunk{.{
        .hash = chunk_hash,
        .byte_range_start = 0,
        .unpacked_segment_bytes = 5,
    }};
    const segments = [_]Segment{.{
        .xorb_hash = object_hash,
        .unpacked_segment_bytes = 5,
        .chunk_index_start = 0,
        .chunk_index_end = 1,
    }};
    const checks = [_]hashing.Hash{hashing.verification(&.{chunk_hash})};
    const bytes = try serialize(allocator, &.{.{
        .hash = file_hash,
        .segments = &segments,
        .verification = &checks,
    }}, &.{.{
        .hash = object_hash,
        .chunks = &chunks,
        .raw_size = 5,
        .serialized_size = 13,
    }});
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 48 + 5 * 48 + 2 * 48 + 12 + 12 + 16 + 200), bytes.len);
    const reader = try Reader.init(bytes);
    const info = (try reader.findFile(file_hash)).?;
    const segment = try info.segment(0);
    try std.testing.expectEqual(object_hash, segment.xorb_hash);
    try std.testing.expectEqual(checks[0], try info.verification(0));
    const object = try reader.xorbAt(0);
    try std.testing.expectEqual(chunk_hash, (try object.chunk(0)).hash);
    var lookup = try reader.findChunks(chunk_hash);
    const located = (try lookup.next()).?;
    try std.testing.expectEqual(object_hash, located.object.hash);
    try std.testing.expectEqual(@as(u32, 0), located.index);
    try std.testing.expect((try lookup.next()) == null);
    var missing = try reader.findChunks(hashing.data("missing"));
    try std.testing.expect((try missing.next()) == null);
    try std.testing.expect((try reader.findFile(hashing.data("missing"))) == null);
}

test "identical duplicate xorbs coalesce but conflicting duplicates fail" {
    const allocator = std.testing.allocator;
    const chunks = [_]Chunk{.{
        .hash = hashing.data("chunk"),
        .byte_range_start = 0,
        .unpacked_segment_bytes = 5,
    }};
    const object = Xorb{
        .hash = hashing.data("object"),
        .chunks = &chunks,
        .raw_size = 5,
        .serialized_size = 13,
    };
    const bytes = try serialize(allocator, &.{}, &.{ object, object });
    defer allocator.free(bytes);
    const reader = try Reader.init(bytes);
    try std.testing.expectEqual(@as(usize, 1), reader.footer.xorb_count);
    var conflicting = object;
    conflicting.serialized_size += 1;
    try std.testing.expectError(error.InvalidCounts, serialize(allocator, &.{}, &.{ object, conflicting }));
}

test "shard rejects malformed counts and offsets" {
    const allocator = std.testing.allocator;
    const bytes = try serialize(allocator, &.{}, &.{});
    defer allocator.free(bytes);
    _ = try Reader.init(bytes);
    bytes[bytes.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidOffset, Reader.init(bytes));
}

test "shard rejects oversized lookup counts without overflowing" {
    const allocator = std.testing.allocator;
    const bytes = try serialize(allocator, &.{}, &.{});
    defer allocator.free(bytes);
    const footer_start = bytes.len - footer_size;
    for ([_]usize{ 32, 48, 64 }) |offset| {
        std.mem.writeInt(u64, bytes[footer_start + offset ..][0..8], std.math.maxInt(u64), .little);
        try std.testing.expectError(error.InvalidCounts, Reader.init(bytes));
    }
}
