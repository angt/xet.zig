//! Standard Xet CAS HTTP adapter. Repository authentication is out of scope

const std = @import("std");
const hashing = @import("hash.zig");
const reconstruction = @import("reconstruction.zig");
const shard = @import("shard.zig");
const xorb = @import("xorb.zig");
const storage = @import("store.zig");
const stream = @import("stream.zig");
const dedup = @import("dedup.zig");

const transfer_buffer_size = stream.scratch_buffer_size;

pub const Error = error{
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    NotImplemented,
    ShardUploadFailed,
    RangeNotSatisfiable,
    RateLimited,
    ServerError,
    InvalidResponse,
    ResponseTooLarge,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    endpoint: []u8,
    access_token: []u8,
    http_client: std.http.Client,
    /// 404/501 responses select V1 for later calls
    reconstruction_version: std.atomic.Value(u8) = .init(2),
    shard_version: std.atomic.Value(u8) = .init(2),

    /// Accepts a CAS origin or an endpoint ending in `/v1` or `/v2`
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        endpoint: []const u8,
        access_token: []const u8,
    ) !Client {
        const trimmed = std.mem.trimEnd(u8, endpoint, "/");
        const has_version = std.mem.endsWith(u8, trimmed, "/v1") or std.mem.endsWith(u8, trimmed, "/v2");
        const owned_endpoint = if (has_version)
            try allocator.dupe(u8, trimmed[0 .. trimmed.len - 3])
        else
            try allocator.dupe(u8, trimmed);
        errdefer allocator.free(owned_endpoint);
        return .{
            .allocator = allocator,
            .endpoint = owned_endpoint,
            .access_token = try allocator.dupe(u8, access_token),
            .http_client = .{ .allocator = allocator, .io = io },
        };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
        self.allocator.free(self.endpoint);
        self.allocator.free(self.access_token);
        self.* = undefined;
    }

    pub fn store(self: *Client) storage.Store {
        return .{ .context = self, .put_fn = putObject };
    }

    pub fn opener(self: *Client) stream.Opener {
        return .{ .context = self, .open_fn = openObject, .close_fn = closeObject, .read_error_fn = readObjectError };
    }

    pub fn upload(
        self: *Client,
        allocator: std.mem.Allocator,
        input: []const u8,
        options: storage.PackOptions,
    ) !storage.PublishResult {
        var global = GlobalDedup{
            .client = self,
            .allocator = self.allocator,
            .io = self.http_client.io,
            .index = .init(allocator),
        };
        defer global.deinit();
        var opts = storage.PublisherOptions.fromPackOptions(options);
        opts.dedup_source = global.source();
        opts.new_xorb_listener = .{
            .context = &global,
            .callback = GlobalDedup.addXorb,
        };
        var publisher = try storage.Publisher.init(allocator, self.store(), opts);
        defer publisher.deinit();
        try publisher.write(input);
        return publisher.finish();
    }

    /// Downloads and verifies a file. The caller owns the returned bytes
    pub fn download(
        self: *Client,
        allocator: std.mem.Allocator,
        file_hash: hashing.Hash,
    ) ![]u8 {
        var plan = try self.getPlan(file_hash, null);
        defer plan.deinit(self.allocator);
        return reconstruction.reconstruct(allocator, &plan, self.opener());
    }

    fn openObject(raw: *anyopaque, item: stream.Request) !*std.Io.Reader {
        const self: *Client = @ptrCast(@alignCast(raw));
        return ResponseStream.open(self, item);
    }

    fn closeObject(_: *anyopaque, reader: *std.Io.Reader) void {
        ResponseStream.close(reader);
    }

    fn readObjectError(_: *anyopaque, reader: *std.Io.Reader) ?anyerror {
        return ResponseStream.readError(reader);
    }

    fn putObject(raw: *anyopaque, item: storage.Object) !void {
        const self: *Client = @ptrCast(@alignCast(raw));
        switch (item.kind) {
            .xorb => try self.putXorb(item.hash, item.data),
            .shard => try self.putShard(item.data),
        }
    }

    fn url(self: *Client, comptime fmt: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}" ++ fmt, .{self.endpoint} ++ args);
    }

    fn authorization(self: *Client) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.access_token});
    }

    fn readResponse(
        allocator: std.mem.Allocator,
        response: *std.http.Client.Response,
        limit: usize,
    ) ![]u8 {
        var transfer_buffer: [transfer_buffer_size]u8 = undefined;
        const decompress_buffer: []u8 = if (response.head.content_encoding == .identity)
            &.{}
        else
            try allocator.alloc(u8, std.compress.flate.max_window_len);
        defer allocator.free(decompress_buffer);
        var decompress: std.http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
        return reader.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
            error.StreamTooLong => error.ResponseTooLarge,
            else => err,
        };
    }

    fn request(
        self: *Client,
        method: std.http.Method,
        target: []const u8,
        body: ?[]const u8,
        authenticated: bool,
        range: ?reconstruction.ByteRange,
        identity_only: bool,
    ) !std.http.Client.Request {
        const auth = if (authenticated) try self.authorization() else null;
        defer if (auth) |value| self.allocator.free(value);
        var headers: [2]std.http.Header = undefined;
        var count: usize = 0;
        if (auth) |value| {
            headers[count] = .{ .name = "Authorization", .value = value };
            count += 1;
        }
        var range_buffer: [80]u8 = undefined;
        if (range) |byte_range| {
            if (byte_range.start > byte_range.end) return error.InvalidResponse;
            const value = try std.fmt.bufPrint(
                &range_buffer,
                "bytes={d}-{d}",
                .{ byte_range.start, byte_range.end },
            );
            headers[count] = .{ .name = "Range", .value = value };
            count += 1;
        }
        const uri = try std.Uri.parse(target);
        var req = try self.http_client.request(method, uri, .{
            .extra_headers = headers[0..count],
            .headers = .{
                .content_type = if (body != null)
                    .{ .override = "application/octet-stream" }
                else
                    .default,
                .accept_encoding = if (identity_only) .{ .override = "identity" } else .default,
            },
        });
        if (identity_only) {
            req.accept_encoding = @splat(false);
            req.accept_encoding[@backingInt(std.http.ContentEncoding.identity)] = true;
        }
        errdefer req.deinit();
        if (body) |bytes| {
            req.transfer_encoding = .{ .content_length = bytes.len };
            var req_body = try req.sendBodyUnflushed(&.{});
            try req_body.writer.writeAll(bytes);
            try req_body.end();
            try req.connection.?.flush();
        } else {
            try req.sendBodiless();
        }
        return req;
    }

    pub fn getPlan(
        self: *Client,
        file_hash: hashing.Hash,
        range: ?reconstruction.ByteRange,
    ) !reconstruction.Plan {
        const hex = hashing.toHex(file_hash);
        var version = self.reconstruction_version.load(.monotonic);
        while (true) {
            const target = try self.url("/v{d}/reconstructions/{s}", .{ version, hex });
            defer self.allocator.free(target);
            var req = try self.request(.GET, target, null, true, range, false);
            defer req.deinit();
            var response = try req.receiveHead(&.{});
            if (response.head.status != .ok) {
                if (version == 2 and (response.head.status == .not_found or response.head.status == .not_implemented)) {
                    version = 1;
                    continue;
                }
                return statusError(response.head.status);
            }
            const body = try readResponse(self.allocator, &response, 32 * 1024 * 1024);
            defer self.allocator.free(body);
            var plan = try parsePlan(self.allocator, body, range, version);
            errdefer plan.deinit(self.allocator);
            if (range == null) plan.file_hash = file_hash;
            self.reconstruction_version.store(version, .release);
            return plan;
        }
    }

    pub fn putXorb(self: *Client, hash: hashing.Hash, bytes: []const u8) !void {
        const hex = hashing.toHex(hash);
        const target = try self.url("/v1/xorbs/default/{s}", .{hex});
        defer self.allocator.free(target);
        const upload_bytes = if (xorb.parseFooter(bytes)) |footer|
            bytes[0..footer.body_length]
        else |_|
            bytes;
        var req = try self.request(.POST, target, upload_bytes, true, null, false);
        defer req.deinit();
        var response = try req.receiveHead(&.{});
        if (response.head.status != .ok) return statusError(response.head.status);
        const body = try readResponse(self.allocator, &response, 64 * 1024);
        defer self.allocator.free(body);
        // Success is authoritative. was_inserted only reports deduplication
    }

    pub fn putShard(self: *Client, bytes: []const u8) !void {
        var owned_bytes: ?[]u8 = null;
        defer if (owned_bytes) |copy| self.allocator.free(copy);
        const upload_bytes = if (shard.Reader.init(bytes)) |reader| blk: {
            if (reader.footer.file_lookup_offset > storage.max_shard_size)
                return error.ResponseTooLarge;
            if (std.mem.readInt(u64, bytes[40..48], .little) == 0) break :blk bytes;
            const copy = try self.allocator.dupe(u8, bytes[0..reader.footer.file_lookup_offset]);
            std.mem.writeInt(u64, copy[40..48], 0, .little);
            owned_bytes = copy;
            break :blk copy;
        } else |_| bytes;

        var version = self.shard_version.load(.monotonic);
        while (true) {
            const target = try self.url("/v{d}/shards", .{version});
            defer self.allocator.free(target);
            var req = try self.request(.POST, target, upload_bytes, true, null, true);
            defer req.deinit();
            var response = try req.receiveHead(&.{});
            if (response.head.status != .ok) {
                if (version == 2 and (response.head.status == .not_found or response.head.status == .not_implemented)) {
                    version = 1;
                    continue;
                }
                return statusError(response.head.status);
            }
            if (version == 2) {
                try validateShardUpload(self.allocator, &response);
            } else {
                const body = try readResponse(self.allocator, &response, 64 * 1024);
                defer self.allocator.free(body);
            }
            self.shard_version.store(version, .release);
            return;
        }
    }
};

const GlobalDedup = struct {
    client: *Client,
    allocator: std.mem.Allocator,
    io: std.Io,
    index: dedup.SessionIndex,

    fn deinit(self: *GlobalDedup) void {
        self.index.deinit();
    }

    fn source(self: *GlobalDedup) storage.DedupSource {
        return .{ .context = self, .query_fn = query };
    }

    fn addXorb(raw: *anyopaque, item: shard.Xorb) !void {
        const self: *GlobalDedup = @ptrCast(@alignCast(raw));
        try self.index.addXorb(item);
    }

    fn query(raw: *anyopaque, alloc: std.mem.Allocator, hashes: []const hashing.Hash) !?dedup.Match {
        const self: *GlobalDedup = @ptrCast(@alignCast(raw));
        const local = self.index.source();
        if (try local.query(alloc, hashes)) |match| return match;
        const bytes = self.fetch(alloc, hashes[0]) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => null,
        };
        if (bytes) |owned| {
            const now = std.Io.Clock.real.now(self.io).nanoseconds;
            const secs = @divFloor(now, std.time.ns_per_s);
            _ = self.index.addGlobalOwned(owned, @intCast(secs)) catch |err| switch (err) {
                error.OutOfMemory => {
                    alloc.free(owned);
                    return err;
                },
                else => false,
            };
        }
        return local.query(alloc, hashes) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => null,
        };
    }

    fn fetch(self: *GlobalDedup, alloc: std.mem.Allocator, hash: hashing.Hash) !?[]u8 {
        const hex = hashing.toHex(hash);
        const target = try self.client.url("/v1/chunks/default-merkledb/{s}", .{hex});
        defer self.allocator.free(target);
        var req = try self.client.request(.GET, target, null, true, null, true);
        defer req.deinit();
        var response = try req.receiveHead(&.{});
        if (response.head.status == .not_found) return null;
        if (response.head.status != .ok) return statusError(response.head.status);
        const bytes = try Client.readResponse(alloc, &response, 80 * 1024 * 1024);
        errdefer alloc.free(bytes);
        return bytes;
    }
};

fn validateShardUpload(allocator: std.mem.Allocator, response: *std.http.Client.Response) !void {
    const max_line_size = 1024 * 1024;
    var transfer_buffer: [transfer_buffer_size]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var line: std.Io.Writer.Allocating = .init(allocator);
    defer line.deinit();

    while (true) {
        line.clearRetainingCapacity();
        _ = reader.streamDelimiterLimit(&line.writer, '\n', .limited(max_line_size + 1)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr() orelse error.InvalidResponse,
            error.WriteFailed => return error.OutOfMemory,
            error.StreamTooLong => return error.ResponseTooLarge,
        };
        const eof = if (reader.takeByte()) |byte|
            byte != '\n'
        else |err| switch (err) {
            error.EndOfStream => true,
            error.ReadFailed => return response.bodyErr() orelse error.InvalidResponse,
        };

        const frame = std.mem.trim(u8, line.written(), " \t\r");
        if (frame.len != 0) {
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, frame, .{}) catch
                return error.InvalidResponse;
            defer parsed.deinit();
            const root = try object(parsed.value);
            const kind = try string(root, "type");
            if (std.mem.eql(u8, kind, "error")) return error.ShardUploadFailed;
            if (std.mem.eql(u8, kind, "result")) return;
        }
        if (eof) return error.InvalidResponse;
    }
}

fn rangeLength(range: reconstruction.ByteRange) !u64 {
    return stream.rangeLength(range) catch error.InvalidResponse;
}

fn contentRange(response: *const std.http.Client.Response) !reconstruction.ByteRange {
    var result: ?reconstruction.ByteRange = null;
    var headers = response.head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "Content-Range")) continue;
        if (result != null) return error.InvalidResponse;
        const value = std.mem.trim(u8, header.value, " \t");
        const space = std.mem.indexOfScalar(u8, value, ' ') orelse return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(value[0..space], "bytes")) return error.InvalidResponse;
        const specification = std.mem.trim(u8, value[space + 1 ..], " \t");
        const slash = std.mem.indexOfScalar(u8, specification, '/') orelse return error.InvalidResponse;
        if (slash + 1 == specification.len) return error.InvalidResponse;
        const interval = std.mem.trim(u8, specification[0..slash], " \t");
        const dash = std.mem.indexOfScalar(u8, interval, '-') orelse return error.InvalidResponse;
        const start = std.fmt.parseUnsigned(u64, interval[0..dash], 10) catch return error.InvalidResponse;
        const end = std.fmt.parseUnsigned(u64, interval[dash + 1 ..], 10) catch return error.InvalidResponse;
        result = .{ .start = start, .end = end };
        _ = try rangeLength(result.?);
    }
    return result orelse error.InvalidResponse;
}

fn responsePrefix(response: *const std.http.Client.Response, range: ?reconstruction.ByteRange) !struct { skip: u64, remaining: u64 } {
    if (response.head.content_encoding != .identity) return error.InvalidResponse;
    const requested = range orelse {
        if (response.head.status != .ok) return statusError(response.head.status);
        return .{ .skip = 0, .remaining = std.math.maxInt(u64) };
    };
    const remaining = try rangeLength(requested);
    const skip = switch (response.head.status) {
        .ok => requested.start,
        .partial_content => skip: {
            const actual = try contentRange(response);
            if (actual.start != requested.start or actual.end != requested.end) return error.InvalidResponse;
            break :skip 0;
        },
        else => return statusError(response.head.status),
    };
    return .{ .skip = skip, .remaining = remaining };
}

const ResponseStream = struct {
    allocator: std.mem.Allocator,
    request: std.http.Client.Request,
    response: std.http.Client.Response,
    limited: std.Io.Reader.Limited,
    transfer_buffer: [16 * 1024]u8,
    range_buffer: [stream.scratch_buffer_size]u8,

    fn open(client: *Client, item: stream.Request) !*std.Io.Reader {
        const self = try client.allocator.create(ResponseStream);
        errdefer client.allocator.destroy(self);
        self.allocator = client.allocator;
        self.request = try client.request(.GET, item.url, null, false, item.byte_range, true);
        errdefer self.request.deinit();
        self.response = try self.request.receiveHead(&.{});
        const prefix = try responsePrefix(&self.response, item.byte_range);
        const body = self.response.reader(&self.transfer_buffer);
        body.discardAll64(prefix.skip) catch |err| return self.responseError(err);
        self.limited = .init(body, .limited64(prefix.remaining), &self.range_buffer);
        return &self.limited.interface;
    }

    fn responseError(self: *ResponseStream, err: std.Io.Reader.Error) anyerror {
        return switch (err) {
            error.EndOfStream => error.InvalidResponse,
            error.ReadFailed => self.response.bodyErr() orelse error.ReadFailed,
        };
    }

    fn readError(reader: *std.Io.Reader) ?anyerror {
        const limited: *std.Io.Reader.Limited = @fieldParentPtr("interface", reader);
        const self: *ResponseStream = @fieldParentPtr("limited", limited);
        return self.response.bodyErr();
    }

    fn close(reader: *std.Io.Reader) void {
        const limited: *std.Io.Reader.Limited = @fieldParentPtr("interface", reader);
        const self: *ResponseStream = @fieldParentPtr("limited", limited);
        self.request.deinit();
        self.allocator.destroy(self);
    }
};

fn statusError(status: std.http.Status) Error {
    return switch (status) {
        .bad_request => error.BadRequest,
        .unauthorized => error.Unauthorized,
        .forbidden => error.Forbidden,
        .not_found => error.NotFound,
        .not_implemented => error.NotImplemented,
        .range_not_satisfiable => error.RangeNotSatisfiable,
        .too_many_requests => error.RateLimited,
        .internal_server_error, .bad_gateway, .service_unavailable, .gateway_timeout => error.ServerError,
        else => error.InvalidResponse,
    };
}

fn object(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |item| item,
        else => error.InvalidResponse,
    };
}

fn array(value: std.json.Value) !std.json.Array {
    return switch (value) {
        .array => |item| item,
        else => error.InvalidResponse,
    };
}

fn field(parent: std.json.ObjectMap, name: []const u8) !std.json.Value {
    return parent.get(name) orelse error.InvalidResponse;
}

fn integer(comptime T: type, parent: std.json.ObjectMap, name: []const u8) !T {
    return switch (try field(parent, name)) {
        .integer => |value| std.math.cast(T, value) orelse error.InvalidResponse,
        else => error.InvalidResponse,
    };
}

fn string(parent: std.json.ObjectMap, name: []const u8) ![]const u8 {
    return switch (try field(parent, name)) {
        .string => |value| value,
        else => error.InvalidResponse,
    };
}

fn parseRange(parent: std.json.ObjectMap, name: []const u8) !reconstruction.Range {
    const value = try object(try field(parent, name));
    const result = reconstruction.Range{
        .start = try integer(u32, value, "start"),
        .end = try integer(u32, value, "end"),
    };
    if (result.start >= result.end) return error.InvalidResponse;
    return result;
}

fn parsePlan(
    allocator: std.mem.Allocator,
    body: []const u8,
    range: ?reconstruction.ByteRange,
    version: u8,
) !reconstruction.Plan {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const root = try object(parsed.value);
    const terms = try array(try field(root, "terms"));
    var plan = reconstruction.Plan{ .terms = &.{}, .locations = &.{} };
    errdefer plan.deinit(allocator);
    plan.terms = try allocator.alloc(reconstruction.Term, terms.items.len);
    for (terms.items, plan.terms) |value, *term| {
        const item = try object(value);
        term.* = .{
            .hash = hashing.fromHex(try string(item, "hash")) catch return error.InvalidResponse,
            .unpacked_length = try integer(u32, item, "unpacked_length"),
            .range = try parseRange(item, "range"),
        };
    }

    const fetches = try object(try field(root, if (version == 2) "xorbs" else "fetch_info"));
    var count: usize = 0;
    var iterator = fetches.iterator();
    while (iterator.next()) |entry| {
        const values = try array(entry.value_ptr.*);
        if (version == 2) {
            for (values.items) |value| {
                const ranges = try array(try field(try object(value), "ranges"));
                count = std.math.add(usize, count, ranges.items.len) catch
                    return error.InvalidResponse;
            }
        } else {
            count = std.math.add(usize, count, values.items.len) catch
                return error.InvalidResponse;
        }
    }
    plan.locations = try allocator.alloc(reconstruction.Location, count);
    for (plan.locations) |*location| location.url = "";
    iterator = fetches.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| {
        const hash = hashing.fromHex(entry.key_ptr.*) catch return error.InvalidResponse;
        const values = try array(entry.value_ptr.*);
        for (values.items) |value| {
            const item = try object(value);
            if (version == 2) {
                const url = try string(item, "url");
                const ranges = try array(try field(item, "ranges"));
                for (ranges.items) |range_value| {
                    const descriptor = try object(range_value);
                    const byte_object = try object(try field(descriptor, "bytes"));
                    const byte_range = reconstruction.ByteRange{
                        .start = try integer(u64, byte_object, "start"),
                        .end = try integer(u64, byte_object, "end"),
                    };
                    if (byte_range.start > byte_range.end) return error.InvalidResponse;
                    plan.locations[index] = .{
                        .hash = hash,
                        .range = try parseRange(descriptor, "chunks"),
                        .url = try allocator.dupe(u8, url),
                        .byte_range = byte_range,
                    };
                    index += 1;
                }
            } else {
                const byte_object = try object(try field(item, "url_range"));
                const byte_range = reconstruction.ByteRange{
                    .start = try integer(u64, byte_object, "start"),
                    .end = try integer(u64, byte_object, "end"),
                };
                if (byte_range.start > byte_range.end) return error.InvalidResponse;
                plan.locations[index] = .{
                    .hash = hash,
                    .range = try parseRange(item, "range"),
                    .url = try allocator.dupe(u8, try string(item, "url")),
                    .byte_range = byte_range,
                };
                index += 1;
            }
        }
    }

    plan.offset_into_first_range = if (root.get("offset_into_first_range")) |_|
        try integer(u64, root, "offset_into_first_range")
    else
        0;
    const requested_length = if (range) |requested| try rangeLength(requested) else null;
    var available: u64 = 0;
    for (plan.terms) |term| available = std.math.add(u64, available, term.unpacked_length) catch
        return error.InvalidResponse;
    if (plan.offset_into_first_range > available) return error.InvalidResponse;
    plan.output_length = if (requested_length) |length|
        @min(length, available - plan.offset_into_first_range)
    else
        null;
    try plan.validate();
    return plan;
}

test "parsePlan releases terms locations and URLs after final validation failure" {
    const allocator = std.testing.allocator;
    const hash = "cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6";
    const other = "118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97";
    const terms = [_]struct {
        hash: []const u8,
        unpacked_length: u32,
        range: reconstruction.Range,
    }{.{
        .hash = hash,
        .unpacked_length = 3,
        .range = .{ .start = 0, .end = 1 },
    }};
    const locations = [_]struct {
        range: reconstruction.Range,
        url: []const u8,
        url_range: reconstruction.ByteRange,
    }{.{
        .range = .{ .start = 0, .end = 1 },
        .url = "https://example.invalid/object",
        .url_range = .{ .start = 0, .end = 10 },
    }};

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var json: std.json.Stringify = .{ .writer = &out.writer };
    try json.beginObject();
    try json.objectField("terms");
    try json.write(terms);
    try json.objectField("fetch_info");
    try json.beginObject();
    try json.objectField(other);
    try json.write(locations);
    try json.endObject();
    try json.endObject();

    try std.testing.expectError(error.MissingLocation, parsePlan(allocator, out.written(), null, 1));
}

const empty_plan_json =
    \\{"terms":[],"fetch_info":{}}
;

fn checkRegressionEndpoints(allocator: std.mem.Allocator, io: std.Io, suffix: []const u8) !void {
    const support = @import("regression_support");
    const responses = [_]support.HttpResponse{ .{}, .{ .status = .not_found }, .{}, .{ .status = .not_found }, .{ .body = empty_plan_json } };
    var server = try support.Loopback.init(allocator, io, &responses);
    defer server.deinit();
    try server.start();
    const origin = try std.fmt.allocPrint(allocator, "{s}{s}", .{ server.origin, suffix });
    defer allocator.free(origin);
    const file_hash = hashing.data("file");
    const xorb_hash = hashing.data("xorb");
    const expected_file = hashing.toHex(file_hash);
    const expected_xorb = hashing.toHex(xorb_hash);
    const get_path = try std.fmt.allocPrint(allocator, "/v1/reconstructions/{s}", .{expected_file});
    defer allocator.free(get_path);
    const xorb_path = try std.fmt.allocPrint(allocator, "/v1/xorbs/default/{s}", .{expected_xorb});
    defer allocator.free(xorb_path);

    var client = try Client.init(allocator, io, origin, "");
    defer client.deinit();
    try client.putXorb(xorb_hash, "xorb");
    try client.putShard("shard");
    var plan = try client.getPlan(file_hash, null);
    plan.deinit(allocator);
    try server.finish(5);
    try std.testing.expectEqualStrings(get_path, server.exchanges.items[4].target);
    try std.testing.expectEqualStrings(xorb_path, server.exchanges.items[0].target);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[1].target);
    try std.testing.expectEqualStrings("/v1/shards", server.exchanges.items[2].target);
    for (server.exchanges.items) |exchange| {
        try std.testing.expect(std.mem.indexOf(u8, exchange.target, "/v1/v1/") == null);
    }
}

test "shard validation streams oversized frames and accepts the result" {
    const support = @import("regression_support");
    const allocator = std.testing.allocator;
    const padding = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(padding);
    @memset(padding, ' ');
    const body = try std.fmt.allocPrint(allocator,
        \\
        \\{s}
        \\{{"type":"progress"}}
        \\{{"type":"result"}}
        \\
    , .{padding});
    defer allocator.free(body);
    const responses = [_]support.HttpResponse{.{ .body = body }};
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    try client.putShard("shard");
    try server.finish(1);
}

test "CAS endpoints add v1 to a bare loopback origin" {
    try checkRegressionEndpoints(std.testing.allocator, std.testing.io, "");
}

test "CAS endpoints preserve exactly one v1 for a versioned origin" {
    try checkRegressionEndpoints(std.testing.allocator, std.testing.io, "/v1");
}

test "parse a CAS reconstruction plan strictly" {
    const allocator = std.testing.allocator;
    const hash = "cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6";
    const terms = [_]struct {
        hash: []const u8,
        unpacked_length: u32,
        range: reconstruction.Range,
    }{.{
        .hash = hash,
        .unpacked_length = 9,
        .range = .{ .start = 1, .end = 3 },
    }};
    const locations = [_]struct {
        range: reconstruction.Range,
        url: []const u8,
        url_range: reconstruction.ByteRange,
    }{.{
        .range = .{ .start = 0, .end = 3 },
        .url = "https://example.invalid/object",
        .url_range = .{ .start = 10, .end = 99 },
    }};

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var json: std.json.Stringify = .{ .writer = &out.writer };
    try json.beginObject();
    try json.objectField("offset_into_first_range");
    try json.write(2);
    try json.objectField("terms");
    try json.write(terms);
    try json.objectField("fetch_info");
    try json.beginObject();
    try json.objectField(hash);
    try json.write(locations);
    try json.endObject();
    try json.endObject();

    var plan = try parsePlan(allocator, out.written(), .{ .start = 2, .end = 6 }, 1);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), plan.offset_into_first_range);
    try std.testing.expectEqual(@as(?u64, 5), plan.output_length);
    try std.testing.expectEqual(@as(u64, 99), plan.locations[0].byte_range.?.end);
}

test "reconstruction ranges reject inclusive length overflow" {
    try std.testing.expectError(error.InvalidResponse, rangeLength(.{
        .start = 0,
        .end = std.math.maxInt(u64),
    }));
    try std.testing.expectError(error.InvalidResponse, parsePlan(
        std.testing.allocator,
        empty_plan_json,
        .{ .start = 0, .end = std.math.maxInt(u64) },
        1,
    ));
}

test "malformed CAS responses are rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidResponse, parsePlan(allocator, "{}", null, 1));
    try std.testing.expectError(error.SyntaxError, parsePlan(allocator, "not json", null, 1));
}
