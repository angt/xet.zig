const std = @import("std");
const xet = @import("xet");

pub const AllocEvent = struct {
    bytes: []u8,
    alignment: std.mem.Alignment,
    live: bool = true,
};

/// Records ownership operations; optionally retains freed storage until teardown.
pub const TrackingAllocator = struct {
    backing: std.mem.Allocator,
    fail_at: ?usize = null,
    allocation_count: usize = 0,
    events: std.ArrayList(AllocEvent) = .empty,
    event_indices: std.AutoHashMapUnmanaged(usize, usize) = .empty,
    duplicate_frees: usize = 0,
    invalid_frees: usize = 0,
    old_storage: std.ArrayList(struct { bytes: []u8, alignment: std.mem.Alignment }) = .empty,
    retain_freed: bool = false,

    pub fn allocator(self: *TrackingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    pub fn deinit(self: *TrackingAllocator) void {
        for (self.events.items) |event| {
            if (self.retain_freed or event.live) self.backing.rawFree(event.bytes, event.alignment, 0);
        }
        if (self.retain_freed) for (self.old_storage.items) |event| self.backing.rawFree(event.bytes, event.alignment, 0);
        self.events.deinit(self.backing);
        self.event_indices.deinit(self.backing);
        self.old_storage.deinit(self.backing);
    }

    pub fn outstanding(self: *const TrackingAllocator) usize {
        var count: usize = 0;
        for (self.events.items) |event| count += @intFromBool(event.live);
        return count;
    }

    fn alloc(raw: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(raw));
        if (self.fail_at == self.allocation_count) return null;
        const index = self.allocation_count;
        const bytes = self.backing.rawAlloc(len, alignment, ra) orelse return null;
        self.events.append(self.backing, .{ .bytes = bytes[0..len], .alignment = alignment }) catch {
            self.backing.rawFree(bytes[0..len], alignment, ra);
            return null;
        };
        self.event_indices.put(self.backing, @intFromPtr(bytes), self.events.items.len - 1) catch return null;
        self.allocation_count = index + 1;
        return bytes;
    }

    fn resize(raw: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *TrackingAllocator = @ptrCast(@alignCast(raw));
        const event = self.findLive(memory, alignment) orelse return false;
        if (!self.backing.rawResize(memory, alignment, new_len, ra)) return false;
        event.bytes = memory.ptr[0..new_len];
        return true;
    }

    fn remap(raw: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(raw));
        if (self.fail_at == self.allocation_count) return null;
        const index = self.allocation_count;
        const event = self.findLive(memory, alignment) orelse return null;
        const replacement = self.backing.rawAlloc(new_len, alignment, ra) orelse return null;
        @memcpy(replacement[0..@min(memory.len, new_len)], memory[0..@min(memory.len, new_len)]);
        if (self.retain_freed) {
            self.old_storage.append(self.backing, .{ .bytes = event.bytes, .alignment = alignment }) catch {
                self.backing.rawFree(replacement[0..new_len], alignment, ra);
                return null;
            };
        } else {
            self.backing.rawFree(memory, alignment, ra);
        }
        event.bytes = replacement[0..new_len];
        const event_index = @intFromPtr(event) - @intFromPtr(self.events.items.ptr);
        self.event_indices.put(self.backing, @intFromPtr(replacement), event_index / @sizeOf(AllocEvent)) catch return null;
        self.allocation_count = index + 1;
        return replacement;
    }

    fn free(raw: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *TrackingAllocator = @ptrCast(@alignCast(raw));
        if (self.findLive(memory, alignment)) |event| {
            event.live = false;
            if (!self.retain_freed) self.backing.rawFree(memory, alignment, ra);
            return;
        }
        if (self.event_indices.get(@intFromPtr(memory.ptr))) |index| {
            const event = &self.events.items[index];
            if (event.bytes.ptr == memory.ptr and event.alignment == alignment) {
                if (self.retain_freed) {
                    for (self.events.items, 0..) |other, other_index| {
                        if (other_index != index and other.bytes.ptr == memory.ptr and
                            other.alignment == alignment and other.live) break;
                    } else {
                        self.duplicate_frees += 1;
                        return;
                    }
                } else {
                    self.duplicate_frees += 1;
                    return;
                }
            }
        }
        self.invalid_frees += 1;
    }

    fn findLive(self: *TrackingAllocator, memory: []u8, alignment: std.mem.Alignment) ?*AllocEvent {
        const index = self.event_indices.get(@intFromPtr(memory.ptr)) orelse return null;
        const event = &self.events.items[index];
        if (event.live and event.alignment == alignment) return event;
        return null;
    }
};

pub const CapturedObject = struct {
    kind: xet.ObjectKind,
    hash: xet.Hash,
    data: []u8,
    raw_size: u64,
};

pub const MemoryStore = struct {
    allocator: std.mem.Allocator,
    objects: std.ArrayList(CapturedObject) = .empty,
    fail_on_put: ?usize = null,
    puts: usize = 0,
    last_attempted_kind: ?xet.ObjectKind = null,
    allocation_count: ?*const usize = null,
    put_allocation_count: ?usize = null,

    pub fn store(self: *MemoryStore) xet.Store {
        return .{ .context = self, .put_fn = put };
    }

    pub fn deinit(self: *MemoryStore) void {
        for (self.objects.items) |object| self.allocator.free(object.data);
        self.objects.deinit(self.allocator);
    }

    pub fn count(self: *const MemoryStore, kind: xet.ObjectKind) usize {
        var result: usize = 0;
        for (self.objects.items) |object| result += @intFromBool(object.kind == kind);
        return result;
    }

    fn put(raw: *anyopaque, object: xet.store.Object) !void {
        const self: *MemoryStore = @ptrCast(@alignCast(raw));
        self.last_attempted_kind = object.kind;
        if (self.put_allocation_count == null) {
            if (self.allocation_count) |allocation_count| self.put_allocation_count = allocation_count.*;
        }
        const index = self.puts;
        self.puts += 1;
        if (self.fail_on_put == index) return error.InjectedStoreFailure;
        const copy = try self.allocator.dupe(u8, object.data);
        errdefer self.allocator.free(copy);
        try self.objects.append(self.allocator, .{
            .kind = object.kind,
            .hash = object.hash,
            .data = copy,
            .raw_size = object.raw_size,
        });
    }
};

pub const SinkBuffer = std.Io.Writer.Allocating;

pub const SliceOpener = struct {
    bytes: []const u8,
    requests: usize = 0,
    closes: usize = 0,
    last_range: ?xet.reconstruction.ByteRange = .{ .start = 0, .end = 0 },
    reader: std.Io.Reader = undefined,

    pub fn opener(self: *SliceOpener) xet.stream.Opener {
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

pub const HttpResponse = struct {
    status: std.http.Status = .ok,
    body: []const u8 = "",
    content_range: ?[]const u8 = null,
    content_encoding: ?[]const u8 = null,
};

pub const HttpExchange = struct {
    target: []u8,
    range: ?[]u8,
    accept_encoding: ?[]u8,
    body: []u8,
};

/// Independent connections isolate failed requests during assertions.
pub const Loopback = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: std.Io.net.Server,
    origin: []u8,
    responses: []const HttpResponse,
    exchanges: std.ArrayList(HttpExchange) = .empty,
    exchange_mutex: std.Io.Mutex = .init,
    futures: std.ArrayList(std.Io.Future(void)) = .empty,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, responses: []const HttpResponse) !Loopback {
        var address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
        var server = try address.listen(io, .{});
        errdefer server.deinit(io);
        address.setPort(server.socket.address.getPort());
        const origin = try std.fmt.allocPrint(allocator, "http://{f}", .{address});
        return .{
            .allocator = allocator,
            .io = io,
            .server = server,
            .origin = origin,
            .responses = responses,
        };
    }

    pub fn start(self: *Loopback) !void {
        if (self.futures.items.len != 0) return error.TestServerAlreadyStarted;
        const future = try self.io.concurrent(serve, .{self});
        try self.futures.append(self.allocator, future);
    }

    pub fn finish(self: *Loopback, count: usize) !void {
        try std.testing.expectEqual(@as(usize, 1), self.futures.items.len);
        self.futures.items[0].await(self.io);
        try std.testing.expectEqual(count, self.exchanges.items.len);
    }

    pub fn deinit(self: *Loopback) void {
        self.server.deinit(self.io);
        for (self.futures.items) |*future| future.cancel(self.io);
        self.futures.deinit(self.allocator);
        for (self.exchanges.items) |exchange| {
            self.allocator.free(exchange.target);
            if (exchange.range) |range| self.allocator.free(range);
            if (exchange.accept_encoding) |value| self.allocator.free(value);
            self.allocator.free(exchange.body);
        }
        self.exchanges.deinit(self.allocator);
        self.allocator.free(self.origin);
    }

    pub fn objectUrl(self: *const Loopback, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/object", .{self.origin});
    }

    fn serve(self: *Loopback) void {
        for (self.responses) |response| self.handleOne(response) catch return;
    }

    fn handleOne(self: *Loopback, response: HttpResponse) !void {
        var connection = try self.server.accept(self.io);
        defer connection.close(self.io);
        var read_buffer: [16 * 1024]u8 = undefined;
        var write_buffer: [16 * 1024]u8 = undefined;
        var reader = connection.reader(self.io, &read_buffer);
        var writer = connection.writer(self.io, &write_buffer);
        var http_server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try http_server.receiveHead();
        const target = try self.allocator.dupe(u8, request.head.target);
        errdefer self.allocator.free(target);
        var range: ?[]u8 = null;
        errdefer if (range) |value| self.allocator.free(value);
        var accept_encoding: ?[]u8 = null;
        errdefer if (accept_encoding) |value| self.allocator.free(value);
        var iterator = request.iterateHeaders();
        while (iterator.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "range")) {
                range = try self.allocator.dupe(u8, header.value);
            }
            if (std.ascii.eqlIgnoreCase(header.name, "accept-encoding")) {
                accept_encoding = try self.allocator.dupe(u8, header.value);
            }
        }
        var body_buffer: [4096]u8 = undefined;
        const body_reader = request.readerExpectNone(&body_buffer);
        const body = try body_reader.allocRemaining(self.allocator, .limited(96 * 1024 * 1024));
        errdefer self.allocator.free(body);
        self.exchange_mutex.lockUncancelable(self.io);
        self.exchanges.append(self.allocator, .{
            .target = target,
            .range = range,
            .accept_encoding = accept_encoding,
            .body = body,
        }) catch |err| {
            self.exchange_mutex.unlock(self.io);
            return err;
        };
        self.exchange_mutex.unlock(self.io);
        var headers: [2]std.http.Header = undefined;
        var header_count: usize = 0;
        if (response.content_range) |value| {
            headers[header_count] = .{ .name = "Content-Range", .value = value };
            header_count += 1;
        }
        if (response.content_encoding) |value| {
            headers[header_count] = .{ .name = "Content-Encoding", .value = value };
            header_count += 1;
        }
        try request.respond(response.body, .{
            .status = response.status,
            .keep_alive = false,
            .extra_headers = headers[0..header_count],
        });
    }
};

pub const XorbChunk = struct {
    bytes: []const u8,
    record_start: usize,
    record_end: usize,
};

/// Independent reader for complete or footerless uncompressed Xorbs.
pub fn readUncompressedXorb(allocator: std.mem.Allocator, bytes: []const u8) ![]XorbChunk {
    if (bytes.len < 4) return error.TestInvalidXorb;
    const footer_length = std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little);
    const footer_start = if (footer_length <= bytes.len - 4 and
        footer_length >= 60 and bytes.len - 4 - footer_length >= 8 and
        std.mem.eql(u8, bytes[bytes.len - 4 - footer_length ..][0..8], "XETBLOB\x01"))
        bytes.len - 4 - footer_length
    else
        bytes.len;
    var chunks: std.ArrayList(XorbChunk) = .empty;
    errdefer chunks.deinit(allocator);
    var position: usize = 0;
    while (position + 8 <= footer_start) {
        const start = position;
        const header = bytes[position..][0..8];
        if (header[0] != 0) return error.TestInvalidXorb;
        const compressed_size = @as(usize, header[1]) | @as(usize, header[2]) << 8 | @as(usize, header[3]) << 16;
        const raw_size = @as(usize, header[5]) | @as(usize, header[6]) << 8 | @as(usize, header[7]) << 16;
        position += 8;
        if (header[4] != 0 or compressed_size != raw_size or position + raw_size > footer_start)
            return error.TestInvalidXorb;
        try chunks.append(allocator, .{
            .bytes = bytes[position..][0..raw_size],
            .record_start = start,
            .record_end = position + raw_size,
        });
        position += raw_size;
        if (position == footer_start) break;
    }
    if (position != footer_start) return error.TestInvalidXorb;
    return chunks.toOwnedSlice(allocator);
}

pub fn syntheticHash(domain: u8, index: usize) xet.Hash {
    var digest: xet.Hash = @splat(0);
    digest[0] = domain;
    std.mem.writeInt(u64, digest[24..32], index, .little);
    return digest;
}
