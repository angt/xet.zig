//! Standard Xet CAS HTTP adapter without repository authentication

const constants = @import("constants.zig");
const std = @import("std");
const chunker = @import("chunker.zig");
const hashing = @import("hash.zig");
const recon = @import("recon.zig");
const shard = @import("shard.zig");
const xorb = @import("xorb.zig");
const storage = @import("store.zig");
const stream = @import("stream.zig");
const concurrent = @import("concurrent.zig");
const dedup = @import("dedup.zig");
const verify = @import("verify.zig");
const cache = @import("shard_cache.zig");

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
    pub const Session = UploadSession;
    pub const DownloadOptions = struct {
        /// Inclusive byte range. A whole-file request additionally verifies the Xet file ID.
        range: ?stream.ByteRange = null,
        strategy: ?chunker.Strategy = null,
        /// At most this many terms can be fetched concurrently. One streams serially.
        window: usize = 8,
    };

    allocator: std.mem.Allocator,
    endpoint: []u8,
    bearer: []u8,
    /// Optional caller-owned private directory for dedup across upload sessions.
    shard_cache: ?std.Io.Dir = null,
    http_client: std.http.Client,
    /// 404/501 responses select V1 for later calls
    recon_version: std.atomic.Value(u8) = .init(2),
    shard_version: std.atomic.Value(u8) = .init(2),
    upload_bytes_mutex: std.Io.Mutex = .init,
    upload_bytes: u64 = 0,

    /// Accepts a CAS origin or an endpoint ending in `/v1` or `/v2`
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        endpoint: []const u8,
        access_token: []const u8,
    ) !Client {
        const trimmed = std.mem.trimEnd(u8, endpoint, "/");
        const has_version = std.mem.endsWith(
            u8,
            trimmed,
            "/v1",
        ) or std.mem.endsWith(u8, trimmed, "/v2");
        const owned_endpoint = if (has_version)
            try allocator.dupe(u8, trimmed[0 .. trimmed.len - 3])
        else
            try allocator.dupe(u8, trimmed);
        errdefer allocator.free(owned_endpoint);
        return .{
            .allocator = allocator,
            .endpoint = owned_endpoint,
            .bearer = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token}),
            .http_client = .{ .allocator = allocator, .io = io, .read_buffer_size = 64 * 1024 },
        };
    }

    pub fn deinit(self: *Client) void {
        self.http_client.deinit();
        self.allocator.free(self.endpoint);
        self.allocator.free(self.bearer);
        self.* = undefined;
    }

    pub fn uploadedBytes(self: *Client) u64 {
        self.upload_bytes_mutex.lockUncancelable(self.http_client.io);
        defer self.upload_bytes_mutex.unlock(self.http_client.io);
        return self.upload_bytes;
    }

    pub fn store(self: *Client) storage.Store {
        return .{ .context = self, .put_fn = putObject };
    }

    pub fn opener(self: *Client) stream.Opener {
        return .{
            .context = self,
            .open_fn = openObject,
            .close_fn = closeObject,
            .read_error_fn = readObjectError,
        };
    }

    pub fn uploadSession(
        self: *Client,
        allocator: std.mem.Allocator,
        opts: storage.PackOptions,
    ) !UploadSession {
        try opts.validate();
        var index = dedup.SessionIndex.init(allocator);
        errdefer index.deinit();
        if (self.shard_cache) |dir| try cache.load(dir, self.http_client.io, self.endpoint, &index);
        return .{
            .client = self,
            .allocator = allocator,
            .opts = opts,
            .global = .{
                .client = self,
                .io = self.http_client.io,
                .index = index,
            },
            .packing = .init(allocator, self.store(), self.store(), opts.compression),
        };
    }

    /// Read through EOF and commit the file's Xorbs and shard before returning.
    pub fn upload(
        self: *Client,
        source: *std.Io.Reader,
        opts: storage.PackOptions,
    ) !storage.PublishResult {
        var session = try self.uploadSession(self.allocator, opts);
        defer session.deinit();
        try session.addFile(source);
        try session.finish();
        return session.results()[0];
    }

    /// Stream file bytes into a caller-owned writer. The caller controls flushing.
    /// For a whole file, publish staged output only after the final hash check succeeds.
    pub fn download(
        self: *Client,
        id: hashing.Hash,
        sink: *std.Io.Writer,
        opts: DownloadOptions,
    ) !u64 {
        if (opts.window == 0) return error.InvalidConcurrency;
        var plan = try self.getPlan(id, opts.range);
        defer plan.deinit(self.allocator);
        return self.downloadPlan(&plan, sink, opts);
    }

    pub const Output = struct { id: hashing.Hash, writer: *std.Io.Writer };

    /// Download whole files in order. Adjacent authorized ranges can share one GET.
    /// Each writer is borrowed and left unflushed. Output can be partial on failure.
    pub fn downloadMany(self: *Client, outputs: []const Output) !void {
        var remaining = outputs;
        while (remaining.len != 0) {
            const count = @min(remaining.len, Batch.limit);
            try Batch.run(self, remaining[0..count]);
            remaining = remaining[count..];
        }
    }

    fn downloadPlan(
        self: *Client,
        plan: *const recon.Plan,
        sink: *std.Io.Writer,
        opts: DownloadOptions,
    ) !u64 {
        var opener_ = self.opener();
        if (plan.file_hash != null) opener_.open_fn = openVerifiedObject;
        if (plan.file_hash != null and opts.strategy == null and opts.window > 1 and plan.terms.len != 0 and
            (plan.terms.len > 1 or plan.terms[0].unpacked_length >= verify.parallel_threshold))
        {
            return concurrent.consumeFile(
                self.allocator,
                self.http_client.io,
                plan,
                opener_,
                sink,
                .{
                    .window = @min(opts.window, plan.terms.len),
                    // The packed frame headers also count against the wire limit.
                    .max_term_size = constants.max_xorb_size + 2 * constants.max_chunk_size,
                },
            );
        }
        return self.consume(plan, opener_, sink, opts);
    }

    fn consume(
        self: *Client,
        plan: *const recon.Plan,
        opener_: stream.Opener,
        sink: *std.Io.Writer,
        opts: DownloadOptions,
    ) !u64 {
        if (opts.window == 1 or plan.terms.len < 2)
            return recon.consumeWith(self.allocator, plan, opener_, sink, opts.strategy);
        return concurrent.consume(self.allocator, self.http_client.io, plan, opener_, sink, .{
            .window = @min(opts.window, plan.terms.len),
            .strategy = opts.strategy,
        });
    }

    fn openObject(raw: *anyopaque, item: stream.Request) !*std.Io.Reader {
        const self: *Client = @ptrCast(@alignCast(raw));
        return ResponseStream.open(self, item, false);
    }

    fn openVerifiedObject(raw: *anyopaque, item: stream.Request) !*std.Io.Reader {
        const self: *Client = @ptrCast(@alignCast(raw));
        return ResponseStream.open(self, item, true);
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
            .shard => {
                try self.putShard(item.data);
                if (self.shard_cache) |dir|
                    cache.save(dir, self.http_client.io, self.endpoint, item) catch {};
            },
        }
    }

    fn url(self: *Client, comptime fmt: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}" ++ fmt, .{self.endpoint} ++ args);
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
        const reader = response.readerDecompressing(
            &transfer_buffer,
            &decompress,
            decompress_buffer,
        );
        return reader.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
            error.StreamTooLong => error.ResponseTooLarge,
            error.ReadFailed => bodyFailure(response, error.ReadFailed),
            else => err,
        };
    }

    fn request(
        self: *Client,
        method: std.http.Method,
        target: []const u8,
        body: ?[]const u8,
        authenticated: bool,
        range: ?recon.ByteRange,
        identity_only: bool,
    ) !std.http.Client.Request {
        var headers: [1]std.http.Header = undefined;
        var range_buffer: [80]u8 = undefined;
        if (range) |byte_range| {
            if (byte_range.start > byte_range.end) return error.InvalidResponse;
            const value = try std.fmt.bufPrint(
                &range_buffer,
                "bytes={d}-{d}",
                .{ byte_range.start, byte_range.end },
            );
            headers[0] = .{ .name = "Range", .value = value };
        }
        const uri = try std.Uri.parse(target);
        var req = try self.http_client.request(method, uri, .{
            .extra_headers = if (range != null) &headers else &.{},
            // Signed object URLs come from the recon response.
            .redirect_behavior = .unhandled,
            .headers = .{
                .authorization = if (authenticated) .{ .override = self.bearer } else .omit,
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
            var req_body = req.sendBodyUnflushed(&.{}) catch |err| return writeFailure(&req, err);
            req_body.writer.writeAll(bytes) catch |err| return writeFailure(&req, err);
            req_body.end() catch |err| return writeFailure(&req, err);
            req.connection.?.flush() catch |err| return writeFailure(&req, err);
            self.upload_bytes_mutex.lockUncancelable(self.http_client.io);
            defer self.upload_bytes_mutex.unlock(self.http_client.io);
            self.upload_bytes += bytes.len;
        } else {
            req.sendBodiless() catch |err| return writeFailure(&req, err);
        }
        return req;
    }

    pub fn getPlan(
        self: *Client,
        file_hash: hashing.Hash,
        range: ?recon.ByteRange,
    ) !recon.Plan {
        const hex = hashing.toHex(file_hash);
        var version = self.recon_version.load(.monotonic);
        while (true) {
            const target = try self.url("/v{d}/reconstructions/{s}", .{ version, hex });
            defer self.allocator.free(target);
            var req = try self.request(.GET, target, null, true, range, false);
            defer req.deinit();
            var response = req.receiveHead(&.{}) catch |err| return readFailure(&req, err);
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
            self.recon_version.store(version, .release);
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
        var response = req.receiveHead(&.{}) catch |err| return readFailure(&req, err);
        if (response.head.status != .ok) return statusError(response.head.status);
        const body = try readResponse(self.allocator, &response, 64 * 1024);
        defer self.allocator.free(body);
        // The body only reports deduplication, so the status is the success signal
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
            var response = req.receiveHead(&.{}) catch |err| return readFailure(&req, err);
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

/// The URI stays below 4 KiB. Only consecutive byte intervals with the same
/// signed URL and Xorb hash are joined. Each file keeps its own trusted root.
const Batch = struct {
    const limit = 8;
    const max_bytes = 8 * 1024 * 1024;

    fn run(client: *Client, outputs: []const Client.Output) !void {
        if (outputs.len == 1) {
            _ = try client.download(outputs[0].id, outputs[0].writer, .{});
            return;
        }
        var arena = std.heap.ArenaAllocator.init(client.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var target: std.Io.Writer.Allocating = .init(allocator);
        try target.writer.print("{s}/v1/reconstructions", .{client.endpoint});
        for (outputs, 0..) |output, i|
            try target.writer.print(
                "{c}file_id={s}",
                .{ @as(u8, if (i == 0) '?' else '&'), hashing.toHex(output.id) },
            );
        const body = body: {
            var req = try client.request(.GET, target.written(), null, true, null, false);
            defer req.deinit();
            var response = req.receiveHead(&.{}) catch |err| return readFailure(&req, err);
            switch (response.head.status) {
                .ok => break :body try Client.readResponse(allocator, &response, 32 * 1024 * 1024),
                .not_found, .method_not_allowed, .not_implemented, .uri_too_long => break :body null,
                else => return statusError(response.head.status),
            }
        } orelse {
            for (outputs) |output| _ = try client.download(output.id, output.writer, .{});
            return;
        };
        const json = try std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{});
        const root = try object(json);
        const files = try object(try field(root, "files"));
        const locations = try parseLocations(
            allocator,
            try object(try field(root, "fetch_info")),
            1,
        );
        var plans: [limit]recon.Plan = undefined;
        var exact: [limit]?recon.Location = @splat(null);
        for (outputs, 0..) |output, i| {
            const hex = hashing.toHex(output.id);
            const values = files.get(&hex) orelse return error.NotFound;
            const terms = try parseTerms(allocator, try array(values));
            plans[i] = .{ .terms = terms, .locations = locations, .file_hash = output.id };
            try plans[i].validate();
            if (terms.len == 1) {
                const term = terms[0];
                const loc = recon.findLocation(locations, term) orelse return error.MissingLocation;
                if (loc.byte_range != null and std.meta.eql(term.range, loc.range)) exact[i] = loc;
            }
        }

        var i: usize = 0;
        while (i < outputs.len) {
            const plan = &plans[i];
            var end = i + 1;
            while (end < outputs.len and hashing.eql(outputs[i].id, outputs[end].id)) end += 1;
            if (end > i + 1) {
                var length: u64 = 0;
                for (plan.terms) |term| length += term.unpacked_length;
                if (length <= max_bytes) {
                    const bytes = try client.allocator.alloc(u8, @intCast(length));
                    defer client.allocator.free(bytes);
                    var sink: std.Io.Writer = .fixed(bytes);
                    _ = try client.downloadPlan(plan, &sink, .{});
                    for (outputs[i..end]) |out| try out.writer.writeAll(sink.buffered());
                    i = end;
                    continue;
                }
            }
            if (exact[i]) |first| {
                var range = first.byte_range.?;
                end = i + 1;
                while (end < outputs.len) : (end += 1) {
                    const next = exact[end] orelse break;
                    const bytes = next.byte_range.?;
                    if (range.end == std.math.maxInt(u64) or bytes.start != range.end + 1 or
                        bytes.end - range.start >= max_bytes or !hashing.eql(
                        next.hash,
                        first.hash,
                    ) or
                        !std.mem.eql(u8, first.url, next.url)) break;
                    range.end = bytes.end;
                }
                if (end > i + 1) {
                    if (try readJoined(
                        client,
                        first,
                        range,
                        outputs[i..end],
                        plans[i..end],
                        exact[i..end],
                    )) {
                        i = end;
                        continue;
                    }
                }
            }
            _ = try client.downloadPlan(plan, outputs[i].writer, .{});
            i += 1;
        }
    }

    fn readJoined(
        client: *Client,
        first: recon.Location,
        range: stream.ByteRange,
        outputs: []const Client.Output,
        plans: []const recon.Plan,
        locations: []const ?recon.Location,
    ) !bool {
        const reader = ResponseStream.open(
            client,
            .{ .hash = first.hash, .url = first.url, .byte_range = range },
            true,
        ) catch |err| switch (err) {
            error.BadRequest, error.Forbidden, error.RangeNotSatisfiable, error.InvalidResponse => return false,
            else => return err,
        };
        defer ResponseStream.close(reader);
        // Bound each decode to its authorized interval even when a peer returns malformed frames.
        for (outputs, plans, locations) |output, plan, entry| {
            const loc = entry.?;
            var buffer: [4096]u8 = undefined;
            var limited = std.Io.Reader.Limited.init(
                reader,
                .limited64(try rangeLength(loc.byte_range.?)),
                &buffer,
            );
            var verifier = verify.Verifier.initWith(client.allocator, output.writer, null);
            defer verifier.deinit();
            const term = plan.terms[0];
            const n = recon.decodeLocatedTerm(
                client.allocator,
                term,
                loc,
                &limited.interface,
                &verifier.interface,
            ) catch |err| switch (err) {
                error.ReadFailed => return ResponseStream.readError(reader) orelse err,
                else => return verifier.failure(err),
            };
            if (n != term.unpacked_length or limited.remaining != .nothing or limited.interface.bufferedLen() != 0)
                return error.SizeMismatch;
            try verifier.finish(output.id);
        }
        return true;
    }
};

pub const UploadFile = struct {
    const State = enum { active, finished, failed };

    session: *UploadSession,
    publisher: storage.Publisher,
    id: u64,
    state: State = .active,

    /// Discards an unfinished file and rolls back its session dedup additions
    pub fn deinit(self: *UploadFile) void {
        if (self.session.active_file_id == self.id) {
            if (self.state == .active or self.state == .failed) {
                // The writer drops this file's chunks, which only its owner may do
                self.publisher.abort();
                self.session.global.rollback();
            }
            self.release();
        }
        self.publisher.deinit();
        self.* = undefined;
    }

    /// Borrows input for this call only, and a failed write is terminal
    pub fn write(self: *UploadFile, input: []const u8) !void {
        switch (self.state) {
            .active => {},
            .finished => return error.AlreadyFinished,
            .failed => return error.WriteFailed,
        }
        self.publisher.write(input) catch |err| {
            self.state = .failed;
            self.publisher.abort();
            self.session.global.rollback();
            self.release();
            return err;
        };
    }

    /// Queues the file plan, so only session.finish publishes the combined shard
    pub fn finish(self: *UploadFile) !storage.PublishResult {
        switch (self.state) {
            .active => {},
            .finished => return error.AlreadyFinished,
            .failed => return error.WriteFailed,
        }
        self.state = .finished;
        errdefer self.state = .failed;
        // The claim holds until the plan is accepted, so a callback cannot finish the session
        errdefer self.release();
        const session = self.session;
        // Plan failure drops the abandoned chunks but keeps stored Xorbs reusable
        errdefer self.publisher.discardBuffered();
        errdefer session.global.rollback();
        try session.results_list.ensureUnusedCapacity(session.allocator, 1);
        const result = try session.packing.endFile(&self.publisher);
        session.global.commit();
        session.results_list.appendAssumeCapacity(result);
        self.release();
        return result;
    }

    fn release(self: *UploadFile) void {
        if (self.session.active_file_id != self.id) return;
        self.session.active_file_id = null;
    }
};

/// Streams files and publishes their metadata together
pub const UploadSession = struct {
    client: *Client,
    allocator: std.mem.Allocator,
    opts: storage.PackOptions,
    global: GlobalDedup,
    packing: storage.Packing,
    results_list: std.ArrayList(storage.PublishResult) = .empty,
    published: []storage.PublishResult = &.{},
    active_file_id: ?u64 = null,
    next_file_id: u64 = 0,
    finished: bool = false,
    pending: ?concurrent.UploadStore = null,

    /// Overlap larger Xorb posts with ingestion and keep the upload queue bounded.
    fn putData(raw: *anyopaque, item: storage.Object) !void {
        const self: *UploadSession = @ptrCast(@alignCast(raw));
        if (self.pending == null) {
            if (item.data.len < 4 * 1024 * 1024) return self.client.store().put(item);
            self.pending = try concurrent.UploadStore.init(
                self.allocator,
                self.client.http_client.io,
                self.client.store(),
                2,
            );
        }
        try self.pending.?.store().put(item);
    }

    pub fn deinit(self: *UploadSession) void {
        if (self.pending) |*pending| pending.deinit();
        self.results_list.deinit(self.allocator);
        self.allocator.free(self.published);
        self.packing.deinit();
        self.global.deinit();
        self.* = undefined;
    }

    /// The file handle borrows this session until deinitialization
    pub fn beginFile(self: *UploadSession) !UploadFile {
        if (self.finished) return error.AlreadyFinished;
        if (self.packing.writer.lost) return error.OperationFailed;
        if (self.active_file_id != null) return error.FileAlreadyActive;
        const id = self.next_file_id;
        self.next_file_id +%= 1;
        // The claim precedes the publisher, since a strategy reset can re-enter this session
        self.active_file_id = id;
        errdefer self.active_file_id = null;
        self.packing.writer.destination = .{ .context = self, .put_fn = putData };
        self.global.beginFile();
        errdefer self.global.rollback();
        self.packing.writer.new_xorb_listener = .{
            .context = &self.global,
            .callback = GlobalDedup.addXorb,
        };
        var opts = storage.PublisherOptions.fromPack(self.opts);
        opts.io = self.client.http_client.io;
        opts.dedup_source = self.global.source();
        const publisher = try self.packing.begin(opts, null);
        return .{ .session = self, .publisher = publisher, .id = id };
    }

    /// Append one file in input order. Only finish() publishes the combined shard.
    pub fn addFile(self: *UploadSession, source: *std.Io.Reader) !void {
        var file = try self.beginFile();
        defer file.deinit();
        // Fixed and buffered readers lend their initial data without a copy.
        const buffered = source.buffered();
        if (buffered.len != 0) {
            try file.write(buffered);
            source.toss(buffered.len);
        }
        var first: [128 * 1024]u8 = undefined;
        const n = try source.readSliceShort(&first);
        if (n != 0) try file.write(first[0..n]);
        if (n == first.len) {
            const buffer = try self.allocator.alloc(u8, constants.target_xorb_size);
            defer self.allocator.free(buffer);
            while (true) {
                const count = try source.readSliceShort(buffer);
                if (count != 0) try file.write(buffer[0..count]);
                if (count != buffer.len) break;
            }
        }
        _ = try file.finish();
    }

    pub fn finish(self: *UploadSession) !void {
        if (self.finished) return error.AlreadyFinished;
        if (self.packing.writer.lost) return error.OperationFailed;
        if (self.active_file_id != null) return error.FileAlreadyActive;
        self.finished = true;
        const owned = try self.results_list.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned);
        try self.packing.seal();
        if (self.pending) |*pending| try pending.finish();
        try self.packing.publish();
        self.published = owned;
    }

    /// Results remain owned by the session and follow file finalization order
    pub fn results(self: *const UploadSession) []const storage.PublishResult {
        return self.published;
    }
};

const GlobalDedup = struct {
    const max_missed_remote = 16 * 1024;

    client: *Client,
    io: std.Io,
    index: dedup.SessionIndex,
    missed_remote: std.AutoHashMapUnmanaged(hashing.Hash, void) = .empty,
    point: ?dedup.SessionIndex.Checkpoint = null,
    first_query: bool = true,

    fn deinit(self: *GlobalDedup) void {
        self.rollback();
        self.missed_remote.deinit(self.index.allocator);
        self.index.deinit();
    }

    fn beginFile(self: *GlobalDedup) void {
        std.debug.assert(self.point == null);
        self.point = self.index.checkpoint();
        self.first_query = true;
    }

    fn commit(self: *GlobalDedup) void {
        if (self.point) |*point| point.deinit(self.index.allocator);
        self.point = null;
    }

    fn rollback(self: *GlobalDedup) void {
        self.index.rollback(&self.point);
    }

    fn source(self: *GlobalDedup) storage.DedupSource {
        return .{ .context = self, .query_fn = query };
    }

    fn addXorb(raw: *anyopaque, item: shard.Xorb) !void {
        const self: *GlobalDedup = @ptrCast(@alignCast(raw));
        try self.index.addXorb(item);
    }

    fn query(
        raw: *anyopaque,
        allocator: std.mem.Allocator,
        hashes: []const hashing.Hash,
    ) !?dedup.Match {
        const self: *GlobalDedup = @ptrCast(@alignCast(raw));
        const allow_remote = self.first_query or dedup.eligible(hashes[0]);
        self.first_query = false;
        const local = self.index.source();
        if (try local.query(allocator, hashes)) |match| return match;
        if (!allow_remote) return null;
        const bytes = self.fetch(allocator, hashes[0]) catch |err| switch (err) {
            // An aborted request must fail the upload rather than become a cache miss
            error.OutOfMemory, error.Canceled => return err,
            else => null,
        };
        const owned = bytes orelse return null;
        {
            const now = std.Io.Clock.real.now(self.io).nanoseconds;
            const seconds = @divFloor(now, std.time.ns_per_s);
            const added = self.index.addGlobalOwned(
                owned,
                @intCast(seconds),
            ) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => false,
            };
            if (!added) return null;
        }
        return local.query(allocator, hashes) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => null,
        };
    }

    fn fetch(self: *GlobalDedup, allocator: std.mem.Allocator, hash: hashing.Hash) !?[]u8 {
        if (self.missed_remote.contains(hash)) return null;
        const hex = hashing.toHex(hash);
        const target = try self.client.url("/v1/chunks/default-merkledb/{s}", .{hex});
        defer self.client.allocator.free(target);
        var req = try self.client.request(.GET, target, null, true, null, true);
        defer req.deinit();
        var response = req.receiveHead(&.{}) catch |err| return readFailure(&req, err);
        if (response.head.status == .not_found) {
            if (self.missed_remote.count() < max_missed_remote)
                try self.missed_remote.put(self.index.allocator, hash, {});
            return null;
        }
        if (response.head.status != .ok) return statusError(response.head.status);
        return try Client.readResponse(allocator, &response, 80 * 1024 * 1024);
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
        _ = reader.streamDelimiterLimit(
            &line.writer,
            '\n',
            .limited(max_line_size + 1),
        ) catch |err| switch (err) {
            error.ReadFailed => return bodyFailure(response, error.InvalidResponse),
            error.WriteFailed => return error.OutOfMemory,
            error.StreamTooLong => return error.ResponseTooLarge,
        };
        const eof = if (reader.takeByte()) |byte|
            byte != '\n'
        else |err| switch (err) {
            error.EndOfStream => true,
            error.ReadFailed => return bodyFailure(response, error.InvalidResponse),
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

fn rangeLength(range: recon.ByteRange) !u64 {
    return stream.rangeLength(range) catch error.InvalidResponse;
}

fn contentRange(response: *const std.http.Client.Response) !?recon.ByteRange {
    var result: ?recon.ByteRange = null;
    var headers = response.head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "Content-Range")) continue;
        if (result != null) return error.InvalidResponse;
        const value = std.mem.trim(u8, header.value, " \t");
        const space = std.mem.indexOfScalar(u8, value, ' ') orelse return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(value[0..space], "bytes")) return error.InvalidResponse;
        const specification = std.mem.trim(u8, value[space + 1 ..], " \t");
        const slash = std.mem.indexOfScalar(
            u8,
            specification,
            '/',
        ) orelse return error.InvalidResponse;
        if (slash + 1 == specification.len) return error.InvalidResponse;
        const interval = std.mem.trim(u8, specification[0..slash], " \t");
        const dash = std.mem.indexOfScalar(u8, interval, '-') orelse return error.InvalidResponse;
        const start = std.fmt.parseUnsigned(
            u64,
            interval[0..dash],
            10,
        ) catch return error.InvalidResponse;
        const end = std.fmt.parseUnsigned(
            u64,
            interval[dash + 1 ..],
            10,
        ) catch return error.InvalidResponse;
        result = .{ .start = start, .end = end };
    }
    return result;
}

fn responsePrefix(
    response: *const std.http.Client.Response,
    range: ?recon.ByteRange,
    verify_file: bool,
) !struct { skip: u64, remaining: u64 } {
    if (response.head.content_encoding != .identity) return error.InvalidResponse;
    const requested = range orelse {
        if (response.head.status != .ok) return statusError(response.head.status);
        return .{ .skip = 0, .remaining = std.math.maxInt(u64) };
    };
    return .{
        .remaining = try rangeLength(requested),
        .skip = switch (response.head.status) {
            // Some CAS V1 servers return the requested slice with status 200.
            // An exact-length body is accepted here only for a checked file ID.
            .ok => if (verify_file and response.head.content_length == try rangeLength(
                requested,
            )) 0 else requested.start,
            .partial_content => skip: {
                if (try contentRange(response)) |actual| {
                    if (actual.start != requested.start or actual.end != requested.end) return error.InvalidResponse;
                } else {
                    // The upstream local CAS omits Content-Range on V2. An exact-length
                    // response is sufficient only when the final file ID is checked.
                    const len = response.head.content_length orelse return error.InvalidResponse;
                    if (!verify_file or len != try rangeLength(
                        requested,
                    )) return error.InvalidResponse;
                }
                break :skip 0;
            },
            else => return statusError(response.head.status),
        },
    };
}

const ResponseStream = struct {
    allocator: std.mem.Allocator,
    request: std.http.Client.Request,
    response: std.http.Client.Response,
    limited: std.Io.Reader.Limited,
    transfer_buffer: [16 * 1024]u8,
    range_buffer: [16 * 1024]u8,
    large_buffer: []u8,

    fn open(client: *Client, item: stream.Request, verify_file: bool) !*std.Io.Reader {
        const self = try client.allocator.create(ResponseStream);
        errdefer client.allocator.destroy(self);
        self.allocator = client.allocator;
        self.request = try client.request(.GET, item.url, null, false, item.byte_range, true);
        errdefer self.request.deinit();
        self.response = self.request.receiveHead(&.{}) catch |err| return readFailure(
            &self.request,
            err,
        );
        const prefix = try responsePrefix(&self.response, item.byte_range, verify_file);
        const body = self.response.reader(&self.transfer_buffer);
        body.discardAll64(prefix.skip) catch |err| return self.responseError(err);
        self.large_buffer = if (prefix.remaining >= 4 * 1024 * 1024)
            try self.allocator.alloc(u8, 256 * 1024)
        else
            &.{};
        const buffer = if (self.large_buffer.len == 0) &self.range_buffer else self.large_buffer;
        self.limited = .init(body, .limited64(prefix.remaining), buffer);
        return &self.limited.interface;
    }

    fn responseError(self: *ResponseStream, err: std.Io.Reader.Error) anyerror {
        return switch (err) {
            error.EndOfStream => error.InvalidResponse,
            error.ReadFailed => self.bodyError(),
        };
    }

    fn readError(reader: *std.Io.Reader) ?anyerror {
        const limited: *std.Io.Reader.Limited = @fieldParentPtr("interface", reader);
        const self: *ResponseStream = @fieldParentPtr("limited", limited);
        return self.bodyError();
    }

    fn bodyError(self: *ResponseStream) anyerror {
        return bodyFailure(&self.response, error.ReadFailed);
    }

    fn close(reader: *std.Io.Reader) void {
        const limited: *std.Io.Reader.Limited = @fieldParentPtr("interface", reader);
        const self: *ResponseStream = @fieldParentPtr("limited", limited);
        self.allocator.free(self.large_buffer);
        self.request.deinit();
        self.allocator.destroy(self);
    }
};

fn bodyFailure(response: *const std.http.Client.Response, fallback: anyerror) anyerror {
    return readFailure(response.request, response.bodyErr() orelse fallback);
}

/// A reader reports `ReadFailed`, so recover the error it stands for
fn readFailure(request: *std.http.Client.Request, fallback: anyerror) anyerror {
    const connection = request.connection orelse return fallback;
    // A cancel request is delivered only once, so later reads would succeed
    return connection.stream_reader.err orelse fallback;
}

/// A failed write leaves a truncated request, so the connection must not be reused
fn writeFailure(request: *std.http.Client.Request, fallback: anyerror) anyerror {
    const connection = request.connection orelse return fallback;
    connection.closing = true;
    return connection.stream_writer.err orelse fallback;
}

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

fn parseRange(parent: std.json.ObjectMap, name: []const u8) !recon.Range {
    const value = try object(try field(parent, name));
    const result = recon.Range{
        .start = try integer(u32, value, "start"),
        .end = try integer(u32, value, "end"),
    };
    if (result.start >= result.end) return error.InvalidResponse;
    return result;
}

fn parseByteRange(value: std.json.Value) !recon.ByteRange {
    const parent = try object(value);
    const result = recon.ByteRange{
        .start = try integer(u64, parent, "start"),
        .end = try integer(u64, parent, "end"),
    };
    if (result.start > result.end) return error.InvalidResponse;
    return result;
}

fn parseTerms(allocator: std.mem.Allocator, terms: std.json.Array) ![]recon.Term {
    const result = try allocator.alloc(recon.Term, terms.items.len);
    errdefer allocator.free(result);
    for (terms.items, result) |value, *term| {
        const item = try object(value);
        term.* = .{
            .hash = hashing.fromHex(try string(item, "hash")) catch return error.InvalidResponse,
            .unpacked_length = try integer(u32, item, "unpacked_length"),
            .range = try parseRange(item, "range"),
        };
    }
    return result;
}

fn parseLocations(
    allocator: std.mem.Allocator,
    fetches: std.json.ObjectMap,
    version: u8,
) ![]recon.Location {
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
    const locations = try allocator.alloc(recon.Location, count);
    for (locations) |*location| location.url = "";
    errdefer {
        for (locations) |location| allocator.free(location.url);
        allocator.free(locations);
    }
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
                    locations[index] = .{
                        .hash = hash,
                        .range = try parseRange(descriptor, "chunks"),
                        .byte_range = try parseByteRange(try field(descriptor, "bytes")),
                        .url = try allocator.dupe(u8, url),
                    };
                    index += 1;
                }
            } else {
                locations[index] = .{
                    .hash = hash,
                    .range = try parseRange(item, "range"),
                    .byte_range = try parseByteRange(try field(item, "url_range")),
                    .url = try allocator.dupe(u8, try string(item, "url")),
                };
                index += 1;
            }
        }
    }
    return locations;
}

fn parsePlan(
    allocator: std.mem.Allocator,
    body: []const u8,
    range: ?recon.ByteRange,
    version: u8,
) !recon.Plan {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const root = try object(parsed.value);
    const terms = try array(try field(root, "terms"));
    var plan = recon.Plan{ .terms = &.{}, .locations = &.{} };
    errdefer plan.deinit(allocator);
    plan.terms = try parseTerms(allocator, terms);

    const fetches = try object(try field(root, if (version == 2) "xorbs" else "fetch_info"));
    plan.locations = try parseLocations(allocator, fetches, version);

    if (root.get("offset_into_first_range") != null)
        plan.offset_into_first_range = try integer(u64, root, "offset_into_first_range");
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
        range: recon.Range,
    }{.{
        .hash = hash,
        .unpacked_length = 3,
        .range = .{ .start = 0, .end = 1 },
    }};
    const locations = [_]struct {
        range: recon.Range,
        url: []const u8,
        url_range: recon.ByteRange,
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

    try std.testing.expectError(error.MissingLocation, parsePlan(
        allocator,
        out.written(),
        null,
        1,
    ));
}

const empty_plan_json =
    \\{"terms":[],"fetch_info":{}}
;

fn checkCasEndpoints(allocator: std.mem.Allocator, io: std.Io, suffix: []const u8) !void {
    const support = @import("test_support");
    const responses = [_]support.HttpResponse{
        .{},
        .{ .status = .not_found },
        .{},
        .{ .status = .not_found },
        .{ .body = empty_plan_json },
    };
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
    try server.finish();
    try std.testing.expectEqual(@as(usize, 5), server.exchanges.items.len);
    try std.testing.expectEqualStrings(get_path, server.exchanges.items[4].target);
    try std.testing.expectEqualStrings(xorb_path, server.exchanges.items[0].target);
    try std.testing.expectEqualStrings("/v2/shards", server.exchanges.items[1].target);
    try std.testing.expectEqualStrings("/v1/shards", server.exchanges.items[2].target);
    for (server.exchanges.items) |exchange| {
        try std.testing.expect(std.mem.indexOf(u8, exchange.target, "/v1/v1/") == null);
    }
}

test "shard validation streams oversized frames and accepts the result" {
    const support = @import("test_support");
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
    try server.finish();
    try std.testing.expectEqual(@as(usize, 1), server.exchanges.items.len);
}

test "CAS endpoints add v1 to a bare loopback origin" {
    try checkCasEndpoints(std.testing.allocator, std.testing.io, "");
}

test "CAS endpoints preserve exactly one v1 for a versioned origin" {
    try checkCasEndpoints(std.testing.allocator, std.testing.io, "/v1");
}

test "parse a CAS recon plan strictly" {
    const allocator = std.testing.allocator;
    const hash = "cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6";
    const terms = [_]struct {
        hash: []const u8,
        unpacked_length: u32,
        range: recon.Range,
    }{.{
        .hash = hash,
        .unpacked_length = 9,
        .range = .{ .start = 1, .end = 3 },
    }};
    const locations = [_]struct {
        range: recon.Range,
        url: []const u8,
        url_range: recon.ByteRange,
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

test "recon ranges reject inclusive length overflow" {
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

test "GlobalDedup caches remote misses but retries errors for the same hash" {
    const support = @import("test_support");
    const allocator = std.testing.allocator;
    const responses = [_]support.HttpResponse{
        .{ .status = .not_found },
        .{ .status = .internal_server_error },
        .{ .status = .internal_server_error },
    };
    var server = try support.Loopback.init(allocator, std.testing.io, &responses);
    defer server.deinit();
    try server.start();
    var client = try Client.init(allocator, std.testing.io, server.origin, "");
    defer client.deinit();
    var global = GlobalDedup{
        .client = &client,
        .io = std.testing.io,
        .index = .init(allocator),
    };
    defer global.deinit();

    const missed_hash = hashing.data("missed");
    const failed_hash = hashing.data("failed");
    try std.testing.expect((try global.fetch(allocator, missed_hash)) == null);
    try std.testing.expect(global.missed_remote.contains(missed_hash));
    try std.testing.expect((try global.fetch(allocator, missed_hash)) == null);
    try std.testing.expectError(error.ServerError, global.fetch(allocator, failed_hash));
    try std.testing.expect(!global.missed_remote.contains(failed_hash));
    try std.testing.expectError(error.ServerError, global.fetch(allocator, failed_hash));
    try server.finish();
    try std.testing.expectEqual(@as(usize, 3), server.exchanges.items.len);
}

test "CAS recon plan rejects missing fields" {
    try std.testing.expectError(error.InvalidResponse, parsePlan(
        std.testing.allocator,
        "{}",
        null,
        1,
    ));
}

test "CAS recon plan rejects malformed JSON" {
    try std.testing.expectError(error.SyntaxError, parsePlan(
        std.testing.allocator,
        "not json",
        null,
        1,
    ));
}
