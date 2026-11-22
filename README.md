# xet.zig

A Zig implementation of the Xet content-addressed storage protocol.

## Example

```zig
const std = @import("std");
const xet = @import("xet");

pub fn roundTrip(
    allocator: std.mem.Allocator,
    io: std.Io,
    cas_url: []const u8,
    cas_token: []const u8,
) !void {
    var cas = try xet.http.Client.init(allocator, io, cas_url, cas_token);
    defer cas.deinit();

    const uploaded = try cas.upload(allocator, "Hello, Xet!", .{});

    // Downloads the complete file, verifies it, and returns caller-owned bytes
    const downloaded = try cas.download(allocator, uploaded.file_hash);
    defer allocator.free(downloaded);
}
```
