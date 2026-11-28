# xet.zig

A standalone Zig library for Xet CAS. It uses the standard library for
I/O, HTTP, threading and cryptography. It reads and writes Xet file IDs,
Xorbs and MDB shards. The library takes an authenticated CAS endpoint
supplied by the application. It has no Hub or filesystem policy.

## Stream a file

```zig
const std = @import("std");
const xet = @import("xet");

pub fn roundTrip(
    gpa: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    token: []const u8,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
) !xet.Hash {
    var client = try xet.Client.init(gpa, io, endpoint, token);
    defer client.deinit();

    const file = try client.upload(input, .{});
    _ = try client.download(file.file_hash, output, .{});
    try output.flush();
    return file.file_hash;
}
```
