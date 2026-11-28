//! White-box imports for the package tests.

pub const Client = @import("http.zig").Client;
pub const Hash = hash.Hash;
pub const hash = @import("hash.zig");
pub const chunker = @import("chunker.zig");
pub const xorb = @import("xorb.zig");
pub const shard = @import("shard.zig");
pub const store = @import("store.zig");
pub const dedup = @import("dedup.zig");
pub const upload = @import("upload.zig");
pub const recon = @import("recon.zig");
pub const stream = @import("stream.zig");
pub const concurrent = @import("concurrent.zig");
pub const delta = @import("delta.zig");
pub const lz4 = @import("lz4.zig");

test {
    _ = @import("shard_cache.zig");
    @import("std").testing.refAllDecls(@import("root.zig"));
    @import("std").testing.refAllDecls(@This());
}
