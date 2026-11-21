//! Transport-independent Xet storage using only Zig's standard library.
//! `http` is an optional standard-CAS adapter, not a Hub client.

pub const Hash = @import("hash.zig").Hash;
pub const Node = @import("hash.zig").Node;
pub const hash = @import("hash.zig");
pub const Chunk = @import("chunker.zig").Chunk;
pub const Chunker = @import("chunker.zig").Chunker;
pub const chunkBuffer = @import("chunker.zig").chunkBuffer;
pub const lz4 = @import("lz4.zig");
pub const stream = @import("stream.zig");
pub const concurrent = @import("concurrent.zig");
pub const xorb = @import("xorb.zig");
pub const shard = @import("shard.zig");
pub const store = @import("store.zig");
pub const Store = store.Store;
pub const StorePublisher = @import("store.zig").Publisher;
pub const ObjectKind = @import("store.zig").ObjectKind;
pub const Package = @import("store.zig").Package;
pub const PackOptions = @import("store.zig").PackOptions;
pub const pack = @import("store.zig").pack;
pub const publish = @import("store.zig").publish;
pub const reconstruction = @import("reconstruction.zig");
pub const http = @import("http.zig");

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
