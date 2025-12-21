const std = @import("std");

const tagalloc = @import("tagalloc");

pub fn main() !void {
    const tag: u32 = 0x44434241; // "ABCD" in little-endian display order

    const p = tagalloc.tagalloc_alloc(tag, 64) orelse return error.OutOfMemory;
    defer tagalloc.tagalloc_free(p);

    const buf: [*]u8 = @ptrCast(p);
    @memset(buf[0..64], 0xAA);

    try std.fs.File.stdout().writeAll("ok\n");
}
