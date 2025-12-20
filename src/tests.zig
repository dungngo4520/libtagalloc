const std = @import("std");

const tagalloc = @import("libtagalloc.zig");

test "size==0 returns null via C ABI" {
    try std.testing.expect(tagalloc.tagalloc_alloc(0x41414141, 0) == null);
}

test "realloc preserves prefix and handles null" {
    const tag: u32 = 0x44434241; // "ABCD"

    // NULL -> alloc
    const p0 = tagalloc.tagalloc_realloc(tag, null, 16) orelse return error.TestUnexpectedResult;
    defer tagalloc.tagalloc_free(p0);

    const p = tagalloc.tagalloc_alloc(tag, 16) orelse return error.TestUnexpectedResult;

    const buf16: [*]u8 = @ptrCast(p);
    @memset(buf16[0..16], 0xA5);

    const p2 = tagalloc.tagalloc_realloc(tag, p, 64) orelse return error.TestUnexpectedResult;
    defer tagalloc.tagalloc_free(p2);

    const buf64: [*]u8 = @ptrCast(p2);
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(@as(u8, 0xA5), buf64[i]);
    }
}

test {
    // Pull in module-local tests.
    _ = @import("core/allocator.zig");
    _ = @import("core/registry.zig");
    _ = @import("core/slab.zig");
}
