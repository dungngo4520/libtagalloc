const std = @import("std");

const tagalloc = @import("libtagalloc.zig");

test "size==0 returns null via C ABI" {
    try std.testing.expect(tagalloc.tagalloc_alloc(0x41414141, 0) == null);
}

test {
    // Pull in module-local tests.
    _ = @import("core/allocator.zig");
    _ = @import("core/registry.zig");
}
