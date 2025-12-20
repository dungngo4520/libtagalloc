comptime {
    // Import-only test root (no testcases here).
    // This pulls in module-local `test "..." {}` blocks for `zig build test`.
    _ = @import("libtagalloc.zig");
    _ = @import("core/allocator.zig");
    _ = @import("core/registry.zig");
    _ = @import("core/slab.zig");
    _ = @import("adapters/allocator.zig");
}
