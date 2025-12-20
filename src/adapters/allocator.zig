const std = @import("std");

const core_allocator = @import("../core/allocator.zig");

pub const TaggedAllocator = struct {
    tag: u32,

    pub fn init(tag: u32) TaggedAllocator {
        return .{ .tag = tag };
    }

    pub fn allocator(self: *TaggedAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn vtableAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        const self: *TaggedAllocator = @ptrCast(@alignCast(ctx));

        if (len == 0) {
            const a = alignment.toByteUnits();
            const aligned = std.mem.alignBackward(usize, std.math.maxInt(usize), a);
            return @ptrFromInt(aligned);
        }

        const a = alignment.toByteUnits();
        const p = core_allocator.alignedAlloc(self.tag, len, a) catch return null;
        return p;
    }

    fn vtableResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        // We don't support in-place resizing yet.
        return false;
    }

    fn vtableRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *TaggedAllocator = @ptrCast(@alignCast(ctx));

        if (memory.len == 0) return vtableAlloc(ctx, new_len, alignment, ret_addr);
        if (new_len == 0) return null;

        const p = core_allocator.realloc(self.tag, memory.ptr, new_len) catch return null;
        return p;
    }

    fn vtableFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        _ = ctx;
        _ = alignment;
        _ = ret_addr;
        if (memory.len == 0) return;
        core_allocator.free(memory.ptr);
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = vtableAlloc,
        .resize = vtableResize,
        .remap = vtableRemap,
        .free = vtableFree,
    };
};

test "TaggedAllocator works with ArrayList" {
    var ta = TaggedAllocator.init(0x4C4C4154); // "TALL" in little-endian display
    const a = ta.allocator();
    var al = std.ArrayList(u8).empty;
    defer al.deinit(a);

    try al.appendSlice(a, "hello");
    try std.testing.expectEqualStrings("hello", al.items);

    // Force a growth.
    var i: usize = 0;
    while (i < 1024) : (i += 1) {
        try al.append(a, @truncate(i));
    }

    try std.testing.expect(al.items.len == 5 + 1024);
}
