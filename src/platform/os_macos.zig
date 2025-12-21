const std = @import("std");
const builtin = @import("builtin");

pub fn pageSize() usize {
    return std.heap.pageSize();
}

pub fn osMmap(len: usize) ![*]u8 {
    if (builtin.os.tag != .macos) return error.Unsupported;

    const posix = std.posix;
    const prot: u32 = posix.PROT.READ | posix.PROT.WRITE;
    const flags: posix.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };

    const mem = try posix.mmap(null, len, prot, flags, -1, 0);
    return @as([*]u8, @ptrCast(mem.ptr));
}

pub fn osMunmap(ptr: [*]u8, len: usize) void {
    if (builtin.os.tag != .macos) return;

    const posix = std.posix;
    const aligned_ptr: [*]align(std.heap.page_size_min) const u8 = @ptrCast(@alignCast(ptr));
    const slice: []align(std.heap.page_size_min) const u8 = aligned_ptr[0..len];
    posix.munmap(slice);
}
