const std = @import("std");
const builtin = @import("builtin");

pub fn pageSize() usize {
    return std.heap.pageSize();
}

pub fn osMmap(len: usize) ![*]u8 {
    if (builtin.os.tag != .windows) return error.Unsupported;

    const windows = std.os.windows;

    const MEM_COMMIT: windows.DWORD = 0x1000;
    const MEM_RESERVE: windows.DWORD = 0x2000;
    const PAGE_READWRITE: windows.DWORD = 0x04;

    const p = try windows.VirtualAlloc(null, len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    return @as([*]u8, @ptrCast(p));
}

pub fn osMunmap(ptr: [*]u8, len: usize) void {
    if (builtin.os.tag != .windows) return;

    const windows = std.os.windows;
    const MEM_RELEASE: windows.DWORD = 0x8000;

    _ = len;
    windows.VirtualFree(@ptrCast(ptr), 0, MEM_RELEASE);
}
