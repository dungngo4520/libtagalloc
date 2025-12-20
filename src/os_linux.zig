const std = @import("std");
const builtin = @import("builtin");

pub fn pageSize() usize {
    return std.heap.pageSize();
}

pub fn osMmap(len: usize) ![*]u8 {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const linux = std.os.linux;
    const prot: usize = linux.PROT.READ | linux.PROT.WRITE;
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };

    const addr = linux.mmap(null, len, prot, flags, -1, 0);
    const err = linux.E.init(addr);
    if (err != .SUCCESS) return switch (err) {
        .NOMEM => error.OutOfMemory,
        else => error.OutOfMemory,
    };

    return @as([*]u8, @ptrFromInt(addr));
}

pub fn osMunmap(ptr: [*]u8, len: usize) void {
    if (builtin.os.tag != .linux) return;

    const linux = std.os.linux;
    _ = linux.munmap(ptr, len);
}
