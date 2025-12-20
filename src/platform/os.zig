const std = @import("std");
const builtin = @import("builtin");

const Linux = @import("os_linux.zig");

const Unsupported = struct {
    pub fn pageSize() usize {
        return std.heap.pageSize();
    }

    pub fn osMmap(_: usize) ![*]u8 {
        return error.Unsupported;
    }

    pub fn osMunmap(_: [*]u8, _: usize) void {}
};

const Impl = switch (builtin.os.tag) {
    .linux => Linux,
    else => Unsupported,
};

pub fn pageSize() usize {
    return Impl.pageSize();
}

pub fn osMmap(len: usize) ![*]u8 {
    return Impl.osMmap(len);
}

pub fn osMunmap(ptr: [*]u8, len: usize) void {
    return Impl.osMunmap(ptr, len);
}
