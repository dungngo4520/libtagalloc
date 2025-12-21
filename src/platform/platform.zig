const std = @import("std");
const builtin = @import("builtin");

const Linux = @import("linux.zig");
const Windows = @import("windows.zig");
const Macos = @import("macos.zig");
const Unsupported = @import("unsupported.zig");

const Impl = switch (builtin.os.tag) {
    .linux => Linux,
    .windows => Windows,
    .macos => Macos,
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
