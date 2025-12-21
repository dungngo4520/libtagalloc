const std = @import("std");

pub fn pageSize() usize {
    return std.heap.pageSize();
}

pub fn osMmap(_: usize) ![*]u8 {
    return error.Unsupported;
}

pub fn osMunmap(_: [*]u8, _: usize) void {}
