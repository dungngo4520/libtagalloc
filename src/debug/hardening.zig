const std = @import("std");
const builtin = @import("builtin");

pub fn enabled() bool {
    return builtin.mode == .Debug;
}

pub fn tailBytes() usize {
    // One u64 tail canary.
    return if (enabled()) @sizeOf(u64) else 0;
}

const TAIL_CANARY: u64 = 0xC0FFEE00_D15EA5E5;

pub fn writeTailCanary(user_ptr: [*]u8, user_size: usize) void {
    if (!enabled()) return;
    const tail_ptr: [*]u8 = user_ptr + user_size;
    const tail: *[8]u8 = @ptrCast(tail_ptr);
    std.mem.writeInt(u64, tail, TAIL_CANARY, .little);
}

pub fn checkTailCanary(user_ptr: [*]u8, user_size: usize) bool {
    if (!enabled()) return true;
    const tail_ptr: [*]u8 = user_ptr + user_size;
    const tail: *const [8]u8 = @ptrCast(tail_ptr);
    return std.mem.readInt(u64, tail, .little) == TAIL_CANARY;
}

pub fn poisonAlloc(user_ptr: [*]u8, user_size: usize) void {
    if (!enabled()) return;
    @memset(user_ptr[0..user_size], 0xAA);
}

pub fn poisonFree(user_ptr: [*]u8, user_size: usize) void {
    if (!enabled()) return;
    @memset(user_ptr[0..user_size], 0xDD);
}

pub fn hardPanic(comptime msg: []const u8) noreturn {
    @panic(msg);
}
