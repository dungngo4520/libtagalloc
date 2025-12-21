const std = @import("std");

pub const MapEntry = struct {
    start: usize,
    end: usize,
    perms: [4]u8,
    offset: usize,
    path: ?[]u8,
};

pub fn readMaps(_: std.mem.Allocator, _: i32) ![]MapEntry {
    return error.Unsupported;
}

pub fn processRead(_: i32, _: usize, _: []u8) !void {
    return error.Unsupported;
}

pub fn findRegistryAddr(_: std.mem.Allocator, _: i32, _: []const MapEntry) !usize {
    return error.RegistryNotFound;
}
