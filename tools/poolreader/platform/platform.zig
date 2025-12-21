const builtin = @import("builtin");

const Impl = switch (builtin.os.tag) {
    .linux => @import("linux.zig"),
    .windows => @import("windows.zig"),
    .macos => @import("macos.zig"),
    else => @import("unsupported.zig"),
};

pub const MapEntry = Impl.MapEntry;

pub const readMaps = Impl.readMaps;
pub const processRead = Impl.processRead;
pub const findRegistryAddr = Impl.findRegistryAddr;
