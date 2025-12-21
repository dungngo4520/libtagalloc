const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");
const platform = @import("platform.zig");

pub const ENTRY_USED: u32 = 1;

pub const MapEntry = platform.MapEntry;

pub fn freeMaps(allocator: std.mem.Allocator, maps: []MapEntry) void {
    for (maps) |m| {
        if (m.path) |p| allocator.free(p);
    }
    allocator.free(maps);
}

pub fn readMaps(allocator: std.mem.Allocator, pid: i32) ![]MapEntry {
    return platform.readMaps(allocator, pid);
}

pub fn findRegistryAddr(allocator: std.mem.Allocator, pid: i32, maps: []const MapEntry) !usize {
    return platform.findRegistryAddr(allocator, pid, maps);
}

pub fn readRegistryStable(pid: i32, addr: usize) !abi.RegistryV1 {
    var attempt: usize = 0;
    while (attempt < 8) : (attempt += 1) {
        const seq1 = try readRemoteU64(pid, addr + @offsetOf(abi.RegistryV1, "publish_seq"));
        if ((seq1 & 1) == 1) continue;

        const reg = try readRemoteType(pid, addr, abi.RegistryV1);

        const seq2 = try readRemoteU64(pid, addr + @offsetOf(abi.RegistryV1, "publish_seq"));
        if (seq1 == seq2 and (seq2 & 1) == 0) return reg;
    }
    return error.UnstableRegistry;
}

pub fn validateRegistryHeader(reg: abi.RegistryV1) !void {
    if (reg.magic != abi.TAGALLOC_REGISTRY_MAGIC) return error.BadMagic;
    if (reg.abi_version != abi.TAGALLOC_ABI_VERSION) return error.BadAbiVersion;
    if (reg.header_size < @sizeOf(abi.RegistryV1)) return error.BadHeaderSize;
    if (reg.ptr_size != @sizeOf(usize)) return error.BadPtrSize;
    if (reg.endianness != 1) return error.BadEndianness;
}

pub fn validateAggSegmentHeader(seg: abi.AggSegmentV1) !void {
    const entry_stride: usize = @intCast(seg.entry_stride);
    const entry_count: usize = @intCast(seg.entry_count);

    if (entry_count == 0) return error.BadEntryCount;
    if (entry_stride < @sizeOf(abi.AggEntryV1)) return error.BadEntryStride;

    const bytes_needed = try std.math.mul(usize, entry_stride, entry_count);
    const expected_min = @sizeOf(abi.AggSegmentV1) + bytes_needed;
    if (seg.segment_size < expected_min) return error.BadSegmentSize;
}

pub const TagStats = struct {
    tag: u32,
    alloc_count: u64,
    alloc_bytes: u64,
    free_count: u64,
    free_bytes: u64,
};

pub fn readTagStats(pid: i32, first_segment: usize, tag: u32) !?TagStats {
    var seg_addr: usize = first_segment;

    while (seg_addr != 0) {
        const seg = try readRemoteType(pid, seg_addr, abi.AggSegmentV1);

        try validateAggSegmentHeader(seg);

        const entry_stride: usize = @intCast(seg.entry_stride);
        const entry_count: usize = @intCast(seg.entry_count);

        const bytes_needed = try std.math.mul(usize, entry_stride, entry_count);

        var entries = try std.heap.page_allocator.alloc(u8, bytes_needed);
        defer std.heap.page_allocator.free(entries);

        const entries_addr = seg_addr + @sizeOf(abi.AggSegmentV1);
        try processVmRead(pid, entries_addr, entries);

        var i: usize = 0;
        while (i < entry_count) : (i += 1) {
            const off = i * entry_stride;
            const view = entries[off .. off + @sizeOf(abi.AggEntryV1)];
            const entry_ptr = std.mem.bytesAsValue(abi.AggEntryV1, view);
            const entry = entry_ptr.*;

            if (entry.reserved0 != ENTRY_USED) continue;
            if (entry.tag != tag) continue;

            return .{
                .tag = entry.tag,
                .alloc_count = entry.alloc_count,
                .alloc_bytes = entry.alloc_bytes,
                .free_count = entry.free_count,
                .free_bytes = entry.free_bytes,
            };
        }

        seg_addr = seg.next_segment;
    }

    return null;
}

test "poolreader registry header validation rejects wrong magic/version" {
    var reg: abi.RegistryV1 = .{
        .magic = abi.TAGALLOC_REGISTRY_MAGIC,
        .abi_version = abi.TAGALLOC_ABI_VERSION,
        .header_size = @intCast(@sizeOf(abi.RegistryV1)),
        .ptr_size = @intCast(@sizeOf(usize)),
        .endianness = 1,
        .reserved0 = 0,
        .publish_seq = 0,
        .flags = 0,
        .first_segment = 0,
        .overflow_tag = 0,
        .reserved1 = 0,
        .tag_mismatch_count = 0,
        .dropped_tag_count = 0,
    };

    try validateRegistryHeader(reg);

    reg.magic ^= 1;
    try std.testing.expectError(error.BadMagic, validateRegistryHeader(reg));
    reg.magic = abi.TAGALLOC_REGISTRY_MAGIC;

    reg.abi_version += 1;
    try std.testing.expectError(error.BadAbiVersion, validateRegistryHeader(reg));
}

test "poolreader registry header validation rejects bad sizes/endianness" {
    var reg: abi.RegistryV1 = .{
        .magic = abi.TAGALLOC_REGISTRY_MAGIC,
        .abi_version = abi.TAGALLOC_ABI_VERSION,
        .header_size = @intCast(@sizeOf(abi.RegistryV1)),
        .ptr_size = @intCast(@sizeOf(usize)),
        .endianness = 1,
        .reserved0 = 0,
        .publish_seq = 0,
        .flags = 0,
        .first_segment = 0,
        .overflow_tag = 0,
        .reserved1 = 0,
        .tag_mismatch_count = 0,
        .dropped_tag_count = 0,
    };

    reg.header_size = 0;
    try std.testing.expectError(error.BadHeaderSize, validateRegistryHeader(reg));
    reg.header_size = @intCast(@sizeOf(abi.RegistryV1));

    reg.ptr_size = 0;
    try std.testing.expectError(error.BadPtrSize, validateRegistryHeader(reg));
    reg.ptr_size = @intCast(@sizeOf(usize));

    reg.endianness = 2;
    try std.testing.expectError(error.BadEndianness, validateRegistryHeader(reg));
}

test "poolreader segment header validation rejects bad stride/size" {
    const entry_size: usize = @sizeOf(abi.AggEntryV1);

    var seg: abi.AggSegmentV1 = .{
        .segment_size = 0,
        .entry_stride = @intCast(entry_size),
        .entry_count = 1,
        .next_segment = 0,
        .reserved0 = 0,
    };

    // Too small for header + one entry.
    seg.segment_size = @intCast(@sizeOf(abi.AggSegmentV1));
    try std.testing.expectError(error.BadSegmentSize, validateAggSegmentHeader(seg));

    // Stride too small.
    seg.segment_size = @intCast(@sizeOf(abi.AggSegmentV1) + entry_size);
    seg.entry_stride = @intCast(entry_size - 1);
    try std.testing.expectError(error.BadEntryStride, validateAggSegmentHeader(seg));

    // Entry count must be non-zero.
    seg.entry_stride = @intCast(entry_size);
    seg.entry_count = 0;
    try std.testing.expectError(error.BadEntryCount, validateAggSegmentHeader(seg));
}

fn readRemoteU64(pid: i32, addr: usize) !u64 {
    var buf: [8]u8 = undefined;
    try processVmRead(pid, addr, buf[0..]);
    return std.mem.readInt(u64, &buf, .little);
}

fn readRemoteType(pid: i32, addr: usize, comptime T: type) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try processVmRead(pid, addr, buf[0..]);
    return std.mem.bytesToValue(T, &buf);
}

pub fn processVmRead(pid: i32, remote_addr: usize, local: []u8) !void {
    return platform.processRead(pid, remote_addr, local);
}
