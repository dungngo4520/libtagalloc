const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi.zig");

const ENTRY_USED: u32 = 1;

const MapEntry = struct {
    start: usize,
    end: usize,
    perms: [4]u8,
    offset: usize,
    path: ?[]u8,
};

pub fn main() !void {
    if (builtin.os.tag != .linux) return error.Unsupported;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        try fprint(std.fs.File.stderr(), "usage: {s} <pid>\n", .{args[0]});
        return error.InvalidArgs;
    }

    const pid: i32 = @intCast(try std.fmt.parseInt(u32, args[1], 10));

    const maps = try readMaps(allocator, pid);
    defer freeMaps(allocator, maps);

    const registry_addr = try findRegistryAddr(pid, maps);

    const reg = try readRegistryStable(pid, registry_addr);

    const stdout = std.fs.File.stdout();
    try fprint(
        stdout,
        "registry=0x{x} abi=v{d} flags=0x{x} seq={d}\n",
        .{ registry_addr, reg.abi_version, reg.flags, reg.publish_seq },
    );

    try dumpSegments(pid, reg.first_segment, stdout);
}

fn fprint(file: std.fs.File, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try file.writeAll(msg);
}

fn freeMaps(allocator: std.mem.Allocator, maps: []MapEntry) void {
    for (maps) |m| {
        if (m.path) |p| allocator.free(p);
    }
    allocator.free(maps);
}

fn readMaps(allocator: std.mem.Allocator, pid: i32) ![]MapEntry {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/maps", .{pid});

    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(data);

    var maps_list: std.ArrayList(MapEntry) = .{};
    defer maps_list.deinit(allocator);

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r\n");
        if (line.len == 0) continue;

        // Format: start-end perms offset dev inode [path]
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const range = it.next() orelse continue;
        const perms_s = it.next() orelse continue;
        const offset_s = it.next() orelse continue;

        const dash = std.mem.indexOfScalar(u8, range, '-') orelse continue;
        const start = try std.fmt.parseInt(usize, range[0..dash], 16);
        const end = try std.fmt.parseInt(usize, range[dash + 1 ..], 16);

        var perms: [4]u8 = .{ '-', '-', '-', '-' };
        @memcpy(perms[0..@min(4, perms_s.len)], perms_s[0..@min(4, perms_s.len)]);

        const offset = try std.fmt.parseInt(usize, offset_s, 16);

        // Skip dev + inode
        _ = it.next();
        _ = it.next();

        const rest = it.rest();
        const path_opt: ?[]u8 = if (rest.len == 0) null else blk: {
            const trimmed = std.mem.trimLeft(u8, rest, " ");
            break :blk try allocator.dupe(u8, trimmed);
        };

        try maps_list.append(allocator, .{
            .start = start,
            .end = end,
            .perms = perms,
            .offset = offset,
            .path = path_opt,
        });
    }

    return try maps_list.toOwnedSlice(allocator);
}

fn findRegistryAddr(pid: i32, maps: []const MapEntry) !usize {
    const magic = abi.TAGALLOC_REGISTRY_MAGIC;
    const magic_bytes = std.mem.asBytes(&magic);

    var saw_permission_denied = false;
    var saw_no_such_process = false;

    // Keep a budget so we never "scan the whole process" by accident.
    var remaining_budget: usize = 64 * 1024 * 1024; // 64 MiB

    // Heuristic: scan readable+writable mappings. We skip obvious special mappings.
    // This avoids scanning the whole process memory via a scan budget.
    for (maps) |m| {
        if (m.perms[0] != 'r' or m.perms[1] != 'w') continue;

        // Avoid special mappings.
        if (m.path) |p| {
            if (std.mem.startsWith(u8, p, "[") and std.mem.endsWith(u8, p, "]")) continue;
        }

        if (remaining_budget == 0) break;

        const span = m.end - m.start;
        const to_scan = @min(span, remaining_budget);

        const found = scanForMagicInRange(pid, m.start, m.start + to_scan, magic_bytes) catch |err| switch (err) {
            error.PermissionDenied => {
                saw_permission_denied = true;
                continue;
            },
            error.NoSuchProcess => {
                saw_no_such_process = true;
                continue;
            },
            else => continue,
        };
        if (found) |addr| {
            const reg = readRemoteType(pid, addr, abi.RegistryV1) catch continue;
            if (reg.magic != abi.TAGALLOC_REGISTRY_MAGIC) continue;
            if (reg.abi_version != abi.TAGALLOC_ABI_VERSION) continue;
            if (reg.header_size < @sizeOf(abi.RegistryV1)) continue;
            if (reg.ptr_size != @sizeOf(usize)) continue;
            if (reg.endianness != 1) continue; // MVP: reader assumes little-endian
            return addr;
        }

        remaining_budget -= to_scan;
    }

    if (saw_no_such_process) return error.NoSuchProcess;
    if (saw_permission_denied) return error.PermissionDenied;
    return error.RegistryNotFound;
}

fn scanForMagicInRange(pid: i32, start: usize, end: usize, magic_bytes: *const [8]u8) !?usize {
    var addr: usize = start;

    // 64 KiB chunks.
    var buf: [64 * 1024]u8 = undefined;
    var carry: [7]u8 = undefined;
    var carry_len: usize = 0;

    var search_buf: [buf.len + carry.len]u8 = undefined;

    while (addr < end) {
        const remaining = end - addr;
        const to_read = @min(buf.len, remaining);
        const slice = buf[0..to_read];
        try processVmRead(pid, addr, slice);

        // Search with overlap (carry) to catch boundary matches.
        const total_len = carry_len + slice.len;
        @memcpy(search_buf[0..carry_len], carry[0..carry_len]);
        @memcpy(search_buf[carry_len..total_len], slice);
        const search = search_buf[0..total_len];

        if (std.mem.indexOf(u8, search, magic_bytes[0..])) |idx| {
            const found_addr = addr - carry_len + idx;
            return found_addr;
        }

        // Save last 7 bytes for overlap.
        carry_len = @min(7, search.len);
        @memcpy(carry[0..carry_len], search[search.len - carry_len ..]);

        addr += to_read;
    }

    return null;
}

fn readRegistryStable(pid: i32, addr: usize) !abi.RegistryV1 {
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

fn dumpSegments(pid: i32, first: usize, out: std.fs.File) !void {
    var seg_addr: usize = first;
    var seg_index: usize = 0;

    while (seg_addr != 0) : (seg_index += 1) {
        const seg = try readRemoteType(pid, seg_addr, abi.AggSegmentV1);

        const entry_stride: usize = @intCast(seg.entry_stride);
        const entry_count: usize = @intCast(seg.entry_count);

        if (entry_stride < @sizeOf(abi.AggEntryV1)) return error.BadEntryStride;

        const bytes_needed = try std.math.mul(usize, entry_stride, entry_count);
        const expected_min = @sizeOf(abi.AggSegmentV1) + bytes_needed;
        if (seg.segment_size < expected_min) return error.BadSegmentSize;

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

            const tag_ascii = abi.tagToAscii(entry.tag);
            try fprint(
                out,
                "{s} alloc={d} bytes={d} free={d} bytes={d}\n",
                .{ tag_ascii[0..], entry.alloc_count, entry.alloc_bytes, entry.free_count, entry.free_bytes },
            );
        }

        seg_addr = seg.next_segment;
    }
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

fn processVmRead(pid: i32, remote_addr: usize, local: []u8) !void {
    const linux = std.os.linux;

    var local_iov = std.posix.iovec{
        .base = @ptrCast(local.ptr),
        .len = local.len,
    };

    var remote_iov = std.posix.iovec{
        .base = @ptrFromInt(remote_addr),
        .len = local.len,
    };

    const rc = linux.syscall6(
        .process_vm_readv,
        @intCast(pid),
        @intFromPtr(&local_iov),
        1,
        @intFromPtr(&remote_iov),
        1,
        0,
    );

    const err = linux.E.init(rc);
    if (err != .SUCCESS) return switch (err) {
        .PERM, .ACCES => error.PermissionDenied,
        .SRCH => error.NoSuchProcess,
        .INVAL => error.InvalidRead,
        else => error.ReadFailed,
    };

    if (rc != local.len) return error.ShortRead;
}
