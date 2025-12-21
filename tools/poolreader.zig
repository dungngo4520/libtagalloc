const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");
const pr = @import("poolreader_lib.zig");

pub fn main() void {
    run() catch |err| {
        const stderr = std.fs.File.stderr();
        reportFatal(stderr, err) catch {};
        std.process.exit(1);
    };
}

fn run() !void {
    if (builtin.os.tag != .linux) return error.Unsupported;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const parsed = parseArgs(args) catch |err| {
        const stderr = std.fs.File.stderr();
        try reportArgsError(stderr, args[0], err);
        return;
    };
    if (parsed.show_help) {
        const stderr = std.fs.File.stderr();
        try fprint(stderr, "usage: {s} <pid> [--scan] [--watch] [--interval-ms N]\n", .{args[0]});
        try fprint(stderr, "  --scan           allow bounded RW mapping scan fallback (opt-in)\n", .{});
        try fprint(stderr, "  --watch          constantly watching (Ctrl-C to quit)\n", .{});
        try fprint(stderr, "  --interval-ms N  watch refresh period (default: 1000)\n", .{});
        return;
    }

    const pid: i32 = parsed.pid;

    const maps = pr.readMaps(allocator, pid) catch |err| {
        const stderr = std.fs.File.stderr();
        try reportCommonError(stderr, pid, err);
        return;
    };
    defer pr.freeMaps(allocator, maps);

    const registry_addr = if (parsed.allow_scan)
        findRegistryAddrScanFallback(allocator, pid, maps) catch |err| {
            const stderr = std.fs.File.stderr();
            try reportCommonError(stderr, pid, err);
            return;
        }
    else
        pr.findRegistryAddr(allocator, pid, maps) catch |err| {
            const stderr = std.fs.File.stderr();
            try reportCommonError(stderr, pid, err);
            return;
        };

    const stdout = std.fs.File.stdout();

    if (!parsed.watch) {
        const reg = pr.readRegistryStable(pid, registry_addr) catch |err| {
            const stderr = std.fs.File.stderr();
            try reportCommonError(stderr, pid, err);
            return;
        };
        try fprint(
            stdout,
            "registry=0x{x} abi=v{d} flags=0x{x} seq={d}\n",
            .{ registry_addr, reg.abi_version, reg.flags, reg.publish_seq },
        );
        dumpSegments(pid, reg.first_segment, stdout) catch |err| {
            const stderr = std.fs.File.stderr();
            try reportCommonError(stderr, pid, err);
            return;
        };
        return;
    }

    // Minimal top-like loop: clear + redraw until Ctrl-C.
    const interval_ns: u64 = parsed.interval_ms * std.time.ns_per_ms;
    while (true) {
        const reg = pr.readRegistryStable(pid, registry_addr) catch |err| {
            const stderr = std.fs.File.stderr();
            try reportCommonError(stderr, pid, err);
            return;
        };

        // ANSI clear screen + home.
        try stdout.writeAll("\x1b[H\x1b[2J");

        const now_ms = std.time.milliTimestamp();
        try fprint(
            stdout,
            "tagalloc-poolreader pid={d} t={d}ms\nregistry=0x{x} abi=v{d} flags=0x{x} seq={d}\n\n",
            .{ pid, now_ms, registry_addr, reg.abi_version, reg.flags, reg.publish_seq },
        );
        dumpSegments(pid, reg.first_segment, stdout) catch |err| {
            const stderr = std.fs.File.stderr();
            try reportCommonError(stderr, pid, err);
            return;
        };
        try stdout.writeAll("\n");

        std.Thread.sleep(interval_ns);
    }
}

fn reportArgsError(stderr: std.fs.File, argv0: []const u8, err: anyerror) !void {
    switch (err) {
        error.InvalidArgs => {
            try fprint(stderr, "error: invalid arguments\n", .{});
            try fprint(stderr, "usage: {s} <pid> [--scan] [--watch] [--interval-ms N]\n", .{argv0});
        },
        else => try reportFatal(stderr, err),
    }
}

fn reportFatal(stderr: std.fs.File, err: anyerror) !void {
    switch (err) {
        error.Unsupported => try fprint(stderr, "error: unsupported platform\n", .{}),
        else => try fprint(stderr, "error: {s}\n", .{@errorName(err)}),
    }
}

fn reportCommonError(stderr: std.fs.File, pid: i32, err: anyerror) !void {
    switch (err) {
        error.PermissionDenied => {
            try fprint(stderr, "error: permission denied reading pid {d}\n", .{pid});
        },
        error.NoSuchProcess => {
            try fprint(stderr, "error: pid {d} does not exist\n", .{pid});
        },
        error.RegistryNotFound => {
            try fprint(stderr, "error: libtagalloc registry not found in pid {d}\n", .{pid});
            try fprint(stderr, "hint: ensure the target uses libtagalloc and exports g_tagalloc_registry.\n", .{});
            try fprint(stderr, "use --scan to enable a bounded RW mapping fallback scan (slower).\n", .{});
        },
        else => {},
    }
}

const ParsedArgs = struct {
    pid: i32,
    allow_scan: bool,
    watch: bool,
    interval_ms: u64,
    show_help: bool,
};

fn parseArgs(args: []const []const u8) !ParsedArgs {
    var allow_scan = false;
    var watch = false;
    var interval_ms: u64 = 1000;
    var show_help = false;
    var pid_opt: ?i32 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            show_help = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--scan")) {
            allow_scan = true;
            continue;
        }

        if (std.mem.eql(u8, a, "--watch")) {
            watch = true;
            continue;
        }

        if (std.mem.eql(u8, a, "--interval-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArgs;
            interval_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.InvalidArgs;
            continue;
        }

        // First non-flag is PID.
        if (pid_opt == null) {
            pid_opt = @intCast(std.fmt.parseInt(u32, a, 10) catch return error.InvalidArgs);
        } else {
            return error.InvalidArgs;
        }
    }

    if (show_help) return .{ .pid = 0, .allow_scan = allow_scan, .watch = watch, .interval_ms = interval_ms, .show_help = true };
    const pid = pid_opt orelse return error.InvalidArgs;
    return .{ .pid = pid, .allow_scan = allow_scan, .watch = watch, .interval_ms = interval_ms, .show_help = false };
}

fn fprint(file: std.fs.File, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try file.writeAll(msg);
}

fn findRegistryAddrScanFallback(allocator: std.mem.Allocator, pid: i32, maps: []const pr.MapEntry) !usize {
    const sym_addr = pr.findRegistryAddr(allocator, pid, maps) catch |err| switch (err) {
        error.RegistryNotFound => 0,
        else => return err,
    };
    if (sym_addr != 0) return sym_addr;

    const magic = abi.TAGALLOC_REGISTRY_MAGIC;
    const magic_bytes = std.mem.asBytes(&magic);

    var saw_permission_denied = false;
    var saw_no_such_process = false;

    var remaining_budget: usize = 64 * 1024 * 1024; // 64 MiB

    for (maps) |m| {
        if (m.perms[0] != 'r' or m.perms[1] != 'w') continue;

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
            const reg = pr.readRegistryStable(pid, addr) catch continue;
            if (reg.magic != abi.TAGALLOC_REGISTRY_MAGIC) continue;
            if (reg.abi_version != abi.TAGALLOC_ABI_VERSION) continue;
            if (reg.header_size < @sizeOf(abi.RegistryV1)) continue;
            if (reg.ptr_size != @sizeOf(usize)) continue;
            if (reg.endianness != 1) continue;
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
        try pr.processVmRead(pid, addr, slice);

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
        try pr.processVmRead(pid, entries_addr, entries);

        var i: usize = 0;
        while (i < entry_count) : (i += 1) {
            const off = i * entry_stride;
            const view = entries[off .. off + @sizeOf(abi.AggEntryV1)];
            const entry_ptr = std.mem.bytesAsValue(abi.AggEntryV1, view);
            const entry = entry_ptr.*;

            if (entry.reserved0 != pr.ENTRY_USED) continue;

            const tag_ascii = abi.tagToAscii(entry.tag);
            const diff: i128 = @as(i128, @intCast(entry.alloc_count)) - @as(i128, @intCast(entry.free_count));
            const diff_bytes: i128 = @as(i128, @intCast(entry.alloc_bytes)) - @as(i128, @intCast(entry.free_bytes));
            try fprint(
                out,
                "{s} alloc={d} bytes={d} free={d} bytes={d} diff={d} diff_bytes={d}\n",
                .{ tag_ascii[0..], entry.alloc_count, entry.alloc_bytes, entry.free_count, entry.free_bytes, diff, diff_bytes },
            );
        }

        seg_addr = seg.next_segment;
    }
}

fn readRemoteU64(pid: i32, addr: usize) !u64 {
    var buf: [8]u8 = undefined;
    try pr.processVmRead(pid, addr, buf[0..]);
    return std.mem.readInt(u64, &buf, .little);
}

fn readRemoteType(pid: i32, addr: usize, comptime T: type) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try pr.processVmRead(pid, addr, buf[0..]);
    return std.mem.bytesToValue(T, &buf);
}
