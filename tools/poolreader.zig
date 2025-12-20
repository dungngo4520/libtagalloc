const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");
const elf = std.elf;

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

    const registry_addr = try findRegistryAddr(allocator, pid, maps);
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

fn findRegistryAddr(allocator: std.mem.Allocator, pid: i32, maps: []const MapEntry) !usize {
    if (try findRegistryAddrBySymbol(allocator, pid, maps)) |addr| return addr;

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

fn findRegistryAddrBySymbol(allocator: std.mem.Allocator, pid: i32, maps: []const MapEntry) !?usize {
    // Preferred method: ELF symbol lookup. This avoids scanning process memory.
    // Works best when `g_tagalloc_registry` is present in `.dynsym` or `.symtab`.
    const sym_name = "g_tagalloc_registry";

    const exe_path = readProcExePath(allocator, pid) catch |err| switch (err) {
        error.NoSuchProcess => return error.NoSuchProcess,
        error.PermissionDenied => return error.PermissionDenied,
        else => return null,
    };
    defer allocator.free(exe_path);

    if (try findRegistryAddrInModuleBySymbol(allocator, pid, maps, exe_path, sym_name)) |addr| return addr;

    // Fallback: try other file-backed executable mappings (shared libs).
    // Keep this bounded; we only look at mapped modules with offset==0.
    var seen: std.StringHashMapUnmanaged(void) = .{};
    defer seen.deinit(allocator);

    for (maps) |m| {
        if (m.perms[2] != 'x') continue;
        if (m.offset != 0) continue;
        const p = m.path orelse continue;
        if (std.mem.startsWith(u8, p, "[") and std.mem.endsWith(u8, p, "]")) continue;

        const norm = normalizeMapsPath(p);
        if (seen.contains(norm)) continue;
        try seen.put(allocator, norm, {});

        if (std.mem.eql(u8, norm, exe_path)) continue;
        if (try findRegistryAddrInModuleBySymbol(allocator, pid, maps, norm, sym_name)) |addr| return addr;
    }

    return null;
}

fn findRegistryAddrInModuleBySymbol(
    allocator: std.mem.Allocator,
    pid: i32,
    maps: []const MapEntry,
    module_path: []const u8,
    symbol_name: []const u8,
) !?usize {
    const base = findModuleBaseAddr(maps, module_path) orelse return null;
    const sym = parseElfForSymbolValue(allocator, module_path, symbol_name) catch return null;

    const remote_addr: usize = switch (sym.elf_type) {
        .EXEC => @intCast(sym.value),
        .DYN => base + @as(usize, @intCast(sym.value)),
        else => return null,
    };

    // Validate quickly by reading the registry header.
    const reg = readRemoteType(pid, remote_addr, abi.RegistryV1) catch |err| switch (err) {
        error.PermissionDenied => return error.PermissionDenied,
        error.NoSuchProcess => return error.NoSuchProcess,
        else => return null,
    };
    if (reg.magic != abi.TAGALLOC_REGISTRY_MAGIC) return null;
    if (reg.abi_version != abi.TAGALLOC_ABI_VERSION) return null;
    if (reg.header_size < @sizeOf(abi.RegistryV1)) return null;
    if (reg.ptr_size != @sizeOf(usize)) return null;
    if (reg.endianness != 1) return null;

    return remote_addr;
}

fn findModuleBaseAddr(maps: []const MapEntry, module_path: []const u8) ?usize {
    // For ET_DYN binaries/libraries (PIE), the mapping with file offset 0 is the base.
    // For ET_EXEC, st_value is absolute, so base doesn't matter (but we still validate mapping).
    var best: ?usize = null;
    for (maps) |m| {
        if (m.offset != 0) continue;
        const p = m.path orelse continue;
        if (!std.mem.eql(u8, normalizeMapsPath(p), module_path)) continue;

        if (best == null or m.start < best.?) best = m.start;
    }
    return best;
}

fn normalizeMapsPath(path: []const u8) []const u8 {
    // /proc/<pid>/maps may append " (deleted)".
    const suffix = " (deleted)";
    if (std.mem.endsWith(u8, path, suffix)) {
        return path[0 .. path.len - suffix.len];
    }
    return path;
}

fn readProcExePath(allocator: std.mem.Allocator, pid: i32) ![]u8 {
    // Readlink /proc/<pid>/exe.
    var link_path_buf: [64]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&link_path_buf, "/proc/{d}/exe", .{pid});

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const out = std.posix.readlink(link_path, buf[0..]) catch |err| switch (err) {
        error.FileNotFound => return error.NoSuchProcess,
        error.AccessDenied => return error.PermissionDenied,
        else => return err,
    };
    return try allocator.dupe(u8, out);
}

const FoundSymbol = struct {
    elf_type: elf.ET,
    value: u64,
};

fn parseElfForSymbolValue(allocator: std.mem.Allocator, file_path: []const u8, symbol_name: []const u8) !FoundSymbol {
    if (@sizeOf(usize) != 8) return error.Unsupported;

    var file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();

    // Keep a sanity limit; binaries should be well below this.
    const data = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
    defer allocator.free(data);

    if (data.len < @sizeOf(elf.Elf64_Ehdr)) return error.BadElf;
    const hdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, data[0..@sizeOf(elf.Elf64_Ehdr)]).*;

    if (!std.mem.eql(u8, hdr.e_ident[0..4], elf.MAGIC)) return error.BadElf;
    if (hdr.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.BadElf;
    if (hdr.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) return error.BadElf;

    const shoff: usize = @intCast(hdr.e_shoff);
    const shentsize: usize = @intCast(hdr.e_shentsize);
    const shnum: usize = @intCast(hdr.e_shnum);
    if (shoff == 0 or shentsize < @sizeOf(elf.Elf64_Shdr) or shnum == 0) return error.BadElf;
    const sh_bytes_needed = try std.math.mul(usize, shentsize, shnum);
    if (shoff + sh_bytes_needed > data.len) return error.BadElf;

    // Load section headers.
    var shdrs = try allocator.alloc(elf.Elf64_Shdr, shnum);
    defer allocator.free(shdrs);
    {
        var i: usize = 0;
        while (i < shnum) : (i += 1) {
            const off = shoff + i * shentsize;
            shdrs[i] = std.mem.bytesAsValue(elf.Elf64_Shdr, data[off .. off + @sizeOf(elf.Elf64_Shdr)]).*;
        }
    }

    // Helper to search a symbol table section.
    const want = symbol_name;
    const symtab_types = [_]u32{ elf.SHT_SYMTAB, elf.SHT_DYNSYM };
    for (symtab_types) |sym_type| {
        var i: usize = 0;
        while (i < shnum) : (i += 1) {
            const sh = shdrs[i];
            if (sh.sh_type != sym_type) continue;
            if (sh.sh_entsize == 0 or sh.sh_size == 0) continue;
            if (sh.sh_entsize < @sizeOf(elf.Elf64_Sym)) continue;

            const link: usize = @intCast(sh.sh_link);
            if (link >= shnum) continue;
            const str_sh = shdrs[link];
            if (str_sh.sh_type != elf.SHT_STRTAB) continue;

            const sym_off: usize = @intCast(sh.sh_offset);
            const sym_size: usize = @intCast(sh.sh_size);
            if (sym_off + sym_size > data.len) continue;

            const str_off: usize = @intCast(str_sh.sh_offset);
            const str_size: usize = @intCast(str_sh.sh_size);
            if (str_off + str_size > data.len) continue;
            const strtab = data[str_off .. str_off + str_size];

            const count: usize = @intCast(sym_size / sh.sh_entsize);
            var si: usize = 0;
            while (si < count) : (si += 1) {
                const off = sym_off + si * @as(usize, @intCast(sh.sh_entsize));
                const sym = std.mem.bytesAsValue(elf.Elf64_Sym, data[off .. off + @sizeOf(elf.Elf64_Sym)]).*;
                if (sym.st_name == 0) continue;
                const name_off: usize = @intCast(sym.st_name);
                if (name_off >= strtab.len) continue;
                const name = std.mem.sliceTo(strtab[name_off..], 0);
                if (std.mem.eql(u8, name, want)) {
                    return .{ .elf_type = hdr.e_type, .value = @intCast(sym.st_value) };
                }
            }
        }
    }

    return error.SymbolNotFound;
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
