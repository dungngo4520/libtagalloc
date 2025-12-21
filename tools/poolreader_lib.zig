const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");
const elf = std.elf;

pub const ENTRY_USED: u32 = 1;

pub const MapEntry = struct {
    start: usize,
    end: usize,
    perms: [4]u8,
    offset: usize,
    path: ?[]u8,
};

pub fn freeMaps(allocator: std.mem.Allocator, maps: []MapEntry) void {
    for (maps) |m| {
        if (m.path) |p| allocator.free(p);
    }
    allocator.free(maps);
}

pub fn readMaps(allocator: std.mem.Allocator, pid: i32) ![]MapEntry {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/maps", .{pid});

    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(data);

    var maps_list: std.ArrayList(MapEntry) = .empty;
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

pub fn readProcExePath(allocator: std.mem.Allocator, pid: i32) ![]u8 {
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

fn normalizeMapsPath(path: []const u8) []const u8 {
    const suffix = " (deleted)";
    if (std.mem.endsWith(u8, path, suffix)) {
        return path[0 .. path.len - suffix.len];
    }
    return path;
}

fn findModuleBaseAddr(maps: []const MapEntry, module_path: []const u8) ?usize {
    var best: ?usize = null;
    for (maps) |m| {
        if (m.offset != 0) continue;
        const p = m.path orelse continue;
        if (!std.mem.eql(u8, normalizeMapsPath(p), module_path)) continue;
        if (best == null or m.start < best.?) best = m.start;
    }
    return best;
}

const FoundSymbol = struct {
    elf_type: elf.ET,
    value: u64,
};

fn parseElfForSymbolValue(allocator: std.mem.Allocator, file_path: []const u8, symbol_name: []const u8) !FoundSymbol {
    if (@sizeOf(usize) != 8) return error.Unsupported;

    var file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();

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

    var shdrs = try allocator.alloc(elf.Elf64_Shdr, shnum);
    defer allocator.free(shdrs);
    {
        var i: usize = 0;
        while (i < shnum) : (i += 1) {
            const off = shoff + i * shentsize;
            shdrs[i] = std.mem.bytesAsValue(elf.Elf64_Shdr, data[off .. off + @sizeOf(elf.Elf64_Shdr)]).*;
        }
    }

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

    const reg = readRemoteType(pid, remote_addr, abi.RegistryV1) catch |err| switch (err) {
        error.PermissionDenied => return error.PermissionDenied,
        error.NoSuchProcess => return error.NoSuchProcess,
        else => return null,
    };

    validateRegistryHeader(reg) catch return null;

    return remote_addr;
}

fn findRegistryAddrBySymbol(allocator: std.mem.Allocator, pid: i32, maps: []const MapEntry) !?usize {
    const sym_name = "g_tagalloc_registry";

    const exe_path = readProcExePath(allocator, pid) catch |err| switch (err) {
        error.NoSuchProcess => return error.NoSuchProcess,
        error.PermissionDenied => return error.PermissionDenied,
        else => return null,
    };
    defer allocator.free(exe_path);

    if (try findRegistryAddrInModuleBySymbol(allocator, pid, maps, exe_path, sym_name)) |addr| return addr;

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

pub fn findRegistryAddr(allocator: std.mem.Allocator, pid: i32, maps: []const MapEntry) !usize {
    if (try findRegistryAddrBySymbol(allocator, pid, maps)) |addr| return addr;
    return error.RegistryNotFound;
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
    if (builtin.os.tag != .linux) return error.Unsupported;

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
