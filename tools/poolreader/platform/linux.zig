const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");
const elf = std.elf;

pub const MapEntry = struct {
    start: usize,
    end: usize,
    perms: [4]u8,
    offset: usize,
    path: ?[]u8,
};

pub fn readMaps(allocator: std.mem.Allocator, pid: i32) ![]MapEntry {
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/maps", .{pid});

    var file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.NoSuchProcess,
        error.AccessDenied => return error.PermissionDenied,
        else => return err,
    };
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

pub fn processRead(pid: i32, remote_addr: usize, local: []u8) !void {
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

pub fn findRegistryAddr(allocator: std.mem.Allocator, pid: i32, maps: []const MapEntry) !usize {
    if (try findRegistryAddrBySymbol(allocator, pid, maps)) |addr| return addr;
    return error.RegistryNotFound;
}

fn readProcExePath(allocator: std.mem.Allocator, pid: i32) ![]u8 {
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

    if (reg.magic != abi.TAGALLOC_REGISTRY_MAGIC) return null;
    if (reg.abi_version != abi.TAGALLOC_ABI_VERSION) return null;
    if (reg.header_size < @sizeOf(abi.RegistryV1)) return null;
    if (reg.ptr_size != @sizeOf(usize)) return null;
    if (reg.endianness != 1) return null;

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

fn readRemoteType(pid: i32, addr: usize, comptime T: type) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try processRead(pid, addr, buf[0..]);
    return std.mem.bytesToValue(T, &buf);
}
