const std = @import("std");

const windows = std.os.windows;
const ntdll = windows.ntdll;

pub const MapEntry = struct {
    start: usize,
    end: usize,
    perms: [4]u8,
    offset: usize,
    path: ?[]u8,
};

const PROCESS_QUERY_INFORMATION: windows.DWORD = 0x0400;
const PROCESS_VM_READ: windows.DWORD = 0x0010;

const MEM_COMMIT: windows.DWORD = 0x1000;

const PAGE_NOACCESS: windows.DWORD = 0x01;
const PAGE_READONLY: windows.DWORD = 0x02;
const PAGE_READWRITE: windows.DWORD = 0x04;
const PAGE_WRITECOPY: windows.DWORD = 0x08;
const PAGE_EXECUTE: windows.DWORD = 0x10;
const PAGE_EXECUTE_READ: windows.DWORD = 0x20;
const PAGE_EXECUTE_READWRITE: windows.DWORD = 0x40;
const PAGE_EXECUTE_WRITECOPY: windows.DWORD = 0x80;

extern "kernel32" fn OpenProcess(dwDesiredAccess: windows.DWORD, bInheritHandle: windows.BOOL, dwProcessId: windows.DWORD) callconv(.winapi) ?windows.HANDLE;
extern "kernel32" fn CloseHandle(hObject: windows.HANDLE) callconv(.winapi) windows.BOOL;
extern "kernel32" fn VirtualQueryEx(
    hProcess: windows.HANDLE,
    lpAddress: ?windows.LPCVOID,
    lpBuffer: windows.PMEMORY_BASIC_INFORMATION,
    dwLength: windows.SIZE_T,
) callconv(.winapi) windows.SIZE_T;

var g_cached_pid: i32 = -1;
var g_cached_handle: ?windows.HANDLE = null;

fn getProcessHandle(pid: i32) !windows.HANDLE {
    if (g_cached_handle) |h| {
        if (g_cached_pid == pid) return h;
        _ = CloseHandle(h);
        g_cached_handle = null;
        g_cached_pid = -1;
    }

    const desired: windows.DWORD = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    const h = OpenProcess(desired, windows.FALSE, @intCast(pid)) orelse return error.PermissionDenied;

    g_cached_pid = pid;
    g_cached_handle = h;
    return h;
}

fn permsFromProtect(prot: windows.DWORD) [4]u8 {
    var p: [4]u8 = .{ '-', '-', '-', 'p' };

    // Strip modifiers (guard/nocache/writecombine) by masking low byte.
    const base: windows.DWORD = prot & 0xFF;

    const readable = switch (base) {
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY => true,
        else => false,
    };
    const writable = switch (base) {
        PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY => true,
        else => false,
    };
    const executable = switch (base) {
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY => true,
        else => false,
    };

    if (readable) p[0] = 'r';
    if (writable) p[1] = 'w';
    if (executable) p[2] = 'x';

    if (base == PAGE_NOACCESS) {
        p[0] = '-';
        p[1] = '-';
        p[2] = '-';
    }

    return p;
}

pub fn readMaps(allocator: std.mem.Allocator, pid: i32) ![]MapEntry {
    const h = try getProcessHandle(pid);

    var out: std.ArrayList(MapEntry) = .empty;
    defer out.deinit(allocator);

    var addr: usize = 0;
    const max_addr: usize = if (@sizeOf(usize) == 8) std.math.maxInt(usize) else std.math.maxInt(u32);

    while (addr < max_addr) {
        var mbi: windows.MEMORY_BASIC_INFORMATION = undefined;
        const rc = VirtualQueryEx(h, @ptrFromInt(addr), &mbi, @sizeOf(windows.MEMORY_BASIC_INFORMATION));
        if (rc == 0) break;

        const base: usize = @intFromPtr(mbi.BaseAddress);
        const size: usize = @intCast(mbi.RegionSize);
        if (size == 0) break;

        if (mbi.State == MEM_COMMIT) {
            const perms = permsFromProtect(mbi.Protect);
            try out.append(allocator, .{
                .start = base,
                .end = base + size,
                .perms = perms,
                .offset = 0,
                .path = null,
            });
        }

        const next = base + size;
        if (next <= addr) break;
        addr = next;
    }

    return try out.toOwnedSlice(allocator);
}

pub fn processRead(pid: i32, remote_addr: usize, local: []u8) !void {
    const h = try getProcessHandle(pid);

    var read_bytes: windows.SIZE_T = 0;
    const status = ntdll.NtReadVirtualMemory(
        h,
        @ptrFromInt(remote_addr),
        @ptrCast(local.ptr),
        local.len,
        &read_bytes,
    );

    if (status != .SUCCESS) {
        return switch (status) {
            .ACCESS_DENIED => error.PermissionDenied,
            .INVALID_CID => error.NoSuchProcess,
            .PARTIAL_COPY => error.ShortRead,
            else => error.ReadFailed,
        };
    }

    if (read_bytes != local.len) return error.ShortRead;
}

pub fn findRegistryAddr(_: std.mem.Allocator, _: i32, _: []const MapEntry) !usize {
    // Windows: symbol-based discovery isn't implemented yet.
    return error.RegistryNotFound;
}
