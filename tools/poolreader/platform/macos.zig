const std = @import("std");

pub const MapEntry = struct {
    start: usize,
    end: usize,
    perms: [4]u8,
    offset: usize,
    path: ?[]u8,
};

// Minimal Mach bindings (enough for task_for_pid, mach_vm_region, mach_vm_read_overwrite).
const kern_return_t = i32;
const mach_port_t = u32;
const mach_vm_address_t = u64;
const mach_vm_size_t = u64;
const vm_prot_t = i32;
const vm_region_flavor_t = i32;
const mach_msg_type_number_t = u32;

extern "c" var mach_task_self_: mach_port_t;
extern "c" fn task_for_pid(parent: mach_port_t, pid: i32, task: *mach_port_t) callconv(.c) kern_return_t;
extern "c" fn mach_vm_read_overwrite(
    target_task: mach_port_t,
    address: mach_vm_address_t,
    size: mach_vm_size_t,
    data: mach_vm_address_t,
    out_size: *mach_vm_size_t,
) callconv(.c) kern_return_t;

extern "c" fn mach_vm_region(
    target_task: mach_port_t,
    address: *mach_vm_address_t,
    size: *mach_vm_size_t,
    flavor: vm_region_flavor_t,
    info: *anyopaque,
    info_count: *mach_msg_type_number_t,
    object_name: *mach_port_t,
) callconv(.c) kern_return_t;

const KERN_SUCCESS: kern_return_t = 0;

// From mach/vm_region.h
const VM_REGION_BASIC_INFO_64: vm_region_flavor_t = 9;

// From mach/vm_prot.h
const VM_PROT_READ: vm_prot_t = 1;
const VM_PROT_WRITE: vm_prot_t = 2;
const VM_PROT_EXECUTE: vm_prot_t = 4;

const vm_region_basic_info_64 = extern struct {
    protection: vm_prot_t,
    max_protection: vm_prot_t,
    inheritance: i32,
    shared: i32,
    reserved: i32,
    offset: u64,
    behavior: i32,
    user_wired_count: u16,
};

var g_cached_pid: i32 = -1;
var g_cached_task: mach_port_t = 0;

fn getTask(pid: i32) !mach_port_t {
    if (pid <= 0) return error.NoSuchProcess;
    if (g_cached_task != 0 and g_cached_pid == pid) return g_cached_task;

    var task: mach_port_t = 0;
    const rc = task_for_pid(mach_task_self_, pid, &task);
    if (rc != KERN_SUCCESS or task == 0) {
        // On macOS this commonly fails without root + task_for_pid entitlement.
        // Also treat invalid-argument as "no such process".
        if (rc == 4) return error.NoSuchProcess; // KERN_INVALID_ARGUMENT
        return error.PermissionDenied;
    }

    g_cached_pid = pid;
    g_cached_task = task;
    return task;
}

fn permsFromProt(prot: vm_prot_t) [4]u8 {
    var p: [4]u8 = .{ '-', '-', '-', 'p' };
    if ((prot & VM_PROT_READ) != 0) p[0] = 'r';
    if ((prot & VM_PROT_WRITE) != 0) p[1] = 'w';
    if ((prot & VM_PROT_EXECUTE) != 0) p[2] = 'x';
    return p;
}

pub fn readMaps(allocator: std.mem.Allocator, pid: i32) ![]MapEntry {
    const task = try getTask(pid);

    var out: std.ArrayList(MapEntry) = .empty;
    defer out.deinit(allocator);

    var address: mach_vm_address_t = 0;
    while (true) {
        var size: mach_vm_size_t = 0;
        var info: vm_region_basic_info_64 = undefined;
        var info_count: mach_msg_type_number_t = @intCast(@sizeOf(vm_region_basic_info_64) / @sizeOf(u32));
        var object_name: mach_port_t = 0;

        const rc = mach_vm_region(
            task,
            &address,
            &size,
            VM_REGION_BASIC_INFO_64,
            &info,
            &info_count,
            &object_name,
        );
        if (rc != KERN_SUCCESS) break;
        if (size == 0) break;

        const start: usize = @intCast(address);
        const end: usize = @intCast(address + size);

        try out.append(allocator, .{
            .start = start,
            .end = end,
            .perms = permsFromProt(info.protection),
            .offset = 0,
            .path = null,
        });

        address += size;
        if (address == 0) break; // overflow wrap
    }

    return try out.toOwnedSlice(allocator);
}

pub fn processRead(pid: i32, remote_addr: usize, local: []u8) !void {
    const task = try getTask(pid);

    var out_size: mach_vm_size_t = 0;
    const rc = mach_vm_read_overwrite(
        task,
        @intCast(remote_addr),
        @intCast(local.len),
        @intFromPtr(local.ptr),
        &out_size,
    );

    if (rc != KERN_SUCCESS) return error.ReadFailed;
    if (out_size != local.len) return error.ShortRead;
}

pub fn findRegistryAddr(_: std.mem.Allocator, _: i32, _: []const MapEntry) !usize {
    // macOS: symbol-based discovery isn't implemented yet.
    return error.RegistryNotFound;
}
