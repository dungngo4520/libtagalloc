const std = @import("std");

const os = @import("../platform/os.zig");
const arena = @import("arena.zig");
const slab = @import("slab.zig");
const registry = @import("registry.zig");
const hardening = @import("../debug/hardening.zig");

pub const DefaultAlign64: usize = 16;
pub const DefaultAlign32: usize = 8;

fn defaultAlign() usize {
    return if (@sizeOf(usize) == 8) DefaultAlign64 else DefaultAlign32;
}

const AllocHeader = extern struct {
    backing_base: usize,
    backing_len: usize,
    user_size: usize,
    tag: u32,
    align_log2: u8,
    kind: u8,
    arena_order: u8,
    reserved0: u8,
};

const HDR_KIND_MMAP: u8 = 0;
const HDR_KIND_ARENA: u8 = 1;
const HDR_KIND_SLAB: u8 = 2;

const HDR_STATE_LIVE: u8 = 0;
const HDR_STATE_FREED: u8 = 0xDE;

var g_arena: arena.Arena = .{};

const FreeRecord = struct {
    kind: u8,
    hdr_addr: usize,
    backing_base: usize,
    backing_len: usize,
    arena_order: u8,
    user_ptr: [*]u8,
    user_size: usize,
};

const QuarantineCapacity: usize = 1024;
var g_quarantine_lock: std.Thread.Mutex = .{};
var g_quarantine: [QuarantineCapacity]?FreeRecord = [_]?FreeRecord{null} ** QuarantineCapacity;
var g_quarantine_head: usize = 0;
var g_quarantine_len: usize = 0;

fn quarantinePush(rec: FreeRecord) void {
    if (!hardening.enabled()) {
        actuallyFree(rec);
        return;
    }

    var to_free: ?FreeRecord = null;

    g_quarantine_lock.lock();
    if (g_quarantine_len == QuarantineCapacity) {
        to_free = g_quarantine[g_quarantine_head].?;
        g_quarantine[g_quarantine_head] = null;
        g_quarantine_head = (g_quarantine_head + 1) % QuarantineCapacity;
        g_quarantine_len -= 1;
    }

    const tail_idx = (g_quarantine_head + g_quarantine_len) % QuarantineCapacity;
    g_quarantine[tail_idx] = rec;
    g_quarantine_len += 1;
    g_quarantine_lock.unlock();

    if (to_free) |old| actuallyFree(old);
}

fn actuallyFree(rec: FreeRecord) void {
    if (rec.kind == HDR_KIND_SLAB) {
        slab.freeSlab(@ptrFromInt(rec.hdr_addr));
    } else if (rec.kind == HDR_KIND_ARENA) {
        g_arena.freeBlock(rec.hdr_addr, rec.arena_order);
    } else {
        os.osMunmap(@ptrFromInt(rec.backing_base), rec.backing_len);
    }
}

fn normalizeAlignment(alignment: usize) !usize {
    const min_align = defaultAlign();
    if (alignment == 0) return min_align;
    if (!std.math.isPowerOfTwo(alignment)) return error.InvalidAlignment;
    if (alignment < min_align) return min_align;
    return alignment;
}

fn allocInternal(tag: u32, size: usize, alignment: usize) ![*]u8 {
    if (size == 0) return error.InvalidSize;

    registry.ensureInit();

    const hdr_size = @sizeOf(AllocHeader);
    const prefix_size = @sizeOf(usize);
    const effective_alignment = try normalizeAlignment(alignment);
    const tail_bytes = hardening.tailBytes();

    if (alignment == 0 or effective_alignment <= defaultAlign()) {
        const overhead = hdr_size + prefix_size + tail_bytes;
        const total_needed = try std.math.add(usize, size, overhead);
        if (slab.sizeToClassIndex(total_needed)) |class_idx| {
            const class_size = slab.SlabSizeClasses[class_idx];
            if (total_needed <= class_size) {
                const slot = slab.allocSlab(class_size) catch {
                    // Slab failed; fall through to arena/mmap
                    return allocFallback(tag, size, effective_alignment);
                };

                const hdr_addr = @intFromPtr(slot);
                const hdr: *AllocHeader = @ptrFromInt(hdr_addr);
                hdr.* = .{
                    .backing_base = 0,
                    .backing_len = class_size,
                    .user_size = size,
                    .tag = tag,
                    .align_log2 = @intCast(@ctz(effective_alignment)),
                    .kind = HDR_KIND_SLAB,
                    .arena_order = 0,
                    .reserved0 = HDR_STATE_LIVE,
                };

                const after_hdr = hdr_addr + hdr_size;
                const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, effective_alignment);
                const prefix_addr = user_addr - prefix_size;
                const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
                prefix_ptr.* = @intFromPtr(hdr);

                const user_ptr: [*]u8 = @ptrFromInt(user_addr);
                hardening.poisonAlloc(user_ptr, size);
                hardening.writeTailCanary(user_ptr, size);
                registry.noteAlloc(tag, size);
                return user_ptr;
            }
        }
    }

    return allocFallback(tag, size, effective_alignment);
}

fn allocFallback(tag: u32, size: usize, effective_alignment: usize) ![*]u8 {
    const hdr_size = @sizeOf(AllocHeader);
    const prefix_size = @sizeOf(usize);

    var raw_needed = try std.math.add(usize, hdr_size, prefix_size);
    raw_needed = try std.math.add(usize, raw_needed, size);
    raw_needed = try std.math.add(usize, raw_needed, hardening.tailBytes());
    raw_needed = try std.math.add(usize, raw_needed, effective_alignment);

    const arena_order = arena.sizeToArenaOrder(raw_needed);

    var hdr: *AllocHeader = undefined;
    var user_ptr: [*]u8 = undefined;
    var used_arena = false;

    if (arena_order) |ord| blk: {
        // If arena init fails, fall back to mmap-per-allocation.
        if (!g_arena.tryInit()) break :blk;
        const block_addr = g_arena.allocBlock(ord) orelse break :blk;

        const hdr_addr = block_addr; // block base
        hdr = @ptrFromInt(hdr_addr);
        hdr.* = .{
            .backing_base = g_arena.base,
            .backing_len = arena.ArenaSize,
            .user_size = size,
            .tag = tag,
            .align_log2 = @intCast(@ctz(effective_alignment)),
            .kind = HDR_KIND_ARENA,
            .arena_order = ord,
            .reserved0 = HDR_STATE_LIVE,
        };

        const after_hdr = hdr_addr + hdr_size;
        const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, effective_alignment);
        const prefix_addr = user_addr - prefix_size;
        const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
        prefix_ptr.* = @intFromPtr(hdr);
        user_ptr = @ptrFromInt(user_addr);
        hardening.poisonAlloc(user_ptr, size);
        hardening.writeTailCanary(user_ptr, size);
        used_arena = true;
        break :blk;
    } else {
        // Not eligible for arena.
    }

    // mmap fallback
    if (!used_arena) {
        const map_len = std.mem.alignForward(usize, raw_needed, os.pageSize());
        const base_ptr = try os.osMmap(map_len);
        const base_addr = @intFromPtr(base_ptr);
        const hdr_addr = std.mem.alignForward(usize, base_addr, effective_alignment);

        hdr = @ptrFromInt(hdr_addr);
        hdr.* = .{
            .backing_base = base_addr,
            .backing_len = map_len,
            .user_size = size,
            .tag = tag,
            .align_log2 = @intCast(@ctz(effective_alignment)),
            .kind = HDR_KIND_MMAP,
            .arena_order = 0,
            .reserved0 = HDR_STATE_LIVE,
        };

        const after_hdr = hdr_addr + hdr_size;
        const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, effective_alignment);
        const prefix_addr = user_addr - prefix_size;
        const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
        prefix_ptr.* = @intFromPtr(hdr);
        user_ptr = @ptrFromInt(user_addr);
        hardening.poisonAlloc(user_ptr, size);
        hardening.writeTailCanary(user_ptr, size);
    }

    registry.noteAlloc(tag, size);

    return user_ptr;
}

fn freeInternal(ptr: [*]u8, expected_tag: ?u32) void {
    if (@intFromPtr(ptr) == 0) return;

    registry.ensureInit();

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(ptr) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *AllocHeader = @ptrFromInt(hdr_addr);

    if (expected_tag) |exp| {
        if (hdr.tag != exp) {
            registry.noteTagMismatch();
        }
    }

    registry.noteFree(hdr.tag, hdr.user_size);

    if (hardening.enabled()) {
        if (hdr.reserved0 == HDR_STATE_FREED) {
            hardening.hardPanic("tagalloc: double free detected");
        }
        if (!hardening.checkTailCanary(ptr, hdr.user_size)) {
            hardening.hardPanic("tagalloc: tail canary corrupted (buffer overrun)");
        }
        hardening.poisonFree(ptr, hdr.user_size);
        hdr.reserved0 = HDR_STATE_FREED;

        quarantinePush(.{
            .kind = hdr.kind,
            .hdr_addr = hdr_addr,
            .backing_base = hdr.backing_base,
            .backing_len = hdr.backing_len,
            .arena_order = hdr.arena_order,
            .user_ptr = ptr,
            .user_size = hdr.user_size,
        });
        return;
    }

    actuallyFree(.{
        .kind = hdr.kind,
        .hdr_addr = hdr_addr,
        .backing_base = hdr.backing_base,
        .backing_len = hdr.backing_len,
        .arena_order = hdr.arena_order,
        .user_ptr = ptr,
        .user_size = hdr.user_size,
    });
}

pub fn alloc(tag: u32, size: usize) ![*]u8 {
    return allocInternal(tag, size, 0);
}

pub fn alignedAlloc(tag: u32, size: usize, alignment: usize) ![*]u8 {
    return allocInternal(tag, size, alignment);
}

pub fn free(ptr: [*]u8) void {
    freeInternal(ptr, null);
}

pub fn freeWithExpectedTag(ptr: [*]u8, expected_tag: u32) void {
    freeInternal(ptr, expected_tag);
}

pub fn realloc(tag: u32, ptr: ?[*]u8, new_size: usize) ![*]u8 {
    if (new_size == 0) return error.InvalidSize;

    if (ptr == null) {
        return alloc(tag, new_size);
    }

    const old_ptr = ptr.?;

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(old_ptr) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *const AllocHeader = @ptrFromInt(hdr_addr);

    const old_size = hdr.user_size;
    const alignment: usize = @as(usize, 1) << @as(u6, @intCast(hdr.align_log2));

    // Allocate first; on failure, the old allocation stays valid.
    const new_ptr = try alignedAlloc(tag, new_size, alignment);
    const to_copy = @min(old_size, new_size);
    @memcpy(new_ptr[0..to_copy], old_ptr[0..to_copy]);
    free(old_ptr);
    return new_ptr;
}

test "aligned alloc returns properly aligned pointer" {
    const tag: u32 = 0x44434241; // "ABCD" in little-endian display order

    {
        const p = try alignedAlloc(tag, 1, 64);
        defer free(p);
        try std.testing.expect((@intFromPtr(p) & 63) == 0);
    }

    {
        const p = try alignedAlloc(tag, 1, 0);
        defer free(p);
        const min_align = defaultAlign();
        try std.testing.expect((@intFromPtr(p) % min_align) == 0);
    }

    {
        const p = try alignedAlloc(tag, 1, 1);
        defer free(p);
        const min_align = defaultAlign();
        try std.testing.expect((@intFromPtr(p) % min_align) == 0);
    }
}

test "freeWithExpectedTag mismatch bumps registry counter" {
    const tag_good: u32 = 0x44434241;
    const tag_bad: u32 = 0x5A595857;

    const reg = registry.getRegistry();
    const before = @atomicLoad(u64, &reg.tag_mismatch_count, .monotonic);

    const p = try alloc(tag_good, 16);
    freeWithExpectedTag(p, tag_bad);

    const after = @atomicLoad(u64, &reg.tag_mismatch_count, .monotonic);
    try std.testing.expectEqual(before + 1, after);
}

test "realloc handles null and preserves prefix" {
    const tag: u32 = 0x44434241; // "ABCD"

    // NULL -> alloc
    const p0 = try realloc(tag, null, 16);
    defer free(p0);

    const p = try alloc(tag, 16);
    const buf16: [*]u8 = p;
    @memset(buf16[0..16], 0xA5);

    const p2 = try realloc(tag, p, 64);
    defer free(p2);

    const buf64: [*]u8 = p2;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        try std.testing.expectEqual(@as(u8, 0xA5), buf64[i]);
    }
}

test "non-slab allocations use arena backing when available" {
    // This test peeks at the internal header via the prefix. It is only intended
    // to validate backend selection, not ABI.
    const tag: u32 = 0x44434241;
    // Use a size that will not fit in the slab size classes once overhead is included.
    const p = try alloc(tag, 1024);
    defer free(p);

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(p) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *const AllocHeader = @ptrFromInt(hdr_addr);

    // Either arena or mmap is acceptable if arena init fails in the test environment.
    try std.testing.expect(hdr.kind == HDR_KIND_ARENA or hdr.kind == HDR_KIND_MMAP);
}

test "small allocations use slab backing when eligible" {
    const tag: u32 = 0x44434241;
    const p = try alloc(tag, 1);
    defer free(p);

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(p) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *const AllocHeader = @ptrFromInt(hdr_addr);

    try std.testing.expectEqual(HDR_KIND_SLAB, hdr.kind);
}
