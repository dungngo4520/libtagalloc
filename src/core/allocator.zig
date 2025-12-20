const std = @import("std");

const os = @import("../platform/os.zig");
const arena = @import("arena.zig");
const slab = @import("slab.zig");
const registry = @import("registry.zig");

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

var g_arena: arena.Arena = .{};

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

    if (alignment == 0 or effective_alignment <= defaultAlign()) {
        const overhead = hdr_size + prefix_size;
        if (slab.sizeToClassIndex(size)) |class_idx| {
            const class_size = slab.SlabSizeClasses[class_idx];
            if (size + overhead <= class_size) {
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
                    .reserved0 = 0,
                };

                const after_hdr = hdr_addr + hdr_size;
                const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, effective_alignment);
                const prefix_addr = user_addr - prefix_size;
                const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
                prefix_ptr.* = @intFromPtr(hdr);

                const user_ptr: [*]u8 = @ptrFromInt(user_addr);
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
            .reserved0 = 0,
        };

        const after_hdr = hdr_addr + hdr_size;
        const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, effective_alignment);
        const prefix_addr = user_addr - prefix_size;
        const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
        prefix_ptr.* = @intFromPtr(hdr);
        user_ptr = @ptrFromInt(user_addr);
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
            .reserved0 = 0,
        };

        const after_hdr = hdr_addr + hdr_size;
        const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, effective_alignment);
        const prefix_addr = user_addr - prefix_size;
        const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
        prefix_ptr.* = @intFromPtr(hdr);
        user_ptr = @ptrFromInt(user_addr);
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

    if (hdr.kind == HDR_KIND_SLAB) {
        slab.freeSlab(@ptrFromInt(hdr_addr));
    } else if (hdr.kind == HDR_KIND_ARENA) {
        g_arena.freeBlock(hdr_addr, hdr.arena_order);
    } else {
        os.osMunmap(@ptrFromInt(hdr.backing_base), hdr.backing_len);
    }
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
}

test "small allocations use arena backing when available" {
    // This test peeks at the internal header via the prefix. It is only intended
    // to validate backend selection, not ABI.
    const tag: u32 = 0x44434241;
    const p = try alloc(tag, 64);
    defer free(p);

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(p) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *const AllocHeader = @ptrFromInt(hdr_addr);

    // Either arena or mmap is acceptable if arena init fails in the test environment.
    try std.testing.expect(hdr.kind == HDR_KIND_ARENA or hdr.kind == HDR_KIND_MMAP);
}
