const std = @import("std");

const os = @import("../platform/os.zig");

// Slab allocator for fixed-size hot paths
// Design: Per-size-class pools with per-thread magazines for lock-free fast path
//
// Size classes: 16, 32, 64, 128, 256, 512 bytes (6 classes)
// Each slab is one OS page containing fixed-size slots
// Slabs are organized in per-class pools with a free list
//
// Performance goal: O(1) allocation/free with no locks on the fast path (per-thread cache hit)
// Fallback: When thread cache misses, take a central lock to refill/flush

pub const SlabSizeClasses = [_]usize{ 16, 32, 64, 128, 256, 512 };
pub const SlabClassCount: usize = SlabSizeClasses.len;

const ThreadCacheCapacity: usize = 64;
const ThreadRefillBatch: usize = 32;
const ThreadFlushBatch: usize = 32;

// Map size to class index (0-5) or null if too large
pub fn sizeToClassIndex(size: usize) ?usize {
    if (size == 0 or size > SlabSizeClasses[SlabSizeClasses.len - 1]) return null;
    // Linear search is fine for 6 classes
    for (SlabSizeClasses, 0..) |class_size, i| {
        if (size <= class_size) return i;
    }
    return null;
}

// Slab metadata header (stored at the start of each slab page)
pub const SlabHeader = struct {
    const FreeBitmapWords: usize = 16; // 16*64 = 1024 slots max per slab page

    class_index: u8,
    slot_size: u16,
    slot_count: u16,
    free_count: u16, // number of free slots in this slab
    next_slab: ?*SlabHeader, // next slab in pool free list
    free_bitmap: [FreeBitmapWords]u64, // bitmap for up to FreeBitmapWords*64 slots

    fn init(class_index: u8, slot_size: usize) SlabHeader {
        const page = os.pageSize();
        const usable = page - @sizeOf(SlabHeader);
        const max_slots: usize = FreeBitmapWords * 64;
        const computed_slots: usize = usable / slot_size;
        const slots: u16 = @intCast(@min(computed_slots, max_slots));
        return .{
            .class_index = class_index,
            .slot_size = @intCast(slot_size),
            .slot_count = slots,
            .free_count = slots,
            .next_slab = null,
            .free_bitmap = [_]u64{std.math.maxInt(u64)} ** FreeBitmapWords,
        };
    }

    fn slotBase(self: *SlabHeader) [*]u8 {
        const header_end = @intFromPtr(self) + @sizeOf(SlabHeader);
        return @ptrFromInt(header_end);
    }

    fn slotAddr(self: *SlabHeader, slot_idx: usize) [*]u8 {
        const base = self.slotBase();
        const offset = slot_idx * @as(usize, self.slot_size);
        return @ptrFromInt(@intFromPtr(base) + offset);
    }

    fn bitTest(self: *SlabHeader, idx: usize) bool {
        const word = idx >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(idx & 63));
        return (self.free_bitmap[word] & mask) != 0;
    }

    fn bitSet(self: *SlabHeader, idx: usize) void {
        const word = idx >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(idx & 63));
        self.free_bitmap[word] |= mask;
    }

    fn bitClear(self: *SlabHeader, idx: usize) void {
        const word = idx >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(idx & 63));
        self.free_bitmap[word] &= ~mask;
    }

    pub fn allocSlot(self: *SlabHeader) ?[*]u8 {
        if (self.free_count == 0) return null;

        // Find first free slot (linear scan is acceptable for small bitmaps)
        var idx: usize = 0;
        while (idx < self.slot_count) : (idx += 1) {
            if (self.bitTest(idx)) {
                self.bitClear(idx);
                self.free_count -= 1;
                return self.slotAddr(idx);
            }
        }

        return null;
    }

    pub fn freeSlot(self: *SlabHeader, ptr: [*]u8) void {
        const base = @intFromPtr(self.slotBase());
        const addr = @intFromPtr(ptr);
        if (addr < base) return;

        const offset = addr - base;
        const slot_idx = offset / @as(usize, self.slot_size);
        if (slot_idx >= self.slot_count) return;

        if (self.bitTest(slot_idx)) {
            // Double free; already free. In debug builds this could be an error.
            return;
        }

        self.bitSet(slot_idx);
        self.free_count += 1;
    }

    pub fn ptrToSlabHeader(ptr: [*]u8) *SlabHeader {
        const page = os.pageSize();
        const addr = @intFromPtr(ptr);
        const slab_base = addr & ~(page - 1);
        return @ptrFromInt(slab_base);
    }
};

// Central pool for one size class (protected by lock)
pub const SlabPool = struct {
    lock: std.Thread.Mutex = .{},
    class_index: u8,
    slot_size: usize,
    partial_slabs: ?*SlabHeader = null, // slabs with some free slots
    full_slabs: ?*SlabHeader = null, // slabs with no free slots (kept for tracking)

    pub fn init(class_index: u8, slot_size: usize) SlabPool {
        return .{
            .class_index = class_index,
            .slot_size = slot_size,
        };
    }

    pub fn allocSlot(self: *SlabPool) ![*]u8 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.allocSlotLocked();
    }

    fn allocSlotLocked(self: *SlabPool) ![*]u8 {
        // Try allocating from an existing partial slab
        if (self.partial_slabs) |slab| {
            if (slab.allocSlot()) |ptr| {
                // If slab is now full, move it to full list
                if (slab.free_count == 0) {
                    self.partial_slabs = slab.next_slab;
                    slab.next_slab = self.full_slabs;
                    self.full_slabs = slab;
                }
                return ptr;
            }
        }

        // No partial slabs available; allocate a new slab
        const slab = try self.createSlab();
        slab.next_slab = self.partial_slabs;
        self.partial_slabs = slab;

        return slab.allocSlot() orelse return error.SlabAllocationFailed;
    }

    fn allocBatchLocked(self: *SlabPool, out: *[ThreadCacheCapacity]?[*]u8, want: usize) usize {
        var got: usize = 0;
        while (got < want and got < ThreadCacheCapacity) : (got += 1) {
            out[got] = self.allocSlotLocked() catch break;
        }
        return got;
    }

    pub fn freeSlot(self: *SlabPool, ptr: [*]u8) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.freeSlotLocked(ptr);
    }

    fn freeSlotLocked(self: *SlabPool, ptr: [*]u8) void {
        const slab_hdr = SlabHeader.ptrToSlabHeader(ptr);
        const was_full = (slab_hdr.free_count == 0);
        slab_hdr.freeSlot(ptr);

        // If slab was full and now has free slots, move to partial list
        if (was_full and slab_hdr.free_count > 0) {
            self.removeFromList(&self.full_slabs, slab_hdr);
            slab_hdr.next_slab = self.partial_slabs;
            self.partial_slabs = slab_hdr;
        }
    }

    fn freeBatchLocked(self: *SlabPool, ptrs: []const [*]u8) void {
        for (ptrs) |p| self.freeSlotLocked(p);
    }

    fn createSlab(self: *SlabPool) !*SlabHeader {
        const page = os.pageSize();
        const ptr = try os.osMmap(page);
        const slab: *SlabHeader = @ptrCast(@alignCast(ptr));
        slab.* = SlabHeader.init(self.class_index, self.slot_size);
        return slab;
    }

    fn removeFromList(self: *SlabPool, head: *?*SlabHeader, slab: *SlabHeader) void {
        _ = self;
        var current = head.*;
        var prev: ?*SlabHeader = null;

        while (current) |node| {
            if (node == slab) {
                if (prev) |p| {
                    p.next_slab = node.next_slab;
                } else {
                    head.* = node.next_slab;
                }
                return;
            }
            prev = node;
            current = node.next_slab;
        }
    }
};

// Global slab pools (one per size class)
var g_slab_pools: [SlabClassCount]SlabPool = undefined;
var g_slab_initialized: bool = false;
var g_slab_init_lock: std.Thread.Mutex = .{};

pub fn ensureInit() void {
    if (@atomicLoad(bool, &g_slab_initialized, .acquire)) return;

    g_slab_init_lock.lock();
    defer g_slab_init_lock.unlock();

    if (g_slab_initialized) return;

    for (SlabSizeClasses, 0..) |size, i| {
        g_slab_pools[i] = SlabPool.init(@intCast(i), size);
    }

    @atomicStore(bool, &g_slab_initialized, true, .release);
}

pub fn allocSlab(size: usize) ![*]u8 {
    ensureInit();

    const class_idx = sizeToClassIndex(size) orelse return error.SizeNotInSlabRange;
    return try threadAlloc(@intCast(class_idx));
}

pub fn freeSlab(ptr: [*]u8) void {
    const slab = SlabHeader.ptrToSlabHeader(ptr);
    const class_idx = slab.class_index;
    if (class_idx >= SlabClassCount) return;

    threadFree(class_idx, ptr);
}

const ThreadCache = struct {
    counts: [SlabClassCount]u8 = [_]u8{0} ** SlabClassCount,
    slots: [SlabClassCount][ThreadCacheCapacity]?[*]u8 = [_][ThreadCacheCapacity]?[*]u8{[_]?[*]u8{null} ** ThreadCacheCapacity} ** SlabClassCount,
};

threadlocal var g_thread_cache: ThreadCache = .{};

fn threadAlloc(class_idx: u8) ![*]u8 {
    const idx: usize = @intCast(class_idx);
    var count = g_thread_cache.counts[idx];
    if (count != 0) {
        count -= 1;
        g_thread_cache.counts[idx] = count;
        const p = g_thread_cache.slots[idx][count].?;
        g_thread_cache.slots[idx][count] = null;
        return p;
    }

    // Refill from central pool under one lock.
    var buf: [ThreadCacheCapacity]?[*]u8 = [_]?[*]u8{null} ** ThreadCacheCapacity;
    const pool = &g_slab_pools[idx];
    pool.lock.lock();
    const got = pool.allocBatchLocked(&buf, ThreadRefillBatch);
    pool.lock.unlock();
    if (got == 0) return error.SlabAllocationFailed;

    // Keep N-1 in cache, return one.
    var i: usize = 0;
    while (i + 1 < got) : (i += 1) {
        g_thread_cache.slots[idx][i] = buf[i];
    }
    g_thread_cache.counts[idx] = @intCast(got - 1);
    return buf[got - 1].?;
}

fn threadFree(class_idx: u8, ptr: [*]u8) void {
    const idx: usize = @intCast(class_idx);
    var count: usize = g_thread_cache.counts[idx];
    if (count < ThreadCacheCapacity) {
        g_thread_cache.slots[idx][count] = ptr;
        g_thread_cache.counts[idx] = @intCast(count + 1);
        return;
    }

    // Cache full: flush a batch to the central pool, then store the new ptr.
    const pool = &g_slab_pools[idx];
    pool.lock.lock();
    var batch: [ThreadFlushBatch][*]u8 = undefined;
    var i: usize = 0;
    while (i < ThreadFlushBatch) : (i += 1) {
        const p = g_thread_cache.slots[idx][count - 1].?;
        g_thread_cache.slots[idx][count - 1] = null;
        count -= 1;
        batch[i] = p;
    }
    g_thread_cache.counts[idx] = @intCast(count);
    pool.freeBatchLocked(batch[0..]);
    pool.lock.unlock();

    // Now we have room.
    g_thread_cache.slots[idx][count] = ptr;
    g_thread_cache.counts[idx] = @intCast(count + 1);
}

test "sizeToClassIndex maps correctly" {
    try std.testing.expectEqual(@as(?usize, 0), sizeToClassIndex(1));
    try std.testing.expectEqual(@as(?usize, 0), sizeToClassIndex(16));
    try std.testing.expectEqual(@as(?usize, 1), sizeToClassIndex(17));
    try std.testing.expectEqual(@as(?usize, 1), sizeToClassIndex(32));
    try std.testing.expectEqual(@as(?usize, 2), sizeToClassIndex(33));
    try std.testing.expectEqual(@as(?usize, 5), sizeToClassIndex(512));
    try std.testing.expectEqual(@as(?usize, null), sizeToClassIndex(513));
    try std.testing.expectEqual(@as(?usize, null), sizeToClassIndex(0));
}

test "slab alloc and free" {
    ensureInit();

    const size: usize = 64;
    const ptr1 = try allocSlab(size);
    const ptr2 = try allocSlab(size);

    // Pointers should be different
    try std.testing.expect(@intFromPtr(ptr1) != @intFromPtr(ptr2));

    // Free and re-allocate
    freeSlab(ptr1);
    const ptr3 = try allocSlab(size);

    // ptr3 should reuse ptr1's slot
    try std.testing.expectEqual(@intFromPtr(ptr1), @intFromPtr(ptr3));

    freeSlab(ptr2);
    freeSlab(ptr3);
}

test "slab cross-size isolation" {
    ensureInit();

    const ptr16 = try allocSlab(16);
    const ptr64 = try allocSlab(64);
    const ptr256 = try allocSlab(256);

    // All should be on different slabs (different pages)
    const slab16 = SlabHeader.ptrToSlabHeader(ptr16);
    const slab64 = SlabHeader.ptrToSlabHeader(ptr64);
    const slab256 = SlabHeader.ptrToSlabHeader(ptr256);

    try std.testing.expect(slab16 != slab64);
    try std.testing.expect(slab16 != slab256);
    try std.testing.expect(slab64 != slab256);

    freeSlab(ptr16);
    freeSlab(ptr64);
    freeSlab(ptr256);
}
