const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");

pub const TAGALLOC_ABI_VERSION = abi.TAGALLOC_ABI_VERSION;
pub const TAGALLOC_REGISTRY_MAGIC = abi.TAGALLOC_REGISTRY_MAGIC;

pub const RegistryV1 = abi.RegistryV1;
pub const AggSegmentV1 = abi.AggSegmentV1;
pub const AggEntryV1 = abi.AggEntryV1;

pub const V1_HEADER_MIN_SIZE = abi.V1_HEADER_MIN_SIZE;
pub const V1_SEGMENT_HEADER_SIZE = abi.V1_SEGMENT_HEADER_SIZE;
pub const V1_ENTRY_MIN_SIZE = abi.V1_ENTRY_MIN_SIZE;

pub const DefaultAlign64: usize = 16;
pub const DefaultAlign32: usize = 8;

fn defaultAlign() usize {
    return if (@sizeOf(usize) == 8) DefaultAlign64 else DefaultAlign32;
}

const FLAG_DEGRADED: u64 = 1 << 0;
const FLAG_COUNTER_OVERFLOW: u64 = 1 << 1;

const OVERFLOW_TAG: u32 = 0x3F_3F_3F_3F; // "????"

const BaseCapacity: usize = 1024;
const SegmentCapacity: usize = 1024;

const ENTRY_EMPTY: u32 = 0;
const ENTRY_USED: u32 = 1;
const ENTRY_WRITING: u32 = 2;

const BaseSegment = struct {
    header: AggSegmentV1,
    entries: [BaseCapacity]AggEntryV1,
};

var g_base_segment: BaseSegment = .{
    .header = .{
        .segment_size = @intCast(@sizeOf(BaseSegment)),
        .entry_stride = @intCast(@sizeOf(AggEntryV1)),
        .entry_count = @intCast(BaseCapacity),
        .next_segment = 0,
        .reserved0 = 0,
    },
    .entries = [_]AggEntryV1{.{
        .tag = 0,
        .reserved0 = 0,
        .alloc_count = 0,
        .alloc_bytes = 0,
        .free_count = 0,
        .free_bytes = 0,
    }} ** BaseCapacity,
};

var g_tag_table_lock: std.Thread.Mutex = .{};

pub export var g_tagalloc_registry: RegistryV1 = .{
    .magic = TAGALLOC_REGISTRY_MAGIC,
    .abi_version = TAGALLOC_ABI_VERSION,
    .header_size = @intCast(@sizeOf(RegistryV1)),

    .ptr_size = @intCast(@sizeOf(usize)),
    .endianness = 1, // little
    .reserved0 = 0,

    .publish_seq = 0,
    .flags = 0,

    .first_segment = 0,

    .overflow_tag = OVERFLOW_TAG,
    .reserved1 = 0,

    .tag_mismatch_count = 0,
    .dropped_tag_count = 0,
};

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

const ArenaMinBlock: usize = 4096;
const ArenaSize64: usize = 64 * 1024 * 1024;
const ArenaSize32: usize = 16 * 1024 * 1024;

const ArenaSize: usize = if (@sizeOf(usize) == 8) ArenaSize64 else ArenaSize32;
const ArenaBlockCount: usize = ArenaSize / ArenaMinBlock;
const ArenaMaxOrder: u8 = @intCast(std.math.log2_int(usize, ArenaBlockCount));
const ArenaOrderCount: usize = @as(usize, ArenaMaxOrder) + 1;

const ArenaBitmapBits: usize = ArenaOrderCount * ArenaBlockCount;
const ArenaBitmapWords: usize = (ArenaBitmapBits + 63) / 64;

const Arena = struct {
    lock: std.Thread.Mutex = .{},
    base: usize = 0,
    initialized: bool = false,

    free_counts: [ArenaOrderCount]u32 = [_]u32{0} ** ArenaOrderCount,
    next_hint: [ArenaOrderCount]u32 = [_]u32{0} ** ArenaOrderCount,
    // Bitmap storing free blocks per order. For simplicity we store ArenaBlockCount bits for each order
    // (higher orders only use the prefix of the row).
    free_bitmap: [ArenaBitmapWords]u64 = [_]u64{0} ** ArenaBitmapWords,

    fn rowBitIndex(order: u8, idx: usize) usize {
        return @as(usize, order) * ArenaBlockCount + idx;
    }

    fn bitTest(self: *Arena, order: u8, idx: usize) bool {
        const bit = rowBitIndex(order, idx);
        const word = bit >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(bit & 63));
        return (self.free_bitmap[word] & mask) != 0;
    }

    fn bitSet(self: *Arena, order: u8, idx: usize) void {
        const bit = rowBitIndex(order, idx);
        const word = bit >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(bit & 63));
        self.free_bitmap[word] |= mask;
    }

    fn bitClear(self: *Arena, order: u8, idx: usize) void {
        const bit = rowBitIndex(order, idx);
        const word = bit >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(bit & 63));
        self.free_bitmap[word] &= ~mask;
    }

    fn orderBlockSize(order: u8) usize {
        return ArenaMinBlock << @as(u6, @intCast(order));
    }

    fn initLocked(self: *Arena) !void {
        if (self.initialized) return;

        const base_ptr = try osMmap(ArenaSize);
        self.base = @intFromPtr(base_ptr);
        self.initialized = true;

        // Entire arena is initially one big free block.
        self.free_counts[ArenaMaxOrder] = 1;
        self.bitSet(ArenaMaxOrder, 0);
    }

    fn tryInit(self: *Arena) bool {
        self.lock.lock();
        defer self.lock.unlock();
        self.initLocked() catch return false;
        return true;
    }

    fn allocBlock(self: *Arena, want_order: u8) ?usize {
        self.lock.lock();
        defer self.lock.unlock();

        self.initLocked() catch return null;

        if (want_order > ArenaMaxOrder) return null;

        var order: u8 = want_order;
        while (order <= ArenaMaxOrder and self.free_counts[order] == 0) : (order += 1) {}
        if (order > ArenaMaxOrder) return null;

        const row_len: usize = ArenaBlockCount >> @as(u6, @intCast(order));
        var start: usize = self.next_hint[order];
        if (start >= row_len) start = 0;

        // Find any free block at this order (linear probe with wrap).
        var found_idx: ?usize = null;
        var i: usize = 0;
        while (i < row_len) : (i += 1) {
            const idx = (start + i) % row_len;
            if (self.bitTest(order, idx)) {
                found_idx = idx;
                self.next_hint[order] = @intCast((idx + 1) % row_len);
                break;
            }
        }
        const idx = found_idx orelse return null;

        self.bitClear(order, idx);
        self.free_counts[order] -= 1;

        // Split down to want_order, freeing the right buddy at each step.
        var cur_order: u8 = order;
        var cur_idx: usize = idx;
        while (cur_order > want_order) {
            cur_order -= 1;
            const right_buddy = cur_idx * 2 + 1;
            cur_idx = cur_idx * 2;
            self.bitSet(cur_order, right_buddy);
            self.free_counts[cur_order] += 1;
        }

        const block_size = orderBlockSize(want_order);
        const addr = self.base + cur_idx * block_size;
        return addr;
    }

    fn freeBlock(self: *Arena, block_addr: usize, order: u8) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (!self.initialized) return;
        if (block_addr < self.base or block_addr >= self.base + ArenaSize) return;

        var cur_order: u8 = order;
        var cur_idx: usize = (block_addr - self.base) / orderBlockSize(cur_order);

        while (cur_order < ArenaMaxOrder) {
            const buddy_idx = cur_idx ^ 1;
            const row_len: usize = ArenaBlockCount >> @as(u6, @intCast(cur_order));
            if (buddy_idx >= row_len) break;
            if (!self.bitTest(cur_order, buddy_idx)) break;

            // Coalesce: remove buddy from free set and move up.
            self.bitClear(cur_order, buddy_idx);
            self.free_counts[cur_order] -= 1;
            cur_idx = @min(cur_idx, buddy_idx) / 2;
            cur_order += 1;
        }

        self.bitSet(cur_order, cur_idx);
        self.free_counts[cur_order] += 1;
    }
};

var g_arena: Arena = .{};

fn sizeToArenaOrder(bytes_needed: usize) ?u8 {
    if (bytes_needed == 0) return null;
    if (bytes_needed > ArenaSize) return null;
    const pow2 = std.math.ceilPowerOfTwo(usize, @max(bytes_needed, ArenaMinBlock)) catch return null;
    if (pow2 > ArenaSize) return null;
    const min_log = std.math.log2_int(usize, ArenaMinBlock);
    const log = std.math.log2_int(usize, pow2);
    const ord: isize = @as(isize, @intCast(log)) - @as(isize, @intCast(min_log));
    if (ord < 0 or ord > ArenaMaxOrder) return null;
    return @intCast(ord);
}

fn isLittleEndian() bool {
    return builtin.cpu.arch.endian() == .little;
}

fn ensureRegistryInit() void {
    // Keep this idempotent and cheap; called on entrypoints.
    g_tagalloc_registry.endianness = if (isLittleEndian()) 1 else 2;
    g_tagalloc_registry.ptr_size = @intCast(@sizeOf(usize));
    g_tagalloc_registry.header_size = @intCast(@sizeOf(RegistryV1));
    g_tagalloc_registry.first_segment = @intFromPtr(&g_base_segment.header);
}

fn hashTag(tag: u32) usize {
    // Knuth multiplicative hash.
    return @as(usize, tag) * 2654435761;
}

fn atomicAddSaturating(ptr: *u64, value: u64) void {
    // Best-effort saturating add.
    // We intentionally keep this simple; statistics only.
    while (true) {
        const cur = @atomicLoad(u64, ptr, .monotonic);
        if (cur == std.math.maxInt(u64)) {
            return;
        }
        const next = if (std.math.maxInt(u64) - cur < value) std.math.maxInt(u64) else cur + value;
        const swapped = @cmpxchgWeak(u64, ptr, cur, next, .monotonic, .monotonic);
        if (swapped == null) {
            if (next == std.math.maxInt(u64) and cur != std.math.maxInt(u64)) {
                _ = @atomicRmw(u64, &g_tagalloc_registry.flags, .Or, FLAG_COUNTER_OVERFLOW, .monotonic);
            }
            return;
        }
    }
}

fn bumpAlloc(entry: *AggEntryV1, size: usize) void {
    _ = @atomicRmw(u64, &entry.alloc_count, .Add, 1, .monotonic);
    atomicAddSaturating(&entry.alloc_bytes, @intCast(size));
}

fn bumpFree(entry: *AggEntryV1, size: usize) void {
    _ = @atomicRmw(u64, &entry.free_count, .Add, 1, .monotonic);
    atomicAddSaturating(&entry.free_bytes, @intCast(size));
}

fn segmentEntriesPtr(seg: *AggSegmentV1) [*]AggEntryV1 {
    const base = @intFromPtr(seg) + @sizeOf(AggSegmentV1);
    return @ptrFromInt(base);
}

fn findInSegment(seg: *AggSegmentV1, tag: u32) ?*AggEntryV1 {
    const count: usize = @intCast(seg.entry_count);
    if (count == 0) return null;

    const mask = count - 1;
    var idx: usize = hashTag(tag) & mask;

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const entry = &segmentEntriesPtr(seg)[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .acquire);
        if (state == ENTRY_EMPTY) return null;
        if (state == ENTRY_USED and @atomicLoad(u32, &entry.tag, .acquire) == tag) return entry;
        idx = (idx + 1) & mask;
    }

    return null;
}

fn insertInSegment(seg: *AggSegmentV1, tag: u32) ?*AggEntryV1 {
    const count: usize = @intCast(seg.entry_count);
    if (count == 0) return null;

    const mask = count - 1;
    var idx: usize = hashTag(tag) & mask;

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const entry = &segmentEntriesPtr(seg)[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .acquire);
        if (state == ENTRY_USED) {
            if (@atomicLoad(u32, &entry.tag, .acquire) == tag) return entry;
        } else if (state == ENTRY_EMPTY) {
            // Publish in two steps so lock-free readers never treat a slot as
            // empty while the tag field is being written.
            @atomicStore(u32, &entry.reserved0, ENTRY_WRITING, .release);
            @atomicStore(u32, &entry.tag, tag, .release);
            @atomicStore(u32, &entry.reserved0, ENTRY_USED, .release);
            return entry;
        }
        idx = (idx + 1) & mask;
    }

    return null;
}

fn createAggSegment(capacity: usize) !*AggSegmentV1 {
    // capacity must be a power of two for mask-based probing.
    if (capacity == 0 or !std.math.isPowerOfTwo(capacity)) return error.InvalidSize;

    const entry_size = @sizeOf(AggEntryV1);
    const header_size = @sizeOf(AggSegmentV1);
    var bytes_needed = try std.math.mul(usize, capacity, entry_size);
    bytes_needed = try std.math.add(usize, bytes_needed, header_size);

    const map_len = std.mem.alignForward(usize, bytes_needed, pageSize());
    if (map_len > std.math.maxInt(u32)) return error.Overflow;
    if (entry_size > std.math.maxInt(u16)) return error.Overflow;
    if (capacity > std.math.maxInt(u16)) return error.Overflow;

    const base_ptr = try osMmap(map_len);
    const seg: *AggSegmentV1 = @ptrCast(@alignCast(base_ptr));
    seg.* = .{
        .segment_size = @intCast(map_len),
        .entry_stride = @intCast(entry_size),
        .entry_count = @intCast(capacity),
        .next_segment = 0,
        .reserved0 = 0,
    };
    // Entries are zeroed by mmap.
    return seg;
}

fn publishBegin() void {
    _ = @atomicRmw(u64, &g_tagalloc_registry.publish_seq, .Add, 1, .acq_rel);
}

fn publishEnd() void {
    _ = @atomicRmw(u64, &g_tagalloc_registry.publish_seq, .Add, 1, .acq_rel);
}

fn appendAggSegmentLocked() !*AggSegmentV1 {
    // Caller must hold g_tag_table_lock.
    publishBegin();
    errdefer publishEnd();

    const new_seg = try createAggSegment(SegmentCapacity);

    // Walk to tail and link.
    var tail: *AggSegmentV1 = &g_base_segment.header;
    while (true) {
        const next = @atomicLoad(usize, &tail.next_segment, .acquire);
        if (next == 0) break;
        tail = @ptrFromInt(next);
    }

    @atomicStore(usize, &tail.next_segment, @intFromPtr(new_seg), .release);
    publishEnd();
    return new_seg;
}

fn findOrInsertEntry(tag: u32) *AggEntryV1 {
    // Fast path: probe without lock for existing entry.
    const cap_mask = BaseCapacity - 1;
    var idx: usize = hashTag(tag) & cap_mask;

    var i: usize = 0;
    while (i < BaseCapacity) : (i += 1) {
        const entry = &g_base_segment.entries[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .acquire);
        const cur_tag = @atomicLoad(u32, &entry.tag, .acquire);
        if (state == ENTRY_USED and cur_tag == tag) return entry;
        if (state == ENTRY_EMPTY) break;
        idx = (idx + 1) & cap_mask;
    }

    // Missed in base; check appended segments without taking locks.
    var next_seg = @atomicLoad(usize, &g_base_segment.header.next_segment, .acquire);
    while (next_seg != 0) {
        const seg: *AggSegmentV1 = @ptrFromInt(next_seg);
        if (findInSegment(seg, tag)) |found| return found;
        next_seg = @atomicLoad(usize, &seg.next_segment, .acquire);
    }

    // Insert path.
    g_tag_table_lock.lock();
    defer g_tag_table_lock.unlock();

    // Re-check all segments under lock to avoid duplicates.
    if (findExistingEntry(tag)) |existing| return existing;

    idx = hashTag(tag) & cap_mask;
    i = 0;
    while (i < BaseCapacity) : (i += 1) {
        const entry = &g_base_segment.entries[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .acquire);
        if (state == ENTRY_USED) {
            if (@atomicLoad(u32, &entry.tag, .acquire) == tag) return entry;
        } else if (state == ENTRY_EMPTY) {
            // Claim (two-step publish for lock-free readers).
            @atomicStore(u32, &entry.reserved0, ENTRY_WRITING, .release);
            @atomicStore(u32, &entry.tag, tag, .release);
            @atomicStore(u32, &entry.reserved0, ENTRY_USED, .release);
            return entry;
        }
        idx = (idx + 1) & cap_mask;
    }

    // Base full: try appended segments.
    next_seg = @atomicLoad(usize, &g_base_segment.header.next_segment, .acquire);
    while (next_seg != 0) {
        const seg: *AggSegmentV1 = @ptrFromInt(next_seg);
        if (insertInSegment(seg, tag)) |inserted| return inserted;
        next_seg = @atomicLoad(usize, &seg.next_segment, .acquire);
    }

    // Need to grow the segment list.
    const new_seg = appendAggSegmentLocked() catch {
        // Degraded: overflow bucket.
        _ = @atomicRmw(u64, &g_tagalloc_registry.flags, .Or, FLAG_DEGRADED, .monotonic);
        _ = @atomicRmw(u64, &g_tagalloc_registry.dropped_tag_count, .Add, 1, .monotonic);

        // Slot 0 is reserved as overflow bucket.
        const overflow = &g_base_segment.entries[0];
        @atomicStore(u32, &overflow.tag, OVERFLOW_TAG, .release);
        @atomicStore(u32, &overflow.reserved0, ENTRY_USED, .release);
        return overflow;
    };

    if (insertInSegment(new_seg, tag)) |inserted| return inserted;

    // Should be impossible: the new segment is empty.
    _ = @atomicRmw(u64, &g_tagalloc_registry.flags, .Or, FLAG_DEGRADED, .monotonic);
    _ = @atomicRmw(u64, &g_tagalloc_registry.dropped_tag_count, .Add, 1, .monotonic);
    const overflow = &g_base_segment.entries[0];
    @atomicStore(u32, &overflow.tag, OVERFLOW_TAG, .release);
    @atomicStore(u32, &overflow.reserved0, ENTRY_USED, .release);
    return overflow;
}

fn findExistingEntry(tag: u32) ?*AggEntryV1 {
    const cap_mask = BaseCapacity - 1;
    var idx: usize = hashTag(tag) & cap_mask;
    var i: usize = 0;
    while (i < BaseCapacity) : (i += 1) {
        const entry = &g_base_segment.entries[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .acquire);
        if (state == ENTRY_EMPTY) break;
        if (state == ENTRY_USED and @atomicLoad(u32, &entry.tag, .acquire) == tag) return entry;
        idx = (idx + 1) & cap_mask;
    }

    var next_seg = @atomicLoad(usize, &g_base_segment.header.next_segment, .acquire);
    while (next_seg != 0) {
        const seg: *AggSegmentV1 = @ptrFromInt(next_seg);
        if (findInSegment(seg, tag)) |found| return found;
        next_seg = @atomicLoad(usize, &seg.next_segment, .acquire);
    }

    return null;
}

fn pageSize() usize {
    return std.heap.pageSize();
}

fn osMmap(len: usize) ![*]u8 {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const linux = std.os.linux;
    const prot: usize = linux.PROT.READ | linux.PROT.WRITE;
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };

    const addr = linux.mmap(null, len, prot, flags, -1, 0);
    const err = linux.E.init(addr);
    if (err != .SUCCESS) return switch (err) {
        .NOMEM => error.OutOfMemory,
        else => error.OutOfMemory,
    };

    return @as([*]u8, @ptrFromInt(addr));
}

fn osMunmap(ptr: [*]u8, len: usize) void {
    if (builtin.os.tag != .linux) return;

    const linux = std.os.linux;
    _ = linux.munmap(ptr, len);
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

    ensureRegistryInit();

    const hdr_size = @sizeOf(AllocHeader);
    const prefix_size = @sizeOf(usize);
    const effective_alignment = try normalizeAlignment(alignment);

    var raw_needed = try std.math.add(usize, hdr_size, prefix_size);
    raw_needed = try std.math.add(usize, raw_needed, size);
    raw_needed = try std.math.add(usize, raw_needed, effective_alignment);

    const arena_order = sizeToArenaOrder(raw_needed);

    var hdr: *AllocHeader = undefined;
    var user_ptr: [*]u8 = undefined;

    if (arena_order) |ord| blk: {
        // If arena init fails, fall back to mmap-per-allocation.
        if (!g_arena.tryInit()) break :blk;
        const block_addr = g_arena.allocBlock(ord) orelse break :blk;

        const hdr_addr = block_addr; // block base
        hdr = @ptrFromInt(hdr_addr);
        hdr.* = .{
            .backing_base = g_arena.base,
            .backing_len = ArenaSize,
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
        break :blk;
    } else {
        // Not eligible for arena.
    }

    // mmap fallback
    if (@TypeOf(hdr) == *AllocHeader and @intFromPtr(hdr) != 0 and hdr.kind == HDR_KIND_ARENA) {
        // already initialized in arena path
    } else {
        const map_len = std.mem.alignForward(usize, raw_needed, pageSize());
        const base_ptr = try osMmap(map_len);
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

    const entry = findOrInsertEntry(tag);
    bumpAlloc(entry, size);

    return user_ptr;
}

fn freeInternal(ptr: [*]u8, expected_tag: ?u32) void {
    if (@intFromPtr(ptr) == 0) return;

    ensureRegistryInit();

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(ptr) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *AllocHeader = @ptrFromInt(hdr_addr);

    if (expected_tag) |exp| {
        if (hdr.tag != exp) {
            _ = @atomicRmw(u64, &g_tagalloc_registry.tag_mismatch_count, .Add, 1, .monotonic);
        }
    }

    const entry = findOrInsertEntry(hdr.tag);
    bumpFree(entry, hdr.user_size);

    if (hdr.kind == HDR_KIND_ARENA) {
        g_arena.freeBlock(hdr_addr, hdr.arena_order);
    } else {
        osMunmap(@ptrFromInt(hdr.backing_base), hdr.backing_len);
    }
}

// C ABI exports
pub export fn tagalloc_alloc(tag: u32, size: usize) ?*anyopaque {
    const p = allocInternal(tag, size, 0) catch return null;
    return @ptrCast(p);
}

pub export fn tagalloc_aligned_alloc(tag: u32, size: usize, alignment: usize) ?*anyopaque {
    const p = allocInternal(tag, size, alignment) catch return null;
    return @ptrCast(p);
}

pub export fn tagalloc_free(ptr: ?*anyopaque) void {
    if (ptr == null) return;
    freeInternal(@ptrCast(ptr.?), null);
}

pub export fn tagalloc_free_with_tag(ptr: ?*anyopaque, expected_tag: u32) void {
    if (ptr == null) return;
    freeInternal(@ptrCast(ptr.?), expected_tag);
}

pub export fn tagalloc_get_registry() *const RegistryV1 {
    ensureRegistryInit();
    return &g_tagalloc_registry;
}

test "size==0 returns null via C ABI" {
    try std.testing.expect(tagalloc_alloc(0x41414141, 0) == null);
}

test "aligned alloc returns properly aligned pointer" {
    const tag: u32 = 0x44434241; // "ABCD" in little-endian display order

    {
        const p = tagalloc_aligned_alloc(tag, 1, 64) orelse return error.TestUnexpectedResult;
        defer tagalloc_free(p);
        try std.testing.expect((@intFromPtr(p) & 63) == 0);
    }

    {
        const p = tagalloc_aligned_alloc(tag, 1, 0) orelse return error.TestUnexpectedResult;
        defer tagalloc_free(p);
        const min_align = defaultAlign();
        try std.testing.expect((@intFromPtr(p) % min_align) == 0);
    }
}

test "small allocations use arena backing when available" {
    // This test peeks at the internal header via the prefix. It is only intended
    // to validate backend selection, not ABI.
    const tag: u32 = 0x44434241;
    const p = tagalloc_alloc(tag, 64) orelse return error.TestUnexpectedResult;
    defer tagalloc_free(p);

    const prefix_size = @sizeOf(usize);
    const prefix_addr = @intFromPtr(p) - prefix_size;
    const hdr_addr = (@as(*const usize, @ptrFromInt(prefix_addr))).*;
    const hdr: *const AllocHeader = @ptrFromInt(hdr_addr);

    // Either arena or mmap is acceptable if arena init fails in the test environment.
    try std.testing.expect(hdr.kind == HDR_KIND_ARENA or hdr.kind == HDR_KIND_MMAP);
}

test "registry initializes and points at base segment" {
    const reg = tagalloc_get_registry();
    try std.testing.expectEqual(TAGALLOC_REGISTRY_MAGIC, reg.magic);
    try std.testing.expectEqual(TAGALLOC_ABI_VERSION, reg.abi_version);
    try std.testing.expect(reg.first_segment != 0);
}

test "segment list walking finds entries in appended segments" {
    ensureRegistryInit();

    const before_seq = @atomicLoad(u64, &g_tagalloc_registry.publish_seq, .acquire);

    g_tag_table_lock.lock();
    const seg = appendAggSegmentLocked() catch {
        g_tag_table_lock.unlock();
        return error.TestUnexpectedResult;
    };

    // Insert a tag into the new segment (not into base).
    const tag: u32 = 0x5A595857; // "WXYZ" in little-endian display order
    const inserted = insertInSegment(seg, tag) orelse {
        g_tag_table_lock.unlock();
        return error.TestUnexpectedResult;
    };
    g_tag_table_lock.unlock();

    const after_seq = @atomicLoad(u64, &g_tagalloc_registry.publish_seq, .acquire);
    try std.testing.expect((after_seq & 1) == 0);
    try std.testing.expectEqual(before_seq + 2, after_seq);

    const found = findOrInsertEntry(tag);
    try std.testing.expectEqual(@intFromPtr(inserted), @intFromPtr(found));
}

test "alloc/free bumps per-tag counters" {
    const tag: u32 = 0x44434241; // "ABCD" in little-endian display order

    const before = findOrInsertEntry(tag);
    const before_alloc_count = @atomicLoad(u64, &before.alloc_count, .monotonic);
    const before_alloc_bytes = @atomicLoad(u64, &before.alloc_bytes, .monotonic);
    const before_free_count = @atomicLoad(u64, &before.free_count, .monotonic);
    const before_free_bytes = @atomicLoad(u64, &before.free_bytes, .monotonic);

    {
        const p = tagalloc_alloc(tag, 64) orelse return error.TestUnexpectedResult;
        defer tagalloc_free(p);

        const entry = findExistingEntry(tag) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(before_alloc_count + 1, @atomicLoad(u64, &entry.alloc_count, .monotonic));
        try std.testing.expectEqual(before_alloc_bytes + 64, @atomicLoad(u64, &entry.alloc_bytes, .monotonic));
    }

    const entry_after = findExistingEntry(tag) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(before_free_count + 1, @atomicLoad(u64, &entry_after.free_count, .monotonic));
    try std.testing.expectEqual(before_free_bytes + 64, @atomicLoad(u64, &entry_after.free_bytes, .monotonic));
}
