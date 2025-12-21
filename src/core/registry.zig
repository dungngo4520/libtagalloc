const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi");
const os = @import("../platform/os.zig");

pub const TAGALLOC_ABI_VERSION = abi.TAGALLOC_ABI_VERSION;
pub const TAGALLOC_REGISTRY_MAGIC = abi.TAGALLOC_REGISTRY_MAGIC;

pub const RegistryV1 = abi.RegistryV1;
pub const AggSegmentV1 = abi.AggSegmentV1;
pub const AggEntryV1 = abi.AggEntryV1;

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

// 0 = not initialized, 1 = initializing, 2 = initialized
var g_init_state: u8 = 0;

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

pub fn getRegistry() *const RegistryV1 {
    ensureInit();
    return &g_tagalloc_registry;
}

fn isLittleEndian() bool {
    return builtin.cpu.arch.endian() == .little;
}

pub fn ensureInit() void {
    // Called on hot paths; keep this cheap.
    if (@atomicLoad(u8, &g_init_state, .acquire) == 2) return;

    if (@cmpxchgStrong(u8, &g_init_state, 0, 1, .acq_rel, .acquire) == null) {
        // Winner initializes invariant fields.
        g_tagalloc_registry.endianness = if (isLittleEndian()) 1 else 2;
        g_tagalloc_registry.ptr_size = @intCast(@sizeOf(usize));
        g_tagalloc_registry.header_size = @intCast(@sizeOf(RegistryV1));
        g_tagalloc_registry.first_segment = @intFromPtr(&g_base_segment.header);
        @atomicStore(u8, &g_init_state, 2, .release);
        return;
    }

    // Someone else is initializing; wait until done.
    while (@atomicLoad(u8, &g_init_state, .acquire) != 2) {
        std.atomic.spinLoopHint();
    }
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

pub fn getOrInsertAggEntry(tag: u32) *AggEntryV1 {
    ensureInit();
    return findOrInsertEntry(tag);
}

pub fn noteAllocEntry(entry: *AggEntryV1, size: usize) void {
    bumpAlloc(entry, size);
}

pub fn noteFreeEntry(entry: *AggEntryV1, size: usize) void {
    bumpFree(entry, size);
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

    const map_len = std.mem.alignForward(usize, bytes_needed, os.pageSize());
    if (map_len > std.math.maxInt(u32)) return error.Overflow;
    if (entry_size > std.math.maxInt(u16)) return error.Overflow;
    if (capacity > std.math.maxInt(u16)) return error.Overflow;

    const base_ptr = try os.osMmap(map_len);
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

pub fn noteAlloc(tag: u32, size: usize) void {
    ensureInit();
    const entry = findOrInsertEntry(tag);
    bumpAlloc(entry, size);
}

pub fn noteFree(tag: u32, size: usize) void {
    ensureInit();
    const entry = findOrInsertEntry(tag);
    bumpFree(entry, size);
}

pub fn noteTagMismatch() void {
    _ = @atomicRmw(u64, &g_tagalloc_registry.tag_mismatch_count, .Add, 1, .monotonic);
}

test "registry initializes and points at base segment" {
    ensureInit();
    try std.testing.expectEqual(TAGALLOC_REGISTRY_MAGIC, g_tagalloc_registry.magic);
    try std.testing.expectEqual(TAGALLOC_ABI_VERSION, g_tagalloc_registry.abi_version);
    try std.testing.expect(g_tagalloc_registry.first_segment != 0);
}

test "segment list walking finds entries in appended segments" {
    ensureInit();

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

test "per-tag counters bump" {
    const tag: u32 = 0x44434241; // "ABCD" in little-endian display order

    ensureInit();
    const before = findOrInsertEntry(tag);
    const before_alloc_count = @atomicLoad(u64, &before.alloc_count, .monotonic);
    const before_alloc_bytes = @atomicLoad(u64, &before.alloc_bytes, .monotonic);
    const before_free_count = @atomicLoad(u64, &before.free_count, .monotonic);
    const before_free_bytes = @atomicLoad(u64, &before.free_bytes, .monotonic);

    noteAlloc(tag, 64);
    {
        const entry = findExistingEntry(tag) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(before_alloc_count + 1, @atomicLoad(u64, &entry.alloc_count, .monotonic));
        try std.testing.expectEqual(before_alloc_bytes + 64, @atomicLoad(u64, &entry.alloc_bytes, .monotonic));
    }

    noteFree(tag, 64);
    {
        const entry_after = findExistingEntry(tag) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(before_free_count + 1, @atomicLoad(u64, &entry_after.free_count, .monotonic));
        try std.testing.expectEqual(before_free_bytes + 64, @atomicLoad(u64, &entry_after.free_bytes, .monotonic));
    }
}

test "counter overflow saturates and sets flag" {
    const tag: u32 = 0x4F564552; // "REVO" in little-endian display order

    ensureInit();
    const entry = findOrInsertEntry(tag);

    const near_max = std.math.maxInt(u64) - 1;
    @atomicStore(u64, &entry.alloc_bytes, near_max, .monotonic);

    noteAlloc(tag, 8);

    try std.testing.expectEqual(std.math.maxInt(u64), @atomicLoad(u64, &entry.alloc_bytes, .monotonic));
    const flags = @atomicLoad(u64, &g_tagalloc_registry.flags, .monotonic);
    try std.testing.expect((flags & FLAG_COUNTER_OVERFLOW) != 0);
}

test "registry walk is stable under concurrent tag insertion" {
    ensureInit();

    const Worker = struct {
        stop: *const bool,

        fn run(ctx: *@This(), tid: usize) void {
            const seed64: u64 = 0x9E3779B9 ^ (@as(u64, tid) * 0x85EBCA6B);
            var x: u32 = @truncate(seed64);
            var i: usize = 0;
            while (!@atomicLoad(bool, ctx.stop, .acquire) and i < 20_000) : (i += 1) {
                // xorshift32
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                const tag: u32 = 0x5400_0000 | (x & 0x00FF_FFFF);
                noteAlloc(tag, 8);
            }
        }
    };

    var stop: bool = false;
    var worker: Worker = .{ .stop = &stop };

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, tid| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &worker, tid });
    }

    // Try to take a few consistent snapshots while writers are active.
    var snapshots: usize = 0;
    while (snapshots < 8) : (snapshots += 1) {
        var tries: usize = 0;
        while (tries < 10_000) : (tries += 1) {
            const seq0 = @atomicLoad(u64, &g_tagalloc_registry.publish_seq, .acquire);
            if ((seq0 & 1) != 0) continue;

            const first = @atomicLoad(usize, &g_tagalloc_registry.first_segment, .acquire);
            if (first == 0) return error.TestUnexpectedResult;

            var seg_addr: usize = first;
            var seg_count: usize = 0;
            while (seg_addr != 0) : (seg_count += 1) {
                if (seg_count > 128) return error.TestUnexpectedResult;
                const seg: *AggSegmentV1 = @ptrFromInt(seg_addr);

                const entry_stride: usize = @intCast(seg.entry_stride);
                const entry_count: usize = @intCast(seg.entry_count);
                if (entry_stride < @sizeOf(AggEntryV1)) return error.TestUnexpectedResult;
                if (entry_count == 0) return error.TestUnexpectedResult;

                const bytes_needed = try std.math.mul(usize, entry_stride, entry_count);
                const expected_min = @sizeOf(AggSegmentV1) + bytes_needed;
                if (seg.segment_size < expected_min) return error.TestUnexpectedResult;

                seg_addr = @atomicLoad(usize, &seg.next_segment, .acquire);
            }

            const seq1 = @atomicLoad(u64, &g_tagalloc_registry.publish_seq, .acquire);
            if (seq0 != seq1) continue;

            // Consistent snapshot.
            break;
        }
    }

    @atomicStore(bool, &stop, true, .release);
    for (threads) |t| t.join();
}
