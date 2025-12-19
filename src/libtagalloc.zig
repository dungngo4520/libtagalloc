const std = @import("std");
const builtin = @import("builtin");

pub const TAGALLOC_ABI_VERSION: u32 = 1;
pub const TAGALLOC_REGISTRY_MAGIC: u64 = 0x5441_4741_4C4C_4F43; // "TAGALLOC"

pub const DefaultAlign64: usize = 16;
pub const DefaultAlign32: usize = 8;

fn defaultAlign() usize {
    return if (@sizeOf(usize) == 8) DefaultAlign64 else DefaultAlign32;
}

pub const RegistryV1 = extern struct {
    magic: u64,
    abi_version: u32,
    header_size: u32,

    ptr_size: u8,
    endianness: u8, // 1=little, 2=big
    reserved0: u16,

    publish_seq: u64, // even=stable, odd=writer in progress
    flags: u64,

    first_segment: usize, // *const AggSegmentV1

    overflow_tag: u32,
    reserved1: u32,

    tag_mismatch_count: u64,
    dropped_tag_count: u64,
};

pub const AggSegmentV1 = extern struct {
    segment_size: u32,
    entry_stride: u16,
    entry_count: u16,
    next_segment: usize, // *const AggSegmentV1
    reserved0: u64,
    // entries follow
};

pub const AggEntryV1 = extern struct {
    tag: u32,
    reserved0: u32, // internal state (0=empty, 1=used)

    alloc_count: u64,
    alloc_bytes: u64,
    free_count: u64,
    free_bytes: u64,
};

pub const V1_HEADER_MIN_SIZE: usize = @sizeOf(RegistryV1);
pub const V1_SEGMENT_HEADER_SIZE: usize = @sizeOf(AggSegmentV1);
pub const V1_ENTRY_MIN_SIZE: usize = @sizeOf(AggEntryV1);

const FLAG_DEGRADED: u64 = 1 << 0;
const FLAG_COUNTER_OVERFLOW: u64 = 1 << 1;

const OVERFLOW_TAG: u32 = 0x3F_3F_3F_3F; // "????"

const BaseCapacity: usize = 1024;

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
    mapping_len: usize,
    user_size: usize,
    tag: u32,
    reserved0: u32,
};

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

fn findOrInsertEntry(tag: u32) *AggEntryV1 {
    // Fast path: probe without lock for existing entry.
    const cap_mask = BaseCapacity - 1;
    var idx: usize = hashTag(tag) & cap_mask;

    var i: usize = 0;
    while (i < BaseCapacity) : (i += 1) {
        const entry = &g_base_segment.entries[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .monotonic);
        const cur_tag = @atomicLoad(u32, &entry.tag, .monotonic);
        if (state == 1 and cur_tag == tag) return entry;
        if (state == 0) break;
        idx = (idx + 1) & cap_mask;
    }

    // Insert path.
    g_tag_table_lock.lock();
    defer g_tag_table_lock.unlock();

    idx = hashTag(tag) & cap_mask;
    i = 0;
    while (i < BaseCapacity) : (i += 1) {
        const entry = &g_base_segment.entries[idx];
        const state = @atomicLoad(u32, &entry.reserved0, .monotonic);
        if (state == 1) {
            if (@atomicLoad(u32, &entry.tag, .monotonic) == tag) return entry;
        } else {
            // Claim.
            @atomicStore(u32, &entry.tag, tag, .monotonic);
            @atomicStore(u32, &entry.reserved0, 1, .monotonic);
            return entry;
        }
        idx = (idx + 1) & cap_mask;
    }

    // Degraded: overflow bucket.
    _ = @atomicRmw(u64, &g_tagalloc_registry.flags, .Or, FLAG_DEGRADED, .monotonic);
    _ = @atomicRmw(u64, &g_tagalloc_registry.dropped_tag_count, .Add, 1, .monotonic);

    // Slot 0 is reserved as overflow bucket.
    const overflow = &g_base_segment.entries[0];
    @atomicStore(u32, &overflow.tag, OVERFLOW_TAG, .monotonic);
    @atomicStore(u32, &overflow.reserved0, 1, .monotonic);
    return overflow;
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

fn allocInternal(tag: u32, size: usize) ![*]u8 {
    if (size == 0) return error.InvalidSize;

    ensureRegistryInit();

    const hdr_size = @sizeOf(AllocHeader);
    const prefix_size = @sizeOf(usize);
    const alignment = defaultAlign();

    const raw_needed = hdr_size + prefix_size + size + alignment;
    const map_len = std.mem.alignForward(usize, raw_needed, pageSize());

    const base_ptr = try osMmap(map_len);

    const hdr: *AllocHeader = @ptrCast(@alignCast(base_ptr));
    hdr.* = .{
        .mapping_len = map_len,
        .user_size = size,
        .tag = tag,
        .reserved0 = 0,
    };

    const after_hdr = @intFromPtr(base_ptr) + hdr_size;
    const user_addr = std.mem.alignForward(usize, after_hdr + prefix_size, alignment);
    const prefix_addr = user_addr - prefix_size;

    const prefix_ptr: *usize = @ptrFromInt(prefix_addr);
    prefix_ptr.* = @intFromPtr(hdr);

    const user_ptr: [*]u8 = @ptrFromInt(user_addr);

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

    osMunmap(@ptrCast(hdr), hdr.mapping_len);
}

// C ABI exports
pub export fn tagalloc_alloc(tag: u32, size: usize) ?*anyopaque {
    const p = allocInternal(tag, size) catch return null;
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
