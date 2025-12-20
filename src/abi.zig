const std = @import("std");

pub const TAGALLOC_VERSION = "0.1.0";
pub const TAGALLOC_ABI_VERSION: u32 = 1;
pub const TAGALLOC_REGISTRY_MAGIC: u64 = 0x5441_4741_4C4C_4F43; // "TAGALLOC"

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
    reserved0: u32, // internal state

    alloc_count: u64,
    alloc_bytes: u64,
    free_count: u64,
    free_bytes: u64,
};

pub const V1_HEADER_MIN_SIZE: usize = @sizeOf(RegistryV1);
pub const V1_SEGMENT_HEADER_SIZE: usize = @sizeOf(AggSegmentV1);
pub const V1_ENTRY_MIN_SIZE: usize = @sizeOf(AggEntryV1);

pub fn tagToAscii(tag: u32) [4]u8 {
    // Poolmon-style: little-endian byte order (lowest byte first), non-printables -> '.'
    var out: [4]u8 = undefined;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const b: u8 = @truncate(tag >> @as(u5, @intCast(i * 8)));
        out[i] = if (std.ascii.isPrint(b)) b else '.';
    }
    return out;
}
