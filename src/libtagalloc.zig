const std = @import("std");

const abi = @import("abi");
const allocator = @import("core/allocator.zig");
const registry = @import("core/registry.zig");

pub const TaggedAllocator = @import("adapters/allocator.zig").TaggedAllocator;

pub const TAGALLOC_ABI_VERSION = abi.TAGALLOC_ABI_VERSION;
pub const TAGALLOC_REGISTRY_MAGIC = abi.TAGALLOC_REGISTRY_MAGIC;

pub const RegistryV1 = abi.RegistryV1;
pub const AggSegmentV1 = abi.AggSegmentV1;
pub const AggEntryV1 = abi.AggEntryV1;

pub const V1_HEADER_MIN_SIZE = abi.V1_HEADER_MIN_SIZE;
pub const V1_SEGMENT_HEADER_SIZE = abi.V1_SEGMENT_HEADER_SIZE;
pub const V1_ENTRY_MIN_SIZE = abi.V1_ENTRY_MIN_SIZE;

pub const DefaultAlign64: usize = allocator.DefaultAlign64;
pub const DefaultAlign32: usize = allocator.DefaultAlign32;

// C ABI exports
pub export fn tagalloc_alloc(tag: u32, size: usize) ?*anyopaque {
    const p = allocator.alloc(tag, size) catch return null;
    return @ptrCast(p);
}

pub export fn tagalloc_aligned_alloc(tag: u32, size: usize, alignment: usize) ?*anyopaque {
    const p = allocator.alignedAlloc(tag, size, alignment) catch return null;
    return @ptrCast(p);
}

pub export fn tagalloc_free(ptr: ?*anyopaque) void {
    if (ptr == null) return;
    allocator.free(@ptrCast(ptr.?));
}

pub export fn tagalloc_free_with_tag(ptr: ?*anyopaque, expected_tag: u32) void {
    if (ptr == null) return;
    allocator.freeWithExpectedTag(@ptrCast(ptr.?), expected_tag);
}

pub export fn tagalloc_realloc(tag: u32, ptr: ?*anyopaque, new_size: usize) ?*anyopaque {
    const p = allocator.realloc(
        tag,
        if (ptr) |p0| @as([*]u8, @ptrCast(p0)) else null,
        new_size,
    ) catch return null;
    return @ptrCast(p);
}

pub export fn tagalloc_get_registry() *const RegistryV1 {
    return registry.getRegistry();
}
