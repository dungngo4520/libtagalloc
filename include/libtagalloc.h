#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Poolmon-style tag display is always 4 ASCII bytes. Tags are stored as a u32.
// Display order is little-endian byte order (lowest byte first).
//
// Example: tag = 'ABCD' should be encoded as:
//   ((uint32_t)'A') | ((uint32_t)'B'<<8) | ((uint32_t)'C'<<16) |
//   ((uint32_t)'D'<<24)

#define TAGALLOC_ABI_VERSION 1u

// Registry magic: ASCII "TAGALLOC" packed into a u64.
#define TAGALLOC_REGISTRY_MAGIC 0x544147414C4C4F43ULL

// Opaque-ish registry/segment types. The monitor may choose to interpret these
// layouts; the library guarantees ABI stability based on abi_version + sizes.

typedef struct tagalloc_registry_v1 {
  uint64_t magic;
  uint32_t abi_version;
  uint32_t header_size;

  uint8_t ptr_size;
  uint8_t endianness; // 1=little, 2=big
  uint16_t reserved0;

  uint64_t publish_seq; // even=stable, odd=writer in progress
  uint64_t flags;

  uintptr_t first_segment; // (struct tagalloc_agg_segment_v1*)

  uint32_t overflow_tag;
  uint32_t reserved1;

  uint64_t tag_mismatch_count;
  uint64_t dropped_tag_count;
} tagalloc_registry_v1;

typedef struct tagalloc_agg_segment_v1 {
  uint32_t segment_size;
  uint16_t entry_stride;
  uint16_t entry_count;
  uintptr_t next_segment; // (struct tagalloc_agg_segment_v1*)
  uint64_t reserved0;
  // entries follow
} tagalloc_agg_segment_v1;

typedef struct tagalloc_agg_entry_v1 {
  uint32_t tag;
  uint32_t reserved0; // may be used as an internal state field

  uint64_t alloc_count;
  uint64_t alloc_bytes;
  uint64_t free_count;
  uint64_t free_bytes;
} tagalloc_agg_entry_v1;

// Public API (ExAllocatePoolWithTag-inspired)
// size must be > 0.

void *tagalloc_alloc(uint32_t tag, size_t size);
void tagalloc_free(void *ptr);
void tagalloc_free_with_tag(void *ptr, uint32_t expected_tag);

// Returns pointer to exported registry header.
const tagalloc_registry_v1 *tagalloc_get_registry(void);

#ifdef __cplusplus
}
#endif
