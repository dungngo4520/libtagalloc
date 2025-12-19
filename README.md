# libtagalloc

Minimal, cross-platform library, written in Zig, to track heap memory allocations with tags.
Inspired by the Windows API `ExAllocatePoolWithTag`.

## Build

```bash
zig build
```

Outputs:

- `zig-out/lib/libtagalloc.a`
- `zig-out/lib/libtagalloc.h`

## Status / scope

- Current backend is Linux-only and uses `mmap/munmap` (no libc heap dependency).
