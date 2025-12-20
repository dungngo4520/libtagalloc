# libtagalloc

Minimal tagged allocation library, written in Zig.
Inspired by the Windows API `ExAllocatePoolWithTag`.

## Build

```bash
zig build --summary all
```

Outputs:

- `zig-out/lib/libtagalloc.a`
- `zig-out/lib/libtagalloc.h`

## Status / scope

- Current backend is Linux-only and uses `mmap/munmap` (no libc heap dependency).

## Tests

Default unit tests:

```bash
zig build test --summary all
```

The multithread stress test is **opt-in**:

```bash
TAGALLOC_STRESS=1 zig build test --summary all
```

## Demo + poolreader

Build Zig demo:

```bash
zig build demo-zig --summary all
./zig-out/bin/tagalloc-demo-zig
```

Build C++ demo:

```bash
zig build demo-cpp --summary all
./zig-out/bin/tagalloc-demo-cpp
```

In another terminal, build and run poolreader (may require elevated privileges):

```bash
zig build poolreader --summary all
./zig-out/bin/tagalloc-poolreader <pid>
```
