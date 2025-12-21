# libtagalloc

Minimal tagged allocation library, written in Zig.
Inspired by the Windows API `ExAllocatePoolWithTag`.

Requires: Zig 0.15.0+.

## Build

```sh
zig build
zig build test
```

Outputs: `zig-out/lib/libtagalloc.{a,h}`, `zig-out/bin/*`

## Usage

### Tag encoding (poolmon-style)

Tags are `u32`, displayed as 4 ASCII bytes in little-endian byte order (lowest byte first).

```c
// "ABCD" tag:
uint32_t tag = ((uint32_t)'A') | ((uint32_t)'B'<<8) | ((uint32_t)'C'<<16) | ((uint32_t)'D'<<24);
```

```sh
# Run demos
zig build demo
./zig-out/bin/tagalloc-demo-zig
./zig-out/bin/tagalloc-demo-cpp

# Inspect live process
zig build poolreader
./zig-out/bin/tagalloc-poolreader <pid>
./zig-out/bin/tagalloc-poolreader <pid> --scan  # fallback
```

## Benchmark

The repository includes a small alloc/free benchmark that compares libtagalloc
against a baseline `std.heap.GeneralPurposeAllocator` loop.

```sh
zig build benchmark -Doptimize=ReleaseFast
./zig-out/bin/tagalloc-bench-slab
```

Example output (ReleaseFast, x86_64 Linux):

```text
libtagalloc slab benchmark
tagalloc size= 16B  1000000 ops in 25ms  25ns/op  40000000 ops/sec
std-gpa size= 16B  1000000 ops in 3573ms  3573ns/op  279876 ops/sec

tagalloc size= 32B  1000000 ops in 24ms  24ns/op  41666666 ops/sec
std-gpa size= 32B  1000000 ops in 3536ms  3536ns/op  282805 ops/sec

tagalloc size= 64B  1000000 ops in 25ms  25ns/op  40000000 ops/sec
std-gpa size= 64B  1000000 ops in 3570ms  3570ns/op  280112 ops/sec

tagalloc size=128B  1000000 ops in 25ms  25ns/op  40000000 ops/sec
std-gpa size=128B  1000000 ops in 3539ms  3539ns/op  282565 ops/sec

tagalloc size=256B  1000000 ops in 25ms  25ns/op  40000000 ops/sec
std-gpa size=256B  1000000 ops in 3555ms  3555ns/op  281293 ops/sec

tagalloc size=512B  1000000 ops in 25ms  25ns/op  40000000 ops/sec
std-gpa size=512B  1000000 ops in 3550ms  3550ns/op  281690 ops/sec
```
