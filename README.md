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
