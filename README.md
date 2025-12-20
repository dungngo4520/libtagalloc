# libtagalloc

Minimal tagged allocation library, written in Zig.
Inspired by the Windows API `ExAllocatePoolWithTag`.

## Build

```sh
zig build
zig build test
```

Outputs: `zig-out/lib/libtagalloc.{a,h}`, `zig-out/bin/*`

## Usage

```sh
# Run demo
zig build demo
./zig-out/bin/tagalloc-demo-zig

# Inspect live process
zig build poolreader
./zig-out/bin/tagalloc-poolreader <pid>
./zig-out/bin/tagalloc-poolreader <pid> --scan  # fallback
```

## Benchmark

```sh
zig build stress
./zig-out/bin/tagalloc-stress [threads] [iterations] [runs]
```
