const std = @import("std");

const tagalloc = @import("tagalloc");

// Benchmark: compare slab performance vs arena/mmap fallback
// Goal: demonstrate 2-3x improvement for slab-eligible sizes

pub fn main() !void {
    const stdout = std.fs.File.stdout();

    try fprint(stdout, "libtagalloc slab benchmark\n", .{});

    const sizes = [_]usize{ 16, 32, 64, 128, 256, 512 };
    const iterations: usize = 1000000;

    for (sizes) |size| {
        try benchmarkSize(stdout, size, iterations);
    }
}

fn benchmarkSize(stdout: std.fs.File, size: usize, iterations: usize) !void {
    const tag: u32 = 0x424E4348; // "HCNB" ("BENCH" in little-endian display)

    // Warmup
    {
        var i: usize = 0;
        while (i < 1000) : (i += 1) {
            const p = tagalloc.tagalloc_alloc(tag, size) orelse return error.OutOfMemory;
            tagalloc.tagalloc_free(p);
        }
    }

    const start = std.time.nanoTimestamp();
    {
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            const p = tagalloc.tagalloc_alloc(tag, size) orelse return error.OutOfMemory;
            tagalloc.tagalloc_free(p);
        }
    }
    const end = std.time.nanoTimestamp();

    const elapsed_ns: u64 = @intCast(end - start);
    const ns_per_op = elapsed_ns / iterations;
    const ops_per_sec = if (ns_per_op > 0) (1_000_000_000 / ns_per_op) else 0;

    try fprint(
        stdout,
        "size={d:>3}B  {d} ops in {d}ms  {d}ns/op  {d} ops/sec\n",
        .{ size, iterations, elapsed_ns / 1_000_000, ns_per_op, ops_per_sec },
    );
}

fn fprint(file: std.fs.File, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try file.writeAll(msg);
}
