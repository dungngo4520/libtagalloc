const std = @import("std");

const tagalloc = @import("tagalloc");

// Benchmark: compare tagalloc vs a baseline std heap allocator.

pub fn main() !void {
    const stdout = std.fs.File.stdout();

    try fprint(stdout, "libtagalloc slab benchmark\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const std_alloc = gpa.allocator();

    const sizes = [_]usize{ 16, 32, 64, 128, 256, 512 };
    const iterations: usize = 1000000;

    for (sizes) |size| {
        try benchmarkSize(stdout, std_alloc, size, iterations);
    }
}

fn benchmarkSize(stdout: std.fs.File, std_alloc: std.mem.Allocator, size: usize, iterations: usize) !void {
    const tag: u32 = 0x424E4348; // "HCNB" ("BENCH" in little-endian display)

    // Warmup
    try warmupTagalloc(tag, size);
    try warmupStd(std_alloc, size);

    const t_tag = try benchTagalloc(tag, size, iterations);
    const t_std = try benchStd(std_alloc, size, iterations);

    try printRow(stdout, "tagalloc", size, iterations, t_tag);
    try printRow(stdout, "std-gpa", size, iterations, t_std);
    try stdout.writeAll("\n");
}

fn warmupTagalloc(tag: u32, size: usize) !void {
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const p = tagalloc.tagalloc_alloc(tag, size) orelse return error.OutOfMemory;
        tagalloc.tagalloc_free(p);
    }
}

fn warmupStd(alloc: std.mem.Allocator, size: usize) !void {
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const buf = try alloc.alloc(u8, size);
        alloc.free(buf);
    }
}

fn benchTagalloc(tag: u32, size: usize, iterations: usize) !u64 {
    const start = std.time.nanoTimestamp();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const p = tagalloc.tagalloc_alloc(tag, size) orelse return error.OutOfMemory;
        tagalloc.tagalloc_free(p);
    }
    const end = std.time.nanoTimestamp();
    return @intCast(end - start);
}

fn benchStd(alloc: std.mem.Allocator, size: usize, iterations: usize) !u64 {
    const start = std.time.nanoTimestamp();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const buf = try alloc.alloc(u8, size);
        alloc.free(buf);
    }
    const end = std.time.nanoTimestamp();
    return @intCast(end - start);
}

fn printRow(stdout: std.fs.File, name: []const u8, size: usize, iterations: usize, elapsed_ns: u64) !void {
    const ns_per_op = if (iterations == 0) 0 else (elapsed_ns / iterations);
    const ops_per_sec = if (ns_per_op > 0) (1_000_000_000 / ns_per_op) else 0;
    try fprint(
        stdout,
        "{s:>7} size={d:>3}B  {d} ops in {d}ms  {d}ns/op  {d} ops/sec\n",
        .{ name, size, iterations, elapsed_ns / 1_000_000, ns_per_op, ops_per_sec },
    );
}

fn fprint(file: std.fs.File, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, fmt, args);
    try file.writeAll(msg);
}
