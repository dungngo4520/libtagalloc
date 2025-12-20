const std = @import("std");
const builtin = @import("builtin");

const tagalloc = @import("tagalloc");

const WorkerCtx = struct {
    id: u32,
    iterations: usize,
    sizes: []const usize,
    aligns: []const usize,
};

pub fn main() !void {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const stdout = std.fs.File.stdout();

    var args_it = try std.process.argsWithAllocator(std.heap.page_allocator);
    defer args_it.deinit();

    _ = args_it.next(); // argv[0]

    const thread_count = parseArgUsize(args_it.next()) orelse 4;
    const iterations = parseArgUsize(args_it.next()) orelse 200_000;
    const runs = parseArgUsize(args_it.next()) orelse 5;

    {
        var buf: [256]u8 = undefined;
        const pid = std.os.linux.getpid();
        const msg = try std.fmt.bufPrint(
            &buf,
            "tagalloc-stress pid={d} threads={d} iters={d} runs={d}\n",
            .{ pid, thread_count, iterations, runs },
        );
        try stdout.writeAll(msg);
    }

    const sizes = [_]usize{ 8, 16, 32, 64, 128, 256, 1024, 4096, 8192 };
    const aligns = [_]usize{ 0, 0, 0, 16, 32, 64 };

    const worker = struct {
        fn run(ctx: *const WorkerCtx) void {
            var x: u64 = (@as(u64, ctx.id) + 1) *% 0x9E3779B97F4A7C15;

            var i: usize = 0;
            while (i < ctx.iterations) : (i += 1) {
                // xorshift64*
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                const rnd = x *% 2685821657736338717;

                const size = ctx.sizes[@as(usize, @intCast(rnd % ctx.sizes.len))];

                // Generate a printable-ish 4CC tag, unique-ish per thread.
                const a: u32 = @as(u32, @intCast('A' + (ctx.id % 26)));
                const b: u32 = @as(u32, @intCast('a' + @as(u32, @intCast((rnd >> 8) % 26))));
                const c: u32 = @as(u32, @intCast('0' + @as(u32, @intCast((rnd >> 16) % 10))));
                const d: u32 = @as(u32, @intCast('0' + @as(u32, @intCast((rnd >> 24) % 10))));
                const tag: u32 = (a) | (b << 8) | (c << 16) | (d << 24);

                const use_aligned = (rnd & 1) == 1;
                const alignment = ctx.aligns[@as(usize, @intCast((rnd >> 32) % ctx.aligns.len))];

                const p = if (use_aligned)
                    tagalloc.tagalloc_aligned_alloc(tag, size, alignment)
                else
                    tagalloc.tagalloc_alloc(tag, size);

                if (p == null) {
                    // OOM is acceptable here; just stop this worker.
                    return;
                }

                // Touch a few bytes to exercise mapping/arena memory.
                const fill: u8 = @truncate(rnd);
                @memset(@as([*]u8, @ptrCast(p.?))[0..@min(size, 32)], fill);

                if ((rnd & 0xF) == 0) {
                    tagalloc.tagalloc_free_with_tag(p.?, tag);
                } else {
                    tagalloc.tagalloc_free(p.?);
                }
            }
        }
    };

    var threads = try std.heap.page_allocator.alloc(std.Thread, thread_count);
    defer std.heap.page_allocator.free(threads);

    var ctxs = try std.heap.page_allocator.alloc(WorkerCtx, thread_count);
    defer std.heap.page_allocator.free(ctxs);

    const warmup_iters = @max(iterations / 10, 10_000);
    try stdout.writeAll("warmup...\n");
    _ = try runOnce(worker, &threads, &ctxs, sizes[0..], aligns[0..], warmup_iters);

    if (runs == 0) return;

    var results_ns = try std.heap.page_allocator.alloc(u64, runs);
    defer std.heap.page_allocator.free(results_ns);

    var r: usize = 0;
    while (r < runs) : (r += 1) {
        const elapsed_ns = try runOnce(worker, &threads, &ctxs, sizes[0..], aligns[0..], iterations);
        results_ns[r] = elapsed_ns;

        const total_ops = thread_count * iterations;
        const secs: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);
        const ops_per_s: f64 = if (secs == 0) 0 else @as(f64, @floatFromInt(total_ops)) / secs;
        const ns_per_op: f64 = if (total_ops == 0) 0 else @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(total_ops));

        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(
            &buf,
            "run {d}/{d}: {d} ops in {d}ms ({d:.2} ops/s, {d:.1} ns/op)\n",
            .{ r + 1, runs, total_ops, elapsed_ns / std.time.ns_per_ms, ops_per_s, ns_per_op },
        );
        try stdout.writeAll(msg);
    }

    const stats = computeStats(results_ns);
    const total_ops = thread_count * iterations;
    const best_ops_s = nsToOpsPerSec(stats.min_ns, total_ops);
    const median_ops_s = nsToOpsPerSec(stats.median_ns, total_ops);
    const worst_ops_s = nsToOpsPerSec(stats.max_ns, total_ops);

    var buf: [256]u8 = undefined;
    const msg = try std.fmt.bufPrint(
        &buf,
        "summary: best/median/worst ops/s = {d:.2} / {d:.2} / {d:.2}\n",
        .{ best_ops_s, median_ops_s, worst_ops_s },
    );
    try stdout.writeAll(msg);
}

fn runOnce(
    worker: anytype,
    threads: *[]std.Thread,
    ctxs: *[]WorkerCtx,
    sizes: []const usize,
    aligns: []const usize,
    iterations: usize,
) !u64 {
    const start_ns = std.time.nanoTimestamp();

    var t: usize = 0;
    while (t < threads.len) : (t += 1) {
        ctxs.*[t] = .{
            .id = @intCast(t),
            .iterations = iterations,
            .sizes = sizes,
            .aligns = aligns,
        };
        threads.*[t] = std.Thread.spawn(.{}, worker.run, .{&ctxs.*[t]}) catch return error.OutOfMemory;
    }
    for (threads.*) |th| th.join();

    const end_ns = std.time.nanoTimestamp();
    return @intCast(@max(end_ns - start_ns, 0));
}

const Stats = struct {
    min_ns: u64,
    median_ns: u64,
    max_ns: u64,
};

fn computeStats(samples_ns: []u64) Stats {
    if (samples_ns.len == 0) return .{ .min_ns = 0, .median_ns = 0, .max_ns = 0 };

    const tmp = std.heap.page_allocator.alloc(u64, samples_ns.len) catch unreachable;
    defer std.heap.page_allocator.free(tmp);
    @memcpy(tmp, samples_ns);
    std.sort.pdq(u64, tmp, {}, comptime std.sort.asc(u64));

    return .{
        .min_ns = tmp[0],
        .median_ns = tmp[tmp.len / 2],
        .max_ns = tmp[tmp.len - 1],
    };
}

fn nsToOpsPerSec(elapsed_ns: u64, total_ops: usize) f64 {
    const secs: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);
    return if (secs == 0) 0 else @as(f64, @floatFromInt(total_ops)) / secs;
}

fn parseArgUsize(s_opt: ?[]const u8) ?usize {
    const s = s_opt orelse return null;
    return std.fmt.parseInt(usize, s, 10) catch null;
}
