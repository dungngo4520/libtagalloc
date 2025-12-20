const std = @import("std");
const builtin = @import("builtin");

const tagalloc = @import("libtagalloc.zig");

fn stressEnabled() bool {
    const v = std.posix.getenv("TAGALLOC_STRESS") orelse return false;
    return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "yes");
}

pub fn runStress() !void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (!stressEnabled()) return;

    const ThreadCount: usize = 4;
    const Iterations: usize = 20_000;

    const sizes = [_]usize{ 8, 16, 32, 64, 128, 256, 1024, 4096, 8192 };
    const aligns = [_]usize{ 0, 0, 0, 16, 32, 64 };

    const WorkerCtx = struct {
        id: u32,
    };

    const worker = struct {
        fn run(ctx: *const WorkerCtx) void {
            var x: u64 = (@as(u64, ctx.id) + 1) *% 0x9E3779B97F4A7C15;

            var i: usize = 0;
            while (i < Iterations) : (i += 1) {
                // xorshift64*
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                const rnd = x *% 2685821657736338717;

                const size = sizes[@as(usize, @intCast(rnd % sizes.len))];

                // Generate a printable-ish 4CC tag, unique-ish per thread.
                const a: u32 = @as(u32, @intCast('A' + (ctx.id % 26)));
                const b: u32 = @as(u32, @intCast('a' + @as(u32, @intCast((rnd >> 8) % 26))));
                const c: u32 = @as(u32, @intCast('0' + @as(u32, @intCast((rnd >> 16) % 10))));
                const d: u32 = @as(u32, @intCast('0' + @as(u32, @intCast((rnd >> 24) % 10))));
                const tag: u32 = (a) | (b << 8) | (c << 16) | (d << 24);

                const use_aligned = (rnd & 1) == 1;
                const alignment = aligns[@as(usize, @intCast((rnd >> 32) % aligns.len))];

                const p = if (use_aligned)
                    tagalloc.tagalloc_aligned_alloc(tag, size, alignment)
                else
                    tagalloc.tagalloc_alloc(tag, size);

                if (p == null) {
                    // OOM is acceptable in stress environments; just stop this worker.
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

    var threads: [ThreadCount]std.Thread = undefined;
    var ctxs: [ThreadCount]WorkerCtx = undefined;

    var t: usize = 0;
    while (t < ThreadCount) : (t += 1) {
        ctxs[t] = .{ .id = @intCast(t) };
        threads[t] = std.Thread.spawn(.{}, worker.run, .{&ctxs[t]}) catch return error.TestUnexpectedResult;
    }

    for (threads) |th| th.join();
}
