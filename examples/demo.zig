const std = @import("std");

const tagalloc = @import("tagalloc");

pub fn main() !void {
    // Simple self-demo: allocate/free a few tagged blocks in a loop.
    // Use tagalloc-poolreader against this PID.

    const stdout = std.fs.File.stdout();

    {
        var buf: [128]u8 = undefined;
        const pid = std.os.linux.getpid();
        const msg = try std.fmt.bufPrint(&buf, "tagalloc-demo pid={d}\n", .{pid});
        try stdout.writeAll(msg);
    }

    const tags = [_]u32{
        0x44434241, // "ABCD" (little-endian display order)
        0x5A595857, // "WXYZ"
        0x31323334, // "4321"
    };

    const sizes = [_]usize{ 64, 256, 4096 };

    var iter: usize = 0;
    while (true) : (iter += 1) {
        var i: usize = 0;
        while (i < tags.len) : (i += 1) {
            const tag = tags[i];
            const size = sizes[i % sizes.len];

            const p = tagalloc.tagalloc_alloc(tag, size) orelse return error.OutOfMemory;
            const fill: u8 = @truncate(iter);
            @memset(@as([*]u8, @ptrCast(p))[0..@min(size, 32)], fill);
            tagalloc.tagalloc_free(p);
        }

        std.Thread.sleep(100 * std.time.ns_per_ms);
    }
}
