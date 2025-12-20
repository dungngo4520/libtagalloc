const std = @import("std");

const tagalloc = @import("tagalloc");

pub fn main() !void {
    const stdout = std.fs.File.stdout();

    const pid = std.os.linux.getpid();
    {
        var buf: [256]u8 = undefined;
        const msg = try std.fmt.bufPrint(
            &buf,
            "tagalloc-fixture pid={d}\n",
            .{pid},
        );
        try stdout.writeAll(msg);
    }

    // Phase 1: allocate+free 100x 64B under tag "ABCD".
    const tag_abcd: u32 = 0x44434241; // "ABCD" (little-endian display order)
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const p = tagalloc.tagalloc_alloc(tag_abcd, 64) orelse return error.OutOfMemory;
        tagalloc.tagalloc_free(p);
    }

    // Phase 2: keep 50 allocations of 256B under tag "WXYZ" alive.
    const tag_wxyz: u32 = 0x5A595857; // "WXYZ"
    var kept: [50]?*anyopaque = [_]?*anyopaque{null} ** 50;
    i = 0;
    while (i < kept.len) : (i += 1) {
        kept[i] = tagalloc.tagalloc_alloc(tag_wxyz, 256) orelse return error.OutOfMemory;
    }

    try stdout.writeAll(
        "fixture ready; run poolreader now (press Enter to continue)\n",
    );

    // Block until any input byte (typically Enter). EOF also continues.
    var buf: [1]u8 = undefined;
    _ = std.fs.File.stdin().read(buf[0..]) catch {};

    // Phase 3: free the kept allocations.
    for (kept) |p_opt| {
        if (p_opt) |p| tagalloc.tagalloc_free(p);
    }

    try stdout.writeAll("fixture done\n");
}
