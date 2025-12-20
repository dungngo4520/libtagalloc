const std = @import("std");

const abi = @import("abi");
const pr = @import("poolreader");
const tagalloc = @import("tagalloc");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len >= 2 and std.mem.eql(u8, args[1], "--child")) {
        return childMain(allocator);
    }

    return parentMain(allocator);
}

fn readLineFromFile(file: std.fs.File, buf: []u8) !?[]u8 {
    var i: usize = 0;
    while (i < buf.len) {
        var one: [1]u8 = undefined;
        const n = try file.read(one[0..]);
        if (n == 0) {
            if (i == 0) return null;
            return buf[0..i];
        }
        if (one[0] == '\n') return buf[0..i];
        buf[i] = one[0];
        i += 1;
    }
    return error.LineTooLong;
}

fn childMain(allocator: std.mem.Allocator) !void {
    _ = allocator;

    const stdout = std.fs.File.stdout();

    const tag_abcd: u32 = 0x44434241; // "ABCD" (little-endian display order)
    const tag_wxyz: u32 = 0x5A595857; // "WXYZ"

    // 100 alloc/free of 64B under ABCD.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const p = tagalloc.tagalloc_alloc(tag_abcd, 64) orelse return error.OutOfMemory;
        tagalloc.tagalloc_free(p);
    }

    // 50 live allocations of 256B under WXYZ.
    var live: [50]?*anyopaque = [_]?*anyopaque{null} ** 50;
    i = 0;
    while (i < live.len) : (i += 1) {
        live[i] = tagalloc.tagalloc_alloc(tag_wxyz, 256) orelse return error.OutOfMemory;
    }

    // Tell parent our PID.
    var buf: [64]u8 = undefined;
    const pid = std.os.linux.getpid();
    const msg = try std.fmt.bufPrint(&buf, "pid={d}\n", .{pid});
    try stdout.writeAll(msg);

    // Wait for parent to signal.
    const stdin = std.fs.File.stdin();
    var one: [1]u8 = undefined;
    _ = try stdin.read(one[0..]);

    // Free live WXYZ allocations.
    i = 0;
    while (i < live.len) : (i += 1) {
        tagalloc.tagalloc_free(live[i]);
        live[i] = null;
    }

    try stdout.writeAll("freed\n");

    // Wait for parent to acknowledge before exiting so it can read stats.
    _ = try stdin.read(one[0..]);
}

fn parentMain(allocator: std.mem.Allocator) !void {
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);

    var child = std.process.Child.init(&.{ self_path, "--child" }, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    const child_stdout = child.stdout.?;

    var line_buf: [128]u8 = undefined;
    const line = (try readLineFromFile(child_stdout, &line_buf)) orelse return error.BadChildOutput;

    const pid = try parsePidLine(line);

    // Give the child a moment to finish publishing its tags.
    std.Thread.sleep(25 * std.time.ns_per_ms);

    const maps = try pr.readMaps(allocator, pid);
    defer pr.freeMaps(allocator, maps);

    const registry_addr = try pr.findRegistryAddr(allocator, pid, maps);
    const reg = try pr.readRegistryStable(pid, registry_addr);

    const tag_abcd: u32 = 0x44434241;
    const tag_wxyz: u32 = 0x5A595857;

    const abcd = (try pr.readTagStats(pid, reg.first_segment, tag_abcd)) orelse return error.TagNotFound;
    try std.testing.expectEqual(@as(u64, 100), abcd.alloc_count);
    try std.testing.expectEqual(@as(u64, 100), abcd.free_count);
    try std.testing.expectEqual(@as(u64, 100 * 64), abcd.alloc_bytes);
    try std.testing.expectEqual(@as(u64, 100 * 64), abcd.free_bytes);

    const wxyz = (try pr.readTagStats(pid, reg.first_segment, tag_wxyz)) orelse return error.TagNotFound;
    try std.testing.expectEqual(@as(u64, 50), wxyz.alloc_count);
    try std.testing.expectEqual(@as(u64, 0), wxyz.free_count);
    try std.testing.expectEqual(@as(u64, 50 * 256), wxyz.alloc_bytes);

    // Signal child to free and wait for ack.
    try child.stdin.?.writeAll("\n");
    const freed_line = (try readLineFromFile(child_stdout, &line_buf)) orelse return error.BadChildOutput;
    if (!std.mem.eql(u8, freed_line, "freed")) return error.BadChildOutput;

    // Re-read stats after free while the process is still alive.
    const w2 = (try pr.readTagStats(pid, reg.first_segment, tag_wxyz)) orelse return error.TagNotFound;
    try std.testing.expectEqual(@as(u64, 50), w2.alloc_count);
    try std.testing.expectEqual(@as(u64, 50), w2.free_count);
    try std.testing.expectEqual(@as(u64, 50 * 256), w2.free_bytes);

    // Let child exit.
    try child.stdin.?.writeAll("\n");
    _ = try child.wait();
}

fn parsePidLine(line: []const u8) !i32 {
    if (!std.mem.startsWith(u8, line, "pid=")) return error.BadChildOutput;
    const pid_u32 = try std.fmt.parseInt(u32, line[4..], 10);
    return @intCast(pid_u32);
}
