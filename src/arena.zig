const std = @import("std");

const os = @import("os.zig");

pub const ArenaMinBlock: usize = 4096;
pub const ArenaSize64: usize = 64 * 1024 * 1024;
pub const ArenaSize32: usize = 16 * 1024 * 1024;

pub const ArenaSize: usize = if (@sizeOf(usize) == 8) ArenaSize64 else ArenaSize32;
pub const ArenaBlockCount: usize = ArenaSize / ArenaMinBlock;
pub const ArenaMaxOrder: u8 = @intCast(std.math.log2_int(usize, ArenaBlockCount));
pub const ArenaOrderCount: usize = @as(usize, ArenaMaxOrder) + 1;

const ArenaBitmapBits: usize = ArenaOrderCount * ArenaBlockCount;
const ArenaBitmapWords: usize = (ArenaBitmapBits + 63) / 64;

pub const Arena = struct {
    lock: std.Thread.Mutex = .{},
    base: usize = 0,
    initialized: bool = false,

    free_counts: [ArenaOrderCount]u32 = [_]u32{0} ** ArenaOrderCount,
    next_hint: [ArenaOrderCount]u32 = [_]u32{0} ** ArenaOrderCount,
    // Bitmap storing free blocks per order. For simplicity we store ArenaBlockCount bits for each order
    // (higher orders only use the prefix of the row).
    free_bitmap: [ArenaBitmapWords]u64 = [_]u64{0} ** ArenaBitmapWords,

    fn rowBitIndex(order: u8, idx: usize) usize {
        return @as(usize, order) * ArenaBlockCount + idx;
    }

    fn bitTest(self: *Arena, order: u8, idx: usize) bool {
        const bit = rowBitIndex(order, idx);
        const word = bit >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(bit & 63));
        return (self.free_bitmap[word] & mask) != 0;
    }

    fn bitSet(self: *Arena, order: u8, idx: usize) void {
        const bit = rowBitIndex(order, idx);
        const word = bit >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(bit & 63));
        self.free_bitmap[word] |= mask;
    }

    fn bitClear(self: *Arena, order: u8, idx: usize) void {
        const bit = rowBitIndex(order, idx);
        const word = bit >> 6;
        const mask: u64 = @as(u64, 1) << @as(u6, @intCast(bit & 63));
        self.free_bitmap[word] &= ~mask;
    }

    fn orderBlockSize(order: u8) usize {
        return ArenaMinBlock << @as(u6, @intCast(order));
    }

    fn initLocked(self: *Arena) !void {
        if (self.initialized) return;

        const base_ptr = try os.osMmap(ArenaSize);
        self.base = @intFromPtr(base_ptr);
        self.initialized = true;

        // Entire arena is initially one big free block.
        self.free_counts[ArenaMaxOrder] = 1;
        self.bitSet(ArenaMaxOrder, 0);
    }

    pub fn tryInit(self: *Arena) bool {
        self.lock.lock();
        defer self.lock.unlock();
        self.initLocked() catch return false;
        return true;
    }

    pub fn allocBlock(self: *Arena, want_order: u8) ?usize {
        self.lock.lock();
        defer self.lock.unlock();

        self.initLocked() catch return null;

        if (want_order > ArenaMaxOrder) return null;

        var order: u8 = want_order;
        while (order <= ArenaMaxOrder and self.free_counts[order] == 0) : (order += 1) {}
        if (order > ArenaMaxOrder) return null;

        const row_len: usize = ArenaBlockCount >> @as(u6, @intCast(order));
        var start: usize = self.next_hint[order];
        if (start >= row_len) start = 0;

        // Find any free block at this order (linear probe with wrap).
        var found_idx: ?usize = null;
        var i: usize = 0;
        while (i < row_len) : (i += 1) {
            const idx = (start + i) % row_len;
            if (self.bitTest(order, idx)) {
                found_idx = idx;
                self.next_hint[order] = @intCast((idx + 1) % row_len);
                break;
            }
        }
        const idx = found_idx orelse return null;

        self.bitClear(order, idx);
        self.free_counts[order] -= 1;

        // Split down to want_order, freeing the right buddy at each step.
        var cur_order: u8 = order;
        var cur_idx: usize = idx;
        while (cur_order > want_order) {
            cur_order -= 1;
            const right_buddy = cur_idx * 2 + 1;
            cur_idx = cur_idx * 2;
            self.bitSet(cur_order, right_buddy);
            self.free_counts[cur_order] += 1;
        }

        const block_size = orderBlockSize(want_order);
        const addr = self.base + cur_idx * block_size;
        return addr;
    }

    pub fn freeBlock(self: *Arena, block_addr: usize, order: u8) void {
        self.lock.lock();
        defer self.lock.unlock();

        if (!self.initialized) return;
        if (block_addr < self.base or block_addr >= self.base + ArenaSize) return;

        var cur_order: u8 = order;
        var cur_idx: usize = (block_addr - self.base) / orderBlockSize(cur_order);

        while (cur_order < ArenaMaxOrder) {
            const buddy_idx = cur_idx ^ 1;
            const row_len: usize = ArenaBlockCount >> @as(u6, @intCast(cur_order));
            if (buddy_idx >= row_len) break;
            if (!self.bitTest(cur_order, buddy_idx)) break;

            // Coalesce: remove buddy from free set and move up.
            self.bitClear(cur_order, buddy_idx);
            self.free_counts[cur_order] -= 1;
            cur_idx = @min(cur_idx, buddy_idx) / 2;
            cur_order += 1;
        }

        self.bitSet(cur_order, cur_idx);
        self.free_counts[cur_order] += 1;
    }
};

pub fn sizeToArenaOrder(bytes_needed: usize) ?u8 {
    if (bytes_needed == 0) return null;
    if (bytes_needed > ArenaSize) return null;
    const pow2 = std.math.ceilPowerOfTwo(usize, @max(bytes_needed, ArenaMinBlock)) catch return null;
    if (pow2 > ArenaSize) return null;
    const min_log = std.math.log2_int(usize, ArenaMinBlock);
    const log = std.math.log2_int(usize, pow2);
    const ord: isize = @as(isize, @intCast(log)) - @as(isize, @intCast(min_log));
    if (ord < 0 or ord > ArenaMaxOrder) return null;
    return @intCast(ord);
}
