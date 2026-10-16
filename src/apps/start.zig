const std = @import("std");
const moxi = @import("moxi");

const client = moxi.client;

pub fn main(init: std.process.Init.Minimal) !void {
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    const executable = args.next() orelse {
        std.debug.print("usage: moxi-start <executable>\n", .{});
        return error.MissingExecutable;
    };

    var allocator_state: std.heap.DebugAllocator(.{}) = .init;
    const allocator = allocator_state.allocator();
    var connection = try client.Connection.init(allocator);
    defer connection.deinit();
    var buffer: [4096]u8 = undefined;
    try connection.send(.start, executable, &buffer);
}
