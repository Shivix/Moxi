const std = @import("std");
const moxi = @import("moxi");

const client = moxi.client;

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;
    var allocator_state: std.heap.DebugAllocator(.{}) = .init;
    const allocator = allocator_state.allocator();
    var connection = try client.Connection.init(allocator);
    defer connection.deinit();
    var buffer: [4096]u8 = undefined;
    try connection.send(.source, "line", &buffer);
    const response = try connection.receive(&buffer);
    std.debug.print("{s}\n", .{response.body});
}
