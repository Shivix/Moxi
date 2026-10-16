const std = @import("std");
const moxi = @import("moxi");

const client = moxi.client;

pub fn main(init: std.process.Init.Minimal) !void {
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    const movement = args.next() orelse "1";

    var allocator_state: std.heap.DebugAllocator(.{}) = .init;
    const allocator = allocator_state.allocator();
    var connection = try client.Connection.init(allocator);
    defer connection.deinit();
    var buffer: [4096]u8 = undefined;
    try connection.send(.next, movement, &buffer);
    const response = try connection.receive(&buffer);
    if (std.mem.eql(u8, response.body, "finished")) std.process.exit(1);
}
