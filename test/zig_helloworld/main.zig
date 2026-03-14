const std = @import("std");
const foo = @import("foo");

pub fn main() !void {
    const hello = "hello";
    const world = "world";
    const hello_world = hello ++ " " ++ world;
    std.debug.print("first message\n", .{});
    const answer = foo.add(1, 5);
    std.debug.print("{s} {d}\n", .{hello_world, answer});
}
