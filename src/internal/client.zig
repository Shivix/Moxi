const std = @import("std");

pub const protocol = struct {
    pub const port: u16 = 44500;
    pub const delimiter: u8 = 1;

    pub const Command = enum {
        start,
        next,
        breakpoint,
        source,
        response,
    };

    pub const Message = struct {
        command: Command,
        body: []const u8,
    };

    pub fn name(command: Command) []const u8 {
        return @tagName(command);
    }

    pub fn parse(input: []const u8) !Command {
        if (std.mem.eql(u8, input, "step")) return .next;
        return std.meta.stringToEnum(Command, input) orelse error.UnknownCommand;
    }

    pub fn write_response(stream: *const std.Io.net.Stream, io: std.Io, body: []const u8, buffer: []u8) !void {
        return write(stream, io, .response, body, buffer);
    }

    pub fn write(stream: *const std.Io.net.Stream, io: std.Io, command: Command, body: []const u8, buffer: []u8) !void {
        var writer = stream.writer(io, buffer);
        try writer.interface.writeAll(name(command));
        try writer.interface.writeByte(delimiter);
        try writer.interface.writeAll(body);
        try writer.interface.writeByte(0);
        try writer.interface.flush();
    }

    pub fn read(stream: std.Io.net.Stream, io: std.Io, buffer: []u8) !Message {
        var reader = stream.reader(io, buffer);
        const message = (try reader.interface.takeDelimiter(0)) orelse return error.EndOfStream;
        const split = std.mem.indexOfScalar(u8, message, delimiter) orelse return error.InvalidMessage;
        return .{
            .command = try parse(message[0..split]),
            .body = message[split + 1 ..],
        };
    }
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    threaded: *std.Io.Threaded,
    io: std.Io,
    stream: std.Io.net.Stream,

    pub fn init(allocator: std.mem.Allocator) !Connection {
        const threaded = try allocator.create(std.Io.Threaded);
        errdefer allocator.destroy(threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = protocol.port } };
        const stream = address.connect(io, .{ .mode = .stream }) catch |err| {
            threaded.deinit();
            return err;
        };
        return .{ .allocator = allocator, .threaded = threaded, .io = io, .stream = stream };
    }

    pub fn deinit(self: *Connection) void {
        self.stream.close(self.io);
        self.threaded.deinit();
        self.allocator.destroy(self.threaded);
    }

    pub fn send(self: *Connection, command: protocol.Command, body: []const u8, buffer: []u8) !void {
        try protocol.write(&self.stream, self.io, command, body, buffer);
    }

    pub fn receive(self: *Connection, buffer: []u8) !protocol.Message {
        return protocol.read(self.stream, self.io, buffer);
    }
};
