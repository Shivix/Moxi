const std = @import("std");

pub const SourceLocation = struct {
    file: std.debug.Coverage.File.Index,
    line: u32,
    column: u32,
};

pub const Resolver = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dwarf: *std.debug.Dwarf,
    endian: std.builtin.Endian,
    load_bias: u64,
    coverage: std.debug.Coverage = .init,

    pub fn deinit(self: *Resolver) void {
        self.coverage.deinit(self.allocator);
    }

    pub fn location(self: *Resolver, address: u64) !?SourceLocation {
        var output: [1]std.debug.Coverage.SourceLocation = undefined;
        try self.coverage.resolveAddressesDwarf(
            self.allocator,
            self.io,
            self.endian,
            &.{address -| self.load_bias},
            &output,
            self.dwarf,
        );
        if (output[0].file == .invalid) return null;
        return .{ .file = output[0].file, .line = output[0].line, .column = output[0].column };
    }

    pub fn print(self: *Resolver, source_location: SourceLocation) void {
        const file = self.coverage.fileAt(source_location.file);
        const directory = self.coverage.stringAt(@fromBackingInt(@intCast(file.directory_index)));
        const basename = self.coverage.stringAt(file.basename);
        if (directory.len == 0) {
            std.debug.print("{s}:{d}:{d}\n", .{ basename, source_location.line, source_location.column });
        } else {
            std.debug.print("{s}/{s}:{d}:{d}\n", .{ directory, basename, source_location.line, source_location.column });
        }
    }

    pub fn format(self: *Resolver, allocator: std.mem.Allocator, source_location: SourceLocation) ![]u8 {
        const file = self.coverage.fileAt(source_location.file);
        const directory = self.coverage.stringAt(@fromBackingInt(@intCast(file.directory_index)));
        const basename = self.coverage.stringAt(file.basename);
        if (directory.len == 0) {
            return std.fmt.allocPrint(allocator, "{s}:{d}:{d}", .{ basename, source_location.line, source_location.column });
        }
        return std.fmt.allocPrint(allocator, "{s}/{s}:{d}:{d}", .{ directory, basename, source_location.line, source_location.column });
    }
};
