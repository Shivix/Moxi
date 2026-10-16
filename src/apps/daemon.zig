const std = @import("std");
const moxi = @import("moxi");

const debugger = moxi.debugger;
const breakpoint = moxi.breakpoint;
const source = moxi.source;
const protocol = moxi.client.protocol;
const c = debugger.c;
const linux = std.os.linux;

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;
    var allocator_state: std.heap.DebugAllocator(.{}) = .init;
    const allocator = allocator_state.allocator();
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = protocol.port } };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    std.debug.print("moxid listening on 127.0.0.1:{d}\n", .{protocol.port});

    var executable_path = try wait_for_start(allocator, io, &server);

    while (true) {
        const replacement = run_session(allocator, io, &server, executable_path) catch |err| {
            allocator.free(executable_path);
            return err;
        };
        allocator.free(executable_path);
        executable_path = replacement orelse try wait_for_start(allocator, io, &server);
    }
}

fn wait_for_start(allocator: std.mem.Allocator, io: std.Io, server: *std.Io.net.Server) ![]u8 {
    while (true) {
        const stream = try server.accept(io);
        var buffer: [4096]u8 = undefined;
        const request = protocol.read(stream, io, &buffer) catch |err| {
            stream.close(io);
            return err;
        };
        if (request.command == .start) {
            const executable_path = try allocator.dupe(u8, request.body);
            stream.close(io);
            return executable_path;
        }
        stream.close(io);
    }
}

fn terminate_debuggee(pid: i32) void {
    _ = linux.ptrace(linux.PTRACE.KILL, pid, 0, 0, 0);
    var wait_status: c_int = undefined;
    _ = std.c.waitpid(pid, &wait_status, 0);
}

fn run_session(
    allocator: std.mem.Allocator,
    io: std.Io,
    server: *std.Io.net.Server,
    executable_path: []const u8,
) !?[]u8 {
    const path = try allocator.allocSentinel(u8, executable_path.len, 0);
    defer allocator.free(path);
    @memcpy(path, executable_path);

    const pid = debugger.spawn_child_process(path);
    defer terminate_debuggee(pid);

    var wait_status: c_int = undefined;
    _ = std.c.waitpid(pid, &wait_status, 0);
    if (!std.posix.W.IFSTOPPED(@bitCast(wait_status))) return error.UnexpectedState;
    _ = linux.ptrace(linux.PTRACE.SETOPTIONS, pid, 0, linux.PTRACE.O.TRACEEXEC, 0);
    _ = linux.ptrace(linux.PTRACE.CONT, pid, 0, 0, 0);
    _ = std.c.waitpid(pid, &wait_status, 0);
    const exec_status: u32 = @bitCast(wait_status);
    if (!std.posix.W.IFSTOPPED(exec_status) or std.posix.W.STOPSIG(exec_status) != std.posix.SIG.TRAP) {
        return error.UnexpectedState;
    }

    var mappings = try debugger.parse_proc_mappings(allocator, io, pid);
    defer mappings.deinit(allocator);
    const file = try std.Io.Dir.cwd().openFile(io, executable_path, .{});
    defer file.close(io);
    var debug_elf = try std.debug.ElfFile.load(allocator, io, file, null, &std.debug.ElfFile.DebugInfoSearchPaths.none);
    defer debug_elf.deinit(allocator);
    if (debug_elf.dwarf == null) return error.MissingDebugInfo;
    try debug_elf.dwarf.?.open(allocator, debug_elf.endian);
    try debug_elf.dwarf.?.populateRanges(allocator, debug_elf.endian);

    _ = c.elf_version(c.EV_CURRENT);
    const elf = c.elf_begin(file.handle, c.ELF_C_READ, null) orelse return error.ElfBeginFailed;
    defer _ = c.elf_end(elf);
    var ehdr: c.Elf64_Ehdr = undefined;
    if (c.gelf_getehdr(elf, &ehdr) == null) return error.ElfGetEhdrFailed;
    const load_bias = try debugger.get_load_bias(elf, &ehdr, mappings.items);

    var resolver = source.Resolver{
        .allocator = allocator,
        .io = io,
        .dwarf = &debug_elf.dwarf.?,
        .endian = debug_elf.endian,
        .load_bias = load_bias,
    };
    defer resolver.deinit();

    const callbacks = c.Dwfl_Callbacks{
        .find_elf = c.dwfl_linux_proc_find_elf,
        .find_debuginfo = c.dwfl_standard_find_debuginfo,
        .section_address = c.dwfl_offline_section_address,
        .debuginfo_path = null,
    };
    const dwfl = c.dwfl_begin(&callbacks) orelse return error.DwflBeginFailed;
    defer c.dwfl_end(dwfl);
    _ = c.dwfl_linux_proc_report(dwfl, pid);
    _ = c.dwfl_report_end(dwfl, null, null);

    const main_function = try debugger.get_main_address(dwfl, load_bias + ehdr.e_entry);
    const main_instruction = try breakpoint.set_breakpoint(pid, main_function.address);
    try breakpoint.continue_until_breakpoint(pid);
    try breakpoint.reset_breakpoint(pid, main_function.address, main_instruction);
    var current = try debugger.next_source_line(pid, &resolver, null, main_function);

    while (true) {
        const stream = try server.accept(io);
        var buffer: [4096]u8 = undefined;
        const request = try protocol.read(stream, io, &buffer);
        var response: []const u8 = "ok";
        var allocated_response: ?[]u8 = null;
        defer if (allocated_response) |value| allocator.free(value);

        switch (request.command) {
            .next => {
                const count = if (request.body.len == 0) 1 else try std.fmt.parseInt(u32, request.body, 10);
                for (0..count) |_| {
                    current = debugger.next_source_line(pid, &resolver, current, main_function) catch |err| switch (err) {
                        error.ProgramFinished => {
                            try protocol.write_response(&stream, io, "finished", &buffer);
                            stream.close(io);
                            return null;
                        },
                        else => return err,
                    };
                }
                allocated_response = try resolver.format(allocator, current);
                response = allocated_response.?;
            },
            .source => {
                allocated_response = try resolver.format(allocator, current);
                response = allocated_response.?;
            },
            .breakpoint => {
                const address_value = try std.fmt.parseInt(usize, request.body, 0);
                _ = try breakpoint.set_breakpoint(pid, address_value);
                response = "breakpoint set";
            },
            .start => {
                const replacement = try allocator.dupe(u8, request.body);
                try protocol.write_response(&stream, io, "restarting", &buffer);
                stream.close(io);
                return replacement;
            },
            .response => return error.InvalidCommandAfterStart,
        }
        try protocol.write_response(&stream, io, response, &buffer);
        stream.close(io);
    }
}
