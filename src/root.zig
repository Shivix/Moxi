//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

pub const c = @cImport({
    @cInclude("elfutils/libdwfl.h");
});


pub const Registers = struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
};

pub const ProcMappings = std.ArrayList(struct { start: u64, end: u64 });

/// Only parent will return from this function
pub fn spawn_child_process(binary_path: []const u8) i32 {
    const pid: i32 = @intCast(std.os.linux.fork());
    // pid 0 is the Child process (the program we are debugging).
    if (pid == 0) {
        if (std.os.linux.ptrace(std.os.linux.PTRACE.TRACEME, 0, 0, 0, 0) != 0) {
            std.debug.print("ptrace TRACEME failed\n", .{});
            std.posix.exit(1);
        }

        // FIXME: Temp error handling
        //_ = std.posix.raise(std.posix.SIG.STOP) catch unreachable;

        const argv = [_:null]?[*:0]const u8{
            @ptrCast(binary_path),
            null,
        };

        const res = std.posix.execveZ(
            argv[0].?,
            &argv,
            &[_:null]?[*:0]const u8{null},
        );

        std.debug.print("execve failed: {}\n", .{res});
        std.posix.exit(1);
    }
    return pid;
}

pub fn parse_proc_mappings(
    allocator: std.mem.Allocator,
    io: std.Io,
    child: i32,
) !ProcMappings {
    var result = ProcMappings.empty;

    const maps_path = try std.fmt.allocPrint(
        allocator,
        "/proc/{d}/maps",
        .{child},
    );
    defer allocator.free(maps_path);

    const file = try std.fs.cwd().openFile(maps_path, .{});
    defer file.close();

    var buffer: [4098]u8 = undefined;
    var fr = file.reader(io, &buffer);
    var reader = &fr.interface;

    while (try reader.takeDelimiter('\n')) |line| {
        std.debug.print("{s}\n", .{line});
        if (std.mem.indexOfScalar(u8, line, '/') != null) {
            if (std.mem.indexOf(u8, line, "r-xp") == null) {
                // TODO: For now, only return the executable portion.
                continue;
            }
            const dash_index = std.mem.indexOfScalar(u8, line, '-') orelse
                return error.InvalidProcMappings;

            const start_str = line[0..dash_index];

            const rest = line[dash_index + 1 ..];
            const space_index = std.mem.indexOfScalar(u8, rest, ' ') orelse
                return error.InvalidProcMappings;

            const end_str = rest[0..space_index];

            const start_address = try std.fmt.parseInt(u64, start_str, 16);
            const end_address = try std.fmt.parseInt(u64, end_str, 16);

            try result.append(allocator, .{
                .start = start_address,
                .end = end_address,
            });
        }
    }

    return result;
}

pub fn get_main_address(dwfl: ?*c.struct_Dwfl, entry_point: u64) !u64 {
    const mod = c.dwfl_addrmodule(dwfl, entry_point);
    if (mod == null) {
        return error.NoModuleFound;
    }

    var idx: c_int = 0;
    while (true) : (idx += 1) {
        var sym: c.GElf_Sym = undefined;
        var shndx: c.GElf_Word = 0;

        const name = c.dwfl_module_getsym(mod, idx, &sym, &shndx);
        if (name == null) {
            break;
        }

        if (std.mem.eql(u8, std.mem.span(name), "main.main")) {
            std.debug.print("found main: {s} @ 0x{x}\n", .{name, sym.st_value});
            return sym.st_value;
        }
    }
    return error.CouldNotFindMain;
}

/// continue_until_breakpoint assumes a breakpoint will eventually be hit, else it will error.
pub fn continue_until_breakpoint(pid: i32) !void {
    while (true) {
        const rc = std.os.linux.ptrace(std.os.linux.PTRACE.CONT, pid, 0, 0, 0);
        if (std.posix.errno(rc) != .SUCCESS) {
            return error.ContinueFailed;
        }
        const wait = std.posix.waitpid(pid, 0);
        if (std.posix.W.IFSTOPPED(wait.status)) {
            const sig = std.posix.W.STOPSIG(wait.status);
            if (sig == @intFromEnum(std.posix.SIG.TRAP)) {
                break;
            }
        }
        if (std.posix.W.IFEXITED(wait.status) or std.posix.W.IFSIGNALED(wait.status)) {
            return error.FailedToHitBreakpoint;
        }
    }
}

pub fn set_breakpoint(pid: i32, address: usize) !usize {
    var instruction: usize = undefined;
    var rc = std.os.linux.ptrace(std.os.linux.PTRACE.PEEKDATA, pid, address, @intFromPtr(&instruction), 0);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.PeekDataFailed;
    }
    std.debug.print("original instruction: 0x{x}\n", .{instruction});
     // TODO: From AI, maybe wrong:
     //     src/root.zig:175 uses instruction & 0xFFFFFF00, which is effectively a 32-bit mask. On x86_64 this can clobber the upper half of the fetched instruction word.
     //     Use a full-width mask (~@as(usize, 0xFF)) consistently.
    // This likely fixes the illegal instruction. If we look at the breakpoint value it was more than a byte before.
    const breakpoint = (instruction & 0xFFFFFF00) | 0xCC;
    std.debug.print("breakpoint: 0x{x}\n", .{breakpoint});
    std.debug.print("old breakpoint: 0x{x}\n", .{(instruction & ~@as(usize, 0xFF)) | 0xCC});
    rc = std.os.linux.ptrace(std.os.linux.PTRACE.POKEDATA, pid, address, breakpoint, 0);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.PokeDataFailed;
    }
    return instruction;
}

pub fn reset_breakpoint(pid: i32, address: usize, original_instruction: usize) !void {
    var rc = std.os.linux.ptrace(std.os.linux.PTRACE.POKEDATA, pid, address, original_instruction, 0);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.PokeDataFailed;
    }

    var regs: Registers = undefined;
    rc = std.os.linux.ptrace(std.os.linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs), 0);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.GetRegsFailed;
    }
    std.debug.assert(regs.rip == address + 1);
    regs.rip -= 1;
    // TODO: Add a wrapper for ptrace calls with error handling and maybe optional debug logging?
    rc = std.os.linux.ptrace(std.os.linux.PTRACE.SETREGS, pid, 0, @intFromPtr(&regs), 0);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.SetRegsFailed;
    }

    // TODO: Temporary for logging.
    var instruction: usize = undefined;
    rc = std.os.linux.ptrace(std.os.linux.PTRACE.PEEKDATA, pid, address, @intFromPtr(&instruction), 0);
    if (std.posix.errno(rc) != .SUCCESS) {
        return error.PeekDataFailed;
    }
    std.debug.print("reinstated instruction: 0x{x}\n", .{instruction});
}
