const std = @import("std");
const daemon = @import("debugger.zig");

fn peek_data(pid: i32, address: usize) !usize {
    const rc = std.c.ptrace(std.os.linux.PTRACE.PEEKDATA, pid, @ptrFromInt(address), null);
    if (std.c.errno(rc) != .SUCCESS) return error.PeekDataFailed;
    return @intCast(rc);
}

fn poke_data(pid: i32, address: usize, data: usize) !void {
    const rc = std.c.ptrace(std.os.linux.PTRACE.POKEDATA, pid, @ptrFromInt(address), @ptrFromInt(data));
    if (std.c.errno(rc) != .SUCCESS) return error.PokeDataFailed;
}

pub fn continue_until_breakpoint(pid: i32) !void {
    while (true) {
        daemon.ptrace_call(std.os.linux.PTRACE.CONT, pid, 0, 0) catch return error.ContinueFailed;
        const status = daemon.wait_for_child(pid) catch |err| switch (err) {
            error.ProgramFinished => return error.FailedToHitBreakpoint,
            else => return err,
        };
        if (std.posix.W.IFSTOPPED(status) and std.posix.W.STOPSIG(status) == std.posix.SIG.TRAP) break;
    }
}

pub fn set_breakpoint(pid: i32, address: usize) !usize {
    const instruction = try peek_data(pid, address);
    try poke_data(pid, address, (instruction & ~@as(usize, 0xFF)) | 0xCC);
    return instruction;
}

pub fn reset_breakpoint(pid: i32, address: usize, original_instruction: usize) !void {
    try poke_data(pid, address, original_instruction);
    var regs = try daemon.get_registers(pid);
    std.debug.assert(regs.rip == address + 1);
    regs.rip -= 1;
    try daemon.set_registers(pid, &regs);
}
