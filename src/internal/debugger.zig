const std = @import("std");
pub const c = @import("c");
const source = @import("source.zig");
const page_size: u64 = 4096;

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

pub fn ptrace_call(request: u32, pid: i32, address: usize, data: usize) !void {
    const rc = std.os.linux.ptrace(request, pid, address, data, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.PtraceFailed;
}

pub fn wait_for_child(pid: i32) !u32 {
    var wait_status: c_int = undefined;
    if (std.c.waitpid(pid, &wait_status, 0) < 0) return error.WaitFailed;
    const status: u32 = @bitCast(wait_status);
    if (std.posix.W.IFEXITED(status) or std.posix.W.IFSIGNALED(status)) return error.ProgramFinished;
    return status;
}

pub fn get_registers(pid: i32) !Registers {
    var regs: Registers = undefined;
    ptrace_call(std.os.linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs)) catch return error.GetRegsFailed;
    return regs;
}

pub fn set_registers(pid: i32, regs: *const Registers) !void {
    ptrace_call(std.os.linux.PTRACE.SETREGS, pid, 0, @intFromPtr(regs)) catch return error.SetRegsFailed;
}

pub const ProcMapping = struct { start: u64, end: u64, offset: u64 };
pub const ProcMappings = std.ArrayList(ProcMapping);

/// Only the parent returns from this function.
pub fn spawn_child_process(executable_path: [:0]const u8) i32 {
    const pid: i32 = @intCast(std.os.linux.fork());
    if (pid == 0) {
        if (std.os.linux.ptrace(std.os.linux.PTRACE.TRACEME, 0, 0, 0, 0) != 0) {
            std.debug.print("ptrace TRACEME failed\n", .{});
            std.os.linux.exit(1);
        }
        _ = std.posix.raise(std.posix.SIG.STOP) catch unreachable;
        const res = std.c.execve(executable_path.ptr, &.{ executable_path.ptr, null }, &.{null});
        std.debug.print("execve failed: {}\n", .{res});
        std.os.linux.exit(1);
    }
    return pid;
}

pub fn parse_proc_mappings(allocator: std.mem.Allocator, io: std.Io, child: i32) !ProcMappings {
    var result = ProcMappings.empty;
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{child});
    defer allocator.free(maps_path);
    const file = try std.Io.Dir.cwd().openFile(io, maps_path, .{});
    defer file.close(io);
    var buffer: [4098]u8 = undefined;
    var fr = file.reader(io, &buffer);
    var reader = &fr.interface;
    while (try reader.takeDelimiter('\n')) |line| {
        if (std.mem.indexOfScalar(u8, line, '/') != null) {
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            const range = fields.next() orelse return error.InvalidProcMappings;
            const permissions = fields.next() orelse return error.InvalidProcMappings;
            const offset_str = fields.next() orelse return error.InvalidProcMappings;
            if (!std.mem.eql(u8, permissions, "r-xp")) continue;
            const dash_index = std.mem.indexOfScalar(u8, range, '-') orelse return error.InvalidProcMappings;
            try result.append(allocator, .{
                .start = try std.fmt.parseInt(u64, range[0..dash_index], 16),
                .end = try std.fmt.parseInt(u64, range[dash_index + 1 ..], 16),
                .offset = try std.fmt.parseInt(u64, offset_str, 16),
            });
        }
    }
    return result;
}

pub fn find_mapping_for_offset(mappings: []const ProcMapping, offset: u64) ?ProcMapping {
    const aligned_offset = offset & ~(page_size - 1);
    for (mappings) |mapping| if (mapping.offset == aligned_offset) return mapping;
    return null;
}

pub fn get_load_bias(elf: ?*c.Elf, ehdr: *const c.Elf64_Ehdr, proc_mappings: []const ProcMapping) !u64 {
    var phdr: c.GElf_Phdr = undefined;
    for (0..ehdr.e_phnum) |phdr_index| {
        if (c.gelf_getphdr(elf, @intCast(phdr_index), &phdr) == null) return error.ElfGetPhdrFailed;
        if (phdr.p_type != c.PT_LOAD or (phdr.p_flags & c.PF_X) == 0) continue;
        const mapping = find_mapping_for_offset(proc_mappings, phdr.p_offset) orelse continue;
        return mapping.start - (phdr.p_vaddr & ~(page_size - 1));
    }
    return error.ExecutableLoadSegmentNotFound;
}

pub const Function = struct { address: u64, size: u64 };

pub fn get_main_address(dwfl: ?*c.struct_Dwfl, entry_point: u64) !Function {
    const mod = c.dwfl_addrmodule(dwfl, entry_point) orelse return error.NoModuleFound;
    var idx: c_int = 0;
    while (true) : (idx += 1) {
        var sym: c.GElf_Sym = undefined;
        var shndx: c.GElf_Word = 0;
        const name = c.dwfl_module_getsym(mod, idx, &sym, &shndx) orelse break;
        const symbol_name = std.mem.span(name);
        if (std.mem.eql(u8, symbol_name, "main.main") or std.mem.eql(u8, symbol_name, "main")) {
            std.debug.print("found main: {s} @ 0x{x}\n", .{ name, sym.st_value });
            return .{ .address = sym.st_value, .size = sym.st_size };
        }
    }
    return error.CouldNotFindMain;
}

/// Advance to the next source line in the selected function.
pub fn next_source_line(
    pid: i32,
    resolver: *source.Resolver,
    current: ?source.SourceLocation,
    function: Function,
) !source.SourceLocation {
    while (true) {
        ptrace_call(std.os.linux.PTRACE.SINGLESTEP, pid, 0, 0) catch return error.SingleStepFailed;
        const status = try wait_for_child(pid);
        if (!std.posix.W.IFSTOPPED(status) or std.posix.W.STOPSIG(status) != std.posix.SIG.TRAP) continue;
        const regs = try get_registers(pid);
        if (regs.rip < function.address or regs.rip >= function.address + function.size) continue;
        const location = (try resolver.location(regs.rip)) orelse continue;
        if (current == null) return location;
        const previous = current.?;
        if (location.file != previous.file or location.line != previous.line) return location;
    }
}

test "find_mapping_for_offset matches page-aligned offsets" {
    const mappings = [_]ProcMapping{
        .{ .start = 0x1000, .end = 0x2000, .offset = 0x732000 },
        .{ .start = 0x3000, .end = 0x4000, .offset = 0x76b000 },
    };
    const mapping = find_mapping_for_offset(&mappings, 0x76b123) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x3000), mapping.start);
}
