const std = @import("std");

pub const c = @import("c");

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

fn ptraceCall(request: u32, pid: i32, address: usize, data: usize) !void {
    const rc = std.os.linux.ptrace(request, pid, address, data, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.PtraceFailed;
}

fn peekData(pid: i32, address: usize) !usize {
    const rc = std.c.ptrace(
        std.os.linux.PTRACE.PEEKDATA,
        pid,
        @ptrFromInt(address),
        null,
    );
    if (std.c.errno(rc) != .SUCCESS) return error.PeekDataFailed;
    return @intCast(rc);
}

fn pokeData(pid: i32, address: usize, data: usize) !void {
    const rc = std.c.ptrace(
        std.os.linux.PTRACE.POKEDATA,
        pid,
        @ptrFromInt(address),
        @ptrFromInt(data),
    );
    if (std.c.errno(rc) != .SUCCESS) return error.PokeDataFailed;
}

fn waitForChild(pid: i32) !u32 {
    var wait_status: c_int = undefined;
    if (std.c.waitpid(pid, &wait_status, 0) < 0) return error.WaitFailed;

    const status: u32 = @bitCast(wait_status);
    if (std.posix.W.IFEXITED(status) or std.posix.W.IFSIGNALED(status)) {
        return error.ProgramFinished;
    }
    return status;
}

fn getRegisters(pid: i32) !Registers {
    var regs: Registers = undefined;
    ptraceCall(
        std.os.linux.PTRACE.GETREGS,
        pid,
        0,
        @intFromPtr(&regs),
    ) catch return error.GetRegsFailed;
    return regs;
}

fn setRegisters(pid: i32, regs: *const Registers) !void {
    ptraceCall(
        std.os.linux.PTRACE.SETREGS,
        pid,
        0,
        @intFromPtr(regs),
    ) catch return error.SetRegsFailed;
}

pub const ProcMapping = struct {
    start: u64,
    end: u64,
    offset: u64,
};
pub const ProcMappings = std.ArrayList(ProcMapping);

/// Only parent will return from this function
pub fn spawn_child_process(executable_path: [:0]const u8) i32 {
    const pid: i32 = @intCast(std.os.linux.fork());
    // pid 0 is the Child process (the program we are debugging).
    if (pid == 0) {
        if (std.os.linux.ptrace(std.os.linux.PTRACE.TRACEME, 0, 0, 0, 0) != 0) {
            std.debug.print("ptrace TRACEME failed\n", .{});
            std.os.linux.exit(1);
        }

        _ = std.posix.raise(std.posix.SIG.STOP) catch unreachable;

        const res = std.c.execve(
            executable_path.ptr,
            &.{ executable_path.ptr, null },
            &.{null},
        );

        std.debug.print("execve failed: {}\n", .{res});
        std.os.linux.exit(1);
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

    const file = try std.Io.Dir.cwd().openFile(io, maps_path, .{});
    defer file.close(io);

    var buffer: [4098]u8 = undefined;
    var fr = file.reader(io, &buffer);
    var reader = &fr.interface;

    while (try reader.takeDelimiter('\n')) |line| {
        std.debug.print("{s}\n", .{line});
        if (std.mem.indexOfScalar(u8, line, '/') != null) {
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            const range = fields.next() orelse return error.InvalidProcMappings;
            const permissions = fields.next() orelse return error.InvalidProcMappings;
            const offset_str = fields.next() orelse return error.InvalidProcMappings;
            if (!std.mem.eql(u8, permissions, "r-xp")) {
                // TODO: For now, only return the executable portion.
                continue;
            }
            const dash_index = std.mem.indexOfScalar(u8, range, '-') orelse
                return error.InvalidProcMappings;

            const start_str = range[0..dash_index];

            const end_str = range[dash_index + 1 ..];

            const start_address = try std.fmt.parseInt(u64, start_str, 16);
            const end_address = try std.fmt.parseInt(u64, end_str, 16);
            const offset = try std.fmt.parseInt(u64, offset_str, 16);

            try result.append(allocator, .{
                .start = start_address,
                .end = end_address,
                .offset = offset,
            });
        }
    }

    return result;
}

pub fn find_mapping_for_offset(
    mappings: []const ProcMapping,
    offset: u64,
) ?ProcMapping {
    const aligned_offset = offset & ~(page_size - 1);

    for (mappings) |mapping| {
        if (mapping.offset == aligned_offset) return mapping;
    }
    return null;
}

pub fn get_load_bias(
    elf: ?*c.Elf,
    ehdr: *const c.Elf64_Ehdr,
    proc_mappings: []const ProcMapping,
) !u64 {
    var phdr: c.GElf_Phdr = undefined;

    for (0..ehdr.e_phnum) |phdr_index| {
        if (c.gelf_getphdr(elf, @intCast(phdr_index), &phdr) == null) {
            return error.ElfGetPhdrFailed;
        }
        if (phdr.p_type != c.PT_LOAD or (phdr.p_flags & c.PF_X) == 0) continue;

        // TODO: Also match the mapping pathname against the executable. An
        // offset-only match could select a library mapping if offsets collide.
        const mapping = find_mapping_for_offset(proc_mappings, phdr.p_offset) orelse continue;
        return mapping.start - (phdr.p_vaddr & ~(page_size - 1));
    }

    return error.ExecutableLoadSegmentNotFound;
}

pub const Function = struct {
    address: u64,
    size: u64,
};

pub fn get_main_address(dwfl: ?*c.struct_Dwfl, entry_point: u64) !Function {
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

        const symbol_name = std.mem.span(name);
        if (std.mem.eql(u8, symbol_name, "main.main") or
            std.mem.eql(u8, symbol_name, "main"))
        {
            std.debug.print("found main: {s} @ 0x{x}\n", .{ name, sym.st_value });
            return .{
                .address = sym.st_value,
                .size = sym.st_size,
            };
        }
    }
    return error.CouldNotFindMain;
}

pub const SourceLocation = struct {
    file: std.debug.Coverage.File.Index,
    line: u32,
    column: u32,
};

pub const SourceResolver = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dwarf: *std.debug.Dwarf,
    endian: std.builtin.Endian,
    load_bias: u64,
    coverage: std.debug.Coverage = .init,

    pub fn deinit(self: *SourceResolver) void {
        self.coverage.deinit(self.allocator);
    }

    pub fn location(self: *SourceResolver, address: u64) !?SourceLocation {
        var output: [1]std.debug.Coverage.SourceLocation = undefined;
        const dwarf_address = address -| self.load_bias;
        try self.coverage.resolveAddressesDwarf(
            self.allocator,
            self.io,
            self.endian,
            &.{dwarf_address},
            &output,
            self.dwarf,
        );
        if (output[0].file == .invalid) return null;
        return .{
            .file = output[0].file,
            .line = output[0].line,
            .column = output[0].column,
        };
    }

    pub fn print(self: *SourceResolver, source_location: SourceLocation) void {
        const file = self.coverage.fileAt(source_location.file);
        const directory = self.coverage.stringAt(@fromBackingInt(@intCast(file.directory_index)));
        const basename = self.coverage.stringAt(file.basename);
        if (directory.len == 0) {
            std.debug.print("{s}:{d}:{d}\n", .{ basename, source_location.line, source_location.column });
        } else {
            std.debug.print("{s}/{s}:{d}:{d}\n", .{
                directory,
                basename,
                source_location.line,
                source_location.column,
            });
        }
    }
};

pub fn next_source_line(
    pid: i32,
    resolver: *SourceResolver,
    current: ?SourceLocation,
    function: Function,
) !SourceLocation {
    while (true) {
        ptraceCall(std.os.linux.PTRACE.SINGLESTEP, pid, 0, 0) catch return error.SingleStepFailed;

        const status = try waitForChild(pid);
        if (!std.posix.W.IFSTOPPED(status) or
            std.posix.W.STOPSIG(status) != std.posix.SIG.TRAP)
        {
            continue;
        }

        const regs = try getRegisters(pid);

        const in_function = regs.rip >= function.address and
            regs.rip < function.address + function.size;
        if (!in_function) continue;

        const location = (try resolver.location(regs.rip)) orelse continue;
        if (current == null) {
            return location;
        }

        const previous = current.?;
        if (location.file != previous.file or location.line != previous.line) {
            return location;
        }
    }
}

/// continue_until_breakpoint assumes a breakpoint will eventually be hit, else it will error.
pub fn continue_until_breakpoint(pid: i32) !void {
    while (true) {
        ptraceCall(std.os.linux.PTRACE.CONT, pid, 0, 0) catch return error.ContinueFailed;
        const status = waitForChild(pid) catch |err| switch (err) {
            error.ProgramFinished => return error.FailedToHitBreakpoint,
            else => return err,
        };
        if (std.posix.W.IFSTOPPED(status)) {
            const sig = std.posix.W.STOPSIG(status);
            if (sig == std.posix.SIG.TRAP) {
                break;
            }
        }
    }
}

pub fn set_breakpoint(pid: i32, address: usize) !usize {
    const instruction = try peekData(pid, address);
    std.debug.print("original instruction: 0x{x}\n", .{instruction});
    const breakpoint = (instruction & ~@as(usize, 0xFF)) | 0xCC;
    std.debug.print("breakpoint: 0x{x}\n", .{breakpoint});
    try pokeData(pid, address, breakpoint);
    return instruction;
}

pub fn reset_breakpoint(pid: i32, address: usize, original_instruction: usize) !void {
    try pokeData(pid, address, original_instruction);

    var regs = try getRegisters(pid);
    std.debug.assert(regs.rip == address + 1);
    regs.rip -= 1;
    try setRegisters(pid, &regs);
}

test "find_mapping_for_offset matches page-aligned offsets" {
    const mappings = [_]ProcMapping{
        .{ .start = 0x1000, .end = 0x2000, .offset = 0x732000 },
        .{ .start = 0x3000, .end = 0x4000, .offset = 0x76b000 },
    };

    const mapping = find_mapping_for_offset(&mappings, 0x76b123) orelse unreachable;
    try std.testing.expectEqual(@as(u64, 0x3000), mapping.start);
}
