const std = @import("std");
const moxi = @import("moxi");

const c = moxi.c;

const linux = std.os.linux;
// moxi init to set up ability to use individual commands like moxi step moxi continue.
// Option to do just moxi or moxi interactive and then can do short commands "step" without "moxi "
// Users could also alias moxi_step to step if they prefer. Could make it a function that calls source after if desired.
// Should still be able to handle commands from other sources when running interactive, so either don't hog socket or support multiple.
// If UDP it's simple to handle multiple sources. TCP harder, each has a session.
// TCP would be needed to support remote debugging. (If going accross the internet)
// I think use UDP by default then opt in TCP.
// Could have a moxi daemon running on containers in UAT not doing anything until someone "moxi start --port 1337 --pid 1 --tcp"
//     If handling multi sources then people could do pair debugging.

// TODO: Plan:
// What structure do I want?
// Create an executable/debuggee class
// Should be able to handle having multiple of them for future features.
// Handles detecting whever or not it's PIE/ ASLR and handles address offsets.
// Handles cleaning up an executable's state when debugging finishes.
//
// What design is best for allowing less logic in daemon and more in the command programs.
// Step: ofc this involves ptracing, so must have daemon do that.
// Source: must get data from daemon, but then using that data can be in command program (printing actual file/ colouring etc)
// Breakpoint: Most logic naturally in daemon anyway, program specific daemon based logic should be simple.
// Print/ Call: Some of the logic can be separate. If lexing is needed can be done here, but need to get/ send data from daemon.
//
// Let's get the application style format set up.
//     Setting up socket to listen on.
//     I assume one program can ptrace many if it tracks the pids
//     How does the user set which one it's controlling?
//     A command to list and adjust the current tracked executable?
//     $ moxi ls
//     ID Executable     PID
//     1  zig_helloworld 2167
//     $ moxi switch 1
//     or
//     $ moxi step -1 --id 1
//     argument for which pid/ executable/ ID?
//
//     When you run moxi start, how do you know if we should replace a debuggee vs add new one?
//     $ moxi stop 1/ all
//     $ moxi start (replaces executable of same name)
//     $ moxi add (adds new executable) or moxi start --add       moxi add could be alias to moxi start --add
//
// Core features:
// Setting breakpoints
//     By file and line
// Step
// Continue
// Get source code (file and line no)
//
// Testing:
// What things can we have simple unit tests for?
// Have unit tests trigger a process and trace it?
//     Simple unit tests for reading and writing command/ socket logic. (no actual sockets)
//     Then slightly more ocmplex unit tests with subprocesses and ptracing.
// External e2e tests?
// expect script?
// lua script
//
//
// When stepping we'd need to handle stepping onto breakpoints I think. Maybe not actually? Surelly we'd just receive a sigtrap as like with continue?
pub fn main(init: std.process.Init.Minimal) !void {
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next(); // argv[0]
    const executable_path = args.next() orelse {
        std.debug.print("usage: moxi <executable>\n", .{});
        return error.MissingExecutablePath;
    };
    std.debug.print("Executable: {s}\n", .{executable_path});

    var debug_alloc: std.heap.DebugAllocator(.{}) = .init;
    const gpa = debug_alloc.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pid = moxi.spawn_child_process(executable_path);

    var wait_status: c_int = undefined;
    _ = std.c.waitpid(pid, &wait_status, 0);
    if (!std.posix.W.IFSTOPPED(@bitCast(wait_status))) {
        return error.UnexpectedState;
    }
    // Ensures the tracee will stop after exec.
    _ = linux.ptrace(linux.PTRACE.SETOPTIONS, pid, 0, linux.PTRACE.O.TRACEEXEC, 0);

    // Child immediately calls SIGSTOP so the parent can have time to set TRACEEXEC.
    _ = linux.ptrace(linux.PTRACE.CONT, pid, 0, 0, 0);
    _ = std.c.waitpid(pid, &wait_status, 0);
    const exec_status: u32 = @bitCast(wait_status);
    if (!std.posix.W.IFSTOPPED(exec_status) or
        std.posix.W.STOPSIG(exec_status) != std.posix.SIG.TRAP)
    {
        return error.UnexpectedState;
    }

    var proc_mappings = try moxi.parse_proc_mappings(gpa, io, pid);
    defer proc_mappings.deinit(gpa);

    const file = try std.Io.Dir.cwd().openFile(io, executable_path, .{});
    defer file.close(io);

    var debug_elf = try std.debug.ElfFile.load(
        gpa,
        io,
        file,
        null,
        &std.debug.ElfFile.DebugInfoSearchPaths.none,
    );
    defer debug_elf.deinit(gpa);
    if (debug_elf.dwarf == null) return error.MissingDebugInfo;
    try debug_elf.dwarf.?.open(gpa, debug_elf.endian);
    try debug_elf.dwarf.?.populateRanges(gpa, debug_elf.endian);
    _ = c.elf_version(c.EV_CURRENT);
    const elf = c.elf_begin(file.handle, c.ELF_C_READ, null);
    if (elf == null) {
        return error.ElfBeginFailed;
    }
    defer _ = c.elf_end(elf);

    var ehdr: c.Elf64_Ehdr = undefined;
    if (c.gelf_getehdr(elf, &ehdr) == null) {
        return error.ElfGetEhdrFailed;
    }

    const load_bias = try moxi.get_load_bias(
        elf,
        &ehdr,
        proc_mappings.items,
    );
    std.debug.print("Load bias: 0x{x}\n", .{load_bias});

    var source_resolver = moxi.SourceResolver{
        .allocator = gpa,
        .io = io,
        .dwarf = &debug_elf.dwarf.?,
        .endian = debug_elf.endian,
        .load_bias = load_bias,
    };
    defer source_resolver.deinit();

    std.debug.print("entry point: 0x{x}\n", .{ehdr.e_entry});
    std.debug.print("is PIE: {}\n", .{ehdr.e_type == c.ET_DYN});

    const callbacks = c.Dwfl_Callbacks{
        .find_elf = c.dwfl_linux_proc_find_elf,
        .find_debuginfo = c.dwfl_standard_find_debuginfo,
        .section_address = c.dwfl_offline_section_address,
        .debuginfo_path = null,
    };

    std.debug.print("dwfl version: {s}\n", .{c.dwfl_version(null)});
    const dwfl = c.dwfl_begin(&callbacks);
    if (dwfl == null) {
        return error.DwflBeginFailed;
    }
    defer c.dwfl_end(dwfl);
    _ = c.dwfl_linux_proc_report(dwfl, pid);
    _ = c.dwfl_report_end(dwfl, null, null);

    const runtime_entry = load_bias + ehdr.e_entry;
    const main_function = try moxi.get_main_address(dwfl, runtime_entry);

    const main_instr = try moxi.set_breakpoint(pid, main_function.address);
    try moxi.continue_until_breakpoint(pid);
    try moxi.reset_breakpoint(pid, main_function.address, main_instr);

    var current_location = moxi.next_source_line(pid, &source_resolver, null, main_function) catch |err| switch (err) {
        error.ProgramFinished => {
            std.debug.print("Program finished\n", .{});
            return;
        },
        else => return err,
    };

    while (true) {
        source_resolver.print(current_location);

        current_location = moxi.next_source_line(
            pid,
            &source_resolver,
            current_location,
            main_function,
        ) catch |err| switch (err) {
            error.ProgramFinished => {
                std.debug.print("Program finished\n", .{});
                return;
            },
            else => return err,
        };
    }
    // TODO: Set up in moxi style, listen etc.
    // Have separate window for running a make file that builds and runs daemon, then in main window can run commands we wanna test.
}
