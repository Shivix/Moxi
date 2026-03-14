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
// Create a binary/ debugee class
// Should be able to handle having multiple of them for future features.
// Handles detecting whever or not it's PIE/ ASLR and handles address offsets.
// Handles cleaning up that binaries stuff if no longer debugging it or it finishes.
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
//     A command to list and adjust the current tracked binary?
//     $ moxi ls
//     ID Binary         PID
//     1  zig_helloworld 2167
//     $ moxi switch 1
//     or
//     $ moxi step -1 --id 1
//     argument for which pid/ binary/ ID?
//
//     When you run moxi start, how do you know if we should replace a debuggee vs add new one?
//     $ moxi stop 1/ all
//     $ moxi start (replaces binary of same name)
//     $ moxi add (adds new binary) or moxi start --add       moxi add could be alias to moxi start --add
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
pub fn main() !void {
    const binary_path = "zig-out/bin/zig_helloworld";
    std.debug.print("Binary: {s}\n", .{binary_path});

    var debug_alloc: std.heap.DebugAllocator(.{}) = .init;
    const gpa = debug_alloc.allocator();

    var threaded: std.Io.Threaded = .init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const pid = moxi.spawn_child_process(binary_path);

    // What the difference between child traceme and attaching from parent? Which is better? Could not get parent attach to work.
    //_ = linux.ptrace(linux.PTRACE.ATTACH, pid, 0, 0, 0);

    var wait = std.posix.waitpid(pid, 0);
    if (!std.posix.W.IFSTOPPED(wait.status)) {
        return error.UnexpectedState;
    }
    // Required? From Rust lib: /// Stop tracee at next execve call.
    _ = linux.ptrace(linux.PTRACE.SETOPTIONS, pid, 0, linux.PTRACE.O.TRACEEXEC, 0);

    var proc_mappings = try moxi.parse_proc_mappings(gpa, io, pid);
    defer proc_mappings.deinit(gpa);
    // TODO: Currently we only grab the first proc mappings, will need to use the rest to support libraries.
    const executable_base = proc_mappings.items[0].start;
    std.debug.print("TEST: 0x{x}\n", .{executable_base});

    // ELFFFFFFFFFFFFFFFF
    const file = try std.fs.cwd().openFile(binary_path, .{});
    defer file.close();

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
    std.debug.print("entry point: 0x{x}\n", .{ehdr.e_entry});
    std.debug.print("is PIE: {}\n", .{ehdr.e_type == c.ET_DYN});

    //var buffer: [4098]u8 = undefined;
    //var fr = file.reader(io, &buffer);
    //const reader = &fr.interface;

    //var header = try std.elf.Header.read(reader);

    //var it = header.iterateSectionHeaders(&fr);

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

    // TODO: This is the address of the very start of main. We should put breakpoint after prologue.
    //
    //Reading symbols from zig-out/bin/zig_helloworld...
    //(gdb) start
    //Temporary breakpoint 1 at 0x1154458: file main.zig, line 5.
    //Starting program: /home/shivix/PersonalProjects/Zig/moxi/zig-out/bin/zig_helloworld
    //
    //Temporary breakpoint 1, main.main () at main.zig:5
    //5    const hello = "hello";
    //(gdb) dis
    //(gdb) disassemble
    //Dump of assembler code for function main.main:
    //   0x0000000001154450 <+0>:    push   %rbp
    //   0x0000000001154451 <+1>:    mov    %rsp,%rbp
    //   0x0000000001154454 <+4>:    sub    $0x30,%rsp
    //=> 0x0000000001154458 <+8>:    mov    $0x11a503d,%rax
    const main_addr = try moxi.get_main_address(dwfl, ehdr.e_entry);

    const main_instr = try moxi.set_breakpoint(pid, main_addr);
    try moxi.continue_until_breakpoint(pid);
    // If we store breakpoints by address, when we hit a SIGTRAP, we know we hit a bp, so reset the
    // one for current address. Wait no usually if we hit a breakpoint we want to keep it, so we
    // should reinstate the instruction, step once, and then set breakpoint again.
    try moxi.reset_breakpoint(pid, main_addr, main_instr);

    while (true) {
        //<2><2d>: Abbrev Number: 16 (DW_TAG_subprogram)
        //   <2e>   Unknown AT value: 2ccd: <0xb6>
        //   <32>   DW_AT_decl_line   : 0x1
        //   <36>   DW_AT_decl_column : 1
        //   <37>   DW_AT_accessibility: 1 (public)
        //   <38>   DW_AT_name        : (indirect string, offset: 0x22e39): add
        //   <3c>   DW_AT_linkage_name: (indirect string, offset: 0x22e3d): root.add
        //   <40>   DW_AT_type        : <0x508e>
        //   <44>   DW_AT_low_pc      : 0x1155430
        //   <4c>   DW_AT_high_pc     : 0x43
        //   <50>   DW_AT_alignment   : 16
        //   <51>   DW_AT_external    : 0
        //   <52>   DW_AT_noreturn    : 0
        _ = linux.ptrace(linux.PTRACE.SINGLESTEP, pid, 0, 0, 0);
        wait = std.posix.waitpid(pid, 0);
        if (std.posix.W.IFEXITED(wait.status) or std.posix.W.IFSIGNALED(wait.status)) {
            std.debug.print("Program finished\n", .{});
            return;
        }

        var regs: moxi.Registers = undefined;
        _ = linux.ptrace(linux.PTRACE.GETREGS, pid, 0, @intFromPtr(&regs), 0);

        const ip: c.Dwarf_Addr = regs.rip;

        // Based on ChatGPT a module can change between things like lib code etc. Should test.
        const mod = c.dwfl_addrmodule(dwfl, regs.rip);
        //std.debug.print("Mod: {any}\n", .{mod});
        if (mod == null) {
            std.debug.print("Mod not found for RIP: 0x{x}\n", .{ip});
            return error.NoModuleFound;
        }

        const func_name = c.dwfl_module_addrname(mod, ip);
        if (func_name != null) {
            //std.debug.print("function: {s}\n", .{func_name});
        } else {
            std.debug.print("Mod not found for RIP: 0x{x}\n", .{ip});
            return error.NoFunctionNameFound;
        }

        const line = c.dwfl_module_getsrc(mod, ip);
        //const line = c.dwfl_getsrc(dwfl, ip);
        if (line != null) {
            var lineno: c_int = 0;
            var colno: c_int = 0;
            const src_info = c.dwfl_lineinfo(
                line,
                null,
                &lineno,
                &colno,
                null,
                null,
            );

            std.debug.print("0x{x} - {s}:{d}:{d}\n", .{ ip, src_info, lineno, colno });
        }
    }
    // TODO: Set up in moxi style, listen etc.
    // Have separate window for running a make file that builds and runs daemon, then in main window can run commands we wanna test.
    // Maybe create an application specifically for testing? Does a bit of all actions for a certain binary? Goes to main, sets break point,
    // continues, hits breakpoint, steps, reads source etc. Maybe even have that as a unit test?
}
