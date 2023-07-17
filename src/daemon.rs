use std::{
    borrow::Cow, collections::HashMap, fs, io::BufRead, net::TcpListener, path::Path,
    process::Command, rc::Rc,
};

use anyhow::{anyhow, Result};

use goblin::elf::Elf;
use nix::sys::{
    ptrace,
    wait::{waitpid, WaitStatus},
};
use nix::{sys::signal::Signal, unistd::Pid};

use addr2line::{
    self,
    gimli::{EndianReader, RunTimeEndian},
    Context,
};
use addr2line::{
    gimli::DW_LANG_C_plus_plus,
    object::{Object, SymbolMap, SymbolMapName},
    Location,
};

#[path = "internal/breakpoints.rs"]
mod breakpoints;
#[path = "internal/reader.rs"]
mod reader;
#[path = "internal/writer.rs"]
mod writer;

use breakpoints::*;
use reader::{Cmd, Reader};
use writer::Writer;

fn make_command() -> clap::Command {
    clap::Command::new("moxid")
        .about("The daemon that attaches to the process to be debugged")
        .version(env!("CARGO_PKG_VERSION"))
}

fn get_source_line(
    address: u64,
    context: &Context<EndianReader<RunTimeEndian, Rc<[u8]>>>,
) -> Option<Location> {
    let Some(location) = context.find_location(address).unwrap() else {
        return None;
    };

    if let Some(file) = location.file {
        println!("File: {:?}", file);
    }
    if let Some(line) = location.line {
        println!("Line: {:?}", line);
    }
    Some(location)
}

fn binary_base_address(child: Pid) -> Vec<(u64, u64)> {
    let maps_path = format!("/proc/{}/maps", child);
    let mappings = std::fs::File::open(maps_path).expect("failed to open memory mappings file");

    let mut result = Vec::new();
    let reader = std::io::BufReader::new(mappings);
    for line in reader.lines() {
        let line = line.unwrap();
        if line.contains("r-xp") && line.contains('/') {
            let address_range = line
                .split_once('-')
                .expect("memory mapping file has invalid format");
            let start_address = u64::from_str_radix(address_range.0, 16)
                .expect("start address is not valid hexadecimal");
            let end_address = u64::from_str_radix(address_range.1.split_once(' ').unwrap().0, 16)
                .expect("end address is not valid hexadecimal");
            println!("{:#x}, {:#x}", start_address, end_address);
            result.push((start_address, end_address));
        }
    }
    if result.is_empty() {
        panic!("unable to find executable base address")
    }
    result
}

fn get_linked_libraries(elf: &Elf) {
    for lib in elf.libraries.iter() {
        println!("{}", lib);
    }
}

fn continue_to_breakpoint(pid: Pid) -> Result<u64> {
    ptrace::cont(pid, None)?;
    loop {
        println!("INFO: continuing");
        let status = waitpid(pid, None).expect("Failed to wait for the process");
        let registers = ptrace::getregs(pid)?;
        println!("INFO: rip: {:#x}, {:?}", registers.rip, status);
        match status {
            WaitStatus::Exited(_, exit_code) => {
                println!("debuggee exited with code {}", exit_code);
                return Err(anyhow!("exited without hitting breakpoint"));
            }
            WaitStatus::Stopped(_, signal) => {
                // TODO: use pattern match.
                if signal == Signal::SIGTRAP {
                    // Process hit the breakpoint
                    break;
                }
                if signal == Signal::SIGSEGV {
                    return Err(anyhow!("Segfault"));
                }
                ptrace::cont(pid, None)?;
            }
            _ => ptrace::cont(pid, None)?,
        }
    }
    let registers = ptrace::getregs(pid)?;
    Ok(registers.rip)
}

struct Debuggee<'a> {
    pid: Pid,
    breakpoints: Breakpoints,
    context: Context<EndianReader<RunTimeEndian, Rc<[u8]>>>,
    symbols: SymbolMap<SymbolMapName<'a>>,
    instr_by_symbol: HashMap<&'a str, u64>,
    instr_by_line: HashMap<String, u64>,
}

fn do_breakpoint(
    debuggee: &Debuggee,
    location: String,
    breakpoints: &mut Breakpoints,
    writer: &mut Writer,
) -> Result<()> {
    let address = if location.contains(':') {
        debuggee.instr_by_line.get(location.as_str())
    } else {
        debuggee.instr_by_symbol.get(location.as_str())
    };

    let Some(address) = address else {
        writer.write(b"invalid location")?;
        return Ok(());
    };
    writer.write(b"breakpoint set")?;

    set_breakpoint(breakpoints, debuggee.pid, *address)?;
    continue_to_breakpoint(debuggee.pid)?;
    reset_breakpoint(breakpoints, debuggee.pid, *address)?;
    Ok(())
}

fn do_source(debuggee: &Debuggee, writer: &mut Writer) -> Result<()> {
    let registers = ptrace::getregs(debuggee.pid)?;
    if let Some(location) = get_source_line(registers.rip, &debuggee.context) {
        // TODO: Improve error handling here.
        writer
            .write(format!("{}:{}\n", location.file.unwrap(), location.line.unwrap()).as_bytes())?;
    }
    Ok(())
}

fn do_step(debuggee: &Debuggee, movement: String) -> Result<()> {
    println!("do_step");
    let steps = if let Ok(steps) = movement.parse::<i32>() {
        steps
    } else {
        1
    };
    for _ in 0..steps {
        let instruction = step(debuggee.pid)?;
        get_source_line(instruction, &debuggee.context);
        let symbol = match debuggee.symbols.get(instruction) {
            Some(symbol) => symbol.name(),
            None => "",
        };
        let demangled_name = addr2line::demangle_auto(Cow::from(symbol), Some(DW_LANG_C_plus_plus));
        println!("symbol: {}", demangled_name);
    }
    Ok(())
}

fn step(pid: Pid) -> Result<u64> {
    ptrace::step(pid, None)?;
    let status = waitpid(pid, None)?;
    let registers = ptrace::getregs(pid)?;
    let instruction = registers.rip;
    //let instruction = registers.rip - base_address[0].0;
    println!("{:?}:{:#x}", status, instruction);
    Ok(instruction)
}

fn main() -> Result<()> {
    let listener = TcpListener::bind("localhost:44500")?;
    let stream = listener.accept()?.0;
    let mut reader = Reader::new(&stream);
    let executable_path;

    loop {
        let (command, path) = reader.read()?;
        if command == Cmd::Start {
            executable_path = path;
            break;
        }
        println!("an executable path must first be provided with moxi start");
    }

    let file = fs::File::open(&executable_path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let object = &addr2line::object::File::parse(&*mmap).unwrap();

    let file = std::fs::read(Path::new(&executable_path)).expect("Failed to read executable file");
    let elf = Elf::parse(&file).expect("Failed to parse ELF file");

    get_linked_libraries(&elf);

    let mut cmd = Command::new(executable_path);
    let child = cmd.spawn()?;
    let child_pid = Pid::from_raw(child.id() as i32);

    ptrace::attach(child_pid)?;
    let status = waitpid(child_pid, None)?;
    ptrace::setoptions(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEEXEC,
    )?;
    println!("attached and options set: {:?}", status);

    let context = Context::new(object).expect("Failed to create context");

    let base_address = binary_base_address(child_pid);
    println!("Base Address: {:#x}", base_address[0].0);

    // If it's statically linked shouldn't this contain lib instructions?
    let instr_by_line: HashMap<String, u64> = context
        .find_location_range(0x1000, 0x564000)
        .unwrap()
        .map(|i| {
            let location = format!("{}:{}", i.2.file.unwrap(), i.2.line.unwrap());
            (location, i.0)
        })
        .collect();

    println!("object has debug symbols: {}", object.has_debug_symbols());
    let exe_symbols = object.symbol_map();

    // FIXME: be consistent with instr vs addr.
    let instr_by_symbol: HashMap<&str, u64> = exe_symbols
        .symbols()
        .iter()
        .map(|elem| (elem.name(), elem.address()))
        .collect();

    let main_addr = *instr_by_symbol.get("main").unwrap();
    println!("main: {:#x}", main_addr);

    let mut breakpoints = Breakpoints::new();
    set_breakpoint(&mut breakpoints, child_pid, main_addr)?;
    continue_to_breakpoint(child_pid)?;
    reset_breakpoint(&mut breakpoints, child_pid, main_addr)?;

    let debuggee = Debuggee {
        pid: child_pid,
        context,
        symbols: exe_symbols,
        instr_by_symbol,
        instr_by_line,
    };

    loop {
        let stream = listener.accept()?.0;
        let mut reader = Reader::new(&stream);
        let mut writer = Writer::new(&stream, "daemon");
        let (command, body) = reader.read()?;
        match command {
            Cmd::Breakpoint => do_breakpoint(&debuggee, body, &mut breakpoints, &mut writer)?,
            Cmd::Source => do_source(&debuggee, &mut writer)?,
            Cmd::Start => todo!(),
            Cmd::Step => do_step(&debuggee, body)?,
            _ => break,
        };
    }

    ptrace::detach(child_pid, None)?;

    Ok(())
}
