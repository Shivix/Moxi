use std::{
    borrow::Cow, collections::HashMap, fs, io::BufRead, net::TcpListener, path::Path,
    process::Command,
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
    Loader,
};
use addr2line::{
    gimli::DW_LANG_C_plus_plus,
    Location,
};

use object::{Object, SymbolMap, SymbolMapName};

#[path = "internal/breakpoints.rs"]
mod breakpoints;
#[path = "internal/reader.rs"]
mod reader;
#[path = "internal/writer.rs"]
mod writer;

use breakpoints::*;
use reader::{Cmd, Reader};
use writer::Writer;

#[allow(dead_code)] // TODO:
fn make_command() -> clap::Command {
    clap::Command::new("moxid")
        .about("The daemon that attaches to the process to be debugged")
        .version(env!("CARGO_PKG_VERSION"))
}

fn get_source_line(
    address: u64,
    loader: &Loader,
) -> Option<Location> {
    println!("Addr for source: {:#x}", address);
    let Some(location) = loader.find_location(address).unwrap() else {
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

fn binary_base_address(child: Pid) -> (u64, Vec<(u64, u64)>) {
    let maps_path = format!("/proc/{}/maps", child);
    let mappings = std::fs::File::open(maps_path).expect("failed to open memory mappings file");
    // TODO: make more robust by getting 00000000 for matching binary name
    let mut result = Vec::new();
    let reader = std::io::BufReader::new(mappings);
    let mut base_address = 0_u64;
    for line in reader.lines() {
        let line = line.unwrap();
        if (line.contains("r-xp") && line.contains('/')) || base_address == 0 {
            let address_range = line
                .split_once('-')
                .expect("memory mapping file has invalid format");
            let start_address = u64::from_str_radix(address_range.0, 16)
                .expect("start address is not valid hexadecimal");
            let end_address = u64::from_str_radix(address_range.1.split_once(' ').unwrap().0, 16)
                .expect("end address is not valid hexadecimal");
            println!("{:#x}, {:#x}", start_address, end_address);
            result.push((start_address, end_address));
            if base_address == 0 {
                base_address = start_address;
            }
        }
    }
    if result.is_empty() {
        panic!("unable to find executable base address")
    }
    (base_address, result)
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
    loader: Loader,
    symbols: SymbolMap<SymbolMapName<'a>>,
    instr_by_symbol: HashMap<&'a str, u64>,
    instr_by_line: HashMap<String, u64>,
}

fn do_breakpoint(
    debuggee: &mut Debuggee,
    location: String,
    writer: &mut Writer,
) -> Result<()> {
    println!("INFO: do_breakpoint");
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

    // TODO: support removing breakpoints
    set_breakpoint(&mut debuggee.breakpoints, debuggee.pid, *address)?;
    Ok(())
}

fn do_source(debuggee: &Debuggee, writer: &mut Writer, base_address: u64) -> Result<()> {
    println!("INFO: do_source");
    let registers = ptrace::getregs(debuggee.pid)?;
    if let Some(location) = get_source_line(registers.rip - base_address, &debuggee.loader) {
        // TODO: Improve error handling here.
        writer
            .write(format!("{}:{}\n", location.file.unwrap(), location.line.unwrap()).as_bytes())?;
    } else {
        println!("ERROR: Could not find source line");
    }
    Ok(())
}

fn do_step(debuggee: &mut Debuggee, movement: String) -> Result<()> {
    println!("INFO: do_step");
    if movement == "continue" {
        println!("INFO: continueing");
        let instr = continue_to_breakpoint(debuggee.pid)?;
        // Better handle continuing to the end
        println!("INFO: resetting breakpoint");
        reset_breakpoint(debuggee.pid, debuggee.breakpoints[&instr])?;
        return Ok(())
    }
    let steps = movement.parse::<i32>().unwrap_or(1);
    for _ in 0..steps {
        let address = step(debuggee.pid)?;
        if let Some(instruction) = debuggee.breakpoints.get(&address) {
            reset_breakpoint(debuggee.pid, *instruction)?;
        }
        get_source_line(address, &debuggee.loader);
        let symbol = match debuggee.symbols.get(address) {
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
    println!("Waiting to accept init");
    let stream = listener.accept()?.0;
    let mut reader = Reader::new(&stream);
    let executable_path;

    loop {
        println!("Waiting for executable path");
        let (command, path) = reader.read()?;
        if command == Cmd::Start {
            executable_path = path;
            break;
        }
        println!("an executable path must first be provided with moxi start");
    }

    let binary_data = fs::read(&executable_path)?;
    let object = object::read::File::parse(&*binary_data)?;

    let loader = addr2line::Loader::new(&executable_path).expect("Failed to load executable");

    let file = std::fs::read(Path::new(&executable_path)).expect("Failed to read executable file");
    let elf = Elf::parse(&file).expect("Failed to parse ELF file");

    get_linked_libraries(&elf);

    let mut cmd = Command::new(executable_path);
    let child = cmd.spawn()?;
    let child_pid = Pid::from_raw(child.id() as i32);

    ptrace::attach(child_pid)?;
    println!("attached to child: {}", child_pid);
    let status = waitpid(child_pid, None)?;
    ptrace::setoptions(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEEXEC,
    )?;
    println!("ptrace options set: {:?}", status);
    // Should be fine to not randomize address since getting offset from maps
    //personality::set(Persona::ADDR_NO_RANDOMIZE)?;
    println!("address space layout randomization not disabled");

    let (base_address, _) = binary_base_address(child_pid);
    println!("Base Address: {:#x}", base_address);

    // If it's statically linked shouldn't this contain lib instructions?
    let instr_by_line: HashMap<String, u64> = loader
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
    // TODO: allow duplicates in these maps? always last/first address?
    // -//-: Maybe have vector of addresses here? then for x by addr make for each addr?
    assert!(exe_symbols.symbols().len() == instr_by_symbol.len());

    /*
    56086b0a4000-56086b0a5000 r--p 00000000 103:02 18221675                  /home/shivix/RustProjects/Moxi/test/a.out
    56086b0a5000-56086b0a6000 r-xp 00001000 103:02 18221675                  /home/shivix/RustProjects/Moxi/test/a.out
    Should I have first line as base address?
    */
    let main_addr = *instr_by_symbol.get("main").unwrap() + base_address;
    println!("found main function: {:#x}", main_addr);

    let mut breakpoints = Breakpoints::new();
    // TODO: How to tell when to offset address?
    set_breakpoint(&mut breakpoints, child_pid, main_addr)?;
    continue_to_breakpoint(child_pid)?;
    reset_breakpoint(child_pid, breakpoints[&main_addr])?;
    println!("INFO: at start of main");

    let mut debuggee = Debuggee {
        pid: child_pid,
        breakpoints,
        loader,
        symbols: exe_symbols,
        instr_by_symbol,
        instr_by_line,
    };

    // TODO: time to refactor overall structure.
    loop {
        let stream = listener.accept()?.0;
        println!("INFO: client accepted");
        let mut reader = Reader::new(&stream);
        let mut writer = Writer::new(&stream, "daemon");
        let (command, body) = reader.read()?;
        println!("INFO: message read: {}", body);
        match command {
            Cmd::Breakpoint => do_breakpoint(&mut debuggee, body, &mut writer)?,
            Cmd::Source => do_source(&debuggee, &mut writer, base_address)?,
            Cmd::Start => todo!(),
            Cmd::Step => do_step(&mut debuggee, body)?,
            _ => break,
        };
    }

    ptrace::detach(child_pid, None)?;

    Ok(())
}
