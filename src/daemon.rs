use std::{ffi::c_void, fs, io::{BufRead, Write}, process::Command, rc::Rc, borrow::Cow, path::Path, collections::HashMap, net::TcpListener};

use anyhow::{Result, anyhow};

use goblin::elf::Elf;
use nix::sys::{
    ptrace,
    wait::{waitpid, WaitStatus},
};
use nix::{sys::signal::Signal, unistd::Pid};

use addr2line::{object::{Object, SymbolMapName, SymbolMap}, gimli::DW_LANG_C_plus_plus, Location};
use addr2line::{
    self,
    gimli::{EndianReader, RunTimeEndian},
    Context,
};

mod writer;
use writer::Writer;
mod reader;
use reader::{Reader, Cmd};

fn make_command() -> clap::Command {
    clap::Command::new("moxid")
        .about("The daemon that attaches to the process to be debugged")
        .version(env!("CARGO_PKG_VERSION"))
}

fn get_source_line(address: u64, context: &Context<EndianReader<RunTimeEndian, Rc<[u8]>>>) -> Option<Location> {
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

type Breakpoints = Vec<(u64, i64)>;

fn set_breakpoint(breakpoints: &mut Breakpoints, pid: Pid, address: u64) -> Result<()> {
    let original_instruction = ptrace::read(pid, address as *mut c_void)?;
    let modified_instruction = (original_instruction & !0xFF) | 0xCC;
    unsafe {
        ptrace::write(pid, address as *mut c_void, modified_instruction as *mut c_void)?;
    }
    breakpoints.push((address, original_instruction));
    Ok(())
}

fn reset_breakpoint(breakpoints: &mut Breakpoints, pid: Pid, address: u64) -> Result<()> {
    let original_instruction = breakpoints.iter().find(|breakpoint| {
        breakpoint.0 == address
    }).ok_or(anyhow!("could not find breakpoint for {}", address))?.1;
    unsafe {
        ptrace::write(pid, address as *mut c_void, original_instruction as *mut c_void).expect("failed to reset breakpoint");
    }
    Ok(())
}

fn continue_to_breakpoint(pid: Pid) -> Result<()> {
    ptrace::cont(pid, None)?;
    loop {
        let status = waitpid(pid, None).expect("Failed to wait for the process");
        let registers = ptrace::getregs(pid)?;
        println!("first{:?}:{:#x}", status, registers.rip);

        if let WaitStatus::Stopped(_, signal) = status {
            if signal == Signal::SIGTRAP {
                // Process hit the breakpoint
                break;
            }
        }
        ptrace::cont(pid, None)?
    }
    Ok(())
}

struct Debuggee<'a> {
    pid: Pid,
    context: Context<EndianReader<RunTimeEndian, Rc<[u8]>>>,
    symbols: SymbolMap<SymbolMapName<'a>>,
    instr_by_symbol: HashMap<&'a str, u64>,
}

fn do_breakpoint(debuggee: &Debuggee, symbol: String, breakpoints: &mut Breakpoints) -> Result<()> {
    println!("do_breakpoint");
    let address = *debuggee.instr_by_symbol.get(symbol.as_str()).unwrap();

    set_breakpoint(breakpoints, debuggee.pid, address)?;
    continue_to_breakpoint(debuggee.pid)?;
    reset_breakpoint(breakpoints, debuggee.pid, address)?;
    Ok(())
}

fn do_source(debuggee: &Debuggee, writer: &mut Writer) -> Result<()> {
    let registers = ptrace::getregs(debuggee.pid)?;
    if let Some(location) = get_source_line(registers.rip, &debuggee.context) {
        // TODO: Improve error handling here.
        println!("test2");
        writer.write(format!("{}:{}\n", location.file.unwrap(), location.line.unwrap()).as_bytes())?;
        println!("test3");
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
    for _i in context.find_location_range(0x1000, 0x564000).unwrap() {
        //println!("{:#x} - {:?}:{:?}", i.0, i.2.file, i.2.line);
    }

    println!("object has debug symbols: {}", object.has_debug_symbols());
    let exe_symbols = object.symbol_map();

    let instr_by_symbol: HashMap<&str, u64> = exe_symbols.symbols().iter().map(|elem| {
        (elem.name(), elem.address())
    }).collect();

    let main_addr = *instr_by_symbol.get("main").unwrap();
    println!("main: {:#x}", main_addr);

    let mut breakpoints = Breakpoints::new();
    set_breakpoint(&mut breakpoints, child_pid, main_addr)?;
    continue_to_breakpoint(child_pid)?;
    reset_breakpoint(&mut breakpoints, child_pid, main_addr)?;

    let debuggee = Debuggee{
        pid: child_pid,
        context,
        symbols: exe_symbols,
        instr_by_symbol,
    };

    loop {
        let stream = listener.accept()?.0;
        let mut reader = Reader::new(&stream);
        let mut writer = Writer::new(&stream, "daemon");
        println!("test6");
        let (command, body) = reader.read()?;
        println!("test5");
        match command {
            Cmd::Breakpoint => do_breakpoint(&debuggee, body, &mut breakpoints)?,
            Cmd::Source => do_source(&debuggee, &mut writer)?,
            Cmd::Start => todo!(),
            Cmd::Step => do_step(&debuggee, body)?,
            _ => break,
        };
    }

    ptrace::detach(child_pid, None)?;

    Ok(())
}
