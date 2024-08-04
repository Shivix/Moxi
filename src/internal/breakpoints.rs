use std::collections::HashMap;

use std::ffi::c_void;

use anyhow::{anyhow, Result};

use nix::sys::ptrace;
use nix::unistd::Pid;

#[derive(Copy, Clone)]
pub struct Breakpoint {
    pub address: u64,
    // The original instruction at the breakpoint location.
    pub instruction: i64,
}

pub type Breakpoints = HashMap<u64, Breakpoint>;

pub fn set_breakpoint(breakpoints: &mut Breakpoints, pid: Pid, address: u64) -> Result<()> {
    if breakpoints.contains_key(&address) {
        return Err(anyhow!("breakpoint already exists"));
    }
    let instruction = ptrace::read(pid, address as *mut c_void)?;
    println!("read instruction");
    let modified_instruction = (instruction & !0xFF) | 0xCC;
    ptrace::write(pid, address as *mut c_void, modified_instruction)?;
    // TODO: possibly need a range of address :thinking:
    breakpoints.insert(
        address,
        Breakpoint {
            address,
            instruction,
        },
    );
    println!("INFO: set breakpoint at {:#x}", address);
    Ok(())
}

pub fn reset_breakpoint(pid: Pid, breakpoint: Breakpoint) -> Result<()> {
    ptrace::write(
        pid,
        breakpoint.address as *mut c_void,
        breakpoint.instruction,
    )
    .expect("failed to reset breakpoint");
    // TODO: remove from Breakpoints. Probably makes sense as method for Breakpoints
    Ok(())
}
