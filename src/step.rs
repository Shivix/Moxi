use std::net::TcpStream;
use anyhow::{Result, anyhow};

mod writer;
use writer::Writer;

use clap::{Arg, Command};

pub fn make_command() -> Command {
    Command::new("step")
        .about("Run through the process to different instructions")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("movement").help(
            "How you'd like to run through the process", // add examples
        ))
}

fn main() -> Result<()> {
    let cmd = make_command();
    let stream = TcpStream::connect("localhost:44500")?;
    let mut writer = Writer::new(stream, cmd.get_name());
    let args = cmd.get_matches();
    let movement = args.get_one::<String>("movement").unwrap();
    // If number step that many times
    // If continue continue
    // If out step out
    // If line step over allow line + number also
    writer.write(movement.as_bytes())?;
    // Simplify logic in daemon by just reducing to fewer things?
    // Continue, step out, line are all basically continue + breakpoint(Symbol?)
    // How to explain where to make breakpoint to daemon?
    // Daemon can if not number assume continue + breakpoint
    Ok(())
}
