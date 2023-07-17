use anyhow::Result;
use std::net::TcpStream;

#[path = "internal/writer.rs"]
mod writer;

use writer::Writer;

use clap::{Arg, Command};

fn main() -> Result<()> {
    let cmd = Command::new("start")
        .about("start a process to be debugged")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("binary").help("The binary file to attach and debug"))
        .arg(Arg::new("main").long("no-main").short('m').help(
            "Prevents the process from automatically setting a breakpoint on main and continueing.",
        ));
    let stream = TcpStream::connect("localhost:44500")?;
    let mut writer = Writer::new(&stream, cmd.get_name());
    let args = cmd.get_matches();
    let executable_path = args.get_one::<String>("binary").unwrap();
    // TODO: turn relative paths into absolute paths for Daemon.
    writer.write(executable_path.as_bytes())?;
    Ok(())
}
