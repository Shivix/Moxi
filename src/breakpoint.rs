use std::net::TcpStream;
use anyhow::Result;

mod writer;
use writer::Writer;

use clap::{Arg, Command};

fn make_command() -> Command {
    Command::new("breakpoint")
        .about("Sets breakpoints at the given instruction")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("instruction/ symbol????").help(
            "",
        ))
}

fn main() -> Result<()> {
    let cmd = make_command();
    let stream = TcpStream::connect("localhost:44500")?;
    let mut writer = Writer::new(stream, cmd.get_name());
    let args = cmd.get_matches();
    let executable_path = args.get_one::<String>("binary").unwrap();
    writer.write(executable_path.as_bytes())?;
    Ok(())
}
