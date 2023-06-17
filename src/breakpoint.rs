use anyhow::Result;
use std::net::TcpStream;

mod writer;
use writer::Writer;
mod reader;
use reader::Reader;

use clap::{Arg, Command};

fn make_command() -> Command {
    Command::new("breakpoint")
        .about("Sets breakpoints at the given instruction")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("location").help("The location of the breakpoint"))
}

fn main() -> Result<()> {
    let cmd = make_command();
    let stream = TcpStream::connect("localhost:44500")?;
    let mut writer = Writer::new(&stream, cmd.get_name());
    let mut reader = Reader::new(&stream);
    let args = cmd.get_matches();
    let location = args
        .get_one::<String>("location")
        .expect("Please provide a location for the breakpoint");
    writer.write(location.as_bytes())?;
    let response = reader.read()?.1;
    println!("{}", response);
    Ok(())
}
