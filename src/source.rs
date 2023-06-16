use std::net::TcpStream;
use anyhow::Result;

mod writer;
use writer::Writer;
mod reader;
use reader::Reader;

use clap::Command;

fn main() -> Result<()> {
    let cmd = Command::new("source")
        .about("print the current file and line of the source code for the current instructions")
        .version(env!("CARGO_PKG_VERSION"));
    let stream = TcpStream::connect("localhost:44500")?;
    let mut reader = Reader::new(&stream);
    let mut writer = Writer::new(&stream, cmd.get_name());
    writer.write(b"line")?;
    let (_, source) = reader.read()?;
    // TODO: args to remove line number?
    let (file, line) = source.split_once(':').unwrap();
    print!("{}", source);
    Ok(())
}
