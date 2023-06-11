use std::io::{BufReader, Read};
use std::net::TcpStream;

use anyhow::{Result, anyhow};

pub struct Reader {
    reader: BufReader<TcpStream>,
}

#[derive(PartialEq, Eq)]
pub enum Cmd {
    Breakpoint,
    Start,
    Step,
}

fn str_to_cmd(input: &str) -> Result<Cmd> {
    Ok(match input {
        "breakpoint" => Cmd::Breakpoint,
        "start" => Cmd::Start,
        "step" => Cmd::Step,
        _ => return Err(anyhow!("failed to parse command name"))
    })
}

impl Reader {
    pub fn new(stream: TcpStream) -> Reader {
        Reader {
            reader: BufReader::new(stream),
        }
    }
    pub fn read(&mut self) -> Result<(Cmd, String)> {
        let mut buffer = String::new();
        self.reader.read_to_string(&mut buffer)?;
        let (command, message) = buffer.split_once('\u{0001}').expect("SOH delimiter not found");
        let command = str_to_cmd(command)?;
        Ok((command, String::from(message)))
    }
}
