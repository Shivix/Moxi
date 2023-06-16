use std::io::{BufReader, BufRead};
use std::net::TcpStream;

use anyhow::{Result, anyhow};

pub struct Reader {
    reader: BufReader<TcpStream>,
}

#[derive(PartialEq, Eq)]
pub enum Cmd {
    Breakpoint,
    Daemon,
    Source,
    Start,
    Step,
}

fn str_to_cmd(input: &str) -> Result<Cmd> {
    Ok(match input {
        "breakpoint" => Cmd::Breakpoint,
        "daemon" => Cmd::Daemon,
        "source" => Cmd::Source,
        "start" => Cmd::Start,
        "step" => Cmd::Step,
        _ => return Err(anyhow!("failed to parse command name"))
    })
}

impl Reader {
    pub fn new(stream: &TcpStream) -> Reader {
        Reader {
            reader: BufReader::new(stream.try_clone().unwrap()),
        }
    }
    pub fn read(&mut self) -> Result<(Cmd, String)> {
        let mut buffer = Vec::<u8>::new();
        let bytes_read = self.reader.read_until(b'\0', &mut buffer)?;
        if bytes_read == 0 {
            todo!();
        }
        let buffer = String::from_utf8_lossy(&buffer[..buffer.len() - 1]);
        let (command, message) = buffer.split_once('\u{0001}').expect("SOH delimiter not found");
        let command = str_to_cmd(command)?;
        Ok((command, String::from(message)))
    }
}
