use std::io::{BufWriter, Write};
use std::net::TcpStream;

pub struct Writer {
    writer: BufWriter<TcpStream>,
    prefix: String,
}

impl Writer {
    pub fn new(stream: TcpStream, cmd_name: &str) -> Writer {
        Writer {
            writer: BufWriter::new(stream),
            prefix: format!("{}{}", cmd_name, '\u{0001}'),
        }
    }
    pub fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let prefixed_input = [self.prefix.as_bytes(), input].concat();
        self.writer.write(&prefixed_input)
    }
}
