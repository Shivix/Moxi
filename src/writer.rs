use std::io::{BufWriter, Write};
use std::net::TcpStream;

pub struct Writer {
    writer: BufWriter<TcpStream>,
    prefix: String,
}

impl Writer {
    pub fn new(stream: &TcpStream, cmd_name: &str) -> Writer {
        Writer {
            writer: BufWriter::new(stream.try_clone().unwrap()),
            prefix: format!("{}{}", cmd_name, '\u{0001}'),
        }
    }
    pub fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let prefixed_input = [self.prefix.as_bytes(), input, b"\0"].concat();
        let bytes_writtern = self.writer.write(&prefixed_input);
        self.writer.flush()?;
        bytes_writtern
    }
}
