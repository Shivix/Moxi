use clap::{Arg, Command};

pub fn make_command() -> Command {
    Command::new("init")
        .about("Configures some helper functions in the shell to use moxi")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("shell").help(
            "",
        ))
}

fn main() {

}
