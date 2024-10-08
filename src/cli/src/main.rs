use crate::utils::socket::send_message;
use clap::{
    Arg,
    Command,
};
use ghostwire_types::{
    ClientMessage,
    ClientReqType,
};
use utils::handler::handle_arguments;

/// The CLI is a thin wrapper around the Unix socket exposed by the firewall
mod utils;

/// Core CLI handler
fn main() {
    let matches = Command::new("ghostwire")
        .name("ghostwire")
        .version("0.1")
        .author("Whole Lotta Heart, Corp.")
        .about("Ghostwire is a stateful XDP firewall")
        .args([
            Arg::new("status")
                .short('s')
                .long("status")
                .action(clap::ArgAction::SetTrue)
                .help("Gets the current status of the firewall"),
            Arg::new("file")
                .short('f')
                .long("file")
                .help("Load the firewall rules from a configuration file"),
        ])
        .get_matches();

    handle_arguments(matches).expect("failure using arguments");
}
