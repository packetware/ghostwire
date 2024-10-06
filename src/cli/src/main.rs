use clap::{Arg, Command};
use std::os::unix::net::UnixStream;
use ghostwire_types::{ClientMessage, ClientReqType};
use crate::utils::socket::send_message;

/// The CLI is a thin wrapper around the Unix socket exposed by the firewall

mod utils;

/// Core CLI handler
fn main() {
    let matches = Command::new("ghostwire")
        .name("ghostwire")
        .version("0.1")
        .author("Edward Coristine and other open-source authors")
        .about("Ghostwire is a stateful XDP firewall")
        .arg(
            Arg::new("status")
                .short('s')
                .long("status")
                .action(clap::ArgAction::SetTrue)
                .help("Gets the current status of the firewall"),
        )
        .get_matches();

    // if the user wants to get the status
    if matches.get_flag("status") {
       send_message(ClientMessage { req_type: ClientReqType::STATUS }).unwrap(); 
    }
}
