use clap::{
    Arg,
    Command,
};
use utils::handler::handle_arguments;

mod utils;

/// Core CLI handler
fn main() {
    let matches = Command::new("ghostwire")
        .name("ghostwire")
        .version("0.1")
        .author("Whole Lotta Heart, Corp.")
        .about("Ghostwire is a stateful XDP firewall")
        .subcommands([
            Command::new("status").about("Gets the current status of the firewall"),
            Command::new("disable").about("Disable the firewall"),
            Command::new("load")
                .about("Load the firewall rules from a configuration file")
                .args([Arg::new("file").required(true)]),
        ])
        .get_matches();

    handle_arguments(matches).expect("failure using arguments");
}
