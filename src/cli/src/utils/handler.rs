use crate::utils::socket::send_message;
use anyhow::{
    Context,
    Result,
};
use clap::ArgMatches;
use ghostwire_types::{
    ClientMessage,
    ClientReqType,
};

pub fn handle_arguments(matches: ArgMatches) -> Result<()> {
    // if the user wishes to retrive the status
    if matches.get_flag("status") {
        send_message(ClientMessage {
            req_type: ClientReqType::STATUS,
        })
        .context("failed to send status message")?
    }

    // if the user is importing a configuration file
    if let Some(file) = matches.get_one::<String>("file") {
        println!("{}", file)
    };

    Ok(())
}
