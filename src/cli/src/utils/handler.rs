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
use colored::*;

pub fn handle_arguments(matches: ArgMatches) -> Result<()> {
    // if the user wishes to retrive the status
    let resp = if matches.get_flag("status") {
        send_message(ClientMessage {
            req_type: ClientReqType::STATUS,
            interface: None,
            rules: None,
        })
        .context("failed to send status message")?
    } else if let Some(interface) = matches.get_one::<String>("enable") {
        send_message(ClientMessage {
            req_type: ClientReqType::ENABLE,
            interface: Some(interface.to_string()),
            rules: None,
        })
        .context("failed to send enable message")?
    } else if matches.get_flag("disable") {
        send_message(ClientMessage {
            req_type: ClientReqType::DISABLE,
            interface: None,
            rules: None,
        })
        .context("failed to send disable message")?
    } else {
        return Ok(());
    };

    print_success(&resp);

    // if the user is importing a configuration file
    if let Some(file) = matches.get_one::<String>("file") {
        println!("{}", file)
    };

    Ok(())
}

fn print_success(message: &str) {
    println!(
        "{} {} {}",
        ">>>".bold().blue(),
        message.bold().green(),
        "<<<".bold().blue()
    );
}
