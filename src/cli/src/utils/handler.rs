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
use std::fs;
use super::yaml::parse_yaml;

pub fn handle_arguments(matches: ArgMatches) -> Result<()> {
    let resp = match matches.subcommand() {
        Some(("status", _)) => send_message(ClientMessage {
            req_type: ClientReqType::STATUS,
            interface: None,
            rules: None,
        }),
        Some(("enable", enable_matches)) => {
            let interface = enable_matches.get_one::<String>("interface").context("No interface provided")?;
            send_message(ClientMessage {
                req_type: ClientReqType::ENABLE,
                interface: Some(interface.to_string()),
                rules: None,
            })
        },
        Some(("disable", _)) => send_message(ClientMessage {
            req_type: ClientReqType::DISABLE,
            interface: None,
            rules: None,
        }),
        Some(("load", file_matches)) => {
            let file = file_matches.get_one::<String>("file").context("No file provided")?;
            let rules = parse_yaml(fs::read_to_string(file)?)?;

            send_message(ClientMessage {
                req_type: ClientReqType::RULES,
                interface: None,
                rules: Some(rules),
            })
        },
        _ => {
            anyhow::bail!("No subcommand provided");
        }
    }?;

    print_success(&resp);

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
