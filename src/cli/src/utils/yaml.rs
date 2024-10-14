/// This file is dedicated to the YAML chief Dobri.
use anyhow::Context;
use ghostwire_types::Rule;
use serde::Deserialize;
use std::net::Ipv4Addr;

/// Convert the YAML into firewall rules. Returns the rule and the correct interface.
pub fn parse_yaml(yaml: String) -> anyhow::Result<(Vec<Rule>, String)> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml)?;
    let rules: Vec<YamlRule> = serde_yaml::from_value(parsed["rules"].clone())?;

    let parsed_rules: Vec<Rule> = rules
        .into_iter()
        .enumerate()
        .map(|(id, yaml_rule)| convert_to_rule(yaml_rule, id as u32))
        .collect::<Result<Vec<Rule>, anyhow::Error>>()?;

    Ok((
        parsed_rules,
        parsed["interface"]
            .as_str()
            .ok_or(anyhow::anyhow!("interface not provided"))?
            .to_string(),
    ))
}

/// Convert a YAML rule into a firewall rule.
fn convert_to_rule(yaml_rule: YamlRule, id: u32) -> anyhow::Result<Rule> {
    // The total length we'll LPM on.
    let mut prefix_length = 0;
    let (source_ip_range, added_length) = parse_ip_range(&yaml_rule.source_ip_range)?;
    prefix_length += added_length;
    let (destination_ip_range, added_length) = parse_ip_range(&yaml_rule.destination_ip_range)?;
    prefix_length += added_length;

    let mut protocol: Option<u8> = None;

    if let Some(protocol_number) = yaml_rule.protocol {
        protocol = Some(match protocol_number.to_lowercase().as_str() {
            "icmp" => 1,
            "tcp" => 6,
            "udp" => 17,
            _ => anyhow::bail!("Invalid protocol"),
        });

        // We're matching against the 8-bit protocol number.
        prefix_length += 8;
    }

    if yaml_rule.port.is_some() {
        if protocol.is_none() {
            anyhow::bail!("Port provided without protocol");
        }

        // We're matching against the 16-bit port number.
        prefix_length += 16;
    }

    Ok(Rule {
        id,
        prefix_length,
        source_ip_range,
        destination_ip_range,
        protocol_number: u8::to_be(protocol.unwrap_or(0)),
        port_number: u16::to_be(yaml_rule.port.unwrap_or(0)),
        ratelimit: yaml_rule.ratelimit,
    })
}

#[derive(Debug, Deserialize)]
/// A rule in the YAML format.
struct YamlRule {
    source_ip_range: String,
    destination_ip_range: String,
    protocol: Option<String>,
    port: Option<u16>,
    ratelimit: Option<u32>,
}

/// Parse an IP range in CIDR notation to the range and the prefix length.
fn parse_ip_range(ip_range: &str) -> anyhow::Result<(u32, u32)> {
    if ip_range == "0.0.0.0/0" {
        return Ok((0, 0));
    }

    // Break up the subnet from the IP.
    let parts: Vec<&str> = ip_range.split('/').collect();
    // Parse the IPv4 part.
    let ip: Ipv4Addr = parts[0].parse().context("Invalid IP address")?;
    // The user didn't provide a prefix length. Assume it's a single ip (/32).
    let prefix_length: u8 = if parts.len() > 1 {
        parts[1].parse().context("Invalid prefix length")?
    } else {
        32
    };
    let mask = !((1u32 << (32 - prefix_length)) - 1);
    let start_ip = u32::from(ip) & mask;

    Ok((start_ip.to_be(), prefix_length as u32))
}
