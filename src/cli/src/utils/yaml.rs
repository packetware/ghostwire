/// This file is dedicated to the YAML chief Dobri.

use ghostwire_types::Rule;
use serde::Deserialize;
use std::net::Ipv4Addr;

/// Convert the YAML into firewall rules.
pub fn parse_yaml(yaml: String) -> anyhow::Result<Vec<Rule>> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml)?;
    let rules: Vec<YamlRule> = serde_yaml::from_value(parsed["rules"].clone())?;

    let parsed_rules: Vec<Rule> = rules
        .into_iter()
        .enumerate()
        .map(|(id, yaml_rule)| convert_to_rule(yaml_rule, id as u32))
        .collect::<Result<Vec<Rule>, anyhow::Error>>()?;


    Ok(parsed_rules)
}

/// Convert a YAML rule into a firewall rule.
fn convert_to_rule(yaml_rule: YamlRule, id: u32) -> anyhow::Result<Rule> {
    let (source_start_ip, source_end_ip) = parse_ip_range(&yaml_rule.source_ip_range)?;
    let (destination_start_ip, destination_end_ip) =
        parse_ip_range(&yaml_rule.destination_ip_range)?;

    let protocol_number = match yaml_rule.protocol.to_lowercase().as_str() {
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        _ => anyhow::bail!("Invalid protocol"),
    };

    Ok(Rule {
        id,
        source_start_ip,
        source_end_ip,
        destination_start_ip,
        destination_end_ip,
        protocol_number: u8::to_be(protocol_number),
        port_number: u16::to_be(yaml_rule.port),
        ratelimiting: yaml_rule.ratelimit,
    })
}

#[derive(Debug, Deserialize)]
/// A rule in the YAML format.
struct YamlRule {
    source_ip_range: String,
    destination_ip_range: String,
    protocol: String,
    port: u16,
    ratelimit: u32,
}

/// Parse an IP range in CIDR notation to two big endian numbers: the start and end of the range.
fn parse_ip_range(ip_range: &str) -> anyhow::Result<(u32, u32)> {
    if ip_range == "0.0.0.0/0" {
        return Ok((0, u32::MAX));
    }

    let parts: Vec<&str> = ip_range.split('/').collect();
    let ip: Ipv4Addr = parts[0].parse().expect("Invalid IP address");
    let prefix_length: u8 = if parts.len() > 1 {
        parts[1].parse().expect("Invalid prefix length")
    } else {
        32
    };
    println!("IP: {:?}, Prefix: {}", ip, prefix_length);
    let mask = !((1u32 << (32 - prefix_length)) - 1);

    let start_ip = u32::from(ip) & mask;
    let end_ip = start_ip | !mask;

    println!("Start: {:?}, End: {:?}", start_ip, end_ip);

    Ok((start_ip.to_be(), end_ip.to_be()))
}
