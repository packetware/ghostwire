use serde::Deserialize;
use ipnetwork::IpNetwork;
use std::net::{IpAddr};
use anyhow::bail;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub interface: String,
    pub source: Source,
    pub default: Option<String>, // Optional: "allow" or "block"
    pub allow: Option<Vec<String>>, // List of IPs to allow
    pub block: Option<Vec<String>>, // List of IPs to block
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Source {
    #[serde(rename = "type")]
    source_type: String, // "local" or "database"
    database: Option<DatabaseConfig>, // Only present if `source_type` is "database"
}

#[derive(Debug, Deserialize)]
struct DatabaseConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    database_name: String,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    action: Option<String>, // Optional: "allow" or "block"
    sources: Option<Vec<String>>, // List of CIDRs or IPs, defaults to 0.0.0.0/0
    destinations: Option<Vec<String>>,    // Required: List of CIDRs or IPs
    protocols: Vec<String>,       // Required: List of protocols
    ports: Option<Vec<u16>>,      // Optional: List of specific ports
    port_range: Option<PortRange>, // Optional: Range of ports
}

#[derive(Debug, Deserialize)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug)]
pub struct ExpandedRule {
    pub source: String,
    pub destination: String,
    pub protocol: u8, // 6 = TCP, 17 = UDP, 1 = ICMP
    pub port: u16,
    pub action: u32, // 0 = allow, 1 = block
}

/// Take a rule from YAML and expand it into multiple rules
pub fn expand_rule(rule: &Rule, default_action: &str) -> anyhow::Result<Vec<ExpandedRule>> {
    // If rule action is not specified it is the opposite of the default
    let action = match rule.action.as_deref() {
        Some("allow") => 0, // Explicit "allow" maps to 0
        Some("block") => 1, // Explicit "block" maps to 1
        None => if default_action == "allow" { 1 } else if default_action == "block" { 0 } else {
            bail!("Invalid default action: {}", default_action)
        }, // Opposite of default_action
        Some(invalid) => panic!("Invalid action: {}", invalid), // Catch invalid actions
    };

  let src_binding = Vec::<String>::new();
  let source_cidrs = rule.sources.as_deref().unwrap_or(&src_binding);
  let dst_binding = Vec::<String>::new();
  let destination_cidrs = rule.destinations.as_deref().unwrap_or(&dst_binding);
  let protocols = rule.protocols.iter().map(|protocol| match protocol.to_uppercase().as_str() {
      "TCP" => 6,
      "UDP" => 17,
      "ICMP" => 1,
      _ => panic!("Unsupported protocol: {}", protocol),
  });

  let ports = if let Some(port_list) = &rule.ports {
      port_list.clone()
  } else if let Some(range) = &rule.port_range {
      (range.start..=range.end).collect()
  } else {
      vec![0] // Default to all ports if neither `ports` nor `port_range` is specified
  };

  let mut expanded_rules = Vec::new();

    // If source_cidrs is empty, we insert 0.0.0.0
    let source_ips = if !source_cidrs.is_empty() {
        source_cidrs.iter().flat_map(|src_cidr| expand_cidr(src_cidr)).collect::<Vec<_>>()
    } else {
        vec![IpAddr::V4("0.0.0.0".parse().unwrap())] // Add 0.0.0.0 if no source CIDR is present
    };

    // If destination_cidrs is empty, we insert 0.0.0.0
    let destination_ips = if !destination_cidrs.is_empty() {
        destination_cidrs.iter().flat_map(|dst_cidr| expand_cidr(dst_cidr)).collect::<Vec<_>>()
    } else {
        vec![IpAddr::V4("0.0.0.0".parse().unwrap())] // Add 0.0.0.0 if no destination CIDR is present
    };
  
    for protocol in protocols {
        for src_ip in &source_ips {
            for dst_ip in &destination_ips {
                if protocol == 1 { // Check if the protocol is ICMP
                    // Add a rule with port 0 for ICMP
                    expanded_rules.push(ExpandedRule {
                        source: src_ip.to_string(),
                        destination: dst_ip.to_string(),
                        protocol,
                        port: 0, // Default port to 0 for ICMP
                        action,
                    });
                } else {
                    for port in &ports {
                        expanded_rules.push(ExpandedRule {
                            source: src_ip.to_string(),
                            destination: dst_ip.to_string(),
                            protocol,
                            port: *port,
                            action,
                        });
                    }
                }
            }
        }
    }
  Ok(expanded_rules)
}

pub fn expand_cidr(cidr: &str) -> Vec<IpAddr> {
  let ip_network: IpNetwork = cidr.parse().expect("Invalid CIDR format");
  ip_network.iter().collect()
}