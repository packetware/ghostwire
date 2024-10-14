extern crate serde;

use serde::{
    Deserialize,
    Serialize,
};

// Types for firewall rules, messages

/// A message between server and client
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientMessage {
    pub req_type: ClientReqType,
    /// Optional rules to send to the server on a RULES request
    pub rules: Option<Vec<Rule>>,
    /// Optional interface to send to the server on a RULES request
    pub interface: Option<String>,
}

/// What the client is requesting from the server
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientReqType {
    /// Client is asking for the current status of the firewall
    STATUS,
    /// Client is providing new rules and the interface to listen on
    RULES,
    /// Client is asking to enable the firewall
    ENABLE,
    /// Client is asking to disable the firewall
    DISABLE,
}

/// A response from the server
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerMessage {
    pub request_success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// A firewall rule in C format, where fields are expected to be in big endian, or network byte order
/// You may have noticed this also exists in the ghostwire_types crate. This is because that's the specific type
/// that is used in the eBPF program.
pub struct Rule {
    /// The ID of this rule with what the API identifies it as. This will also be the key of the
    /// ratelimiting map if ratelimiting is enabled for this rule.
    pub id: u32,
    /// The specificity of the rule for the LPM trie
    pub prefix_length: u32,
    /// The source IP address / range in big endian
    pub source_ip_range: u32,
    /// The destination IP address / range in big endian
    pub destination_ip_range: u32,
    /// The protocol number in big endian
    pub protocol_number: u8,
    /// The port number in big endian
    pub port_number: u16,
    /// If the rule is a ratelimiting one, represent the amount of traffic allowed per IP over a minute.
    pub ratelimit: Option<u32>,
}

/// A network protocol. This is used in the Rule struct to determine what protocol the rule applies to.
#[derive(Serialize, Deserialize, Debug)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}
