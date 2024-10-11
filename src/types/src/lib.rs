extern crate serde;

use serde::{Deserialize, Serialize};

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

/// A firewall rule
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
/// A firewall rule in C format
pub struct Rule {
    /// The ID of this rule with what the API identifies it as. This will also be the key of the
    /// ratelimiting map if ratelimiting is enabled for this rule.
    pub id: u32,
    /// The start source IP address in big endian
    pub source_start_ip: u32,
    /// The end source IP address in big endian
    pub source_end_ip: u32,
    /// The start destination IP address in big endian. If this rule applies everywhere, all bytes
    /// will show 0
    pub destination_start_ip: u32,
    /// The end destination IP address in big endian. If this rule applies everywhere, all bytes
    /// will show 0
    pub destination_end_ip: u32,
    /// Protocol number (currently limited to either 1, 6, 17 for ICMP, TCP, and UDP respectively.
    /// if this rule applies to all protocols, this will be zero)
    pub protocol_number: u8,
    /// The port if TCP or UDP (if not, 0)
    pub port_number: u16,
    /// If the rule is a ratelimiting one, represent the amount of traffic allowed per IP over 10
    /// seconds. If there's no ratelimiting rule, this is 0.
    pub ratelimiting: u32,
}

// trait implementations to make the map fulfill the TryFrom trait used by the hashmap
// indicates our type can be converted from byte arrays
// @see https://discord.com/channels/855676609003651072/855676609003651075/1244017102080315594


/// A network protocol
#[derive(Serialize, Deserialize, Debug)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}
