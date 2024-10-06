extern crate serde;

use serde::{Serialize, Deserialize};

/// Types for firewall rules, messages

/// A message between server and client 
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientMessage {
    pub req_type: ClientReqType
}

/// What the client is requesting from the server
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientReqType {
    STATUS
}

/// A response from the server
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerMessage {
    pub request_success: bool,
    pub message: Option<String>
}

/// A firewall rule
#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    pub source: u32,
    pub protocol: Protocol,
    pub port: Option<u16>,
}

/// A network protocol
#[derive(Serialize, Deserialize, Debug)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}
