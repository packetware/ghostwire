#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Analytics for each rule
pub struct RuleAnalytics {
    /// The ID of the rule this is referencing
    pub rule_id: u32,
    /// Number of times this rule was evaluated
    pub evaluated: u128,
    /// Number of times traffic passed this rule
    pub passed: u128,
}

// trait implementations to make the map fulfill the TryFrom trait used by the hashmap
// indicates our type can be converted from byte arrays
// @see https://discord.com/channels/855676609003651072/855676609003651075/1244017102080315594
#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleAnalytics {}
