#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// The LPM trie key for a rule
pub struct RuleKey {
    /// The source IP address in big endian
    pub source_ip_range: u32,
    /// The destination IP address in big endian
    pub destination_ip_range: u32,
    /// The protocol number in big endian
    pub protocol: u8,
    /// The port number in big endian
    pub port_number: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleKey {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// The LPM trie value for a rule
pub struct RuleValue {
    /// The ID of the rule this value is associated with. We use this for analytics.
    pub id: u32,
    /// The ratelimiting value for this rule per minute. If this is 0, there is no ratelimiting.
    pub ratelimit: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleValue {}

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleAnalytics {}
