use aya_ebpf::{
    bindings::xdp_action::{
        XDP_ABORTED,
        XDP_DROP,
        XDP_PASS,
    },
    helpers::bpf_ktime_get_ns,
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use network_types::{
    eth::EthHdr,
    ip::{
        IpProto::{
            Icmp,
            Tcp,
            Udp,
        },
        Ipv4Hdr,
    },
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    utils::ptr_at::xdp_ptr_at_fallible,
    HOLEPUNCHED,
    RATELIMITING,
    RULES,
    RULE_ANALYTICS,
};
use ghostwire_common::{
    RuleAnalytics,
    RuleKey,
};

/// The function called whenever a packet enters through the wire. This should:
/// 1. Parse the packet;
///     - Letting the packet through if it's an internal protocol (like ARP)
///     - Dropping or rejecting clearly malformed traffic
/// 2. Look for rules;
///     - Evaluating rules to see if they're applicable to this rule
///     - Performing ratelimiting if the rule has it enabled
/// 3. Look for entries that are holepunched;
///     - Since we're a stateful firewall, look for when we established a connection outbound and allow that traffic back in
///     - When connections are terminated (like if the client sends a FIN or RST to the port), remove from the holepunched map
/// 4. Drop traffic
///     - When traffic has made it to this point, it's not whitelisted or holepunched. Since we're (at least currently) a default-drop firewall, drop it.
pub unsafe fn ghostwire_ingress_fallible(ctx: XdpContext) -> Result<u32, u32> {
    // skip the ethernet header, that's not providing us with any value right now
    // attempt to parse the ip header
    let ip_header: *const Ipv4Hdr =
        xdp_ptr_at_fallible(&ctx, EthHdr::LEN).map_err(|_| XDP_ABORTED)?;

    // Read the source and destination IPs from the IP header.
    let source_ip = unsafe { (*ip_header).src_addr };
    let destination_ip = unsafe { (*ip_header).dst_addr };
    let protocol = unsafe { (*ip_header).proto };
    let (source_port, destination_port) = match protocol {
        Tcp => {
            // parse the TCP header
            let tcp_header: *const TcpHdr =
                xdp_ptr_at_fallible::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)
                    .map_err(|_| XDP_ABORTED)?;

            // get the source and destination ports
            ((*tcp_header).source, (*tcp_header).dest)
        }
        Udp => {
            // parse the UDP header
            let udp_header: *const UdpHdr =
                xdp_ptr_at_fallible::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)
                    .map_err(|_| XDP_ABORTED)?;

            // get the source and destination ports
            ((*udp_header).source, (*udp_header).dest)
        }
        Icmp => (0, 0),
        // Currently, we don't support any other protocols
        _ => return Ok(XDP_PASS),
    };

    // Create a key for the holepunched map, upgrading the type to u64 to avoid overflow
    let key =
        source_ip as u64 + source_port as u64 + destination_ip as u64 + destination_port as u64;

    if let Some(last_time) = HOLEPUNCHED.get_ptr_mut(&key) {
        // Update the time of the connection.
        (*last_time) = bpf_ktime_get_ns();

        return Ok(XDP_PASS);
    }

    if let Some(rule) = RULES.get(&Key {
        // 32 bit source IP + 32 bit destination IP + 8 bit protocol + 16 bit port number
        prefix_len: 88,
        data: RuleKey {
            source_ip_range: source_ip,
            destination_ip_range: destination_ip,
            protocol: protocol as u8,
            port_number: destination_port,
        },
    }) {
        // Indicate we have evaulated this rule.
        match RULE_ANALYTICS.get_ptr_mut(&rule.id) {
            Some(analytics) => {
                (*analytics).evaluated += 1;
            }
            None => {
                let _ = RULE_ANALYTICS.insert(
                    &rule.id,
                    &RuleAnalytics {
                        rule_id: rule.id,
                        evaluated: 1,
                        passed: 0,
                    },
                    0,
                );
            }
        }

        // Determine if we should perform ratelimiting.
        if rule.ratelimit != 0 {
            // Create a ratelimit key. This is a combination of the source IP and the rule ID.
            let key = (source_ip + rule.id) as u64;
            // Fetch and increment ratelimit value for this key.
            let current_value = match RATELIMITING.get_ptr_mut(&key) {
                Some(value) => {
                    *value += 1;
                    *value
                }
                None => {
                    let _ = RATELIMITING.insert(&key, &1, 0);
                    0
                }
            };

            // If we've exceeded the ratelimiting, drop the packet, and record the action
            if rule.ratelimit as u64 <= current_value {
                // The source has exceeded the ratelimit, drop the packet.
                return Ok(XDP_DROP);
            }
        }

        // The packet has passed all checks, increment the rule's analytics.
        match RULE_ANALYTICS.get_ptr_mut(&rule.id) {
            Some(analytics) => {
                (*analytics).passed += 1;
            }
            None => {
                let _ = RULE_ANALYTICS.insert(
                    &rule.id,
                    &RuleAnalytics {
                        rule_id: rule.id,
                        evaluated: 0,
                        passed: 1,
                    },
                    0,
                );
            }
        }

        // Packet passed protocol conformity checks and ratelimit (if enabled)
        return Ok(XDP_PASS);
    }

    // The packet isn't holepunched or whitelisted, drop it.
    Ok(XDP_DROP)
}
