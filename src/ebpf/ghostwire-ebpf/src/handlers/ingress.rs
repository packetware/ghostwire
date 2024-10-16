use aya_ebpf::{
    bindings::xdp_action::{
        XDP_ABORTED,
        XDP_DROP,
        XDP_PASS,
    },
    helpers::bpf_ktime_get_ns,
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
use ghostwire_common::RuleAnalytics;

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

    // pull the source and destination IP addresses and the protocol
    let src_ip = unsafe { (*ip_header).src_addr };
    let dst_ip = unsafe { (*ip_header).dst_addr };
    let protocol = unsafe { (*ip_header).proto };
    let (src_port, dst_port) = match protocol {
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
        // for now, we're only supporting TCP and UDP
        // let everything else in
        _ => return Ok(XDP_PASS),
    };

    // the index of where we are in the map
    // we're using maps and not an array because arrays are immutable, meanwhile we can update maps
    // on the fly
    for index in 0..100 {
        if let Some(rule) = RULES.get(&index) {
            if src_ip >= rule.source_start_ip && src_ip <= rule.source_end_ip {
                // Determine if should perform a protocol check.
                if rule.protocol_number != 0 {
                    if rule.protocol_number != protocol as u8 {
                        continue;
                    }

                    // Compare port if relevant.
                    if rule.port_number != 0 && rule.port_number != dst_port {
                        continue;
                    }
                }

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
                if rule.ratelimiting != 0 {
                    // Create a ratelimit key. This is a combination of the source IP and the rule ID.
                    let key = (src_ip + rule.id) as u64;
                    // Fetch and increment ratelimit value for this key.
                    let current_value = match RATELIMITING.get_ptr_mut(&key) {
                        Some(value) => {
                            *value += 1;
                            *value - 1
                        }
                        None => {
                            let _ = RATELIMITING.insert(&key, &1, 0);
                            0
                        }
                    };

                    // If we've exceeded the ratelimiting, drop the packet, and record the action
                    if rule.ratelimiting as u64 >= current_value {
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
                    } else {
                        return Ok(XDP_DROP);
                    }
                }

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
        } else {
            break;
        }
    }

    // Create a key for the holepunched map, upgrading the type to u64 to avoid overflow
    let key = src_ip as u64 + src_port as u64 + dst_ip as u64 + dst_port as u64;

    match HOLEPUNCHED.get_ptr_mut(&key) {
        Some(last_time) => {
            // Update the time of the connection.
            (*last_time) = bpf_ktime_get_ns();

            Ok(XDP_PASS)
        }
        None => {
            // Drop the connection if no other case is met.
            Ok(XDP_DROP)
        }
    }
}
