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
/// 3. Look for entries that are holepunched:
///     - Since we're a stateful firewall, look for when we established a connection outbound and allow that traffic back in
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
        // if there's a rule matching this traffic
        if let Some(rule) = RULES.get(&index) {
            if src_ip >= rule.source_start_ip && src_ip <= rule.source_end_ip {
                // determine if we need to do a protocol comparison
                if rule.protocol_number != 0 {
                    if rule.protocol_number != protocol as u8 {
                        continue;
                    }

                    // if we need to do a port comparison
                    if rule.port_number != 0 {
                        // if the port doesn't match, continue
                    aya_log_ebpf::info!(&ctx, "{}, {}", rule.port_number, dst_port);
                        if rule.port_number != dst_port {
                            continue;
                        }
                    }
                }

                // update the metric for this rule
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

                // determine if we need to do ratelimiting
                if rule.ratelimiting != 0 {
                    // get the ratelimiting key
                    let key = (src_ip + rule.id) as u64;
                    // get the ratelimiting value
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

                    // if we've exceeded the ratelimiting, drop the packet
                    if rule.ratelimiting as u128 >= current_value {
                        // update the metric for this rule
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

                // passed source / dest ip checks, port checks, and ratelimiting wasn't enabled
                return Ok(XDP_PASS);
            }
        } else {
            break;
        }
    }

    let key = (src_ip as u64 + src_port as u64 + dst_ip as u64 + dst_port as u64) as u128;

    match HOLEPUNCHED.get_ptr_mut(&key) {
        Some(last_time) => {
            // update the time
            (*last_time) = bpf_ktime_get_ns();

            Ok(XDP_PASS)
        }
        None => {
            // drop it if it matches no other case
            Ok(XDP_DROP)
        }
    }
}
