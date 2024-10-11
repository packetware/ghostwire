use crate::{
    utils::ptr_at::tc_ptr_at_fallible,
    HOLEPUNCHED,
};
use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::bpf_ktime_get_ns,
    programs::TcContext,
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

/// The function is called whenever a packet is leaving the server through the traffic control
/// hook. It should:
/// 1. Parse the packet;
///     - Get the source & destination IP addresses and the port (if the protocol is portless, like ICMP, both ports will be 0)
/// 2. Update the holepunched LRU map;
///     - Key is the source IP + source port + destination IP + destination port
///     - If the connection is already in the map, update the timestamp
///     - If the connection is not in the map, add it
///     - If the connection is a TCP connection and the FIN / RST flags are set, remove from the map
pub unsafe fn ghostwire_egress_fallible(tc: TcContext) -> Result<i32, ()> {
    // Skip the ethernet header, that's not providing us with any value right now.
    // Attempt to parse the IP header.
    let ip_header: *const Ipv4Hdr = tc_ptr_at_fallible(&tc, EthHdr::LEN).map_err(|_| ())?;

    // Pull the source and destination IP addresses and the protocol.
    let src_ip = unsafe { (*ip_header).src_addr };
    let dst_ip = unsafe { (*ip_header).dst_addr };
    let protocol = unsafe { (*ip_header).proto };
    // Store whether the connection should be removed from the holepunched map, instead of
    // appended.
    let mut remove = false;
    let (src_port, dst_port) = match protocol {
        Tcp => {
            // Parse the TCP header.
            let tcp_header: *const TcpHdr =
                tc_ptr_at_fallible::<TcpHdr>(&tc, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

            // Check if the connection is being closed.
            // Currently, this is limited to the RST flag. The problem with FIN is the server will
            // keep waiting for the generic ACK to close the connection, which will never come if
            // we remove it from the map. A potential solution is to create another map for pending
            // closing connections.
            if unsafe { (*tcp_header)._bitfield_1.get(3, 1) } != 0 {
                remove = true;
            }

            // Get the source and destination ports.
            ((*tcp_header).source, (*tcp_header).dest)
        }
        Udp => {
            // Parse the UDP header.
            let udp_header: *const UdpHdr =
                tc_ptr_at_fallible::<UdpHdr>(&tc, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

            // Get the source and destination ports.
            ((*udp_header).source, (*udp_header).dest)
        }
        Icmp => (0, 0),
        _ => return Ok(TC_ACT_PIPE),
    };

    // Get the key for the holepunched map, upgrading each type to u64 to avoid overflow.
    let key = src_ip as u64 + src_port as u64 + dst_ip as u64 + dst_port as u64;

    match remove {
        true => {
            // Remove the connection from the holepunched map.
            let _ = HOLEPUNCHED.remove(&key);
        }
        false => {
            // Update the holepunched map with the latest connection time.
            let _ = HOLEPUNCHED.insert(&key, &bpf_ktime_get_ns(), 0);
        }
    }

    // Let traffic go through.
    Ok(TC_ACT_PIPE)
}
