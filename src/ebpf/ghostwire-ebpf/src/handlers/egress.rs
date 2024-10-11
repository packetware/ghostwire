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
    // skip the ethernet header, that's not providing us with any value right now
    // attempt to parse the ip header
    let ip_header: *const Ipv4Hdr = tc_ptr_at_fallible(&tc, EthHdr::LEN).map_err(|_| ())?;

    // pull the source and destination IP addresses and the protocol
    let src_ip = unsafe { (*ip_header).src_addr };
    let dst_ip = unsafe { (*ip_header).dst_addr };
    let protocol = unsafe { (*ip_header).proto };
    let (src_port, dst_port) = match protocol {
        Tcp => {
            // parse the TCP header
            let tcp_header: *const TcpHdr =
                tc_ptr_at_fallible::<TcpHdr>(&tc, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

            // get the source and destination ports
            ((*tcp_header).source, (*tcp_header).dest)
        }
        Udp => {
            // parse the UDP header
            let udp_header: *const UdpHdr =
                tc_ptr_at_fallible::<UdpHdr>(&tc, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;

            // get the source and destination ports
            ((*udp_header).source, (*udp_header).dest)
        }
        Icmp => (0, 0),
        _ => return Ok(TC_ACT_PIPE),
    };

    // get the key for the holepunched map
    let key = src_ip as u64 + src_port as u64 + dst_ip as u64 + dst_port as u64;

    // update the holepunched map
    let _ = HOLEPUNCHED.insert(&(key as u128), &bpf_ktime_get_ns(), 0);

    // Let traffic go through.
    Ok(TC_ACT_PIPE)
}
