#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::gen::bpf_ktime_get_ns,
    macros::{map, xdp, classifier},
    maps::{HashMap, LruHashMap},
    programs::{XdpContext, TcContext},
};
use aya_log_ebpf::info;

use core::{mem};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use ghostwire_common::{FiveTuple, Flow, Punch, Connection};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map] // This defines the flow map
static FLOWS: HashMap<FiveTuple, Flow> =
    HashMap::<FiveTuple, Flow>::with_max_entries(1048576, 0);

#[map] // 
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

// Map to store punch rules
#[map] 
static PUNCHES: HashMap<FiveTuple, Punch> =
    HashMap::<FiveTuple, Punch>::with_max_entries(1048576, 0);

// Outgoing connections are allowed back in for 60 seconds after the last packet
#[map]
static CONNECTIONS: LruHashMap<FiveTuple, Connection> = 
    LruHashMap::<FiveTuple, Connection>::with_max_entries(1048576, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/*#[classifier]
pub fn tc_egress(tc: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}*/

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

// Function to get the timestamp (using kernel's ktime_get_ns)
fn get_timestamp() -> u64 {
    unsafe {
        bpf_ktime_get_ns() // This is the eBPF helper for ktime_get_ns
    }
}

fn get_packet_size(ctx: &XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    
    // Compute the size of the packet
    unsafe {
        data_end.offset_from(data) as u32
    }
}

fn parse_ports(ctx: &XdpContext, protocol: IpProto) -> Result<(u16, u16), ()> {
    match protocol {
        IpProto::Tcp => {
            let tcp_header: *const TcpHdr =
                unsafe { ptr_at::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            Ok((u16::from_be(unsafe { (*tcp_header).source }), u16::from_be(unsafe { (*tcp_header).dest })))
        }
        IpProto::Udp => {
            let udp_header: *const UdpHdr =
                unsafe { ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            Ok((u16::from_be(unsafe { (*udp_header).source }), u16::from_be(unsafe { (*udp_header).dest })))
        }
        _ => Ok((0, 0)), // Default ports for unsupported protocols
    }
}

#[inline(always)]
fn prepare_action(
    ctx: &XdpContext,
    timestamp: u64,
    key: FiveTuple,
    action: u32,
    reason: &'static str
) -> Result<u32, ()> {
    let pkt_size = get_packet_size(ctx);

    let protocol_str = match key.protocol {
        6 => "TCP",  // TCP protocol number
        17 => "UDP", // UDP protocol number
        _ => "Unknown",  // For other protocols
    };

    let action_str = match action {
        xdp_action::XDP_PASS => "PASS",
        xdp_action::XDP_DROP => "DROP",
        xdp_action::XDP_ABORTED => "ABORTED",
        xdp_action::XDP_TX => "TX",
        xdp_action::XDP_REDIRECT => "REDIRECT",
        _ => "UNKNOWN",
    };

    let flow_entry = FLOWS.get_ptr_mut(&key);

    match flow_entry {
        Some(ptr) => {
            // Dereference the pointer to modify the flow
            let entry = unsafe { &mut *ptr };
            entry.packets += 1;
            entry.bytes += pkt_size as u64; // Example, bytes should come from the packet size
            entry.end_time = timestamp; // Update end time
            // No need to return anything, just modify the flow
        }
        None => {
            // New flow, create it
            let new_flow = Flow {
                start_time: timestamp,
                end_time: timestamp, // Set to 0 for now
                bytes: pkt_size as u64, // Set initial packet size here
                packets: 1,
                action,
                reason: 0, // Optional, set reason if needed
                //src_mac: 0, // Optional, if you capture MAC addresses
                //dst_mac: 0, // Optional, if you capture MAC addresses
                //in_iface: 0, // Optional, if you track interface
            };
            FLOWS.insert(&key, &new_flow, 0); // Insert with flags set to 0
            // No need to return anything, just insert the new flow
        }
    }

    // Log the action using valid format specifiers
    info!(
        ctx,
        "TIME: {}, SIZE: {}, SRC_IP: {:i}, DST_IP: {:i}, PROTO: {}, SRC_PORT: {}, DST_PORT: {}, ACTION: {}, REASON: {}",
        timestamp,
        pkt_size,
        key.src_ip,
        key.dst_ip,
        protocol_str,
        key.src_port,
        key.dst_port,
        action_str,
        reason
    );

    Ok(action)
}

fn blocked_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let timestamp = get_timestamp();

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination_ip = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let protocol = IpProto::from(unsafe { (*ipv4hdr).proto });

    // Parse source and destination ports using the helper function
    let (source_port, destination_port) = parse_ports(&ctx, protocol)?;

    let key = FiveTuple {
        src_ip: source_ip,
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: source_port,
        dst_port: destination_port,
    };

    if blocked_ip(source_ip) {
        return prepare_action(
            &ctx,
            timestamp,
            key,
            xdp_action::XDP_DROP,
            "BLOCKLIST"
        )
    }

    // Handle the case where src_ip == 0 or src_port == 0 (wildcard)
    let key_with_wildcard_src_ip_and_src_port = FiveTuple {
        src_ip: 0, // Wildcard for any source IP
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: 0, // Wildcard for any source port
        dst_port: destination_port,
    };

    /*let key_with_wildcard_src_ip = FiveTuple {
        src_ip: 0, // Wildcard for any source IP
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: source_port,
        dst_port: destination_port,
    };*/

    let key_with_wildcard_src_port = FiveTuple {
        src_ip: source_ip,
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: 0, // Wildcard for any source port
        dst_port: destination_port,
    };

    // Allow outbound connections back in
    if let Some(connection) = unsafe { CONNECTIONS.get(&key) } {
        if connection.expires != 0 && timestamp > connection.expires {
            CONNECTIONS.remove(&key);
            return prepare_action(&ctx, timestamp, key, xdp_action::XDP_DROP, "EXPIRED_CONNECTION");
        }
        return prepare_action(&ctx, timestamp, key, xdp_action::XDP_PASS, "CONNECTION_LIVE");
    }

    let punch_rule = unsafe {
        PUNCHES.get(&key_with_wildcard_src_ip_and_src_port)
            .or_else(|| PUNCHES.get(&key_with_wildcard_src_port))
    };

    match punch_rule {
        Some(punch) => {
            // Check if the punch rule is expired
            /*if punch.expires != 0 && timestamp > punch.expires {
                PUNCHES.remove(&key);

                return prepare_action(&ctx, timestamp, key, xdp_action::XDP_DROP, "EXPIRED_PUNCH");
            }*/

            // If punch allows (punch.allow == 1), permit the traffic
            if punch.action == 0 {
                return prepare_action(&ctx, timestamp, key, xdp_action::XDP_PASS, "PUNCHED");
            } else {
                // If punch disallows (punch.allow == 0), drop the traffic;
                return prepare_action(&ctx, timestamp, key, xdp_action::XDP_DROP, "PUNCHED");
            }
        }
        None => {
            // If no punch rule exists, proceed with the default action
            return prepare_action(&ctx, timestamp, key, xdp_action::XDP_DROP, "DEFAULT");
        }
    }
}

/*fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = u32::from_be(ipv4hdr.dst_addr);

    let action = if blocked_ip(destination) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };

    info!(&ctx, "DEST {:i}, ACTION {}", destination, action);

    Ok(action)
}*/