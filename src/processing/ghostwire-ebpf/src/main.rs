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

use ghostwire_common::{PASS, DROP, FiveTuple, Flow, Punch};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map] // This defines the flow map
static FLOWS: LruHashMap<FiveTuple, Flow> =
    LruHashMap::<FiveTuple, Flow>::with_max_entries(1048576, 0);

#[map] // 
static IPV4LIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

// Map to store punch rules
#[map] 
static PUNCHES: HashMap<FiveTuple, Punch> =
    HashMap::<FiveTuple, Punch>::with_max_entries(1048576, 0);

// Outgoing connections are allowed back in for 60 seconds after the last packet
//#[map]
//static CONNECTIONS: LruHashMap<FiveTuple, Connection> = 
//    LruHashMap::<FiveTuple, Connection>::with_max_entries(1048576, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

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

fn xdp_get_packet_size(ctx: &XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    
    // Compute the size of the packet
    unsafe {
        data_end.offset_from(data) as u32
    }
}

fn tc_get_packet_size(ctx: &TcContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    
    // Compute the size of the packet
    unsafe {
        data_end.offset_from(data) as u32
    }
}

fn get_protocol_str(protocol: u8) -> &'static str {
    return match protocol {
        1 => "ICMP", // ICMP protocol number
        6 => "TCP",  // TCP protocol number
        17 => "UDP", // UDP protocol number
        _ => "Unknown",  // For other protocols
    };
}

fn get_action_str(action: u32) -> &'static str {
    return match action {
        0 => "PASS",
        1 => "DROP",
        _ => "UNKNOWN",
    };
}

fn xdp_parse_ports(ctx: &XdpContext, protocol: IpProto) -> Result<(u16, u16), ()> {
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

fn tc_parse_ports(ctx: &TcContext, protocol: IpProto) -> Result<(u16, u16), i32> {
    match protocol {
        IpProto::Tcp => {
            let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1)?; // Use i32 error code
            Ok((u16::from_be(tcphdr.source), u16::from_be(tcphdr.dest)))
        }
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1)?; // Use i32 error code
            Ok((u16::from_be(udphdr.source), u16::from_be(udphdr.dest)))
        }
        _ => Ok((0, 0)), // Default ports for unsupported protocols
    }
}

#[inline(always)]
fn prepare_ingress_action(
    ctx: &XdpContext,
    timestamp: u64,
    key: FiveTuple,
    action: u32,
    reason: &'static str
) -> Result<u32, ()> {
    let pkt_size = xdp_get_packet_size(ctx);

    let protocol_str = get_protocol_str(key.protocol);
    let action_str = get_action_str(action);

    let procede = match action {
        value if value == PASS => xdp_action::XDP_PASS,
        value if value == DROP => xdp_action::XDP_DROP,
        _ => xdp_action::XDP_DROP,
    };

    let flow_entry = FLOWS.get_ptr_mut(&key);

    match flow_entry {
        Some(ptr) => {
            // Dereference the pointer to modify the flow
            let entry = unsafe { &mut *ptr };
            entry.packets += 1;
            entry.bytes += pkt_size as u64;
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
        "RECIEVED TIME: {}, SIZE: {}, SRC_IP: {:i}, DST_IP: {:i}, PROTO: {}, SRC_PORT: {}, DST_PORT: {}, ACTION: {}, REASON: {}",
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

    Ok(procede)
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
    let (source_port, destination_port) = xdp_parse_ports(&ctx, protocol)?;

    let key = FiveTuple {
        src_ip: source_ip,
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: source_port,
        dst_port: destination_port,
    };

    // Check if the address is allowed / dropped otherwise continue
    if let Some(address) = unsafe { IPV4LIST.get(&source_ip) } {
        if *address == PASS {
            return prepare_ingress_action(&ctx, timestamp, key, PASS, "ALLOW_ADDRESS_LIST");
        } else if *address == DROP {
            return prepare_ingress_action(&ctx, timestamp, key, DROP, "BLOCK_ADDRESS_LIST");
        }
    }

    let existing_connection = FiveTuple {
        src_ip: destination_ip,
        dst_ip: source_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: destination_port,
        dst_port: source_port,
    };

    // Allow outbound connections back in
    if let Some(flow) = unsafe { FLOWS.get(&existing_connection) } {
        // Add 3 minutes (180 seconds) in nanoseconds to flow.end_time
        let expired = flow.end_time + 180_000_000_000;

        // If the timestamp is greater than the extended end time, drop the connection
        if timestamp > expired {
            return prepare_ingress_action(&ctx, timestamp, key, DROP, "EXPIRED_FLOW_CONNECTION");
        }
        return prepare_ingress_action(&ctx, timestamp, key, PASS, "LIVE_FLOW_CONNECTION");
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

    let key_with_wildcard_src_port = FiveTuple {
        src_ip: source_ip,
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: 0, // Wildcard for any source port
        dst_port: destination_port,
    };

    let punch_rule = unsafe {
        PUNCHES.get(&key_with_wildcard_src_ip_and_src_port)
            .or_else(|| PUNCHES.get(&key_with_wildcard_src_port))
    };

    match punch_rule {
        Some(punch) => {
            // If punch allows permit the traffic
            if punch.action == PASS {
                return prepare_ingress_action(&ctx, timestamp, key, PASS, "PUNCHED");
            } else {
                // If punch disallows drop the traffic
                return prepare_ingress_action(&ctx, timestamp, key, DROP, "PUNCHED");
            }
        }
        None => {
            // If no punch rule exists, proceed with the default action
            return prepare_ingress_action(&ctx, timestamp, key, DROP, "DEFAULT");
        }
    }
}

#[inline(always)]
fn prepare_egress_action(
    ctx: &TcContext,
    timestamp: u64,
    key: FiveTuple,
    action: u32,
    reason: &'static str
) -> Result<i32, i32> {
    let pkt_size = tc_get_packet_size(ctx);

    let protocol_str = get_protocol_str(key.protocol);
    let action_str = get_action_str(action);

    let procede = match action {
        value if value == PASS => TC_ACT_PIPE,
        value if value == DROP => TC_ACT_SHOT,
        _ => TC_ACT_SHOT,
    };

    let flow_entry = FLOWS.get_ptr_mut(&key);

    match flow_entry {
        Some(ptr) => {
            // Dereference the pointer to modify the flow
            let entry = unsafe { &mut *ptr };
            entry.packets += 1;
            entry.bytes += pkt_size as u64;
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
        "SENT TIME: {}, SIZE: {}, SRC_IP: {:i}, DST_IP: {:i}, PROTO: {}, SRC_PORT: {}, DST_PORT: {}, ACTION: {}, REASON: {}",
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

    Ok(procede)
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, i32> {
    let timestamp = get_timestamp();
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| -1)?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| -1)?;
    let source_ip = u32::from_be(ipv4hdr.src_addr);
    let destination_ip = u32::from_be(ipv4hdr.dst_addr);
    let protocol = IpProto::from(ipv4hdr.proto);

    // Get source and destination ports
    let (source_port, destination_port) = tc_parse_ports(&ctx, protocol)?;

    let key = FiveTuple {
        src_ip: source_ip,
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: source_port,
        dst_port: destination_port,
    };

    // Handle the case where dst_ip == 0 or dst_port == 0 (wildcard)
    let key_with_wildcard_dst_ip_and_dst_port = FiveTuple {
        src_ip: source_ip,
        dst_ip: 0,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: source_port,
        dst_port: 0,
    };

    let key_with_wildcard_dst_port = FiveTuple {
        src_ip: source_ip,
        dst_ip: destination_ip,
        protocol: protocol as u8,
        padding: [0; 3],
        src_port: source_port,
        dst_port: 0,
    };

    let punch_rule = unsafe {
        PUNCHES.get(&key_with_wildcard_dst_ip_and_dst_port)
            .or_else(|| PUNCHES.get(&key_with_wildcard_dst_port))
    };

    match punch_rule {
        Some(punch) => {
            // If punch allows permit the traffic
            if punch.action == PASS {
                return prepare_egress_action(&ctx, timestamp, key, PASS, "PUNCHED");
            } else {
                // If punch disallows drop the traffic;
                return prepare_egress_action(&ctx, timestamp, key, DROP, "PUNCHED");
            }
        }
        None => {
            // If no punch rule exists, proceed with the default action
            return prepare_egress_action(&ctx, timestamp, key, PASS, "OUT");
        }
    }
}