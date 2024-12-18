use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, error};
use std::net::Ipv4Addr;
use std::fs::File;
use tokio::signal;
use serde_yaml::from_reader;

use ghostwire_common::{FiveTuple, Punch};

use config::{Config, expand_rules};

mod config;

/*#[derive(Debug, Parser)]
struct Opt {
    /// Optional override for the network interface
    #[clap(short, long)]
    iface: Option<String>,
}*/

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Load the configuration file
    let config_path = "/etc/ghostwire/config";
    let config_file = File::open(config_path).context("Failed to open the configuration file")?;
    let config: Config = from_reader(config_file).context("Failed to parse the configuration file")?;

    // Determine the interface to use
    /*let iface = if !opt.iface.is_empty() {
        opt.iface.clone()
    } else {
        config.interface.clone()
    };*/

    let iface = config.interface.clone();
    
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ghostwire"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp =
        bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // 
    /*let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    // 
    let block_addr: u32 = Ipv4Addr::new(192, 168, 56, 1).into();

    // 
    blocklist.insert(block_addr, 0, 0)?;*/

    // Initialize the PUNCHES map
    let mut punches: HashMap<_, FiveTuple, Punch> =
        HashMap::try_from(bpf.map_mut("PUNCHES").unwrap())?;

    // Define a FiveTuple key for a punch rule
    let punch_key = FiveTuple {
        src_ip: Ipv4Addr::new(0, 0, 0, 0).into(), // Any Source
        dst_ip: Ipv4Addr::new(192, 168, 56, 101).into(),
        protocol: 6, // TCP
        padding: [0; 3],  // Padding must be explicitly set
        src_port: 0, // Any Source
        dst_port: 3001,
    };

    // Define the corresponding Punch value
    let punch_value = Punch {
        action: 0,
        padding: [0; 7],    // Padding must be explicitly set
        expires: 0, // Set an expiration time (0 for no expiration)
    };

    // Insert the punch rule into the map
    punches.insert(punch_key, punch_value, 0)?;

    info!("Loaded test rule");

    // Expand and load rules into the BPF map
    //let default_action = config.default.as_deref().unwrap_or("block");
    for rule in &config.rules {
        let expanded_rules = match &config.default {
            Some(default_action) => expand_rules(rule, default_action),
            None => expand_rules(rule, "block"), // Provide a fallback
        };
        for expanded_rule in expanded_rules {
            let punch_key = FiveTuple {
                src_ip: expanded_rule.source.parse::<Ipv4Addr>().unwrap().into(),
                dst_ip: expanded_rule.destination.parse::<Ipv4Addr>().unwrap().into(),
                protocol: expanded_rule.protocol,
                padding: [0; 3],
                src_port: 0, // Any source port
                dst_port: expanded_rule.port,
            };

            let punch_value = Punch {
                action: expanded_rule.action,
                padding: [0; 7],
                expires: 0, // No expiration
            };

            match punches.insert(punch_key, punch_value, 0) {
                Ok(_) => {
                    info!(
                        "Inserted rule: src_ip={}, dst_ip={}, protocol={}, src_port={}, dst_port={}, action={}",
                        expanded_rule.source,
                        expanded_rule.destination,
                        expanded_rule.protocol,
                        0, // src_port is set to 0 in this case
                        expanded_rule.port,
                        if expanded_rule.action == 0 { "allow" } else { "block" }
                    );
                }
                Err(e) => {
                    error!("Failed to insert rule into PUNCHES map: {}", e);
                }
            }
        }
    }

    info!("Loaded rules into the BPF map. Attached to interface: {}", iface);

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}