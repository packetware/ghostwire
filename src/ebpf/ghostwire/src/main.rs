use crate::utils::state::State;
use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{
        tc,
        SchedClassifier,
        TcAttachType,
        Xdp,
        XdpFlags,
    },
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use ghostwire_common::{
    Rule,
    RuleAnalytics,
};
use log::{
    debug,
    info,
    warn,
};
use tokio::signal;
use tokio_schedule::{every, Job};
use tokio::task;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use hyper_util::rt::TokioIo;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use prometheus::{IntCounterVec, Registry};
use crate::utils::prom_http::handle_prom_listener;

mod utils;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ghostwire"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ghostwire"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("ghostwire_xdp").unwrap().try_into()?;
    program.load().unwrap();
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE").unwrap();
    let _ = tc::qdisc_add_clsact(&opt.iface);

    let program: &mut SchedClassifier = bpf.program_mut("ghostwire_tc").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;

    // attach the rules map
    let mut rule_map: HashMap<_, u32, Rule> = HashMap::try_from(bpf.take_map("RULES").unwrap())?;

    rule_map.insert(
        0,
        Rule {
            id: 0,
            source_start_ip: 0,
            source_end_ip: 0,
            destination_start_ip: 0,
            destination_end_ip: 0,
            protocol_number: 6,
            port_number: u16::to_be(22),
            ratelimiting: 0,
        },
        0,
    )?;

    let mut rule_analytic_map: HashMap<_, u32, RuleAnalytics> =
        HashMap::try_from(bpf.take_map("RULE_ANALYTICS").unwrap())?;

    let mut xdp_analytic_map: HashMap<_, u32, u128> =
        HashMap::try_from(bpf.take_map("XDP_ACTION_ANALYTICS").unwrap())?;

    let mut tc_analytic_map: HashMap<_, i32, u128> =
        HashMap::try_from(bpf.take_map("TC_ACTION_ANALYTICS").unwrap())?;


    let registry = Registry::new();

    let rule_evaluated = IntCounterVec::new(
        prometheus::Opts::new(
            "gw_rule_evaluated",
            "The number of times a rule was evaluated",
        ),
        &["rule_id"],
    )?;
    registry.register(Box::new(rule_evaluated.clone()))?;

    let rule_passed = IntCounterVec::new(
        prometheus::Opts::new(
            "gw_rule_passed",
            "The number of times a rule allowed traffic",
        ),
        &["rule_id"],
    )?;
    registry.register(Box::new(rule_passed.clone()))?;

    let xdp_action = IntCounterVec::new(
        prometheus::Opts::new(
            "gw_xdp_action",
            "The number of times an XDP action was taken",
        ),
        &["action"],
    )?;
    registry.register(Box::new(xdp_action.clone()))?;

    let tc_action = IntCounterVec::new(
        prometheus::Opts::new(
            "gw_tc_action",
            "The number of times a TC action was taken",
        ),
        &["action"],
    )?;
    registry.register(Box::new(tc_action.clone()))?;


    let state = Arc::new(State {
        rule_map,
        rule_analytic_map,
        xdp_analytic_map,
        tc_analytic_map,
        registry,
        rule_evaluated,
        rule_passed,
        xdp_action,
        tc_action,
    });

    // Start the task to listen for incoming connections over the UNIX socket.

    { 
        let state = state.clone();

        task::spawn(every(10).seconds().perform(move || {
            let state = state.clone();

            async move {
                state.prometheus_metrics().await;
            }
        }));
    }

    {
        let state = state.clone();
        task::spawn(handle_prom_listener(state)); 
    }

    state.listen().await;

    Ok(())
}
