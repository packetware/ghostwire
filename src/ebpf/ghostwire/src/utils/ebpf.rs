use super::state::State;
use crate::OVERALL_STATE;
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
use ghostwire_common::{
    Rule,
    RuleAnalytics,
};
use std::sync::Arc;
use tokio::{
    sync::RwLock,
    task,
    task::AbortHandle,
};
use tokio_schedule::{
    every,
    Job,
};

/// Load the eBPF program, fetching the maps and creating state from partial arguments
pub async fn load_ebpf(initial_rules: Vec<Rule>, interface: String) -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        tracing::debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/ghostwire"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/ghostwire"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        tracing::warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("ghostwire_xdp").unwrap().try_into()?;
    program.load().unwrap();
    program.attach(&interface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    let _ = tc::qdisc_add_clsact(&interface);

    let program: &mut SchedClassifier = bpf.program_mut("ghostwire_tc").unwrap().try_into()?;
    program.load()?;
    program.attach(&interface, TcAttachType::Egress)?;

    // fetch the eBPF maps
    let mut rule_map: HashMap<_, u32, Rule> = HashMap::try_from(bpf.take_map("RULES").unwrap())?;

    for (i, rule) in initial_rules.iter().enumerate() {
        rule_map.insert(i as u32, rule, 0)?;
    }

    let rule_analytic_map: HashMap<_, u32, RuleAnalytics> =
        HashMap::try_from(bpf.take_map("RULE_ANALYTICS").unwrap())?;

    let xdp_analytic_map: HashMap<_, u32, u128> =
        HashMap::try_from(bpf.take_map("XDP_ACTION_ANALYTICS").unwrap())?;

    let tc_analytic_map: HashMap<_, i32, u128> =
        HashMap::try_from(bpf.take_map("TC_ACTION_ANALYTICS").unwrap())?;

    let state = Arc::new(State {
        interface,
        ebpf: RwLock::new(bpf),
        rule_map: RwLock::new(rule_map),
        rule_analytic_map,
        xdp_analytic_map,
        tc_analytic_map,
    });

    // Load the state.
    let mut write = OVERALL_STATE.write().await;

    write.state = Some(state);

    Ok(())
}

/// Unload the eBPF program
pub async fn unload_ebpf() {
    let mut write = OVERALL_STATE.write().await;

    // writing None to the state necessarily will drop the eBPF program
    // @see https://aya-rs.dev/book/aya/lifecycle/#populating-our-map-from-userspace
    // a critical assumption is that the state is not being used anywhere else in the program (this
    // assumption is currently correct, these are the only two references persistently reading
    // state)
    write.state = None;
}

