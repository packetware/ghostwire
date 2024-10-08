use super::state::{
    PromCounters,
    State,
};

/// Load the eBPF program, fetching the maps and creating state from partial arguments
pub fn load_ebpf(counters: PromCounters, initial_rules: Vec<Rule>) -> anyhow::Result<State> {
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

    // fetch the eBPF maps
    let rule_map: HashMap<_, u32, Rule> = HashMap::try_from(bpf.take_map("RULES").unwrap())?;

    for (i, rule) in initial_rules.iter() {
        rule_map.insert(i, rule, 0);
    }

    let rule_analytic_map: HashMap<_, u32, RuleAnalytics> =
        HashMap::try_from(bpf.take_map("RULE_ANALYTICS").unwrap())?;

    let xdp_analytic_map: HashMap<_, u32, u128> =
        HashMap::try_from(bpf.take_map("XDP_ACTION_ANALYTICS").unwrap())?;

    let tc_analytic_map: HashMap<_, i32, u128> =
        HashMap::try_from(bpf.take_map("TC_ACTION_ANALYTICS").unwrap())?;

    Ok(State {
        rule_map,
        rule_analytic_map,
        xdp_analytic_map,
        tc_analytic_map,
        counters,
    })
}
