/*
 * A TODO is to load the previous state of the firewall on startup, probably over a oneshot. This
 * file is not included as a module yet for that reason.
 *
 * (random code proceeds)
 *
 *
    let (tx, rx) = oneshot::channel::<(Vec<Rule>, String)>();

    {
        let mut overall_state = OVERALL_STATE.write().await;

        overall_state.oneshot_send = Some(tx)
    }
     // block until we get the initial rules or a startup message
    let (initial_rules, interface) = rx.await?;

    // ok, we're ready to start
    if initial_rules.is_empty() {
        tracing::warn!(
            "Starting firewall with no rules - all inbound new connections will be dropped!"
        )
    }

    // load the eBPF into the kernel
    let state = Arc::new(load_ebpf(counters.clone(), initial_rules, interface)?);*    // update the CLI with the new state
    {
        let state = Arc::clone(&state);
        let mut overall_state = OVERALL_STATE.write().await;

        overall_state.enabled = true;
        overall_state.state = Some(state);
    }
*/
