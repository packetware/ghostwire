use crate::OVERALL_STATE;

/// Function to manage eBPF maps in the background, such as the ratelimiter. Designed to be run in a task.
pub async fn manage_maps() -> anyhow::Result<()> {
    let overall_state = OVERALL_STATE.read().await;

    // Read the state and determine if an eBPF program is loaded.
    if let Some(state) = &overall_state.state {
        // Acquire the write lock to the ratelimit map and purge it.
        let mut rule_map = state.rule_ratelimit_map.write().await;

        for key in rule_map.keys() {
            rule_map.delete(*key)?;
        }
    }

    Ok(())
}
