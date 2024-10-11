use crate::OVERALL_STATE;

/// Function to manage eBPF maps in the background, such as the ratelimiter. Designed to be run in a task.
pub async fn manage_maps() {
    let overall_state = OVERALL_STATE.read().await;

    // Read the state and determine if an eBPF program is loaded.
    if let Some(state) = &overall_state.state {
        // Acquire the write lock to the ratelimit map and purge it.
        let mut rule_map = state.rule_ratelimit_map.write().await;

        let keys = rule_map.keys().collect::<Vec<_>>();

        for key in keys {
            match key {
                Ok(t) => {
                    if let Err(e) = rule_map.remove(&t) {
                        tracing::error!("Failed to remove key from ratelimit map: {}", e);
                    };
                }
                Err(e) => {
                    tracing::error!("Failed to iterate over keys in ratelimit map: {}", e);
                }
            }
        }
    }
}
