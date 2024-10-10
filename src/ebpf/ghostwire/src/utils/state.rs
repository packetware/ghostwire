use crate::OVERALL_STATE;
use aya::maps::{
    HashMap,
    MapData,
};
use aya::Bpf;
use ghostwire_common::{
    Rule,
    RuleAnalytics,
};
use prometheus::{
    IntCounterVec,
    Registry,
};
use std::{
    fmt::{
        Display,
        Formatter,
    },
    sync::Arc,
};
use tokio::{
    sync::RwLock,
    task::AbortHandle,
};

/// The overall state of the firewall, to be exposed to the CLI
pub struct OverallState {
    pub enabled: bool,
    /// The state of the firewall when active
    pub state: Option<Arc<State>>,
    /// The Prometheus counters to update from the maps
    pub counters: PromCounters,
}

/// The state of the firewall when active
pub struct State {
    /// Reference to the eBPF program
    pub ebpf: RwLock<Bpf>,
    /// The interface to apply the XDP hook to
    pub interface: String,
    /// The applied rules
    pub rule_map: RwLock<HashMap<MapData, u32, Rule>>,
    /// The rule metrics
    pub rule_analytic_map: HashMap<MapData, u32, RuleAnalytics>,
    /// The aggregate XDP metrics
    pub xdp_analytic_map: HashMap<MapData, u32, u128>,
    /// The aggregate traffic control metrics
    pub tc_analytic_map: HashMap<MapData, i32, u128>,
}

/// The state of the Prometheus counters
pub struct PromCounters {
    /// The prometheus registry
    pub registry: Registry,
    /// The number of times a rule was evaluated
    pub rule_evaluated: IntCounterVec,
    /// The number of times a rule allowed traffic
    pub rule_passed: IntCounterVec,
    /// The number of times an XDP action was taken
    pub xdp_action: IntCounterVec,
    /// The number of times a TC action was taken
    pub tc_action: IntCounterVec,
}

impl OverallState {
    /// Implement format for OverallState that shows the overall status of the application. Not a trait
    /// because we access the rule map async.
    pub async fn fmt(&self) -> String {
        let mut str = String::new();

        if self.enabled {
            str.push_str("Ghostwire is enabled");
        } else {
            str.push_str("Ghostwire is disabled");
        }

        // summarize the rules
        if let Some(state) = self.state.as_ref() {
            str.push_str(&format!(" on interface {}", state.interface));
            let rule_map = state.rule_map.read().await;
            // eBPF maps don't have a length method
            str.push_str(&format!(
                " with {} rules",
                rule_map.iter().collect::<Vec<_>>().len()
            ));
        }

        str
    }
}
