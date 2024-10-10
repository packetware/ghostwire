use crate::OVERALL_STATE;
use aya::maps::{
    HashMap,
    MapData,
};
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
    sync::{
        oneshot,
        RwLock,
    },
    task::AbortHandle,
};

/// The overall state of the firewall, to be exposed to the CLI
pub struct OverallState {
    pub enabled: bool,
    /// oneshot sent from the YAML parsing or from the CLI with the initial rules and the interface
    /// to listen on
    pub state: Option<Arc<State>>,
    /// Holds the reference to the background task pulling from the analytic maps. Used to abort
    /// when eBPF is unloaded.
    pub analytic_handle: Option<AbortHandle>,
    /// The Prometheus counters to update from the maps
    pub counters: PromCounters,
}

/// The state of the firewall when active
pub struct State {
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

impl State {
    /// Pull the maps and update the Prometheus metrics. Designed to be run as a task.
    pub async fn prometheus_metrics(&self) {
        let state = OVERALL_STATE.read().await;

        for (key, value) in self.rule_analytic_map.iter().flatten() {
            let evaluated_diff = value.evaluated
                - state
                    .counters
                    .rule_evaluated
                    .with_label_values(&[&key.to_string()])
                    .get() as u128;

            state
                .counters
                .rule_evaluated
                .with_label_values(&[&key.to_string()])
                .inc_by(evaluated_diff as u64);

            let passed_diff = value.passed
                - state
                    .counters
                    .rule_passed
                    .with_label_values(&[&key.to_string()])
                    .get() as u128;

            state
                .counters
                .rule_passed
                .with_label_values(&[&key.to_string()])
                .inc_by(passed_diff as u64);
        }

        for (key, value) in self.xdp_analytic_map.iter().flatten() {
            state
                .counters
                .xdp_action
                .with_label_values(&[&key.to_string()])
                .inc_by(value as u64);
        }

        for (key, value) in self.tc_analytic_map.iter().flatten() {
            state
                .counters
                .tc_action
                .with_label_values(&[&key.to_string()])
                .inc_by(value as u64);
        }
    }
}

/// Implement format for OverallState that shows the overall status of the application
impl Display for OverallState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.enabled {
            write!(f, "Ghostwire is enabled")?;
        } else {
            write!(f, "Ghostwire is disabled")?;
        }

        if let Some(state) = self.state.as_ref() {
            write!(f, " on interface {}", state.interface)?;
            let rule_map = state.rule_map.blocking_read();
            // eBPF maps don't have a length method
            write!(
                f,
                " with {} rules",
                rule_map.iter().collect::<Vec<_>>().len()
            )?;
        }

        Ok(())
    }
}
