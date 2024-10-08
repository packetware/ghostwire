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
use tokio::sync::oneshot;

/// The overall state of the firewall, to be exposed to the CLI
pub struct OverallState {
    pub enabled: bool,
    /// oneshot sent from the YAML parsing or from the CLI with the initial rules
    pub oneshot_send: Option<oneshot::Sender<Vec<Rule>>>,
    pub state: Option<Arc<State>>,
}

/// The state of the firewall when active
pub struct State {
    /// The applied rules
    pub rule_map: HashMap<MapData, u32, Rule>,
    /// The rule metrics
    pub rule_analytic_map: HashMap<MapData, u32, RuleAnalytics>,
    /// The aggregate XDP metrics
    pub xdp_analytic_map: HashMap<MapData, u32, u128>,
    /// The aggregate traffic control metrics
    pub tc_analytic_map: HashMap<MapData, i32, u128>,
    /// The Prometheus counters to update from the maps
    pub counters: Arc<PromCounters>,
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
        for (key, value) in self.rule_analytic_map.iter().flatten() {
            let evaluated_diff = value.evaluated
                - self
                    .rule_evaluated
                    .with_label_values(&[&key.to_string()])
                    .get() as u128;

            self.rule_evaluated
                .with_label_values(&[&key.to_string()])
                .inc_by(evaluated_diff as u64);

            let passed_diff = value.passed
                - self
                    .rule_passed
                    .with_label_values(&[&key.to_string()])
                    .get() as u128;

            self.rule_passed
                .with_label_values(&[&key.to_string()])
                .inc_by(passed_diff as u64);
        }

        for (key, value) in self.xdp_analytic_map.iter().flatten() {
            self.xdp_action
                .with_label_values(&[&key.to_string()])
                .inc_by(value as u64);
        }

        for (key, value) in self.tc_analytic_map.iter().flatten() {
            self.tc_action
                .with_label_values(&[&key.to_string()])
                .inc_by(value as u64);
        }
    }
}
