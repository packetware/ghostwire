use std::convert::Infallible;

use crate::OVERALL_STATE;
use anyhow::Context;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    server::conn::http1,
    service::service_fn,
    Request,
    Response,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use prometheus::{
    Encoder,
    IntCounterVec,
    Registry,
    TextEncoder,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;

use super::state::PromCounters;

/// Create the Prometheus counters and Registry.
pub fn create_prometheus_counters() -> anyhow::Result<PromCounters> {
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
        prometheus::Opts::new("gw_tc_action", "The number of times a TC action was taken"),
        &["action"],
    )?;
    registry.register(Box::new(tc_action.clone()))?;

    Ok(PromCounters {
        registry,
        rule_evaluated,
        rule_passed,
        xdp_action,
        tc_action,
    })
}

/// Pull the maps and update the Prometheus metrics. Designed to be run as a task.
pub async fn prometheus_metrics() {
    let overall_state = OVERALL_STATE.read().await;

    if let Some(state) = &overall_state.state { 

    for (key, value) in state.rule_analytic_map.iter().flatten() {
        let evaluated_diff = value.evaluated
            - overall_state
                .counters
                .rule_evaluated
                .with_label_values(&[&key.to_string()])
                .get() as u128;

        overall_state
            .counters
            .rule_evaluated
            .with_label_values(&[&key.to_string()])
            .inc_by(evaluated_diff as u64);

        let passed_diff = value.passed
            - overall_state
                .counters
                .rule_passed
                .with_label_values(&[&key.to_string()])
                .get() as u128;

        overall_state
            .counters
            .rule_passed
            .with_label_values(&[&key.to_string()])
            .inc_by(passed_diff as u64);
    }

    for (key, value) in state.xdp_analytic_map.iter().flatten() {
        overall_state
            .counters
            .xdp_action
            .with_label_values(&[xdp_action_to_string(key)])
            .inc_by(value as u64);
    }

    for (key, value) in state.tc_analytic_map.iter().flatten() {
        overall_state
            .counters
            .tc_action
            .with_label_values(&[tc_action_to_string(key)])
            .inc_by(value as u64);
    }
    }
}

/// Convert an XDP action to a string.
/// @see https://docs.aya-rs.dev/aya_ebpf/bindings/xdp_action/
fn xdp_action_to_string(action: u32) -> &'static str {
    match action {
        0 => "XDP_ABORTED",
        1 => "XDP_DROP",
        2 => "XDP_PASS",
        3 => "XDP_TX",
        4 => "XDP_REDIRECT",
        _ => "Unknown",
    }
}

/// Convert a TC action to a string.
fn tc_action_to_string(action: i32) -> &'static str {
    match action {
        0 => "TC_ACT_OK",
        2 => "TC_ACT_SHOT",
        3 => "TC_ACT_PIPE",
        _ => "Unknown",
    }
}

pub async fn handle_prom_listener() -> anyhow::Result<()> {
    // TODO: implement different ports
    let socket_addr: SocketAddr = "127.0.0.1:4343".parse()?;

    let listener = TcpListener::bind(socket_addr)
        .await
        .context("could not listen on port 4343")?;

    tracing::info!("Prometheus is starting on port 4343");

    loop {
        let (stream, _ip) = listener.accept().await?;

        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    io,
                    service_fn(|req: Request<hyper::body::Incoming>| prom_http(req)),
                )
                .await
            {
                tracing::warn!("error serving connection: {:?}", err);
            }
        });
    }
}

/// Expose Prometheus metrics
pub async fn prom_http(
    _: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let overall_state = OVERALL_STATE.read().await;
    let metric_families = overall_state.counters.registry.gather();
    // Drop the reference to the state, as we don't need it for the preceeding IO.
    drop(overall_state);

    let encoder = TextEncoder::new();
    let mut buffer = vec![];

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => Ok(Response::new(Full::new(Bytes::from(buffer)))),
        Err(err) => {
            tracing::warn!("Failed to encode prometheus metrics: {err:?}");

            let mut err_resp = Response::new(Full::new(Bytes::from(
                "Failed to encode prometheus metrics",
            )));

            *err_resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

            Ok(err_resp)
        }
    }
}
