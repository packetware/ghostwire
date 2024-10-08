use std::convert::Infallible;

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
    Registry,
    TextEncoder,
};
use std::{
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::TcpListener;

use crate::utils::state::State;

use super::state::PromCounters;

/// Create the Prometheus counters to be used in the state
pub async fn create_prometheus_counters() -> anyhow::Result<PromCounters> {
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

pub async fn handle_prom_listener(state: Arc<PromCounters>) -> anyhow::Result<()> {
    /// TODO: implement different ports
    let socket_addr: SocketAddr = format!("127.0.0.1:4242").as_str().parse()?;

    let listener = TcpListener::bind(socket_addr)
        .await
        .context(format!("could not listen on port 4242"))?;

    tracing::info!("Prometheus is starting on port 4242");
    loop {
        let (stream, _ip) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    io,
                    service_fn(|req: Request<hyper::body::Incoming>| state.prom_http(req)),
                )
                .await
            {
                tracing::warn!("error serving connection: {:?}", err);
            }
        });
    }
}

impl PromCounters {
    /// Expose Prometheus metrics
    pub async fn prom_http(
        &self,
        _: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
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
}
