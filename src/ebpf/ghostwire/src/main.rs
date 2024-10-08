use crate::utils::{
    prom_http::handle_prom_listener,
    state::State,
};
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
use clap::Parser;
use ghostwire_common::{
    Rule,
    RuleAnalytics,
};
use hyper::{
    server::conn::http1,
    service::service_fn,
    Request,
};
use hyper_util::rt::TokioIo;
use log::{
    debug,
    info,
    warn,
};
use prometheus::{
    IntCounterVec,
    Registry,
};
use std::{
    net::SocketAddr,
    sync::Arc,
};
use tokio::{
    net::TcpListener,
    signal,
    sync::RwLock,
    task,
};
use tokio_schedule::{
    every,
    Job,
};
use utils::{
    prometheus::{
        create_prometheus_counters,
        handle_prom_listener,
    },
    state::PromCounters,
};

mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Starting Ghostwire ...");

    tracing_subscriber::fmt::Subscriber::builder()
        .pretty()
        .finish();

    // wait for startup signal from reading config file or from the cli
    let (tx, rx) = oneshot::channel::<Vec<Rule>>();

    // start the task to listen for incoming connections over the UNIX socket.

    // start the prometheus listener
    let counters = create_prometheus_counters().context("failed to create prometheus counters")?;

    {
        let counters = Arc::clone(&counters);
        task::spawn(handle_prom_listener(counters))
    }

    // block until we get the initial rules or a startup message
    let inital_rules = rx.await?;

    // ok, we're ready to start
    if inital_rules.is_empty() {
        tracing::warn!(
            "Starting firewall with no rules - all inbound new connections will be dropped!"
        )
    }

    // wait until we get the new response

    {
        let state = state.clone();

        task::spawn(every(10).seconds().perform(move || {
            let state = state.clone();

            async move {
                state.prometheus_metrics().await;
            }
        }));
    }

    {
        let state = state.clone();
        task::spawn(handle_prom_listener(state));
    }

    state.listen().await;

    Ok(())
}
