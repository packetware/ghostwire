use crate::utils::prometheus::handle_prom_listener;
use anyhow::Context;
use ghostwire_common::Rule;
use lazy_static::lazy_static;
use std::sync::Arc;
use tokio::{
    signal,
    sync::{
        oneshot,
        RwLock,
    },
    task,
};
use tokio_schedule::{
    every,
    Job,
};
use utils::{
    ebpf::load_ebpf,
    prometheus::create_prometheus_counters,
    socket::socket_server,
    state::OverallState,
};

lazy_static! {
    /// State shared with the socket listener
    static ref OVERALL_STATE: RwLock<OverallState> = RwLock::new(OverallState { enabled: false, state: None, analytic_handle: None, counters: create_prometheus_counters().expect("infallible prometheus counter generation failed") });
}

mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Starting Ghostwire ...");

    tracing_subscriber::fmt::Subscriber::builder()
        .pretty()
        .finish();

    // TODO: read the previous state on startup (@see utils/bootloader.rs)

    // Start the UNIX socket server.
    task::spawn(socket_server());

    // Start the Prometheus HTTP listener.
    task::spawn(handle_prom_listener());

    // Allow the user to unload the eBPF program with Ctrl-C.
    tracing::info!("Waiting for Ctrl-C...");

    signal::ctrl_c().await?;

    tracing::info!("Exiting...");

    Ok(())
}
