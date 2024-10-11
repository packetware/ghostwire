use crate::utils::prometheus::handle_prom_listener;
use lazy_static::lazy_static;
use tokio::{
    signal,
    sync::RwLock,
    task,
};
use utils::{
    prometheus::{create_prometheus_counters, prometheus_metrics},
    socket::socket_server,
    state::OverallState,
    map_management::manage_maps,
};
use tokio_schedule::{every, Job};

lazy_static! {
    /// State shared with the socket listener.
    static ref OVERALL_STATE: RwLock<OverallState> = RwLock::new(OverallState { enabled: false, state: None, counters: create_prometheus_counters().expect("infallible prometheus counter generation failed") });
}

mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("Starting Ghostwire ...");

    // Set our own tracing subscriber.
    tracing_subscriber::fmt::Subscriber::builder()
        .pretty()
        .with_max_level(tracing::Level::TRACE)
        .finish();

    // Start the Aya logger.
    env_logger::init();

    // TODO: read the previous state on startup (@see utils/bootloader.rs)

    // Start the UNIX socket server.
    task::spawn(socket_server());

    // Start the Prometheus metrics task.
    task::spawn(every(10).seconds().perform(|| {
        async {
            prometheus_metrics().await;
        }
    }));

    // Begin to manage the eBPF maps.
    task::spawn(every(1).minute().perform(|| {
        async {
            manage_maps().await;
        }
    }));

    // Start the Prometheus HTTP listener.
    task::spawn(handle_prom_listener());

    // Allow the user to unload the eBPF program and the socket server with Ctrl-C.
    tracing::info!("Waiting for Ctrl-C...");

    signal::ctrl_c().await?;

    tracing::info!("Exiting...");

    Ok(())
}
