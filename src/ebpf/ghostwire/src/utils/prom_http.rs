use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use prometheus::{Encoder, TextEncoder};
use tokio::net::TcpListener;
use std::net::SocketAddr;
use hyper_util::rt::TokioIo;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use std::sync::Arc;
use anyhow::Context;

use crate::utils::state::State;

pub async fn handle_prom_listener(state: Arc<State>) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = format!("127.0.0.1:4242").as_str().parse()?;

    let listener = TcpListener::bind(socket_addr)
        .await
        .context(format!("couldn't listen on :4242. is it in use?"))?;

    tracing::info!("Starting to accept new connections (visit at http://localhost:4242) ...");
    // loop to accept new ingress connections to the prom endpoint
    loop {
        let (stream, _ip) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    io,
                    service_fn(|req: Request<hyper::body::Incoming>| state.prometheus_handler(req)),
                )
                .await
            {
                tracing::warn!("error serving connection: {:?}", err);
            }
        });
    }
}

impl State {


    /// Respond to any request with prometheus data.
    pub async fn prometheus_handler(
        &self,
        _: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // serialize and encode the histogram metric
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
