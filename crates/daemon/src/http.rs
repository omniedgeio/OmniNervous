use crate::metrics::Metrics;
use anyhow::Result;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{error, info};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

/// Start the HTTP metrics server on the specified port.
pub async fn serve_metrics(metrics: Arc<Metrics>, port: u16) -> Result<()> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Metrics server listening on http://{}/metrics", addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Accept error: {}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let metrics = Arc::clone(&metrics);
                handle_request(req, metrics)
            });

            let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, service);

            if let Err(e) = conn.await {
                error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    metrics: Arc<Metrics>,
) -> Result<Response<String>, Infallible> {
    match req.uri().path() {
        "/metrics" => {
            let body = metrics.to_prometheus();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(body)
                .unwrap())
        }
        "/health" => Ok(Response::builder()
            .status(StatusCode::OK)
            .body("OK".to_string())
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not Found".to_string())
            .unwrap()),
    }
}
