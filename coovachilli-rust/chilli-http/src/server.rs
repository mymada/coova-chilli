use axum::{routing::get, Router};
use chilli_core::Config;
use std::net::SocketAddr;
use tracing::info;

async fn root() -> &'static str {
    "Hello, World!"
}

pub async fn run_server(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route("/", get(root));

    let addr = SocketAddr::new(config.uamlisten.into(), config.uamport);
    info!("UAM server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
