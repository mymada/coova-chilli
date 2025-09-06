mod config;

use anyhow::Result;
use chilli_core::Config;
use chilli_http::server;
use chilli_net::dhcp::DhcpServer;
use chilli_net::radius::RadiusClient;
use chilli_net::tun;
use tokio::io::AsyncReadExt;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting CoovaChilli-Rust");

    let config = match config::load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    info!("Config loaded: {:?}", config);

    let mut iface = match tun::create_tun(&config) {
        Ok(iface) => iface,
        Err(e) => {
            error!("Error creating TUN interface: {}", e);
            std::process::exit(1);
        }
    };

    let config_clone_http = config.clone();
    let http_server_handle = tokio::spawn(async move {
        if let Err(e) = server::run_server(&config_clone_http).await {
            error!("HTTP server error: {}", e);
        }
    });

    let dhcp_server = DhcpServer::new(config.clone()).await?;
    let dhcp_server_handle = tokio::spawn(async move {
        if let Err(e) = dhcp_server.run().await {
            error!("DHCP server error: {}", e);
        }
    });

    let radius_client = RadiusClient::new(config.clone()).await?;
    let radius_client_handle = tokio::spawn(async move {
        if let Err(e) = radius_client.run().await {
            error!("RADIUS client error: {}", e);
        }
    });

    let mut buf = [0u8; 1504];
    loop {
        let n = iface.read(&mut buf).await?;
        info!("Read {} bytes from TUN interface", n);
        // Here we would process the packet
    }
}
