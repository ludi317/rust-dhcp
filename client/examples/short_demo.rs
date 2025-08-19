//! Short RFC client demonstration example

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use eui48::MacAddress;
use env_logger;
use log::info;
use tokio::time::timeout;

use dhcp_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x56]);
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    let mut client = Client::new(
        bind_addr,
        client_mac,
        None,
        Some("rust-demo-client".to_string()),
        None,
        None,
        true,
    ).await?;

    info!("🎬 Short RFC client demonstration");

    // Get initial configuration
    let config = client.configure().await?;
    info!("📍 Obtained IP: {}", config.your_ip_address);

    // Simulate running for a while
    info!("⏳ Simulating client operation for 30 seconds...");
    
    // Use timeout to limit the lifecycle demo
    match timeout(Duration::from_secs(30), client.run_lifecycle()).await {
        Ok(Ok(())) => {
            info!("🏁 Lifecycle completed");
        }
        Ok(Err(e)) => {
            info!("⚠️  Lifecycle ended with: {}", e);
        }
        Err(_) => {
            info!("⏰ Demo timeout reached");
        }
    }

    // Release the lease
    client.release().await?;
    info!("✅ Demo completed and lease released");

    Ok(())
}