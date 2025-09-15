//! Short RFC client demonstration example

use std::time::Duration;

use env_logger;
use eui48::MacAddress;
use log::{info, warn};
use tokio::time::timeout;
use tokio::{select, signal};

use dhcp_client::{Client, ClientError};
use dhcp_client::netlink::NetlinkHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x56]);
    
    let interface_name = "en0";
    let mut client = Client::new(interface_name, client_mac).await?;
    let netlink_handle = NetlinkHandle::new(interface_name).await?;

    info!("🎬 Short RFC client demonstration");

    // Get initial configuration
    // Perform initial DHCP configuration (DORA sequence)
    match client.configure(&netlink_handle).await {
        Ok(()) => {
            info!("🔄 Current state: {}", client.state());
        }
        Err(e) => {
            warn!("❌ DHCP configuration failed: {}", e);
            return Err(e.into());
        }
    }

    // Simulate running for a while
    info!("⏳ Simulating client operation for 10 seconds...");

    select! {
        result = timeout(Duration::from_secs(10), client.run_lifecycle(&netlink_handle)) => {
            match result {
                Ok(Ok(())) => {
                    info!("🏁 Client lifecycle completed normally");
                }
                Ok(Err(ClientError::LeaseExpired)) => {
                    warn!("⏰ Lease expired, would need to restart DHCP process");
                }
                Ok(Err(e)) => {
                    warn!("❌ Client lifecycle error: {}", e);
                    return Err(e.into());
                }
                Err(_) => {
                    info!("⏰ 10 second timeout reached, stopping lifecycle");
                }
            }
        }
        _ = signal::ctrl_c() => {
            info!("🛑 Shutdown signal received");

        }
    }
    // Gracefully release the lease
    info!("📤 Releasing DHCP lease...");
    if let Err(e) = client.release("demo timeout".to_string()).await {
        warn!("⚠️  Failed to release lease: {}", e);
    } else {
        info!("✅ Lease released successfully");
    }
    client.undo_lease(&netlink_handle).await;
    Ok(())
}
