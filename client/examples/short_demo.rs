//! Short RFC client demonstration example

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use env_logger;
use eui48::MacAddress;
use log::{info, warn};
use tokio::time::timeout;
use tokio::{select, signal};

use dhcp_client::{Client, ClientError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x56]);
    

    let mut client = Client::new("en0", client_mac).await?;

    info!("🎬 Short RFC client demonstration");

    // Get initial configuration
    // Perform initial DHCP configuration (DORA sequence)
    match client.configure().await {
        Ok(config) => {
            info!("✅ DHCP Configuration obtained:");
            info!("   📍 Your IP: {}", config.your_ip_address);
            info!("   🏠 Server IP: {}", config.server_ip_address);
            if let Some(mask) = config.subnet_mask {
                info!("   🔍 Subnet: {}", mask);
            }
            if let Some(gw) = config.routers.as_ref().and_then(|r| r.first()) {
                info!("   🚪 Gateway: {}", gw);
            }
            if let Some(dns) = config.domain_name_servers.as_ref().and_then(|d| d.first()) {
                info!("   🌐 DNS: {}", dns);
            }

            // Display lease information
            if let Some(lease) = client.lease() {
                info!("📋 Lease Information:");
                info!("   ⏰ Lease Duration: {}s", lease.lease_time);
                info!("   ⏰ T1 (Renewal): {}s", lease.t1());
                info!("   ⏰ T2 (Rebinding): {}s", lease.t2());
            }

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
        result = timeout(Duration::from_secs(10), client.run_lifecycle()) => {
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
    if let Err(e) = client.release().await {
        warn!("⚠️  Failed to release lease: {}", e);
    } else {
        info!("✅ Lease released successfully");
    }
    Ok(())
}
