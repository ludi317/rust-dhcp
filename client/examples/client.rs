//! RFC 2131 compliant DHCP client example with full state machine

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use eui48::MacAddress;
use env_logger;
use log::{info, warn};
use tokio::select;
use tokio::signal;

use dhcp_client::{Client, ClientError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Example MAC address - replace with actual network interface MAC
    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Bind to DHCP client port on all interfaces
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    info!("🚀 Starting DHCP client");

    // Create RFC compliant client
    let mut client = Client::new(
        bind_addr,
        client_mac,
        None, // client_id (will use MAC)
        Some("rust-rfc-dhcp-client".to_string()),
        None, // server_address (broadcast discovery)
        None, // max_message_size
        true, // use broadcast
    ).await?;

    info!("📡 Initial state: {}", client.state());

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
                info!("   🔄 T1 (Renewal): {}s", lease.t1());
                info!("   🔄 T2 (Rebinding): {}s", lease.t2());
                info!("   ⏳ Time until renewal: {:?}", lease.time_until_renewal());
                info!("   ⏳ Time until rebinding: {:?}", lease.time_until_rebinding());
                info!("   ⏳ Time until expiry: {:?}", lease.time_until_expiry());
            }

            info!("🔄 Current state: {}", client.state());
        }
        Err(e) => {
            warn!("❌ DHCP configuration failed: {}", e);
            return Err(e.into());
        }
    }

    // Run the client lifecycle with graceful shutdown
    info!("🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)");
    
    select! {
        result = client.run_lifecycle() => {
            match result {
                Ok(()) => {
                    info!("🏁 Client lifecycle completed normally");
                }
                Err(ClientError::LeaseExpired) => {
                    warn!("⏰ Lease expired, would need to restart DHCP process");
                }
                Err(e) => {
                    warn!("❌ Client lifecycle error: {}", e);
                    return Err(e.into());
                }
            }
        }
        _ = signal::ctrl_c() => {
            info!("🛑 Shutdown signal received");
            
            // Gracefully release the lease
            info!("📤 Releasing DHCP lease...");
            if let Err(e) = client.release().await {
                warn!("⚠️  Failed to release lease: {}", e);
            } else {
                info!("✅ Lease released successfully");
            }
            
            info!("🔄 Final state: {}", client.state());
        }
    }

    Ok(())
}