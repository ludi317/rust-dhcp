//! RFC 2131 INIT-REBOOT demonstration example

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use eui48::MacAddress;
use env_logger;
use log::info;

use dhcp_client::{Client, ClientError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x57]);
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    info!("🔄 INIT-REBOOT demonstration");

    // Store the IP for later reuse
    let previous_ip = {
        // Create RFC compliant client in its own scope
        let mut client = Client::new(
            bind_addr,
            client_mac,
            None,
            Some("rust-init-reboot-demo".to_string()),
            None,
            None,
            true,
        ).await?;

        // First, get an initial lease through normal DORA process
        info!("🚀 Phase 1: Initial DHCP configuration (DORA)");
        let initial_config = client.configure().await?;
        info!("✅ Initial IP obtained: {}", initial_config.your_ip_address);
        
        let ip = initial_config.your_ip_address;
        
        // Release the current lease to simulate client restart
        info!("📤 Releasing current lease to simulate client restart...");
        client.release().await?;
        
        ip
    }; // Client is dropped here, releasing the socket
    
    // Wait for socket to be released by the OS
    info!("⏳ Waiting for socket release...");
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Simulate client restart - create new client instance with previous IP
    info!("🔄 Phase 2: Client restart with INIT-REBOOT");
    let mut reboot_client = Client::new(
        bind_addr,
        client_mac,
        None,
        Some("rust-init-reboot-demo".to_string()),
        None,
        None,
        true,
    ).await?;

    // Set the previous IP for INIT-REBOOT attempt
    reboot_client.set_previous_ip(previous_ip);
    info!("📍 Set previous IP for reboot: {}", previous_ip);

    // Attempt to reconfigure - this will try INIT-REBOOT first
    match reboot_client.configure().await {
        Ok(config) => {
            if config.your_ip_address == previous_ip {
                info!("🎉 SUCCESS: INIT-REBOOT successful! Reused IP: {}", config.your_ip_address);
            } else {
                info!("🔄 INIT-REBOOT failed, got new IP through DORA: {}", config.your_ip_address);
            }
            
            // Display configuration
            info!("📋 Final Configuration:");
            info!("   📍 IP Address: {}", config.your_ip_address);
            info!("   🏠 Server IP: {}", config.server_ip_address);
            if let Some(mask) = config.subnet_mask {
                info!("   🔍 Subnet Mask: {}", mask);
            }
            if let Some(gw) = config.routers.as_ref().and_then(|r| r.first()) {
                info!("   🚪 Gateway: {}", gw);
            }
        }
        Err(ClientError::Nak) => {
            info!("❌ INIT-REBOOT failed: Previous IP no longer valid");
            info!("🔄 Would normally fall back to full DORA sequence");
        }
        Err(e) => {
            info!("❌ Configuration failed: {}", e);
            return Err(e.into());
        }
    }

    // Clean up
    reboot_client.release().await?;
    info!("✅ INIT-REBOOT demonstration completed");

    Ok(())
}

/// Example showing manual INIT-REBOOT process
#[allow(dead_code)]
async fn manual_init_reboot_demo() -> Result<(), Box<dyn std::error::Error>> {
    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x58]);
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    let mut client = Client::new(
        bind_addr,
        client_mac,
        None,
        Some("manual-init-reboot".to_string()),
        None,
        None,
        true,
    ).await?;

    // Simulate having a previous IP (e.g., from persistent storage)
    let previous_ip = Ipv4Addr::new(192, 168, 1, 100);
    
    info!("🔄 Manual INIT-REBOOT attempt for IP: {}", previous_ip);

    // Directly attempt INIT-REBOOT
    match client.init_reboot(previous_ip).await {
        Ok(config) => {
            info!("✅ INIT-REBOOT successful!");
            info!("   📍 Verified IP: {}", config.your_ip_address);
            info!("   ⏰ Lease time: {}s", client.lease().unwrap().lease_time);
        }
        Err(ClientError::Nak) => {
            info!("❌ Previous IP {} is no longer valid", previous_ip);
            info!("🔄 Starting fresh DORA sequence...");
            let config = client.configure().await?;
            info!("✅ Got new IP: {}", config.your_ip_address);
        }
        Err(e) => {
            info!("❌ INIT-REBOOT failed: {}", e);
        }
    }

    client.release().await?;
    Ok(())
}