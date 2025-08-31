//! DHCP INFORM demonstration example

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use eui48::MacAddress;
use env_logger;
use log::info;

use dhcp_client::{Client, ClientError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Note: these values are taken from my work laptop
    let assigned_ip = "192.168.8.59".parse::<Ipv4Addr>().unwrap();
    let client_mac = MacAddress::new([0xbc, 0xd0, 0x74, 0x59, 0x92, 0x41]);


    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    info!("📡 DHCP INFORM demonstration");

    // Create RFC compliant client
    let mut client = Client::new(
        bind_addr,
        client_mac,
        None,
        Some("rust-inform-demo".to_string()),
        None,
        None,
        true,
    ).await?;


    // Now use DHCP INFORM to get additional configuration information
    match client.inform(assigned_ip).await {
        Ok(inform_config) => {
            info!("✅ DHCP INFORM successful!");
            
            // Display configuration from INFORM
            info!("📋 Configuration from INFORM:");
            info!("   🏠 Server IP: {}", inform_config.server_ip_address);
            if let Some(mask) = inform_config.subnet_mask {
                info!("   🔍 Subnet Mask: {}", mask);
            }
            if let Some(gw) = inform_config.routers.as_ref().and_then(|r| r.first()) {
                info!("   🚪 Gateway: {}", gw);
            }
            if let Some(dns) = inform_config.domain_name_servers.as_ref().and_then(|d| d.first()) {
                info!("   🌐 DNS: {}", dns);
            }

        }
        Err(ClientError::Timeout { .. }) => {
            info!("⏰ DHCP INFORM timed out");
        }
        Err(e) => {
            info!("❌ DHCP INFORM failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}