//! DHCP INFORM demonstration example

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use env_logger;
use log::info;

use dhcp_client::{
    network::{get_interface_ip, get_interface_mac},
    Client, ClientError,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    let interface_name = match args.get(1) {
        Some(name) => name,
        None => {
            eprintln!("Usage: {} <interface_name>", args[0]);
            eprintln!("Example: {} eth0", args[0]);
            std::process::exit(1);
        }
    };

    let assigned_ip = get_interface_ip(interface_name).await?;
    let client_mac = get_interface_mac(interface_name).await?;

    info!("Detected IP: {}", assigned_ip);
    info!("Detected MAC: {}", client_mac);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    info!("📡 DHCP INFORM demonstration");

    // Create RFC compliant client
    let mut client = Client::new(bind_addr, client_mac, None, Some("rust-inform-demo".to_string()), None, None).await?;

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
