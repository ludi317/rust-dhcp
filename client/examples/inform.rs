//! DHCP INFORM demonstration example

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use env_logger;
use log::info;

use dhcp_client::{netlink::NetlinkHandle, Client, ClientError};

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

    let network_handle = NetlinkHandle::new(interface_name).await?;
    let assigned_ip = network_handle.get_interface_ip().await?;
    let client_mac = network_handle.interface_mac;

    info!("Detected IP: {}", assigned_ip);
    info!("Detected MAC: {}", client_mac);

    info!("📡 DHCP INFORM demonstration");

    // Create RFC compliant client
    let mut client = Client::new(interface_name, client_mac).await?;

    // Now use DHCP INFORM to get additional configuration information
    match client.inform(assigned_ip).await {
        Ok(()) => {}
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
