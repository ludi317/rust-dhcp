//! Modern async DHCP client example

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use eui48::MacAddress;
use env_logger;
use log::info;

use dhcp_client::{get_dhcp_config, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Example MAC address - replace with actual network interface MAC
    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Bind to DHCP client port on all interfaces
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    info!("Starting modern DHCP client example");

    /*
    // Simple high-level interface
    match get_dhcp_config(bind_addr, client_mac, Some("rust-dhcp-client".to_string())).await {
        Ok(config) => {
            println!("DHCP Configuration obtained:");
            println!("  Your IP: {}", config.your_ip_address);
            println!("  Server IP: {}", config.server_ip_address);
            if let Some(mask) = config.subnet_mask {
                println!("  Subnet Mask: {}", mask);
            }
            if let Some(routers) = &config.routers {
                println!("  Routers: {:?}", routers);
            }
            if let Some(dns) = &config.domain_name_servers {
                println!("  DNS Servers: {:?}", dns);
            }
        }
        Err(e) => {
            eprintln!("DHCP client error: {}", e);
            return Err(e.into());
        }
    }
    */

    // Advanced usage example
    info!("Demonstrating advanced client usage");
    
    let mut advanced_client = Client::new(
        bind_addr,
        client_mac,
        None, // client_id
        Some("rust-dhcp-advanced".to_string()),
        None, // server_address (broadcast)
        None, // max_message_size
        true, // broadcast
    ).await?;

    // Perform discovery
    let config = advanced_client.discover(None, Some(3600)).await?; // Request 1 hour lease
    println!("Advanced client got IP: {}", config.your_ip_address);

    // Example: Release the lease
    if let Some(server_id) = config.server_ip_address.into() {
        advanced_client.release(
            config.your_ip_address,
            server_id,
            Some("Example release".to_string())
        ).await?;
        println!("Released IP address");
    }

    Ok(())
}