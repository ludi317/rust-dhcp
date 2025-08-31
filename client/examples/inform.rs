//! DHCP INFORM demonstration example

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::str::FromStr;

use eui48::MacAddress;
use env_logger;
use log::info;

use dhcp_client::{Client, ClientError};

/// Get the primary network interface's IP address and MAC address
fn get_network_info() -> Result<(Ipv4Addr, MacAddress), Box<dyn std::error::Error>> {
    // Get IP address using route command to find the default interface
    let output = Command::new("route")
        .args(&["-n", "get", "default"])
        .output()?;
    
    let route_output = String::from_utf8(output.stdout)?;
    
    // Extract interface name
    let interface = route_output
        .lines()
        .find(|line| line.trim().starts_with("interface:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Could not find default interface")?;
    
    info!("Using interface: {}", interface);
    
    // Get IP address for this interface
    let ip_output = Command::new("ifconfig")
        .arg(interface)
        .output()?;
    
    let ifconfig_output = String::from_utf8(ip_output.stdout)?;
    
    // Extract IP address
    let ip_str = ifconfig_output
        .lines()
        .find(|line| line.trim().starts_with("inet ") && !line.contains("127.0.0.1"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Could not find IP address")?;
    
    let ip = Ipv4Addr::from_str(ip_str)?;
    
    // Extract MAC address
    let mac_str = ifconfig_output
        .lines()
        .find(|line| line.trim().starts_with("ether "))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Could not find MAC address")?;
    
    let mac = MacAddress::from_str(mac_str)?;
    
    Ok((ip, mac))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    let (assigned_ip, client_mac) = get_network_info()?;
    
    info!("Detected IP: {}", assigned_ip);
    info!("Detected MAC: {}", client_mac);

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