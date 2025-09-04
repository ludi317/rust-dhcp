//! Network configuration utilities - interface management, routing, and DNS setup

use eui48::MacAddress;
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use futures::stream::TryStreamExt;
#[cfg(target_os = "linux")]
use rtnetlink::new_connection;
#[cfg(target_os = "linux")]
use std::net::IpAddr;

#[cfg(not(target_os = "linux"))]
use std::process::Command;
#[cfg(not(target_os = "linux"))]
use std::str::FromStr;

/// Get network interface by name and return its MAC address
#[cfg(target_os = "linux")]
pub async fn get_interface_mac(interface_name: &str) -> Result<MacAddress, Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(interface_name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        // Look for the hardware address attribute in the link attributes
        for attr in link.attributes.iter() {
            if let netlink_packet_route::link::LinkAttribute::Address(address) = attr {
                if address.len() == 6 {
                    let mac_bytes: [u8; 6] = address.clone().try_into()
                        .map_err(|_| "Invalid MAC address length")?;
                    return Ok(MacAddress::new(mac_bytes));
                }
            }
        }
        return Err(format!("No MAC address found for interface {}", interface_name).into());
    }

    Err(format!("Interface '{}' not found", interface_name).into())
}

/// Get network interface by name and return its MAC address (macOS/other platforms)
#[cfg(not(target_os = "linux"))]
pub async fn get_interface_mac(interface_name: &str) -> Result<MacAddress, Box<dyn std::error::Error>> {
    let output = Command::new("ifconfig")
        .arg(interface_name)
        .output()?;
    
    let ifconfig_output = String::from_utf8(output.stdout)?;
    
    // Extract MAC address
    let mac_str = ifconfig_output
        .lines()
        .find(|line| line.trim().starts_with("ether "))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Could not find MAC address")?;
    
    let mac = MacAddress::from_str(mac_str)?;
    Ok(mac)
}

/// Get the assigned IP address of a network interface by name
#[cfg(target_os = "linux")]
pub async fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // First get the interface index
    let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
    
    if let Some(link) = links.try_next().await? {
        let if_index = link.header.index;
        
        // Get addresses for this interface
        let mut addrs = handle.address().get().set_link_index_filter(if_index).execute();
        
        while let Some(addr) = addrs.try_next().await? {
            // Look for IPv4 or IPv6 address
            for attr in addr.attributes.iter() {
                if let netlink_packet_route::address::AddressAttribute::Address(IpAddr::V4(ip)) = attr {
                    return Ok(*ip);
                }
            }
        }
        return Err(format!("No IP address found for interface {}", interface_name).into());
    }

    Err(format!("Interface '{}' not found", interface_name).into())
}

/// Get the assigned IP address of a network interface by name (macOS/other platforms)
#[cfg(not(target_os = "linux"))]
pub async fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let output = Command::new("ifconfig")
        .arg(interface_name)
        .output()?;
    
    let ifconfig_output = String::from_utf8(output.stdout)?;
    
    // Extract IP address
    let ip_str = ifconfig_output
        .lines()
        .find(|line| line.trim().starts_with("inet ") && !line.contains("127.0.0.1"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Could not find IP address")?;
    
    let ip = Ipv4Addr::from_str(ip_str)?;
    Ok(ip)
}
