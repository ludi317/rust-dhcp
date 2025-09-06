//! Utility functions for network interface detection

use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

use eui48::MacAddress;

/// Get the primary network interface's IP address and MAC address
pub fn get_network_info() -> Result<(Ipv4Addr, MacAddress), Box<dyn std::error::Error>> {
    // Get IP address using route command to find the default interface
    let output = Command::new("route").args(&["-n", "get", "default"]).output()?;

    let route_output = String::from_utf8(output.stdout)?;

    // Extract interface name
    let interface = route_output
        .lines()
        .find(|line| line.trim().starts_with("interface:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("Could not find default interface")?;

    log::info!("Using interface: {}", interface);

    // Get IP address for this interface
    let ip_output = Command::new("ifconfig").arg(interface).output()?;

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
