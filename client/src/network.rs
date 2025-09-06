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
use std::ffi::CString;
#[cfg(not(target_os = "linux"))]
use std::process::Command;
#[cfg(not(target_os = "linux"))]
use std::str::FromStr;

/// Get interface index from interface name
#[cfg(target_os = "linux")]
pub async fn get_interface_index(interface_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(interface_name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        Err(format!("Interface '{}' not found", interface_name).into())
    }
}

/// Get interface index from interface name
#[cfg(not(target_os = "linux"))]
pub async fn get_interface_index(interface_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let c_interface_name = CString::new(interface_name)?;
    let index = unsafe { libc::if_nametoindex(c_interface_name.as_ptr()) };

    if index == 0 {
        Err(format!("Interface '{}' not found", interface_name).into())
    } else {
        Ok(index)
    }
}

/// Get network interface MAC address
#[cfg(target_os = "linux")]
pub async fn get_interface_mac(interface_name: &str) -> Result<MacAddress, Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(interface_name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        // Look for the hardware address attribute in the link attributes
        for attr in link.attributes.iter() {
            if let netlink_packet_route::link::LinkAttribute::Address(address) = attr {
                let mac_bytes: [u8; 6] = address.clone().try_into().map_err(|_| "Invalid MAC address length")?;
                return Ok(MacAddress::new(mac_bytes));
            }
        }
        return Err(format!("No MAC address found for interface {}", interface_name).into());
    }

    Err(format!("Interface '{}' not found", interface_name).into())
}

/// Get network interface MAC address
#[cfg(not(target_os = "linux"))]
pub async fn get_interface_mac(interface_name: &str) -> Result<MacAddress, Box<dyn std::error::Error>> {
    let output = Command::new("ifconfig").arg(interface_name).output()?;

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

/// Get the assigned IP address of a network interface
#[cfg(target_os = "linux")]
pub async fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let if_index = get_interface_index(interface_name).await?;

    // Get addresses for this interface
    let mut addrs = handle.address().get().set_link_index_filter(if_index).execute();

    while let Some(addr) = addrs.try_next().await? {
        // Look for IPv4 address
        for attr in addr.attributes.iter() {
            if let netlink_packet_route::address::AddressAttribute::Address(IpAddr::V4(ip)) = attr {
                return Ok(*ip);
            }
        }
    }

    Err(format!("No IP address found for interface {}", interface_name).into())
}

/// Get the assigned IP address of a network interface
#[cfg(not(target_os = "linux"))]
pub async fn get_interface_ip(interface_name: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let output = Command::new("ifconfig").arg(interface_name).output()?;

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

/// Add an IPv4 address to a network interface by index
#[cfg(target_os = "linux")]
pub async fn add_interface_ip(if_index: u32, ip_addr: Ipv4Addr, prefix_len: u8) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Add the IPv4 address
    handle.address().add(if_index, IpAddr::V4(ip_addr), prefix_len).execute().await?;

    Ok(())
}

/// Get interface name from interface index
#[cfg(not(target_os = "linux"))]
fn get_interface_name(if_index: u32) -> Result<String, Box<dyn std::error::Error>> {
    let mut name_buf = [0u8; libc::IFNAMSIZ];
    let name_ptr = unsafe { libc::if_indextoname(if_index, name_buf.as_mut_ptr() as *mut i8) };

    if name_ptr.is_null() {
        return Err(format!("Interface with index {} not found", if_index).into());
    }

    let name_len = unsafe { libc::strlen(name_ptr) };
    let name_bytes = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len) };
    let interface_name = std::str::from_utf8(name_bytes)?;

    Ok(interface_name.to_string())
}

/// Add an IPv4 address to a network interface
#[cfg(not(target_os = "linux"))]
pub async fn add_interface_ip(if_index: u32, ip_addr: Ipv4Addr, prefix_len: u8) -> Result<(), Box<dyn std::error::Error>> {
    let interface_name = get_interface_name(if_index)?;
    let output = Command::new("sudo")
        .args(&[
            "ifconfig",
            &interface_name,
            "inet",
            &ip_addr.to_string(),
            "netmask",
            &prefix_to_netmask(prefix_len),
            "alias",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to add IP address: {}", stderr).into());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prefix_to_netmask(prefix_len: u8) -> String {
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let a = (mask >> 24) as u8;
    let b = (mask >> 16) as u8;
    let c = (mask >> 8) as u8;
    let d = mask as u8;
    format!("{}.{}.{}.{}", a, b, c, d)
}

pub fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let octets = netmask.octets();
    let mask_u32 = ((octets[0] as u32) << 24) | ((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | (octets[3] as u32);
    mask_u32.count_ones() as u8
}
