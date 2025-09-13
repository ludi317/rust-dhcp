//! Network configuration utilities - interface management, routing, and DNS setup

use eui48::MacAddress;
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use {
    futures::stream::TryStreamExt,
    netlink_packet_route::link::LinkFlags,
    netlink_packet_route::route::RouteScope,
    rtnetlink::LinkUnspec,
    rtnetlink::RouteMessageBuilder,
    rtnetlink::{new_connection, Handle},
    std::net::IpAddr,
};

#[cfg(target_os = "linux")]
pub struct NetlinkHandle {
    handle: Handle,
    pub interface_name: String,
    pub interface_idx: u32,
    pub interface_mac: MacAddress,
}

#[cfg(target_os = "linux")]
impl NetlinkHandle {
    pub async fn new(interface_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        let interface_idx;
        let mut interface_mac = MacAddress::nil();

        // Get interface index immediately when creating the handle
        let mut links = handle.link().get().match_name(interface_name.to_string()).execute();
        if let Some(link) = links.try_next().await? {
            interface_idx = link.header.index;

            // Check if interface is already up
            if (link.header.flags & LinkFlags::Up) != LinkFlags::Up {
                // Interface is down, bring it up
                handle
                    .link()
                    .set(LinkUnspec::new_with_index(interface_idx).up().build())
                    .execute()
                    .await?;
            }
            for attr in link.attributes.iter() {
                if let netlink_packet_route::link::LinkAttribute::Address(address) = attr {
                    let mac_bytes: [u8; 6] = address.clone().try_into().map_err(|_| "Invalid MAC address length")?;
                    interface_mac = MacAddress::new(mac_bytes);
                    break;
                }
            }
        } else {
            return Err(format!("Interface '{}' not found", interface_name).into());
        };

        Ok(NetlinkHandle {
            handle,
            interface_name: interface_name.to_string(),
            interface_idx,
            interface_mac,
        })
    }

    pub async fn get_interface_ip(&self) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
        // Get addresses for this interface
        let mut addrs = self.handle.address().get().set_link_index_filter(self.interface_idx).execute();

        while let Some(addr) = addrs.try_next().await? {
            // Look for IPv4 address
            for attr in addr.attributes.iter() {
                if let netlink_packet_route::address::AddressAttribute::Address(IpAddr::V4(ip)) = attr {
                    return Ok(*ip);
                }
            }
        }

        Err(format!("No IP address found for interface {}", self.interface_name).into())
    }

    pub async fn add_interface_ip(&self, ip_addr: Ipv4Addr, prefix_len: u8) -> Result<(), Box<dyn std::error::Error>> {
        self.handle
            .address()
            .add(self.interface_idx, IpAddr::V4(ip_addr), prefix_len)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn add_host_route(&self, gateway: Ipv4Addr, priority: u32) -> Result<(), Box<dyn std::error::Error>> {
        // ip route add `gw`/32 via `ifname`
        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(self.interface_idx)
            .scope(RouteScope::Link)
            .destination_prefix(gateway, 32)
            .priority(priority)
            .build();

        self.handle.route().add(route).replace().execute().await?;
        Ok(())
    }

    pub async fn replace_route(
        &self, dst: Ipv4Addr, dst_mask: u8, gw: Ipv4Addr, if_ip: Ipv4Addr, if_subnet: u8, priority: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !is_same_subnet(if_ip, if_subnet, gw) {
            self.add_host_route(gw, priority).await?
        }

        let route = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst, dst_mask)
            .gateway(gw)
            .priority(priority)
            .build();
        self.handle.route().add(route).replace().execute().await?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub struct NetlinkHandle {
    pub interface_name: String,
    pub interface_idx: u32,
    pub interface_mac: MacAddress,
}

#[cfg(not(target_os = "linux"))]
impl NetlinkHandle {
    pub async fn new(interface_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        use std::process::Command;
        use std::str::FromStr;

        // Check if interface exists by running ifconfig
        let output = Command::new("ifconfig").arg(interface_name).output()?;

        if !output.status.success() {
            return Err(format!("Interface '{}' not found", interface_name).into());
        }

        let ifconfig_output = String::from_utf8(output.stdout)?;

        // Extract MAC address from ifconfig output
        let mac_str = ifconfig_output
            .lines()
            .find(|line| line.trim().starts_with("ether "))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or("Could not find MAC address")?;

        let interface_mac = MacAddress::from_str(mac_str)?;

        // Check if interface is up, and bring it up if not
        if !(ifconfig_output.contains("flags=") && ifconfig_output.contains("UP")) {
            // Interface is down, bring it up
            let up_output = Command::new("sudo").args(&["ifconfig", interface_name, "up"]).output()?;

            if !up_output.status.success() {
                let stderr = String::from_utf8_lossy(&up_output.stderr);
                return Err(format!("Failed to bring interface up: {}", stderr).into());
            }
        }

        // For non-Linux, we'll just use a hash of the interface name as the index
        // This is not a real interface index but serves the same purpose for our use case
        let hash = interface_name
            .bytes()
            .fold(1u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));

        Ok(NetlinkHandle {
            interface_name: interface_name.to_string(),
            interface_idx: hash,
            interface_mac,
        })
    }

    pub async fn get_interface_ip(&self) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
        use std::process::Command;
        use std::str::FromStr;

        let output = Command::new("ifconfig").arg(&self.interface_name).output()?;
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

    pub async fn add_interface_ip(&self, ip_addr: Ipv4Addr, prefix_len: u8) -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;

        let output = Command::new("sudo")
            .args(&[
                "ifconfig",
                &self.interface_name,
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

    pub async fn add_host_route(&self, _gateway: Ipv4Addr, _priority: u32) -> Result<(), Box<dyn std::error::Error>> {
        Err("add_host_route not implemented for this platform".into())
    }

    pub async fn replace_route(
        &self, 
        _dst: Ipv4Addr, 
        _dst_mask: u8, 
        _gw: Ipv4Addr, 
        _if_ip: Ipv4Addr, 
        _if_subnet: u8, 
        _priority: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err("replace_route not implemented for this platform".into())
    }

    pub async fn replace_default_route(&self, _gateway: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        Err("replace_default_route not implemented for this platform".into())
    }
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

pub fn is_same_subnet(interface_ip: Ipv4Addr, interface_subnet: u8, gateway: Ipv4Addr) -> bool {
    let mask_bits = (0xFFFFFFFFu32 << (32 - interface_subnet)) & 0xFFFFFFFF;
    let client_network = u32::from(interface_ip) & mask_bits;
    let gateway_network = u32::from(gateway) & mask_bits;
    client_network == gateway_network
}
