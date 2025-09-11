//! Network configuration application utilities

use crate::network::{netmask_to_prefix, NetlinkHandle, };
use crate::ClientError;
use arp::{announce_address, arp_probe, ArpProbeResult};
use log::{info, warn};


/// DHCP configuration result from a successful lease.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub your_ip_address: std::net::Ipv4Addr,
    pub server_ip_address: std::net::Ipv4Addr,
    pub subnet_mask: Option<std::net::Ipv4Addr>,
    pub routers: Option<Vec<std::net::Ipv4Addr>>,
    pub domain_name_servers: Option<Vec<std::net::Ipv4Addr>>,
    pub static_routes: Option<Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)>>,
    pub classless_static_routes: Option<Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr, std::net::Ipv4Addr)>>,
}

impl Configuration {
    pub fn from_response(mut response: dhcp_protocol::Message) -> Self {
        /*
        RFC 3442
        If the DHCP server returns both a Classless Static Routes option and
        a Router option, the DHCP client MUST ignore the Router option.
        Similarly, if the DHCP server returns both a Classless Static Routes
        option and a Static Routes option, the DHCP client MUST ignore the
        Static Routes option.
        */
        if response.options.classless_static_routes.is_some() {
            response.options.routers = None;
            response.options.static_routes = None;
        }

        Configuration {
            your_ip_address: response.your_ip_address,
            // your_ip_address: Ipv4Addr::from_str("192.168.65.4").unwrap(),
            server_ip_address: response.server_ip_address,
            subnet_mask: response.options.subnet_mask,
            routers: response.options.routers,
            domain_name_servers: response.options.domain_name_servers,
            static_routes: response.options.static_routes,
            classless_static_routes: response.options.classless_static_routes,
        }
    }
}

/// Apply DHCP configuration to the network interface
pub async fn apply_config(netlink_handle: &NetlinkHandle, config: &Configuration) -> Result<(), Box<dyn std::error::Error>> {
    // Calculate prefix length from subnet mask
    let prefix_len = config.subnet_mask.map(|mask| netmask_to_prefix(mask)).unwrap_or(24); // Default to /24 if no subnet mask provided
    

    // Get interface details
    let interface_idx = netlink_handle.interface_idx;
    let our_mac = netlink_handle.interface_mac;

    // Perform ARP probe to make sure no one else is using this ip address
    match arp_probe(interface_idx, config.your_ip_address, our_mac).await {
        ArpProbeResult::Available => {
            info!("✅ ARP probe successful - IP address {} is available", config.your_ip_address);
        }
        ArpProbeResult::InUse => {
            warn!("❌ IP address {} is already in use (detected via ARP)", config.your_ip_address);
            return Err(ClientError::IpConflict.into());
        }
        ArpProbeResult::Error(e) => {
            warn!("⚠️  ARP probe failed: {} - proceeding anyway", e);
        }
    }

    // Send ARP announcements
    if let Err(e) = announce_address(interface_idx, config.your_ip_address, our_mac).await {
        warn!("⚠️  Failed to send gratuitous ARP announcement: {}", e);
    }

    info!(
        "🔧 Assigning IP address {}/{} to interface {}",
        config.your_ip_address, prefix_len, netlink_handle.interface_name
    );

    // Assign the IP address
    match netlink_handle.add_interface_ip(config.your_ip_address, prefix_len).await {
        Ok(()) => {
            info!("✅ Successfully assigned IP address to interface");
        }
        Err(e) => {
            warn!("⚠️  Failed to assign IP address to interface {}: {}", netlink_handle.interface_name, e);
            return Err(e);
        }
    }

    // TODO: Apply additional configuration like routes, DNS, etc.

    Ok(())
}

