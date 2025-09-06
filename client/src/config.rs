//! Network configuration application utilities

use crate::network::{NetlinkHandle, netmask_to_prefix,};
use crate::{ClientError, Configuration};
use arp::{announce_address, arp_probe, ArpProbeResult};
use log::{info, warn};

/// Apply DHCP configuration to the network interface
pub async fn apply_config(netlink_handle: &NetlinkHandle, config: &Configuration) -> Result<(), Box<dyn std::error::Error>> {
    // Calculate prefix length from subnet mask
    let prefix_len = config.subnet_mask.map(|mask| netmask_to_prefix(mask)).unwrap_or(24); // Default to /24 if no subnet mask provided

    info!(
        "🔧 Assigning IP address {}/{} to interface {}",
        config.your_ip_address, prefix_len, netlink_handle.interface_name
    );

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
