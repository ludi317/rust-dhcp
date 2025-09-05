//! Network configuration application utilities

use log::{info, warn};
use crate::network::{add_interface_ip, get_interface_index, get_interface_mac, netmask_to_prefix};
use arp::{arp_probe, announce_address, ArpProbeResult};
use crate::Configuration;

/// Apply DHCP configuration to the network interface
pub async fn apply_config(
    interface_name: &str,
    config: &Configuration,
) -> Result<(), Box<dyn std::error::Error>> {
    // Calculate prefix length from subnet mask
    let prefix_len = config.subnet_mask.map(|mask| netmask_to_prefix(mask)).unwrap_or(24); // Default to /24 if no subnet mask provided

    info!("🔧 Assigning IP address {}/{} to interface {}",config.your_ip_address, prefix_len, interface_name);

    // Get interface details
    let interface_idx = get_interface_index(interface_name).await?;
    let our_mac = get_interface_mac(interface_name).await?;
    
    // Perform ARP probe as per RFC 2131
    match arp_probe(interface_idx, config.your_ip_address, our_mac).await {
        ArpProbeResult::Available => {
            info!("✅ ARP probe successful - IP address {} is available", config.your_ip_address);
        },
        ArpProbeResult::InUse => {
            warn!("❌ IP address {} is already in use (detected via ARP)", config.your_ip_address);
            return Err(format!("IP address {} is already in use - should send DHCPDECLINE", config.your_ip_address).into());
        },
        ArpProbeResult::Error(e) => {
            warn!("⚠️  ARP probe failed: {} - proceeding anyway", e);
        }
    }
    
    // Assign the IP address
    match add_interface_ip(interface_idx, config.your_ip_address, prefix_len).await {
        Ok(()) => {
            info!("✅ Successfully assigned IP address to interface");
            
            // Send gratuitous ARP as per RFC 2131
            if let Err(e) = announce_address(interface_idx, config.your_ip_address, our_mac).await {
                warn!("⚠️  Failed to send gratuitous ARP announcement: {}", e);
            }
        }
        Err(e) => {
            warn!(
                "⚠️  Failed to assign IP address to interface {}: {}",
                interface_name, e
            );
            return Err(e);
        }
    }

    // TODO: Apply additional configuration like routes, DNS, etc.

    Ok(())
}
