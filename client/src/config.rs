//! Network configuration application utilities

use log::{info, warn};
use crate::network::{add_interface_ip, get_interface_index, netmask_to_prefix};
use crate::Configuration;

/// Apply DHCP configuration to the network interface
pub async fn apply_config(
    interface_name: &str,
    config: &Configuration,
) -> Result<(), Box<dyn std::error::Error>> {
    // Calculate prefix length from subnet mask
    let prefix_len = config
        .subnet_mask
        .map(|mask| netmask_to_prefix(mask))
        .unwrap_or(24); // Default to /24 if no subnet mask provided

    info!(
        "🔧 Assigning IP address {}/{} to interface {}",
        config.your_ip_address, prefix_len, interface_name
    );

    // Assign interface index
    let interface_idx = get_interface_index(interface_name).await?;
    // let ip = Ipv4Addr::from_str("192.168.65.4").unwrap();
    match add_interface_ip(interface_idx, config.your_ip_address, prefix_len).await {
        Ok(()) => {
            info!("✅ Successfully assigned IP address to interface");
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
