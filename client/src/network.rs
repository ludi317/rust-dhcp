//! Network configuration utilities for Linux - interface management, routing, and DNS setup

use eui48::MacAddress;
use futures::stream::TryStreamExt;
use rtnetlink::new_connection;

/// Get network interface by name and return its MAC address
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
