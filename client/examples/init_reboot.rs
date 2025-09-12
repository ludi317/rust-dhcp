//! RFC 2131 INIT-REBOOT demonstration example

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use env_logger;
use eui48::MacAddress;
use log::info;

use dhcp_client::{Client, ClientError};
use dhcp_client::network::NetlinkHandle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x57]);
    let args: Vec<String> = env::args().collect();
    let interface_name = match args.get(1) {
        Some(name) => name,
        None => {
            eprintln!("Usage: {} <interface_name>", args[0]);
            eprintln!("Example: {} eth0", args[0]);
            std::process::exit(1);
        }
    };
    info!("🔄 INIT-REBOOT demonstration");
    let netlink_handle = NetlinkHandle::new(interface_name).await?;

    // Store the IP for later reuse
    let previous_ip = {
        // Create RFC compliant client in its own scope
        let mut client = Client::new("en0", client_mac).await?;

        // First, get an initial lease through normal DORA process
        info!("🚀 Phase 1: Initial DHCP configuration (DORA)");
        client.configure(&netlink_handle).await?;
        let ip = client.lease().unwrap().assigned_ip;
        info!("✅ Initial IP obtained: {}", ip);


        // Release the current lease to simulate client restart
        info!("📤 Releasing current lease to simulate client restart...");
        client.release().await?;

        ip
    };

    // Simulate client restart - create new client instance with previous IP
    info!("🔄 Phase 2: Client restart with INIT-REBOOT");
    let mut reboot_client = Client::new("en0", client_mac).await?;

    info!("📍 Attempting INIT-REBOOT for IP: {}", previous_ip);
    match reboot_client.init_reboot(previous_ip, &netlink_handle).await {
        Ok(()) => {
            info!("✅ DHCP Configuration obtained:");
            if let Some(lease) = &reboot_client.lease {
                info!("✅ DHCP Lease obtained:");
                info!("   📍 Your IP: {}/{}", lease.assigned_ip, lease.subnet_prefix);
                info!("   🚪 Gateway: {}", lease.gateway_ip);
                info!("   ⏰ Lease Duration: {}s", lease.lease_time);

                if let Some(ref dns_servers) = lease.dns_servers {
                    info!("   🌐 DNS servers: {:?}", dns_servers);
                }

                if let Some(ref domain_name) = lease.domain_name {
                    info!("   🏷️ Domain name: {}", domain_name);
                }

                if let Some(ref ntp_servers) = lease.ntp_servers {
                    info!("   🕰️ NTP servers: {:?}", ntp_servers);
                }
            }

            info!("🔄 Current state: {}", reboot_client.state());
        }
        Err(ClientError::Nak) => {
            info!("❌ INIT-REBOOT failed: Previous IP no longer valid");
        }
        Err(e) => {
            info!("❌ INIT-REBOOT failed: {}", e);
            return Err(e.into());
        }
    }

    // Clean up
    reboot_client.release().await?;
    info!("✅ INIT-REBOOT demonstration completed");

    Ok(())
}
