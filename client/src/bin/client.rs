//! DHCP client executable

use dhcp_client::netlink::NetlinkHandle;
use dhcp_client::{Client, ClientError};
use env_logger;
use log::{info, warn};
use std::env;
use std::process;
use tokio::{select, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <interface_name>", args[0]);
        eprintln!("Example: {} eth0", args[0]);
        process::exit(1);
    }

    let interface_name = &args[1];
    let netlink_handle = match NetlinkHandle::new(interface_name).await {
        Ok(handle) => {
            info!(
                "Created netlink handle: interface={}, index={}, mac={}",
                handle.interface_name, handle.interface_idx, handle.interface_mac
            );
            handle
        }
        Err(e) => {
            eprintln!("Failed to create netlink handle: {}", e);
            process::exit(1);
        }
    };

    let mut client = Client::new(&netlink_handle.interface_name, netlink_handle.interface_mac).await?;

    info!("🚀 Starting DHCP client");
    // Main DHCP client loop with configuration and lifecycle management
    loop {
        match client.configure(&netlink_handle).await {
            Ok(()) => {
                info!("✅ DHCP Lease applied");
                info!("🔄 Current state: {}", client.state());
            }
            Err(e) => {
                warn!("❌ DHCP configuration failed: {}", e);
                if let ClientError::IpConflict { assigned_ip, server_id } = e {
                    warn!("🚨 IP address conflict detected! Sending DHCPDECLINE...");
                    let _ = client
                        .decline(assigned_ip, server_id, "IP address conflict detected via ARP probe".to_string())
                        .await;
                }
                info!("⏳ Waiting 10 seconds before retrying...");
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                info!("🔄 Restarting DHCP configuration process...");
                continue; // Restart the configuration loop
            }
        };

        // Run the client lifecycle with graceful shutdown
        info!("🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)");

        select! {
            result = client.run_lifecycle(&netlink_handle) => {
                match result {
                    Ok(()) => {
                        info!("🏁 Lifecycle completed (infinite lease or clean exit)");
                        break; // Exit main loop for infinite leases
                    }
                    Err(ClientError::LeaseExpired) | Err(ClientError::Nak) |
                    Err(ClientError::InvalidLease) | Err(ClientError::IpConflict{..}) => {
                        client.undo_lease(&netlink_handle).await;
                        info!("⏳ Waiting 10 seconds before retrying...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        info!("🔄 Restarting DHCP configuration process...");
                        continue; // Restart configuration loop
                    }
                    Err(_) => {
                        unreachable!()
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("🛑 Shutdown signal received");

                // Gracefully release the lease
                if !client.ip_preconfigured {
                    info!("📤 Releasing DHCP lease...");
                    let _ = client.release("Shutdown signal received".to_string()).await;
                }
                client.undo_lease(&netlink_handle).await;
                break;
            }
        }
    }
    Ok(())
}
