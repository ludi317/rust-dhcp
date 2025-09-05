//! DHCP client executable

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use dhcp_client::{Client, ClientError};
use dhcp_client::network::{get_interface_mac};
use dhcp_client::config::apply_config;
use env_logger;
use log::{info, warn};
use tokio::{select, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <interface_name>", args[0]);
        eprintln!("Example: {} eth0", args[0]);
        process::exit(1);
    }

    let interface_name = &args[1];
    
    info!("Getting MAC address for interface: {}", interface_name);
    let client_mac = match get_interface_mac(interface_name).await {
        Ok(mac) => {
            info!("Found MAC address: {}", mac);
            mac
        },
        Err(e) => {
            eprintln!("Failed to get MAC address for interface '{}': {}", interface_name, e);
            process::exit(1);
        }
    };

    info!("🚀 Starting DHCP client");

    let mut client = Client::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68),
        client_mac,
        None, // client_id (will use MAC)
        Some("rust-rfc-dhcp-client".to_string()),
        None, // server_address (broadcast discovery)
        None,
    )
    .await?;

    info!("📡 Initial state: {}", client.state());

    // Main DHCP client loop with configuration and lifecycle management
    loop {
        match client.configure().await {
            Ok(config) => {
                info!("✅ DHCP Configuration obtained:");
                info!("   📍 Your IP: {}", config.your_ip_address);
                info!("   🏠 Server IP: {}", config.server_ip_address);
                if let Some(mask) = config.subnet_mask {
                    info!("   🔍 Subnet: {}", mask);
                }
                if let Some(gw) = config.routers.as_ref().and_then(|r| r.first()) {
                    info!("   🚪 Gateway: {}", gw);
                }
                if let Some(dns) = config.domain_name_servers.as_ref().and_then(|d| d.first()) {
                    info!("   🌐 DNS: {}", dns);
                }

                // Apply network configuration
                if let Err(e) = apply_config(interface_name, &config).await {
                    // Check if this is an IP conflict error
                    if let Some(ClientError::IpConflict) = e.downcast_ref::<ClientError>() {
                        warn!("🚨 IP address conflict detected! Sending DHCPDECLINE...");
                        
                        match client.decline(config.your_ip_address, config.server_ip_address,
                                           "IP address conflict detected via ARP probe".to_string()).await {
                            Ok(()) => {
                                info!("📤 DHCPDECLINE sent successfully");
                                info!("🔄 Restarting DHCP configuration process...");
                                continue; // Restart the configuration loop
                            },
                            Err(decline_err) => {
                                warn!("❌ Failed to send DHCPDECLINE: {}", decline_err);
                                continue; // Still restart the configuration loop
                            }
                        }
                    } else {
                        warn!("⚠️  Failed to apply network configuration: {}", e);
                    }
                }

                // Display lease information
                if let Some(lease) = client.lease() {
                    info!("📋 Lease Information:");
                    info!("   ⏰ Lease Duration: {}s", lease.lease_duration);
                    info!("   ⏰ T1 (Renewal): {}s", lease.t1());
                    info!("   ⏰ T2 (Rebinding): {}s", lease.t2());
                }

                info!("🔄 Current state: {}", client.state());
            }
            Err(ClientError::Nak) => {
                warn!("❌ Received DHCP NAK, restarting configuration process");
                continue;
            }
            Err(e) => {
                warn!("❌ DHCP configuration failed: {}", e);
                return Err(e.into());
            }
        };

        // Run the client lifecycle with graceful shutdown
        info!("🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)");

        select! {
            result = client.run_lifecycle() => {
                match result {
                    Ok(()) => {
                        unreachable!("lifecycle should run indefinitely");
                    }
                    Err(ClientError::LeaseExpired) => {
                        warn!("⏰ Lease expired, returning to INIT and restarting configuration");
                        continue; // Restart configuration loop
                    }
                    Err(e) => {
                        warn!("❌ Client lifecycle error: {}", e);
                        return Err(e.into());
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("🛑 Shutdown signal received");

                // Gracefully release the lease
                info!("📤 Releasing DHCP lease...");
                if let Err(e) = client.release().await {
                    warn!("⚠️  Failed to release lease: {}", e);
                } else {
                    info!("✅ Lease released successfully");
                }

                info!("🔄 Final state: {}", client.state());
                break;
            }
        }
    }
    Ok(())
}
