//! DHCP client executable

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::env;
use std::process;

use eui48::MacAddress;
use log::{info, warn};
use env_logger;
use tokio::{select, signal};
use dhcp_client::{Client, ClientError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <interface_mac_address> [server_ip]", args[0]);
        eprintln!("Example: {} 00:11:22:33:44:55", args[0]);
        eprintln!("Example: {} 00:11:22:33:44:55 192.168.1.1", args[0]);
        process::exit(1);
    }

    let client_mac = match args[1].parse::<MacAddress>() {
        Ok(mac) => mac,
        Err(e) => {
            eprintln!("Invalid MAC address '{}': {}", args[1], e);
            process::exit(1);
        }
    };

    let server_address = if args.len() > 2 {
        match args[2].parse::<Ipv4Addr>() {
            Ok(ip) => Some(ip),
            Err(e) => {
                eprintln!("Invalid server IP address '{}': {}", args[2], e);
                process::exit(1);
            }
        }
    } else {
        None
    };

    info!("Starting DHCP client with MAC address: {}", client_mac);
    if let Some(server_ip) = server_address {
        info!("Using server IP: {}", server_ip);
    } else {
        info!("Using broadcast for server discovery");
    }

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    info!("🚀 Starting DHCP client");

    let mut client = Client::new(
        bind_addr,
        client_mac,
        None, // client_id (will use MAC)
        Some("rust-rfc-dhcp-client".to_string()),
        None, // server_address (broadcast discovery)
        None, // max_message_size
        true, // use broadcast
    ).await?;

    info!("📡 Initial state: {}", client.state());

    // Perform initial DHCP configuration (DORA sequence) with retries per RFC 2131
    let config = loop {
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

                // Display lease information
                if let Some(lease) = client.lease() {
                    info!("📋 Lease Information:");
                    info!("   ⏰ Lease Duration: {}s", lease.lease_duration);
                    info!("   🔄 T1 (Renewal): {}s", lease.t1());
                    info!("   🔄 T2 (Rebinding): {}s", lease.t2());
                    info!("   ⏳ Time until renewal: {:?}", lease.time_until_renewal());
                    info!("   ⏳ Time until rebinding: {:?}", lease.time_until_rebinding());
                    info!("   ⏳ Time until expiry: {:?}", lease.time_until_expiry());
                }

                info!("🔄 Current state: {}", client.state());
                break config;
            }
            Err(ClientError::Nak) => {
                warn!("❌ Received DHCP NAK, restarting configuration process");
                // RFC 2131: restart the configuration process on NAK
                continue;
            }
            Err(e) => {
                warn!("❌ DHCP configuration failed: {}", e);
                return Err(e.into());
            }
        }
    };

    // Run the client lifecycle with graceful shutdown
    info!("🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)");

    select! {
        result = client.run_lifecycle() => {
            match result {
                Ok(()) => {
                    info!("🏁 Client lifecycle completed normally");
                }
                Err(ClientError::LeaseExpired) => {
                    warn!("⏰ Lease expired, would need to restart DHCP process");
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
        }
    }
    Ok(())
}
