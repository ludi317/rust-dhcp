//! ARP probe test example

use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;

use arp::{arp_probe, get_interface_index, get_interface_mac, ArpProbeResult};
use env_logger;
use log::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <interface_name> <target_ip>", args[0]);
        eprintln!("Example: {} eth0 192.168.65.1", args[0]);
        std::process::exit(1);
    }

    let interface_name = &args[1];
    let target_ip = Ipv4Addr::from_str(&args[2])?;
    let interface_idx = get_interface_index(interface_name)?;
    let our_mac = get_interface_mac(interface_name).await?;

    info!("🔍 ARP Probe Test");
    info!("   Interface: {}", interface_name);
    info!("   Target IP: {}", target_ip);

    match arp_probe(interface_idx, target_ip, our_mac).await {
        ArpProbeResult::Available => {
            info!("✅ SUCCESS: IP address {} is AVAILABLE (no ARP response)", target_ip);
            info!("   This IP can be safely used - no device responded to the ARP probe");
        }
        ArpProbeResult::InUse => {
            warn!("⚠️  CONFLICT: IP address {} is IN USE (ARP response received)", target_ip);
            warn!("   Another device on the network is already using this IP address");
            warn!("   In a real DHCP client, this would trigger sending DHCPDECLINE");
        }
        ArpProbeResult::Error(e) => {
            warn!("❌ ERROR: ARP probe failed: {}", e);
            warn!("   This could be due to insufficient privileges, missing interface, etc.");
        }
    }

    info!("🏁 ARP probe test completed");
    Ok(())
}
