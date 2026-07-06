//! DHCP client executable. Dispatches between IPv4 and IPv6 modes.

use dhcp_client::netlink::NetlinkHandle;
use dhcp_client::v6::ClientV6Error;
use dhcp_client::{Client, ClientError, ClientV6, DhcpState};
use log::{info, warn};
use std::env;
use std::path::PathBuf;
use std::process;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::select;

struct Args {
    ipv6: bool,
    resolv_conf_path: Option<PathBuf>,
    duid_path: PathBuf,
    solicit_timeout: Duration,
    interface_name: String,
}

fn print_usage_and_exit(prog: &str) -> ! {
    eprintln!(
        "Usage: {} [--ipv6 | --ipv4] [--resolv-conf-path PATH] [--duid-path PATH] [--solicit-timeout SEC] <interface_name>",
        prog
    );
    process::exit(1);
}

fn parse_args() -> Args {
    let raw: Vec<String> = env::args().collect();
    if raw.len() < 2 {
        print_usage_and_exit(&raw[0]);
    }
    let prog = raw[0].clone();

    let mut ipv6 = false;
    let mut resolv_conf_path: Option<PathBuf> = None;
    let mut duid_path = PathBuf::from("/var/lib/rust-dhcp/duid");
    let mut solicit_timeout = Duration::from_secs(30);
    let mut interface_name: Option<String> = None;

    let mut i = 1;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "--ipv6" => ipv6 = true,
            "--ipv4" => ipv6 = false,
            "--resolv-conf-path" => {
                i += 1;
                resolv_conf_path = Some(PathBuf::from(raw.get(i).unwrap_or_else(|| print_usage_and_exit(&prog))));
            }
            "--duid-path" => {
                i += 1;
                duid_path = PathBuf::from(raw.get(i).unwrap_or_else(|| print_usage_and_exit(&prog)));
            }
            "--solicit-timeout" => {
                i += 1;
                let s = raw.get(i).unwrap_or_else(|| print_usage_and_exit(&prog));
                let secs: u64 = s.parse().unwrap_or_else(|_| print_usage_and_exit(&prog));
                solicit_timeout = Duration::from_secs(secs);
            }
            s if s.starts_with("--") => {
                eprintln!("Unknown flag: {}", s);
                print_usage_and_exit(&prog);
            }
            _ => {
                if interface_name.is_some() {
                    eprintln!("Unexpected positional argument: {}", arg);
                    print_usage_and_exit(&prog);
                }
                interface_name = Some(arg.clone());
            }
        }
        i += 1;
    }

    Args {
        ipv6,
        resolv_conf_path,
        duid_path,
        solicit_timeout,
        interface_name: interface_name.unwrap_or_else(|| print_usage_and_exit(&prog)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = parse_args();

    let netlink_handle = match NetlinkHandle::new(&args.interface_name).await {
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

    if args.ipv6 {
        run_v6(args, netlink_handle).await
    } else {
        run_v4(netlink_handle).await
    }
}

async fn run_v6(args: Args, netlink_handle: NetlinkHandle) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientV6::new(
        &netlink_handle.interface_name,
        netlink_handle.interface_idx,
        netlink_handle.interface_mac,
        &args.duid_path,
        Some(args.solicit_timeout),
        args.resolv_conf_path.clone(),
    )
    .await?;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;
    let mut sighup = signal(SignalKind::hangup())?;

    info!("🚀 Starting DHCPv6 client");
    loop {
        if client.state() != dhcp_client::DhcpV6State::Bound {
            match client.configure(&netlink_handle).await {
                Ok(()) => info!("✅ DHCPv6 lease applied"),
                Err(ClientV6Error::SolicitTimeout) => {
                    warn!("❌ DHCPv6 SOLICIT timed out — no server responded");
                    return Err(Box::new(ClientV6Error::SolicitTimeout));
                }
                Err(e) => {
                    warn!("❌ DHCPv6 configuration failed: {}", e);
                    info!("⏳ Waiting 10 seconds before retrying...");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }
        }

        info!("🏃 Running DHCPv6 lifecycle (press Ctrl+C to exit gracefully)");
        select! {
            result = client.run_lifecycle(&netlink_handle) => {
                match result {
                    Ok(()) => {
                        info!("🏁 DHCPv6 lifecycle completed");
                        break;
                    }
                    Err(ClientV6Error::LeaseExpired) => {
                        client.undo_lease(&netlink_handle).await;
                        info!("⏳ Waiting 10 seconds before retrying...");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                    Err(e) => {
                        warn!("❌ DHCPv6 lifecycle error: {}", e);
                        client.undo_lease(&netlink_handle).await;
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Shutdown signal received (Ctrl+C)");
                let _ = client.release("Shutdown signal received").await;
                client.undo_lease(&netlink_handle).await;
                break;
            }
            _ = sigterm.recv() => {
                info!("🛑 SIGTERM received - graceful shutdown");
                let _ = client.release("SIGTERM received").await;
                client.undo_lease(&netlink_handle).await;
                break;
            }
            _ = sigusr1.recv() => {
                info!("🔄 SIGUSR1 received - initiating DHCPv6 lease renewal");
                match client.renew(&netlink_handle).await {
                    Ok(()) => info!("✅ DHCPv6 lease renewed via SIGUSR1"),
                    Err(e) => {
                        warn!("❌ DHCPv6 renewal failed: {}", e);
                        client.undo_lease(&netlink_handle).await;
                    }
                }
                continue;
            }
            _ = sigusr2.recv() => {
                info!("📤 SIGUSR2 received - releasing DHCPv6 lease and exiting");
                let _ = client.release("SIGUSR2 received").await;
                client.undo_lease(&netlink_handle).await;
                break;
            }
            _ = sighup.recv() => {
                info!("🔄 SIGHUP received - initiating DHCPv6 lease renewal");
                match client.renew(&netlink_handle).await {
                    Ok(()) => info!("✅ DHCPv6 lease renewed via SIGHUP"),
                    Err(e) => {
                        warn!("❌ DHCPv6 renewal failed: {}", e);
                        client.undo_lease(&netlink_handle).await;
                    }
                }
                continue;
            }
        }
    }
    Ok(())
}

async fn run_v4(netlink_handle: NetlinkHandle) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new(&netlink_handle.interface_name, netlink_handle.interface_mac).await?;

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigusr2 = signal(SignalKind::user_defined2())?;
    let mut sighup = signal(SignalKind::hangup())?;

    info!("🚀 Starting DHCP client");
    loop {
        if client.state() != DhcpState::Bound {
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
                    continue;
                }
            };
        }

        info!("🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)");

        select! {
            result = client.run_lifecycle(&netlink_handle) => {
                match result {
                    Ok(()) => {
                        info!("🏁 Lifecycle completed for infinite lease");
                        break;
                    }
                    Err(ClientError::LeaseExpired) | Err(ClientError::Nak) |
                    Err(ClientError::InvalidLease) | Err(ClientError::IpConflict{..}) => {
                        client.undo_lease(&netlink_handle).await;
                        info!("⏳ Waiting 10 seconds before retrying...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        info!("🔄 Restarting DHCP configuration process...");
                        continue;
                    }
                    Err(_) => {
                        unreachable!()
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Shutdown signal received (Ctrl+C)");
                if !client.ip_preconfigured {
                    info!("📤 Releasing DHCP lease...");
                    let _ = client.release("Shutdown signal received".to_string()).await;
                }
                client.undo_lease(&netlink_handle).await;
                break;
            }
            _ = sigterm.recv() => {
                info!("🛑 SIGTERM received - graceful shutdown");
                if !client.ip_preconfigured {
                    info!("📤 Releasing DHCP lease...");
                    let _ = client.release("SIGTERM received".to_string()).await;
                }
                client.undo_lease(&netlink_handle).await;
                break;
            }
            _ = sigusr1.recv() => {
                info!("🔄 SIGUSR1 received - initiating lease renewal");
                match client.renew(&netlink_handle).await {
                    Ok(()) => {
                        info!("✅ Lease renewed successfully via SIGUSR1");
                        continue;
                    }
                    Err(e) => {
                        warn!("❌ Renewal failed: {:?}, falling back to full DORA", e);
                        client.undo_lease(&netlink_handle).await;
                        continue;
                    }
                }
            }
            _ = sigusr2.recv() => {
                info!("📤 SIGUSR2 received - releasing lease and exiting");
                if !client.ip_preconfigured {
                    let _ = client.release("SIGUSR2 received".to_string()).await;
                }
                client.undo_lease(&netlink_handle).await;
                break;
            }
            _ = sighup.recv() => {
                info!("🔄 SIGHUP received - initiating lease renewal");
                match client.renew(&netlink_handle).await {
                    Ok(()) => {
                        info!("✅ Lease renewed successfully via SIGHUP");
                        continue;
                    }
                    Err(e) => {
                        warn!("❌ Renewal failed: {:?}, falling back to full DORA", e);
                        client.undo_lease(&netlink_handle).await;
                        continue;
                    }
                }
            }
        }
    }
    Ok(())
}
