//! NTP configuration utilities

use log::info;
use std::net::Ipv4Addr;
use std::process::Command;

/// Apply NTP configuration by restarting NTP service with new servers
pub async fn apply_ntp_config(ntp_servers: &[Ipv4Addr]) -> Result<(), Box<dyn std::error::Error>> {
    let mut servers = ntp_servers.to_vec();
    servers.truncate(3);

    let mut args = vec!["restart".to_string()];

    for ip in &servers {
        args.push("-p".to_string());
        args.push(ip.to_string());
    }

    if servers.is_empty() {
        args.push("-p".to_string());
        args.push("pool.ntp.org".to_string()); // server of last resort
    }

    let output = Command::new("/etc/init.d/ntp").args(&args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("restarting ntp failed: {}", stderr).into());
    }

    info!("📝 Applied {} NTP servers and restarted NTP service", servers.len());
    Ok(())
}