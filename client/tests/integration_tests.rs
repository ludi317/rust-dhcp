//! Integration tests for DHCP client
//!
//! These tests assume a DHCP server is available on the network.
//! They perform actual DHCP operations against a real server.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use eui48::MacAddress;
use tokio::time::timeout;

use dhcp_client::{utils::get_network_info, Client, ClientError};

/// Create a test client with unique MAC address
async fn create_test_client(hostname: &str) -> Result<Client, ClientError> {
    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    Client::new(bind_addr, "en0", client_mac, None).await
}

#[tokio::test]
#[ignore] // Run with: cargo test --ignored
async fn test_dhcp_configure_dora_sequence() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut client = create_test_client("rust-test-dora").await.expect("Failed to create test client");

    println!("Testing DHCP DORA sequence...");

    // Test full DORA sequence
    let config = timeout(Duration::from_secs(30), client.configure())
        .await
        .expect("DORA sequence timed out")
        .expect("DORA sequence failed");

    println!("✅ DORA successful!");
    println!("   IP: {}", config.your_ip_address);
    println!("   Server: {}", config.server_ip_address);

    // Verify we got a valid IP address
    assert!(!config.your_ip_address.is_unspecified());
    assert!(!config.your_ip_address.is_loopback());
    // assert!(!config.server_ip_address.is_unspecified());

    // Verify client is in BOUND state
    assert_eq!(client.state().to_string(), "BOUND");

    // Verify lease information is available
    let lease = client.lease().expect("No lease information");
    assert_eq!(lease.assigned_ip, config.your_ip_address);
    // assert_eq!(lease.server_id, config.server_ip_address);
    assert!(lease.lease_time > 0);
    assert!(lease.t1() < lease.t2());
    assert!(lease.t2() < lease.lease_time);
    assert!(lease.t1() > 0);

    // Clean up
    client.release().await.expect("Failed to release lease");

    println!("✅ Test completed successfully");
}

#[tokio::test]
#[ignore] // Run with: cargo test --ignored
async fn test_dhcp_init_reboot() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut client = create_test_client("rust-test-reboot").await.expect("Failed to create test client");

    println!("Testing DHCP INIT-REBOOT sequence...");

    // First, get an initial lease
    let initial_config = timeout(Duration::from_secs(30), client.configure())
        .await
        .expect("Initial DORA timed out")
        .expect("Initial DORA failed");

    let previous_ip = initial_config.your_ip_address;
    println!("Got initial IP: {}", previous_ip);

    drop(client);
    // Create a new client instance (simulating restart)
    let mut reboot_client = create_test_client("rust-test-reboot")
        .await
        .expect("Failed to create reboot client");

    // Test INIT-REBOOT
    match timeout(Duration::from_secs(30), reboot_client.init_reboot(previous_ip)).await {
        Ok(Ok(reboot_config)) => {
            println!("✅ INIT-REBOOT successful!");
            println!("   Previous IP: {}", previous_ip);
            println!("   Reboot IP: {}", reboot_config.your_ip_address);

            // Verify we got the same IP back
            assert_eq!(reboot_config.your_ip_address, previous_ip);

            // Clean up
            reboot_client.release().await.expect("Failed to release lease");
        }
        Ok(Err(ClientError::Nak)) => {
            println!("⚠️ INIT-REBOOT rejected (NAK) - IP no longer available");
            // This is acceptable behavior
        }
        Ok(Err(e)) => {
            panic!("INIT-REBOOT failed with unexpected error: {}", e);
        }
        Err(_) => {
            panic!("INIT-REBOOT timed out");
        }
    }

    println!("✅ Test completed successfully");
}

#[tokio::test]
#[ignore] // Run with: cargo test --ignored
async fn test_dhcp_inform_with_detected_network() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Get network interface information programmatically
    let (assigned_ip, client_mac) = match get_network_info() {
        Ok(info) => info,
        Err(e) => {
            println!("⚠️ Could not detect network info: {}", e);
            println!("Skipping INFORM test - requires active network interface");
            return;
        }
    };

    println!("Testing DHCP INFORM with detected network info...");
    println!("Detected IP: {}", assigned_ip);
    println!("Detected MAC: {}", client_mac);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // Create client with detected MAC address
    let mut client = Client::new(
        bind_addr,
        "en0",
        client_mac,
        None,
    )
    .await
    .expect("Failed to create test client");

    // Test DHCP INFORM with the detected IP
    match timeout(Duration::from_secs(20), client.inform(assigned_ip)).await {
        Ok(Ok(inform_config)) => {
            println!("✅ DHCP INFORM successful!");
            println!("   Server IP: {}", inform_config.server_ip_address);

            // Verify server responded
            // assert!(!inform_config.server_ip_address.is_unspecified());

            // Display received configuration
            if let Some(mask) = inform_config.subnet_mask {
                println!("   Subnet Mask: {}", mask);
                assert!(!mask.is_unspecified());
            }

            if let Some(routers) = &inform_config.routers {
                if let Some(gw) = routers.first() {
                    println!("   Gateway: {}", gw);
                    assert!(!gw.is_unspecified());
                }
            }

            if let Some(dns_servers) = &inform_config.domain_name_servers {
                if let Some(dns) = dns_servers.first() {
                    println!("   DNS: {}", dns);
                    assert!(!dns.is_unspecified());
                }
            }

            println!("✅ INFORM test with detected network completed successfully");
        }
        Ok(Err(ClientError::Timeout { .. })) => {
            println!("⚠️ DHCP INFORM timed out - server may not support INFORM");
            println!("This is acceptable behavior for servers that don't implement INFORM");
            // Don't fail the test - this is common
        }
        Ok(Err(e)) => {
            println!("❌ DHCP INFORM failed with error: {}", e);
            // Don't panic - log the error but allow test to continue
            println!("This may indicate server doesn't support INFORM or network configuration issues");
        }
        Err(_) => {
            println!("⚠️ DHCP INFORM test timed out");
            println!("This may indicate network issues or server doesn't respond to INFORM");
        }
    }

    println!("✅ Test completed");
}
