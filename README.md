# Rust DHCP Server and Client

A Rust implementation of DHCP (Dynamic Host Configuration Protocol) server and client using async/await.
Based on https://github.com/lancastr/rust-dhcp and modernized with Claude Code.
## Features

- ✅ **Complete DHCP Protocol Support** - Full RFC 2131 compliance
- ✅ **Modern Async/Await API** - Clean, readable async operations  
- ✅ **Cross-Platform** - Linux, macOS, Windows support
- ✅ **Zero-Copy Operations** - Efficient packet processing
- ✅ **Comprehensive Error Handling** - Structured error types with `thiserror`

## Quick Start

### Modern Async Client

```rust
use dhcp_client::{get_dhcp_config, Client};
use eui48::MacAddress;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);
    
    // Simple high-level API
    let config = get_dhcp_config(bind_addr, client_mac, Some("my-client".to_string())).await?;
    
    println!("Obtained IP: {}", config.your_ip_address);
    println!("Gateway: {:?}", config.routers);
    println!("DNS: {:?}", config.domain_name_servers);
    
    Ok(())
}
```

### Advanced Usage

```rust
use dhcp_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new(
        bind_addr,
        client_mac,
        None, // client_id
        Some("rust-dhcp-client".to_string()),
        None, // server_address (broadcast)
        None, // max_message_size
        true, // use broadcast
    ).await?;

    // Full DHCP operations
    let config = client.discover(None, Some(7200)).await?; // Request 2-hour lease
    println!("Got lease: {}", config.your_ip_address);
    
    // Renew the lease
    let renewed = client.renew(config.your_ip_address, config.server_ip_address).await?;
    
    // Release when done
    client.release(config.your_ip_address, config.server_ip_address, None).await?;
    
    Ok(())
}
```

## Running Examples

### Prerequisites

DHCP clients need to bind to port 68, which typically requires root privileges:

```bash
# Run with elevated privileges
$ sudo cargo run --example client
[2025-08-18T03:46:15Z INFO  client] Starting modern DHCP client example
[2025-08-18T03:46:15Z INFO  dhcp_client::client] Sent DHCP DISCOVER
[2025-08-18T03:46:15Z INFO  dhcp_client::client] Received DHCP OFFER from 192.168.10.1:67
[2025-08-18T03:46:15Z INFO  dhcp_client::client] Sent DHCP REQUEST for 192.168.8.54
[2025-08-18T03:46:15Z INFO  dhcp_client::client] Received DHCP ACK from 192.168.10.1:67
DHCP Configuration obtained:
  Your IP: 192.168.8.54
  Server IP: 0.0.0.0
  Subnet Mask: 255.255.252.0
  Routers: [192.168.10.1]
  DNS Servers: [192.168.8.53]
```

## Observing DHCP Traffic

Monitor DHCP packet exchange with tcpdump:

```bash
# Capture DHCP packets
tcpdump -i en0 -v -n port 67 or port 68
```

### Example DHCP Transaction

The following shows a complete DHCP Discovery → Offer → Request → Acknowledge sequence captured by tcpdump:

```shell
$ tcpdump -i en0 -v -n port 67 or port 68
tcpdump: listening on en0, link-type EN10MB (Ethernet), snapshot length 524288 bytes
19:40:13.235170 IP (tos 0x0, ttl 64, id 26499, offset 0, flags [none], proto UDP (17), length 313)
    192.168.8.59.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 00:11:22:33:44:55, length 285, xid 0x53a2da3f, Flags [Broadcast]
	  Client-Ethernet-Address 00:11:22:33:44:55
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Discover
	    Lease-Time (51), length 4: 3600
	    Parameter-Request (55), length 5: 
	      Subnet-Mask (1), Domain-Name-Server (6), Classless-Static-Route (121), Default-Gateway (3)
	      Static-Route (33)
	    Client-ID (61), length 6: "^Q"3DU"
	    Hostname (12), length 18: "rust-dhcp-advanced"
19:40:13.303802 IP (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto UDP (17), length 328)
    192.168.10.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300, xid 0x53a2da3f, Flags [Broadcast]
	  Your-IP 192.168.8.54
	  Client-Ethernet-Address 00:11:22:33:44:55
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Offer
	    Server-ID (54), length 4: 192.168.10.1
	    Lease-Time (51), length 4: 3600
	    Subnet-Mask (1), length 4: 255.255.252.0
	    Default-Gateway (3), length 4: 192.168.10.1
	    Domain-Name-Server (6), length 4: 192.168.8.53
19:40:13.319404 IP (tos 0x0, ttl 64, id 56776, offset 0, flags [none], proto UDP (17), length 325)
    192.168.8.59.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 00:11:22:33:44:55, length 297, xid 0x53a2da3f, Flags [Broadcast]
	  Client-Ethernet-Address 00:11:22:33:44:55
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Request
	    Server-ID (54), length 4: 192.168.10.1
	    Requested-IP (50), length 4: 192.168.8.54
	    Lease-Time (51), length 4: 3600
	    Parameter-Request (55), length 5: 
	      Subnet-Mask (1), Domain-Name-Server (6), Classless-Static-Route (121), Default-Gateway (3)
	      Static-Route (33)
	    Client-ID (61), length 6: "^Q"3DU"
	    Hostname (12), length 18: "rust-dhcp-advanced"
19:40:13.407545 IP (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto UDP (17), length 328)
    192.168.10.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300, xid 0x53a2da3f, Flags [Broadcast]
	  Your-IP 192.168.8.54
	  Client-Ethernet-Address 00:11:22:33:44:55
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: ACK
	    Server-ID (54), length 4: 192.168.10.1
	    Lease-Time (51), length 4: 3600
	    Subnet-Mask (1), length 4: 255.255.252.0
	    Default-Gateway (3), length 4: 192.168.10.1
	    Domain-Name-Server (6), length 4: 192.168.8.53
```
