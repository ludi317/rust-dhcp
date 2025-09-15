# Rust DHCP Client

A Rust implementation of DHCP (Dynamic Host Configuration Protocol) client.
DHCP message exchanges with a DHCP server is supported on Linux and MacOS. 
Application of network configuration is only supported on Linux.

## Features

- ✅ **DHCP client state machine** (RFC 2131)
- ✅ **Address Conflict Detection**  ARP probes and announcements (RFC 5227)  
- ✅ **Lease Management** - T1/T2 timers, renewal, rebinding, and expiration handling
- ✅ **Lease Application** - Applies network configuration returned by DHCP server, including adding IP, routes, DNS, NTP

## Running Client Executable
```bash
[2025-09-15T23:19:40Z INFO  client] Created netlink handle: interface=eth0, index=4, mac=12-ec-db-4d-b2-9a
[2025-09-15T23:19:40Z INFO  client] 🚀 Starting DHCP client
[2025-09-15T23:19:40Z INFO  dhcp_client::client] Starting DHCP configuration process
[2025-09-15T23:19:40Z INFO  dhcp_client::client] Sent DHCP DISCOVER (attempt 1)
[2025-09-15T23:19:40Z INFO  dhcp_client::client] Received DHCP OFFER for 192.168.65.3
[2025-09-15T23:19:40Z INFO  dhcp_client::client] Sent DHCP REQUEST for 192.168.65.3 (attempt 1)
[2025-09-15T23:19:40Z INFO  dhcp_client::client] DORA sequence completed in 1 ms
[2025-09-15T23:19:40Z INFO  dhcp_client::client] ✅ DHCP Lease received:
[2025-09-15T23:19:40Z INFO  dhcp_client::client]    📍 Your IP: 192.168.65.3/24
[2025-09-15T23:19:40Z INFO  dhcp_client::client]    🚪 Gateway: 192.168.65.1
[2025-09-15T23:19:40Z INFO  dhcp_client::client]    ⏰ Lease Duration: 3600s
[2025-09-15T23:19:40Z INFO  dhcp_client::client]    🌐 DNS servers: [192.168.65.1]
[2025-09-15T23:19:40Z INFO  arp] 🔍 Sending ARP probes for 192.168.65.3
[2025-09-15T23:19:40Z INFO  dhcp_client::client] ✅ ARP probe successful - IP address 192.168.65.3 is available
[2025-09-15T23:19:40Z INFO  arp] 📢 Broadcasting gratuitous ARP to announce 192.168.65.3
[2025-09-15T23:19:40Z INFO  dhcp_client::client] 🔧 Assigning IP address 192.168.65.3/24 to interface eth0
[2025-09-15T23:19:40Z INFO  dhcp_client::client] ✋ IP address already assigned to interface
[2025-09-15T23:19:40Z INFO  dhcp_client::client] ✅ Successfully added 192.168.65.1 as default gateway
[2025-09-15T23:19:40Z INFO  dhcp_client::dns] 📝 Updated /etc/resolv.conf with 1 DNS servers
[2025-09-15T23:19:40Z INFO  dhcp_client::client] ✅ Successfully applied DNS configuration
[2025-09-15T23:19:40Z INFO  client] ✅ DHCP Lease applied
[2025-09-15T23:19:40Z INFO  client] 🔄 Current state: BOUND
[2025-09-15T23:19:40Z INFO  client] 🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)
[2025-09-15T23:19:40Z INFO  dhcp_client::client] Waiting 1800s until renewal time (T1)
[2025-09-15T23:49:40Z INFO  dhcp_client::client] T1 reached, transitioning to RENEWING
[2025-09-15T23:49:40Z INFO  dhcp_client::client] Attempting lease renewal
[2025-09-15T23:49:40Z INFO  dhcp_client::client] Sent DHCP REQUEST (renew) to 192.168.65.1 (attempt 1)
[2025-09-15T23:49:40Z WARN  dhcp_client::client] Ignoring message with wrong transaction ID: 295636790 (expected 2945469755)
[2025-09-15T23:49:40Z WARN  dhcp_client::client] Ignoring message with wrong transaction ID: 295636790 (expected 2945469755)
[2025-09-15T23:49:40Z INFO  dhcp_client::client] 🤝 No change in lease parameters
[2025-09-15T23:49:40Z INFO  dhcp_client::client] Lease renewed successfully
[2025-09-15T23:49:40Z INFO  dhcp_client::client] Waiting 1800s until renewal time (T1)
```

## Running Examples
The examples only exchange messages with a server to obtain a lease. They do not configure a new IP address or apply any network settings.
```bash
$ cargo run --example short_demo
$ cargo run --example inform
```

## Acknowledgements
DHCP message [de]serialization taken from https://github.com/lancastr/rust-dhcp