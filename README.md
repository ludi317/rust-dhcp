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
$ cargo run --bin client 11-22-33-44-55-66
[2025-08-31T22:58:12Z INFO  client] Starting DHCP client with MAC address: 00-11-22-33-44-55
[2025-08-31T22:58:12Z INFO  client] Using broadcast for server discovery
[2025-08-31T22:58:12Z INFO  client] 🚀 Starting DHCP client
[2025-08-31T22:58:12Z INFO  client] 📡 Initial state: INIT
[2025-08-31T22:58:12Z INFO  dhcp_client::client] Starting DHCP configuration process
[2025-08-31T22:58:12Z INFO  dhcp_client::client] Sent DHCP DISCOVER (attempt 1)
[2025-08-31T22:58:12Z INFO  dhcp_client::client] Received DHCP OFFER for 192.168.8.67
[2025-08-31T22:58:12Z INFO  dhcp_client::client] Sent DHCP REQUEST for 192.168.8.67 (attempt 1)
[2025-08-31T22:58:12Z INFO  dhcp_client::client] Received DHCP ACK
[2025-08-31T22:58:12Z INFO  dhcp_client::client] Lease established: IP=192.168.8.67, Server=192.168.10.1, Duration=7200s
[2025-08-31T22:58:12Z INFO  dhcp_client::client] DORA sequence completed in 219 ms
[2025-08-31T22:58:12Z INFO  client] ✅ DHCP Configuration obtained:
[2025-08-31T22:58:12Z INFO  client]    📍 Your IP: 192.168.8.67
[2025-08-31T22:58:12Z INFO  client]    🏠 Server IP: 192.168.10.1
[2025-08-31T22:58:12Z INFO  client]    🔍 Subnet: 255.255.252.0
[2025-08-31T22:58:12Z INFO  client]    🚪 Gateway: 192.168.10.1
[2025-08-31T22:58:12Z INFO  client]    🌐 DNS: 192.168.8.53
[2025-08-31T22:58:12Z INFO  client] 📋 Lease Information:
[2025-08-31T22:58:12Z INFO  client]    ⏰ Lease Duration: 7200s
[2025-08-31T22:58:12Z INFO  client]    ⏰ T1 (Renewal): 3600s
[2025-08-31T22:58:12Z INFO  client]    ⏰ T2 (Rebinding): 6300s
[2025-08-31T22:58:12Z INFO  client] 🔄 Current state: BOUND
[2025-08-31T22:58:12Z INFO  client] 🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)
```

## Running Examples
The examples only exchange messages with a server to obtain a lease. They do not configure a new IP address or apply any network settings.
```bash
$ cargo run --example short_demo
$ cargo run --example inform
```

## Acknowledgements
DHCP message [de]serialiation taken from https://github.com/lancastr/rust-dhcp