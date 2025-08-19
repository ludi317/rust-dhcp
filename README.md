# Rust DHCP Client

A Rust implementation of DHCP (Dynamic Host Configuration Protocol) client using async/await.
Based on https://github.com/lancastr/rust-dhcp and modernized with Claude Code.

TODO: Server

## Features

- ✅ **Complete RFC 2131 Compliance** - Full DHCP state machine with proper transitions
- ✅ **Automatic Lease Management** - T1/T2 timers, renewal, rebinding, and expiration handling
- ✅ **INIT-REBOOT Support** - Efficient IP reuse on client restart (RFC 2131 section 4.3.2)
- ✅ **IP Conflict Detection** - ARP/ICMP probing with DHCP DECLINE (RFC 2131 section 2.2)
- ✅ **RFC-Compliant Retry Logic** - Exponential backoff for initial requests, standards-compliant intervals for renewal/rebinding
- ✅ **Modern Async/Await API** - Clean, readable async operations using Tokio
- ✅ **Flexible API** - Simple high-level function or full client with lifecycle management
- ✅ **Cross-Platform** - Linux, macOS, Windows support
- ✅ **Zero-Copy Operations** - Efficient packet processing
- ✅ **Comprehensive Error Handling** - Structured error types with `thiserror`
- ✅ **Production Ready** - Graceful shutdown, proper resource cleanup

## Running Examples

### Prerequisites

DHCP clients need to bind to port 68, which typically requires root privileges:

```bash
# Full lifecycle client (production use)
sudo cargo run --example client
[2025-08-19T00:36:11Z INFO  client] 🚀 Starting RFC 2131 compliant DHCP client
[2025-08-19T00:36:11Z INFO  client] 📡 Initial state: INIT
[2025-08-19T00:36:11Z INFO  dhcp_client::client] Starting DHCP configuration process
[2025-08-19T00:36:11Z INFO  dhcp_client::client] Sent DHCP DISCOVER (attempt 1)
[2025-08-19T00:36:11Z INFO  dhcp_client::client] Received DHCP OFFER for 192.168.8.63
[2025-08-19T00:36:11Z INFO  dhcp_client::client] Sent DHCP REQUEST for 192.168.8.63 (attempt 1)
[2025-08-19T00:36:11Z INFO  dhcp_client::client] Received DHCP ACK
[2025-08-19T00:36:11Z INFO  dhcp_client::client] Checking for IP conflict: 192.168.8.63
[2025-08-19T00:36:13Z INFO  dhcp_client::client] Lease established: IP=192.168.8.63, Server=192.168.10.1, Duration=7200s
[2025-08-19T00:36:13Z INFO  client] ✅ DHCP Configuration obtained:
[2025-08-19T00:36:13Z INFO  client]    📍 Your IP: 192.168.8.63
[2025-08-19T00:36:13Z INFO  client]    🏠 Server IP: 0.0.0.0
[2025-08-19T00:36:13Z INFO  client]    🔍 Subnet: 255.255.252.0
[2025-08-19T00:36:13Z INFO  client]    🚪 Gateway: 192.168.10.1
[2025-08-19T00:36:13Z INFO  client]    🌐 DNS: 192.168.8.53
[2025-08-19T00:36:13Z INFO  client] 📋 Lease Information:
[2025-08-19T00:36:13Z INFO  client]    ⏰ Lease Duration: 7200s
[2025-08-19T00:36:13Z INFO  client]    🔄 T1 (Renewal): 3600s
[2025-08-19T00:36:13Z INFO  client]    🔄 T2 (Rebinding): 6300s
[2025-08-19T00:36:13Z INFO  client]    ⏳ Time until renewal: 3600s
[2025-08-19T00:36:13Z INFO  client]    ⏳ Time until rebinding: 6300s
[2025-08-19T00:36:13Z INFO  client]    ⏳ Time until expiry: 7200s
[2025-08-19T00:36:13Z INFO  client] 🔄 Current state: BOUND
[2025-08-19T00:36:13Z INFO  client] 🏃 Running DHCP client lifecycle (press Ctrl+C to exit gracefully)
^C[2025-08-19T00:36:21Z INFO  client] 🛑 Shutdown signal received
[2025-08-19T00:36:21Z INFO  client] 📤 Releasing DHCP lease...
[2025-08-19T00:36:21Z INFO  dhcp_client::client] Sent DHCP RELEASE to 192.168.10.1
[2025-08-19T00:36:21Z INFO  client] ✅ Lease released successfully
[2025-08-19T00:36:21Z INFO  client] 🔄 Final state: INIT

```

## Observing DHCP Traffic

The following shows a complete DHCP Discovery → Offer → Request → Acknowledge sequence captured by tcpdump:

```shell
$ tcpdump -i en0 -v -n port 67 or port 68
16:57:28.381089 IP (tos 0x0, ttl 64, id 63101, offset 0, flags [none], proto UDP (17), length 305)
    192.168.8.59.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 00:11:22:33:44:56, length 277, xid 0xc54a77f3, Flags [Broadcast]
	  Client-Ethernet-Address 00:11:22:33:44:56
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Discover
	    Parameter-Request (55), length 5: 
	      Subnet-Mask (1), Domain-Name-Server (6), Classless-Static-Route (121), Default-Gateway (3)
	      Static-Route (33)
	    Client-ID (61), length 6: "^Q"3DV"
	    Hostname (12), length 16: "rust-demo-client"
16:57:28.944115 IP (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto UDP (17), length 328)
    192.168.10.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300, xid 0xc54a77f3, Flags [Broadcast]
	  Your-IP 192.168.8.54
	  Client-Ethernet-Address 00:11:22:33:44:56
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Offer
	    Server-ID (54), length 4: 192.168.10.1
	    Lease-Time (51), length 4: 7200
	    Subnet-Mask (1), length 4: 255.255.252.0
	    Default-Gateway (3), length 4: 192.168.10.1
	    Domain-Name-Server (6), length 4: 192.168.8.53
16:57:28.976312 IP (tos 0x0, ttl 64, id 12308, offset 0, flags [none], proto UDP (17), length 317)
    192.168.8.59.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 00:11:22:33:44:56, length 289, xid 0xc54a77f3, Flags [Broadcast]
	  Client-Ethernet-Address 00:11:22:33:44:56
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Request
	    Server-ID (54), length 4: 192.168.10.1
	    Requested-IP (50), length 4: 192.168.8.54
	    Parameter-Request (55), length 5: 
	      Subnet-Mask (1), Domain-Name-Server (6), Classless-Static-Route (121), Default-Gateway (3)
	      Static-Route (33)
	    Client-ID (61), length 6: "^Q"3DV"
	    Hostname (12), length 16: "rust-demo-client"
16:57:29.047012 IP (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto UDP (17), length 328)
    192.168.10.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300, xid 0xc54a77f3, Flags [Broadcast]
	  Your-IP 192.168.8.54
	  Client-Ethernet-Address 00:11:22:33:44:56
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: ACK
	    Server-ID (54), length 4: 192.168.10.1
	    Lease-Time (51), length 4: 7200
	    Subnet-Mask (1), length 4: 255.255.252.0
	    Default-Gateway (3), length 4: 192.168.10.1
	    Domain-Name-Server (6), length 4: 192.168.8.53
16:58:01.069326 IP (tos 0x0, ttl 64, id 30087, offset 0, flags [none], proto UDP (17), length 330)
    192.168.8.59.68 > 192.168.10.1.67: BOOTP/DHCP, Request from 00:11:22:33:44:56, length 302, xid 0xc54a77f3, Flags [none]
	  Client-IP 192.168.8.54
	  Client-Ethernet-Address 00:11:22:33:44:56
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message (53), length 1: Release
	    Server-ID (54), length 4: 192.168.10.1
	    Client-ID (61), length 6: "^Q"3DV"
	    Hostname (12), length 16: "rust-demo-client"
	    MSG (56), length 24: "Client initiated release"
```