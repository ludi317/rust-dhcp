//! ARP operations using raw sockets

use eui48::MacAddress;
use log::{debug, info, warn};
use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;
#[cfg(target_os = "linux")]
use libc::c_int;

// Protocol constants
const BROADCAST_ADDR: [u8; 6] = [0xFF; 6];
const ETH_P_ARP: u16 = 0x0806;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_HLEN_ETHERNET: u8 = 6;
const ARP_PLEN_IPV4: u8 = 4;
const ARP_OP_REQUEST: u16 = 1;

// Packet size constants
const ETHERNET_HEADER_SIZE: usize = 14;
const ARP_HEADER_SIZE: usize = 28;
const MIN_ARP_PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + ARP_HEADER_SIZE; // 42 bytes

// ARP Probe RFC 5227 constants
const PROBE_NUM: usize = 3; // Send 3 probe packets
const PROBE_MIN_WAIT_MS: u64 = 1000; // Wait 1 second between probes
const PROBE_MAX_WAIT_MS: u64 = 2000; // Wait up to 2 seconds between probes
const ANNOUNCE_WAIT_MS: u64 = 2000; // Delay 2 seconds before announcing
const ANNOUNCE_INTERVAL_SECS: u64 = 2; // Time between Announcement packets

// Buffer size constants
const RECV_BUFFER_SIZE: usize = 1024;

fn mac_to_bytes(mac: MacAddress) -> [u8; 6] {
    let bytes = mac.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
}

/// ARP probe result
#[derive(Debug, PartialEq)]
pub enum ArpProbeResult {
    /// IP address is available (no ARP response received)
    Available,
    /// IP address is already in use (ARP response received)
    InUse,
    /// Probe failed due to error
    Error(String),
}

/// ARP packet structure
#[repr(C, packed)]
struct ArpPacket {
    // Ethernet header
    eth_dst: [u8; 6], // Destination MAC (broadcast)
    eth_src: [u8; 6], // Source MAC (our MAC)
    eth_type: u16,    // 0x0806 for ARP

    // ARP header
    hw_type: u16,    // Hardware type (1 for Ethernet)
    proto_type: u16, // Protocol type (0x0800 for IPv4)
    hw_len: u8,      // Hardware length (6 for MAC)
    proto_len: u8,   // Protocol length (4 for IPv4)
    opcode: u16,     // Operation (1 for request, 2 for reply)

    // ARP data
    sender_hw: [u8; 6], // Sender hardware address (our MAC)
    sender_ip: [u8; 4], // Sender IP address (0.0.0.0 for probe)
    target_hw: [u8; 6], // Target hardware address (all zeros)
    target_ip: [u8; 4], // Target IP address (IP we're probing)
}

impl ArpPacket {
    fn new_probe(our_mac: MacAddress, target_ip: Ipv4Addr) -> Self {
        let our_mac_bytes = mac_to_bytes(our_mac);
        let target_ip_bytes = target_ip.octets();

        ArpPacket {
            // Ethernet header
            eth_dst: BROADCAST_ADDR,
            eth_src: our_mac_bytes,
            eth_type: ETH_P_ARP.to_be(),

            // ARP header
            hw_type: ARP_HTYPE_ETHERNET.to_be(),
            proto_type: ARP_PTYPE_IPV4.to_be(),
            hw_len: ARP_HLEN_ETHERNET,
            proto_len: ARP_PLEN_IPV4,
            opcode: ARP_OP_REQUEST.to_be(),

            // ARP data
            sender_hw: our_mac_bytes,
            sender_ip: [0, 0, 0, 0], // 0.0.0.0
            target_hw: [0, 0, 0, 0, 0, 0],
            target_ip: target_ip_bytes,
        }
    }

    fn new_announcement(our_mac: MacAddress, our_ip: Ipv4Addr) -> Self {
        let our_mac_bytes = mac_to_bytes(our_mac);
        let our_ip_bytes = our_ip.octets();

        ArpPacket {
            // Ethernet header
            eth_dst: BROADCAST_ADDR,
            eth_src: our_mac_bytes,
            eth_type: ETH_P_ARP.to_be(),

            // ARP header
            hw_type: ARP_HTYPE_ETHERNET.to_be(),
            proto_type: ARP_PTYPE_IPV4.to_be(),
            hw_len: ARP_HLEN_ETHERNET,
            proto_len: ARP_PLEN_IPV4,
            opcode: ARP_OP_REQUEST.to_be(), // RFC 5227 Section 3 says to use REQUEST

            // ARP data - gratuitous ARP announcement
            sender_hw: our_mac_bytes,
            sender_ip: our_ip_bytes, // Our IP
            target_hw: our_mac_bytes,
            target_ip: our_ip_bytes,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const ArpPacket as *const u8, std::mem::size_of::<ArpPacket>()) }
    }

    #[cfg(target_os = "linux")]
    fn send(&self, interface_idx: u32) -> Result<c_int, Box<dyn Error>> {
        // Create raw socket
        let sock_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ARP.to_be()) };
        if sock_fd < 0 {
            return Err("Failed to create raw socket".into());
        }

        // Bind socket to interface
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
        addr.sll_ifindex = interface_idx as i32;

        let bind_result = unsafe {
            libc::bind(
                sock_fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };

        if bind_result < 0 {
            unsafe {
                libc::close(sock_fd);
            }
            return Err("Failed to bind socket to interface".into());
        }
        let packet_bytes = self.as_bytes();
        // Send ARP probe
        let sent = unsafe { libc::send(sock_fd, packet_bytes.as_ptr() as *const libc::c_void, packet_bytes.len(), 0) };

        if sent < 0 {
            unsafe {
                libc::close(sock_fd);
            }
            return Err("Failed to send ARP probe".into());
        }
        Ok(sock_fd)
    }

    #[cfg(not(target_os = "linux"))]
    fn send(&self, interface_idx: u32) -> Result<c_int, Box<dyn Error>> {
        Err("Raw packet sending not implemented for this platform".into())
    }
}

/// Perform ARP probe using raw sockets to check if IP address is already in use
///
/// Implements RFC 5227 Address Conflict Detection (ACD)
pub async fn arp_probe(interface_idx: u32, target_ip: Ipv4Addr, our_mac: MacAddress) -> ArpProbeResult {
    use rand::Rng;

    info!("🔍 Sending ARP probes for {} on interface index {}", target_ip, interface_idx);

    // Create ARP probe packet
    let arp_packet = ArpPacket::new_probe(our_mac, target_ip);

    let mut rng = rand::thread_rng();
    // time to wait listening for a response after sending each packet
    let timeouts = [
        rng.gen_range(PROBE_MIN_WAIT_MS..=PROBE_MAX_WAIT_MS),
        rng.gen_range(PROBE_MIN_WAIT_MS..=PROBE_MAX_WAIT_MS),
        ANNOUNCE_WAIT_MS,
    ];

    for probe_num in 1..=PROBE_NUM {
        debug!("📡 Sending ARP probe {}/{} for {}", probe_num, PROBE_NUM, target_ip);

        match send_arp_and_listen(interface_idx, &arp_packet, target_ip, timeouts[probe_num.saturating_sub(1)]).await {
            Ok(conflict_detected) => {
                if conflict_detected {
                    warn!("❌ ARP probe {}/{} detected {} is already in use", probe_num, PROBE_NUM, target_ip);
                    return ArpProbeResult::InUse;
                } else {
                    debug!("✅ ARP probe {}/{} - no response for {}", probe_num, PROBE_NUM, target_ip);
                }
            }
            Err(e) => {
                warn!("⚠️ ARP probe {}/{} failed: {}", probe_num, PROBE_NUM, e);
                return ArpProbeResult::Error(e.to_string());
            }
        }
    }

    debug!("✅ All {} ARP probes completed - address {} is available", PROBE_NUM, target_ip);
    ArpProbeResult::Available
}

/// Send gratuitous ARP to announce our new IP address
///
/// RFC 5227: The host may begin legitimately using the IP address immediately
/// after sending the first of the two ARP Announcements; the sending of the
/// second ARP Announcement may be completed asynchronously.
pub async fn announce_address(interface_idx: u32, our_ip: Ipv4Addr, our_mac: MacAddress) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "📢 Broadcasting gratuitous ARP to announce {} on interface index {}",
        our_ip, interface_idx
    );

    // Create gratuitous ARP packet
    let arp_packet = ArpPacket::new_announcement(our_mac, our_ip);

    // Send first ARP announcement immediately
    debug!("📢 Sending first ARP announcement for {}", our_ip);
    arp_packet.send(interface_idx)?;

    // Send second announcement asynchronously
    let second_announcement_task = async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS)).await;
        debug!("📢 Sending second ARP announcement for {}", our_ip);
        if let Err(e) = arp_packet.send(interface_idx) {
            warn!("⚠️  Failed to send second ARP announcement: {}", e);
        } else {
            debug!("✅ Second ARP announcement sent for {}", our_ip);
        }
    };

    tokio::spawn(second_announcement_task);

    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_arp_and_listen(
    interface_idx: u32, arp_packet: &ArpPacket, target_ip: Ipv4Addr, timeout_ms: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Send ARP packet
    let sock_fd = match arp_packet.send(interface_idx) {
        Ok(value) => value,
        Err(value) => return Err(value),
    };

    debug!("Sent ARP probe, waiting for responses...");

    // Listen for ARP replies with timeout
    let timeout_result = timeout(
        Duration::from_millis(timeout_ms),
        listen_for_arp_reply(sock_fd, target_ip, arp_packet.sender_hw),
    )
    .await;

    unsafe {
        libc::close(sock_fd);
    }

    match timeout_result {
        Ok(result) => result,
        Err(_) => {
            debug!("ARP probe timeout - assuming address is available");
            Ok(false) // Timeout means no reply, address available
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn send_arp_and_listen(
    _interface_idx: u32, _arp_packet: &ArpPacket, _target_ip: Ipv4Addr, _timeout_ms: u64,
) -> Result<bool, Box<dyn std::error::Error>> {
    // For non-Linux platforms, we could implement using different raw socket APIs
    // For now, return error to indicate this needs platform-specific implementation
    Err("Raw socket ARP probe not implemented for this platform".into())
}

#[cfg(target_os = "linux")]
async fn listen_for_arp_reply(sock_fd: i32, target_ip: Ipv4Addr, our_mac: [u8; 6]) -> Result<bool, Box<dyn std::error::Error>> {
    let target_ip_bytes = target_ip.octets();
    let mut buffer = [0u8; RECV_BUFFER_SIZE];

    // Set socket to non-blocking for async operation
    let flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err("Failed to get socket flags".into());
    }

    if unsafe { libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("Failed to set socket non-blocking".into());
    }

    loop {
        let received = unsafe { libc::recv(sock_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0) };

        if received < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                // No data available, yield and try again
                tokio::task::yield_now().await;
                continue;
            } else {
                return Err(format!("Failed to receive from socket: errno {}", errno).into());
            }
        }

        if received >= MIN_ARP_PACKET_SIZE as isize {
            // Minimum ARP packet size
            debug!("📦 Received packet ({} bytes)", received);

            // Check if it's an ARP packet by looking at ethertype
            if u16::from_be_bytes([buffer[12], buffer[13]]) == ETH_P_ARP {
                // ARP ethertype
                debug!("🎯 Found ARP packet!");

                // Parse ARP packet
                if let Some(arp_reply) = parse_arp_reply(&buffer[..received as usize]) {
                    debug!(
                        "📨 ARP Reply from {}.{}.{}.{} to {}.{}.{}.{}",
                        arp_reply.sender_ip[0],
                        arp_reply.sender_ip[1],
                        arp_reply.sender_ip[2],
                        arp_reply.sender_ip[3],
                        arp_reply.target_ip[0],
                        arp_reply.target_ip[1],
                        arp_reply.target_ip[2],
                        arp_reply.target_ip[3]
                    );

                    // Check if this is a reply for our target IP
                    if arp_reply.sender_ip == target_ip_bytes ||
                        // or if someone else is probing
                        (arp_reply.opcode == ARP_OP_REQUEST &&
                            arp_reply.target_ip == target_ip_bytes &&
                            arp_reply.sender_ip == [0u8;4] &&
                            arp_reply.target_hw == [0u8;6] &&
                            arp_reply.sender_hw != our_mac)
                    {
                        debug!("🎯 Address conflict detected");
                        return Ok(true); // Address is in use
                    }
                } else {
                    debug!("❌ Failed to parse ARP packet");
                }
            } else {
                debug!("⏭️ Non-ARP packet (ethertype: {:02x}{:02x})", buffer[12], buffer[13]);
            }
        }
    }
}

struct ArpReply {
    opcode: u16,
    sender_hw: [u8; 6],
    sender_ip: [u8; 4],
    target_hw: [u8; 6],
    target_ip: [u8; 4],
}

fn parse_arp_reply(data: &[u8]) -> Option<ArpReply> {
    if data.len() < MIN_ARP_PACKET_SIZE {
        return None;
    }

    // Skip Ethernet header and check ARP packet
    let arp_start = ETHERNET_HEADER_SIZE;
    if data.len() < arp_start + ARP_HEADER_SIZE {
        return None;
    }

    let arp_data = &data[arp_start..];

    // Check if it's an ARP packet
    let hw_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
    let proto_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
    let opcode = u16::from_be_bytes([arp_data[6], arp_data[7]]);

    if hw_type == ARP_HTYPE_ETHERNET && proto_type == ARP_PTYPE_IPV4 {
        let sender_hw = [arp_data[8], arp_data[9], arp_data[10], arp_data[11], arp_data[12], arp_data[13]];
        let sender_ip = [arp_data[14], arp_data[15], arp_data[16], arp_data[17]];
        let target_hw = [arp_data[18], arp_data[19], arp_data[20], arp_data[21], arp_data[22], arp_data[23]];
        let target_ip = [arp_data[24], arp_data[25], arp_data[26], arp_data[27]];
        Some(ArpReply {
            opcode,
            sender_hw,
            sender_ip,
            target_hw,
            target_ip,
        })
    } else {
        None
    }
}
