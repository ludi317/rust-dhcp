//! ARP operations using raw sockets

use eui48::MacAddress;
use log::{debug, info, warn};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

#[cfg(target_os = "linux")]
use futures::stream::TryStreamExt;
#[cfg(target_os = "linux")]
use rtnetlink::new_connection;
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
        let our_mac_bytes = our_mac.as_bytes();
        let target_ip_bytes = target_ip.octets();

        ArpPacket {
            // Ethernet header - broadcast
            eth_dst: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            eth_src: [
                our_mac_bytes[0],
                our_mac_bytes[1],
                our_mac_bytes[2],
                our_mac_bytes[3],
                our_mac_bytes[4],
                our_mac_bytes[5],
            ],
            eth_type: 0x0806_u16.to_be(),

            // ARP header
            hw_type: 1_u16.to_be(),         // Ethernet
            proto_type: 0x0800_u16.to_be(), // IPv4
            hw_len: 6,
            proto_len: 4,
            opcode: 1_u16.to_be(), // ARP request

            sender_hw: [
                our_mac_bytes[0],
                our_mac_bytes[1],
                our_mac_bytes[2],
                our_mac_bytes[3],
                our_mac_bytes[4],
                our_mac_bytes[5],
            ],
            sender_ip: [0, 0, 0, 0],       // 0.0.0.0 as per RFC 2131
            target_hw: [0, 0, 0, 0, 0, 0], // Unknown target MAC
            target_ip: target_ip_bytes,
        }
    }

    fn new_announcement(our_mac: MacAddress, our_ip: Ipv4Addr) -> Self {
        let our_mac_bytes = our_mac.as_bytes();
        let our_ip_bytes = our_ip.octets();

        ArpPacket {
            // Ethernet header - broadcast
            eth_dst: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            eth_src: [
                our_mac_bytes[0],
                our_mac_bytes[1],
                our_mac_bytes[2],
                our_mac_bytes[3],
                our_mac_bytes[4],
                our_mac_bytes[5],
            ],
            eth_type: 0x0806_u16.to_be(),

            // ARP header
            hw_type: 1_u16.to_be(),
            proto_type: 0x0800_u16.to_be(),
            hw_len: 6,
            proto_len: 4,
            opcode: 2_u16.to_be(), // ARP reply (gratuitous)

            // ARP data - gratuitous ARP announcement
            sender_hw: [
                our_mac_bytes[0],
                our_mac_bytes[1],
                our_mac_bytes[2],
                our_mac_bytes[3],
                our_mac_bytes[4],
                our_mac_bytes[5],
            ],
            sender_ip: our_ip_bytes,
            target_hw: [
                our_mac_bytes[0],
                our_mac_bytes[1],
                our_mac_bytes[2],
                our_mac_bytes[3],
                our_mac_bytes[4],
                our_mac_bytes[5],
            ], // Our own MAC for gratuitous ARP
            target_ip: our_ip_bytes, // Our own IP
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const ArpPacket as *const u8,
                std::mem::size_of::<ArpPacket>(),
            )
        }
    }
}

/// Perform ARP probe using raw sockets to check if IP address is already in use
///
/// According to RFC 2131: "The client may issue an ARP request for the suggested
/// request. When broadcasting an ARP request for the suggested address, the client
/// must fill in its own hardware address as the sender's hardware address, and 0
/// as the sender's IP address, to avoid confusing ARP caches in other hosts"
pub async fn arp_probe(interface_name: &str, target_ip: Ipv4Addr, our_mac: MacAddress) -> ArpProbeResult {
    info!("🔍 Performing raw ARP probe for {} on interface {}", target_ip, interface_name);

    // Create ARP probe packet
    let arp_packet = ArpPacket::new_probe(our_mac, target_ip);

    match send_arp_and_listen(interface_name, &arp_packet, target_ip).await {
        Ok(received_reply) => {
            if received_reply {
                warn!("ARP probe detected {} is already in use", target_ip);
                ArpProbeResult::InUse
            } else {
                debug!("ARP probe completed, address {} is available", target_ip);
                ArpProbeResult::Available
            }
        }
        Err(e) => {
            warn!("Failed to perform ARP probe: {}", e);
            ArpProbeResult::Error(e.to_string())
        }
    }
}

/// Send gratuitous ARP to announce our new IP address
///
/// According to RFC 2131: "The client SHOULD broadcast an ARP reply to announce
/// the client's new IP address and clear any outdated ARP cache entries in hosts
/// on the client's subnet."
pub async fn announce_address(interface_name: &str, our_ip: Ipv4Addr, our_mac: MacAddress) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "📢 Broadcasting gratuitous ARP to announce {} on interface {}",
        our_ip, interface_name
    );

    // Create gratuitous ARP packet
    let arp_packet = ArpPacket::new_announcement(our_mac, our_ip);

    // Send gratuitous ARP (no need to listen for replies)
    send_raw_packet(interface_name, &arp_packet).await?;

    info!(
        "✅ Successfully announced IP address {} via gratuitous ARP",
        our_ip
    );
    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_arp_and_listen(interface_name: &str, arp_packet: &ArpPacket, target_ip: Ipv4Addr) -> Result<bool, Box<dyn std::error::Error>> {
    use std::ffi::CString;

    // Create raw socket
    let sock_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        )
    };
    if sock_fd < 0 {
        return Err("Failed to create raw socket".into());
    }

    // Get interface index
    let if_name_c = CString::new(interface_name)?;
    let if_index = unsafe { libc::if_nametoindex(if_name_c.as_ptr()) };
    if if_index == 0 {
        unsafe {
            libc::close(sock_fd);
        }
        return Err(format!("Interface {} not found", interface_name).into());
    }

    // Bind socket to interface
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    addr.sll_ifindex = if_index as i32;

    let bind_result = unsafe {
        libc::bind(sock_fd, &addr as *const libc::sockaddr_ll as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32)
    };

    if bind_result < 0 {
        unsafe {
            libc::close(sock_fd);
        }
        return Err("Failed to bind socket to interface".into());
    }

    // Send ARP probe
    let packet_bytes = arp_packet.as_bytes();
    let sent = unsafe {
        libc::send(sock_fd, packet_bytes.as_ptr() as *const libc::c_void, packet_bytes.len(), 0)
    };

    if sent < 0 {
        unsafe {
            libc::close(sock_fd);
        }
        return Err("Failed to send ARP probe".into());
    }

    debug!("Sent ARP probe, waiting for responses...");

    // Listen for ARP replies with timeout
    let timeout_result = timeout(Duration::from_secs(2), listen_for_arp_reply(sock_fd, target_ip)).await;

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
    _interface_name: &str,
    _arp_packet: &ArpPacket,
    _target_ip: Ipv4Addr,
) -> Result<bool, Box<dyn std::error::Error>> {
    // For non-Linux platforms, we could implement using different raw socket APIs
    // For now, return error to indicate this needs platform-specific implementation
    Err("Raw socket ARP probe not implemented for this platform".into())
}

#[cfg(target_os = "linux")]
async fn listen_for_arp_reply(sock_fd: i32, target_ip: Ipv4Addr) -> Result<bool, Box<dyn std::error::Error>> {
    let target_ip_bytes = target_ip.octets();
    let mut buffer = [0u8; 1024];

    // Set socket to non-blocking for async operation
    let flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err("Failed to get socket flags".into());
    }

    if unsafe { libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("Failed to set socket non-blocking".into());
    }

    loop {
        let received = unsafe {libc::recv(sock_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0)};

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

        if received >= 42 {
            // Minimum ARP packet size (14 bytes Ethernet + 28 bytes ARP)
            debug!("📦 Received packet ({} bytes)", received);

            // Check if it's an ARP packet by looking at ethertype
            if buffer[12] == 0x08 && buffer[13] == 0x06 {
                // ARP ethertype
                debug!("🎯 Found ARP packet!");

                // Parse ARP packet
                if let Some(arp_reply) = parse_arp_reply(&buffer[..received as usize]) {
                    debug!(
                        "📨 ARP Reply from {}.{}.{}.{}",
                        arp_reply.sender_ip[0],
                        arp_reply.sender_ip[1],
                        arp_reply.sender_ip[2],
                        arp_reply.sender_ip[3]
                    );

                    // Check if this is a reply for our target IP
                    if arp_reply.sender_ip == target_ip_bytes && arp_reply.opcode == 2 {
                        debug!("🎯 This is a reply for our target IP {}!", target_ip);
                        return Ok(true); // Address is in use
                    }
                } else {
                    debug!("❌ Failed to parse ARP packet");
                }
            } else {
                debug!(
                    "⏭️ Non-ARP packet (ethertype: {:02x}{:02x})",
                    buffer[12], buffer[13]
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn send_raw_packet(interface_name: &str, arp_packet: &ArpPacket) -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::CString;

    // Create raw socket
    let sock_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        )
    };
    if sock_fd < 0 {
        return Err("Failed to create raw socket".into());
    }

    // Get interface index
    let if_name_c = CString::new(interface_name)?;
    let if_index = unsafe { libc::if_nametoindex(if_name_c.as_ptr()) };
    if if_index == 0 {
        unsafe {
            libc::close(sock_fd);
        }
        return Err(format!("Interface {} not found", interface_name).into());
    }

    // Set up destination address
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    addr.sll_ifindex = if_index as i32;
    addr.sll_halen = 6;
    addr.sll_addr[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // Broadcast

    // Send packet
    let packet_bytes = arp_packet.as_bytes();
    let sent = unsafe {
        libc::sendto(
            sock_fd,
            packet_bytes.as_ptr() as *const libc::c_void,
            packet_bytes.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };

    unsafe {
        libc::close(sock_fd);
    }

    if sent < 0 {
        return Err("Failed to send packet".into());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn send_raw_packet(
    _interface_name: &str,
    _arp_packet: &ArpPacket,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Raw packet sending not implemented for this platform".into())
}

struct ArpReply {
    sender_ip: [u8; 4],
    opcode: u16,
}

fn parse_arp_reply(data: &[u8]) -> Option<ArpReply> {
    if data.len() < 42 {
        // Minimum ARP packet size (14 bytes Ethernet + 28 bytes ARP)
        return None;
    }

    // Skip Ethernet header (14 bytes) and check ARP packet
    let arp_start = 14;
    if data.len() < arp_start + 28 {
        // ARP packet is 28 bytes
        return None;
    }

    let arp_data = &data[arp_start..];

    // Check if it's an ARP packet
    let hw_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
    let proto_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
    let opcode = u16::from_be_bytes([arp_data[6], arp_data[7]]);

    if hw_type == 1 && proto_type == 0x0800 {
        let sender_ip = [arp_data[14], arp_data[15], arp_data[16], arp_data[17]];
        Some(ArpReply { sender_ip, opcode })
    } else {
        None
    }
}

/// Get the MAC address for a given network interface
/// Get network interface MAC address
#[cfg(target_os = "linux")]
pub async fn get_interface_mac(interface_name: &str) -> Result<MacAddress, Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();

    if let Some(link) = links.try_next().await? {
        // Look for the hardware address attribute in the link attributes
        for attr in link.attributes.iter() {
            if let netlink_packet_route::link::LinkAttribute::Address(address) = attr {
                let mac_bytes: [u8; 6] = address
                    .clone()
                    .try_into()
                    .map_err(|_| "Invalid MAC address length")?;
                return Ok(MacAddress::new(mac_bytes));
            }
        }
        return Err(format!("No MAC address found for interface {}", interface_name).into());
    }

    Err(format!("Interface '{}' not found", interface_name).into())
}

#[cfg(not(target_os = "linux"))]
pub async fn get_interface_mac(
    _interface_name: &str,
) -> Result<MacAddress, Box<dyn std::error::Error>> {
    Err("get_interface_mac not implemented for this platform".into())
}
