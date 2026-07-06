//! IPv6 multicast UDP socket for DHCPv6 client.
//!
//! Binds `[::]:546`, joins `ff02::1:2` on the target interface, sends to
//! `ff02::1:2:547`. Link-local hop limits only.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// DHCPv6 client port (RFC 8415 §7.2).
pub const DHCPV6_CLIENT_PORT: u16 = 546;
/// DHCPv6 server/relay port.
pub const DHCPV6_SERVER_PORT: u16 = 547;
/// ff02::1:2 — All_DHCP_Relay_Agents_and_Servers.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

pub struct DhcpV6Framed {
    socket: UdpSocket,
    interface_idx: u32,
}

impl DhcpV6Framed {
    /// Bind a new client-side DHCPv6 socket on the given interface.
    pub async fn bind(interface_name: &str, interface_idx: u32) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.set_multicast_loop_v6(false)?;
        socket.set_multicast_hops_v6(1)?;
        socket.set_unicast_hops_v6(1)?;
        socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, interface_idx)?;

        let bind_addr: SocketAddr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DHCPV6_CLIENT_PORT, 0, 0).into();
        socket.bind(&bind_addr.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)?;

        #[cfg(target_os = "linux")]
        tokio_socket.bind_device(Some(interface_name.as_bytes()))?;
        #[cfg(not(target_os = "linux"))]
        let _ = interface_name;

        Ok(Self {
            socket: tokio_socket,
            interface_idx,
        })
    }

    /// Send `bytes` to the All_DHCP_Relay_Agents_and_Servers multicast address.
    pub async fn send_multicast(&self, bytes: &[u8]) -> io::Result<usize> {
        let dst = SocketAddrV6::new(
            ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
            DHCPV6_SERVER_PORT,
            0,
            self.interface_idx,
        );
        self.socket.send_to(bytes, SocketAddr::V6(dst)).await
    }

    /// Send `bytes` unicast to `dst`. Used for RENEW.
    pub async fn send_unicast(&self, bytes: &[u8], dst: Ipv6Addr) -> io::Result<usize> {
        let dst = SocketAddrV6::new(dst, DHCPV6_SERVER_PORT, 0, self.interface_idx);
        self.socket.send_to(bytes, SocketAddr::V6(dst)).await
    }

    /// Recv a single datagram with a wall-clock timeout.
    pub async fn recv_with_timeout(
        &self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> io::Result<Option<(usize, SocketAddr)>> {
        match tokio::time::timeout(timeout, self.socket.recv_from(buf)).await {
            Ok(Ok((n, addr))) => Ok(Some((n, addr))),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }
}
