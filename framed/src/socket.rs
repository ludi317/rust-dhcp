//! The main DHCP socket module.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use tokio::{io, net::UdpSocket};

use dhcp_protocol::*;

/// Must be enough to decode all the options.
pub const BUFFER_READ_CAPACITY: usize = 8192;
/// Must be enough to encode all the options.
pub const BUFFER_WRITE_CAPACITY: usize = 8192;

/// The modified version of the `tokio::UdpFramed`.
///
/// Works with high level DHCP messages.
pub struct DhcpFramed {
    /// `tokio::UdpSocket`.
    socket: UdpSocket,
    /// Stores received data and is used for deserialization.
    buf_read: Vec<u8>,
    /// Stores pending data and is used for serialization.
    buf_write: Vec<u8>,
    /// Stores the destination address and the number of bytes to send.
    pending: Option<(SocketAddr, usize)>,
}

pub type DhcpStreamItem = (SocketAddr, Message);
pub type DhcpSinkItem = (SocketAddr, (Message, Option<u16>));

impl DhcpFramed {
    /// Creates a new DhcpFramed from a UdpSocket.
    ///
    /// # Errors
    /// `io::Error` on unsuccessful socket operations.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        Ok(DhcpFramed {
            socket,
            buf_read: vec![0u8; BUFFER_READ_CAPACITY],
            buf_write: vec![0u8; BUFFER_WRITE_CAPACITY],
            pending: None,
        })
    }

    /// Convenience method to create and bind a socket.
    pub async fn bind(interface_name: &str) -> io::Result<Self> {
        use socket2::{Socket, Domain, Type, Protocol};
        
        // Create socket with socket2 for more control
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        
        // Set the same socket options as isc-dhcp and udhcpc:
        // isc-dhcp: https://github.com/isc-projects/dhcp/blob/master/common/socket.c
        // udhcpc:   https://coral.googlesource.com/busybox/+/refs/tags/1_16_1/networking/udhcp/socket.c

        socket.set_reuse_address(true)?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;

        // Bind to address
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DHCP_PORT_CLIENT);
        socket.bind(&addr.into())?;
        
        // Convert to std socket then to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)?;

        // Bind to specific interface
        #[cfg(target_os = "linux")]
        tokio_socket.bind_device(Some(interface_name.as_bytes()))?;
        
        Self::new(tokio_socket)
    }
}

impl Stream for DhcpFramed {
    type Item = Result<DhcpStreamItem, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buf = tokio::io::ReadBuf::new(&mut this.buf_read);

        match this.socket.poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(addr)) => {
                let amount = buf.filled().len();
                match Message::from_bytes(&buf.filled()[..amount]) {
                    Ok(frame) => Poll::Ready(Some(Ok((addr, frame)))),
                    Err(_) => {
                        // Invalid message, continue to next one
                        // Return None to indicate no valid message this time
                        Poll::Ready(None)
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<DhcpSinkItem> for DhcpFramed {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.pending.is_some() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: DhcpSinkItem) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Sink not ready for sending - call poll_ready first",
            ));
        }

        let (addr, (message, max_size)) = item;
        let amount = message.to_bytes(&mut this.buf_write, max_size)?;
        this.pending = Some((addr, amount));

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.pending.take() {
            None => Poll::Ready(Ok(())),
            Some((addr, amount)) => {
                match this.socket.poll_send_to(cx, &this.buf_write[..amount], addr) {
                    Poll::Ready(Ok(sent)) => {
                        if sent != amount {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "Failed to write entire datagram to socket",
                            )))
                        } else {
                            Poll::Ready(Ok(()))
                        }
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // Put the pending item back
                        this.pending = Some((addr, amount));
                        Poll::Pending
                    }
                }
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

// Convenience async methods
impl DhcpFramed {
    /// Async method to send a DHCP message
    pub async fn send_message(&mut self, item: DhcpSinkItem) -> Result<(), io::Error> {
        use futures::SinkExt;
        SinkExt::send(self, item).await
    }

    /// Async method to receive a DHCP message
    pub async fn recv_message(&mut self) -> Option<Result<DhcpStreamItem, io::Error>> {
        use futures::StreamExt;
        StreamExt::next(self).await
    }
}
