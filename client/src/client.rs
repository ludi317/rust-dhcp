//! Async DHCP client implementation.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use eui48::MacAddress;
use tokio::time::timeout;
use log::{info, warn, debug};

use dhcp_protocol::{Message, MessageType, DHCP_PORT_SERVER};
use dhcp_framed::DhcpFramed;

use crate::builder::MessageBuilder;
use crate::Configuration;

/// Errors that can occur during DHCP client operations
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout waiting for response")]
    Timeout,
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Invalid server response")]
    InvalidResponse,
}

/// Async DHCP client
pub struct Client {
    socket: DhcpFramed,
    builder: MessageBuilder,
    server_address: Option<Ipv4Addr>,
    broadcast: bool,
    xid: u32,
}

impl Client {
    /// Create a new DHCP client
    pub async fn new(
        bind_addr: SocketAddr,
        client_hardware_address: MacAddress,
        client_id: Option<Vec<u8>>,
        hostname: Option<String>,
        server_address: Option<Ipv4Addr>,
        max_message_size: Option<u16>,
        broadcast: bool,
    ) -> Result<Self, ClientError> {
        let socket = DhcpFramed::bind(bind_addr).await?;
        
        let hostname = if hostname.is_none() {
            hostname::get().ok().and_then(|s| s.into_string().ok())
        } else {
            hostname
        };

        let client_id = client_id.unwrap_or(client_hardware_address.as_bytes().to_vec());

        let builder = MessageBuilder::new(
            client_hardware_address,
            client_id,
            hostname,
            max_message_size,
        );

        let xid = rand::random();

        Ok(Client {
            socket,
            builder,
            server_address,
            broadcast,
            xid,
        })
    }

    /// Perform DHCP discovery and obtain network configuration
    pub async fn discover(&mut self, 
        address_request: Option<Ipv4Addr>,
        address_time: Option<u32>
    ) -> Result<Configuration, ClientError> {
        // Step 1: Send DHCP DISCOVER
        let discover = self.builder.discover(
            self.xid,
            self.broadcast,
            address_request,
            address_time,
        );

        self.send_message(discover).await?;
        info!("Sent DHCP DISCOVER");

        // Step 2: Wait for DHCP OFFER
        let offer = self.wait_for_message_type(MessageType::DhcpOffer, Duration::from_secs(10)).await?;
        info!("Received DHCP OFFER from {}", offer.0);

        let offer_message = offer.1;
        let server_id = offer_message.options.dhcp_server_id
            .ok_or_else(|| ClientError::Protocol("OFFER missing server ID".to_string()))?;

        // Step 3: Send DHCP REQUEST
        let request = self.builder.request_selecting(
            self.xid,
            self.broadcast,
            offer_message.your_ip_address,
            address_time,
            server_id,
        );

        self.send_message(request).await?;
        info!("Sent DHCP REQUEST for {}", offer_message.your_ip_address);

        // Step 4: Wait for DHCP ACK
        let ack = self.wait_for_message_type(MessageType::DhcpAck, Duration::from_secs(10)).await?;
        info!("Received DHCP ACK from {}", ack.0);

        Ok(Configuration::from_response(ack.1))
    }

    /// Renew an existing lease
    pub async fn renew(&mut self, current_ip: Ipv4Addr, server_id: Ipv4Addr) -> Result<Configuration, ClientError> {
        let request = self.builder.request_renew(
            self.xid,
            false, // not broadcast for renewal
            current_ip,
            None, // address_time
        );

        // Send unicast to server for renewal
        let server_addr = SocketAddr::new(IpAddr::V4(server_id), DHCP_PORT_SERVER);
        self.send_message_to(request, server_addr).await?;
        info!("Sent DHCP REQUEST (renew) to {}", server_id);

        let response = self.wait_for_message_type(MessageType::DhcpAck, Duration::from_secs(5)).await?;
        info!("Received DHCP ACK (renew) from {}", response.0);

        Ok(Configuration::from_response(response.1))
    }

    /// Release the current lease
    pub async fn release(&mut self, current_ip: Ipv4Addr, server_id: Ipv4Addr, message: Option<String>) -> Result<(), ClientError> {
        let release = self.builder.release(
            self.xid,
            current_ip,
            server_id,
            message,
        );

        let server_addr = SocketAddr::new(IpAddr::V4(server_id), DHCP_PORT_SERVER);
        self.send_message_to(release, server_addr).await?;
        info!("Sent DHCP RELEASE to {}", server_id);

        Ok(())
    }

    /// Send a DHCP INFORM message
    pub async fn inform(&mut self, current_ip: Ipv4Addr) -> Result<Configuration, ClientError> {
        let inform = self.builder.inform(self.xid, self.broadcast, current_ip);

        self.send_message(inform).await?;
        info!("Sent DHCP INFORM");

        let response = self.wait_for_message_type(MessageType::DhcpAck, Duration::from_secs(5)).await?;
        info!("Received DHCP ACK (inform) from {}", response.0);

        Ok(Configuration::from_response(response.1))
    }

    /// Send a message using broadcast or unicast based on configuration
    async fn send_message(&mut self, message: Message) -> Result<(), ClientError> {
        let dest_addr = if let Some(server_ip) = self.server_address {
            SocketAddr::new(IpAddr::V4(server_ip), DHCP_PORT_SERVER)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DHCP_PORT_SERVER)
        };

        self.send_message_to(message, dest_addr).await
    }

    /// Send a message to a specific address
    async fn send_message_to(&mut self, message: Message, addr: SocketAddr) -> Result<(), ClientError> {
        let item = (addr, (message, None));
        self.socket.send_message(item).await?;
        Ok(())
    }

    /// Wait for a specific message type with timeout
    async fn wait_for_message_type(&mut self, expected_type: MessageType, timeout_duration: Duration) -> Result<(SocketAddr, Message), ClientError> {
        let result = timeout(timeout_duration, async {
            loop {
                if let Some(result) = self.socket.recv_message().await {
                    match result {
                        Ok((addr, message)) => {
                            // Validate the message
                            match message.validate() {
                                Ok(msg_type) => {
                                    // Check transaction ID
                                    if message.transaction_id != self.xid {
                                        warn!("Got response with wrong transaction ID: {} (expected {})", 
                                              message.transaction_id, self.xid);
                                        continue;
                                    }

                                    if msg_type == expected_type {
                                        return Ok((addr, message));
                                    } else {
                                        debug!("Got {} but expected {}", msg_type, expected_type);
                                        // For NAK, return it as an error
                                        if msg_type == MessageType::DhcpNak {
                                            return Err(ClientError::Protocol("Received DHCP NAK".to_string()));
                                        }
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    warn!("Invalid message from {}: {}", addr, e);
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Socket error: {}", e);
                            continue;
                        }
                    }
                } else {
                    // Stream ended
                    return Err(ClientError::Protocol("Socket stream ended".to_string()));
                }
            }
        }).await;

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ClientError::Timeout),
        }
    }
}

/// A simple high-level async DHCP client function
pub async fn get_dhcp_config(
    bind_addr: SocketAddr,
    client_mac: MacAddress,
    hostname: Option<String>,
) -> Result<Configuration, ClientError> {
    let mut client = Client::new(
        bind_addr,
        client_mac,
        None, // client_id
        hostname,
        None, // server_address (use broadcast)
        None, // max_message_size
        true, // broadcast
    ).await?;

    client.discover(None, None).await
}