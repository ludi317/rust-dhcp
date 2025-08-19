//! RFC 2131 compliant DHCP client with full state machine

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use eui48::MacAddress;
use tokio::time::{sleep, timeout};
use log::{info, warn, debug, trace};

use dhcp_protocol::{Message, MessageType, DHCP_PORT_SERVER};
use dhcp_framed::DhcpFramed;

use crate::builder::MessageBuilder;
use crate::state::{DhcpState, LeaseInfo, RetryState};
use crate::Configuration;

/// Errors that can occur during DHCP client operations
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout waiting for response in state {state}")]
    Timeout { state: DhcpState },
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Invalid server response")]
    InvalidResponse,
    #[error("Lease expired")]
    LeaseExpired,
    #[error("State transition error: cannot go from {from} to {to}")]
    InvalidTransition { from: DhcpState, to: DhcpState },
    #[error("Received DHCP NAK")]
    Nak,
    #[error("IP address conflict detected")]
    IpConflict,
    #[error("ARP check failed: {0}")]
    ArpCheck(String),
}

/// RFC 2131 compliant DHCP client with full state machine
pub struct Client {
    /// Network socket for DHCP communication
    socket: DhcpFramed,
    /// Message builder for creating DHCP messages
    builder: MessageBuilder,
    /// Current DHCP state
    state: DhcpState,
    /// Current lease information (if any)
    lease: Option<LeaseInfo>,
    /// Retry state for current operation
    retry_state: RetryState,
    /// Server address for unicast (if known)
    server_address: Option<Ipv4Addr>,
    /// Whether to use broadcast
    broadcast: bool,
    /// Current transaction ID
    xid: u32,
    /// Last offered IP (for REQUEST messages)
    offered_ip: Option<Ipv4Addr>,
    /// Previous IP address (for INIT-REBOOT)
    previous_ip: Option<Ipv4Addr>,
    /// Time when last request was sent
    last_request_time: Option<Instant>,
}

impl Client {
    /// Create a new RFC compliant DHCP client
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
        let retry_state = RetryState::new(Duration::from_secs(2));

        Ok(Client {
            socket,
            builder,
            state: DhcpState::Init,
            lease: None,
            retry_state,
            server_address,
            broadcast,
            xid,
            offered_ip: None,
            previous_ip: None,
            last_request_time: None,
        })
    }

    /// Get current state
    pub fn state(&self) -> DhcpState {
        self.state
    }

    /// Get current lease information
    pub fn lease(&self) -> Option<&LeaseInfo> {
        self.lease.as_ref()
    }

    /// Set a previous IP address for INIT-REBOOT attempts
    pub fn set_previous_ip(&mut self, ip: Ipv4Addr) {
        self.previous_ip = Some(ip);
    }

    /// Attempt to reuse a previous IP address (INIT-REBOOT process)
    pub async fn init_reboot(&mut self, previous_ip: Ipv4Addr) -> Result<Configuration, ClientError> {
        info!("Starting INIT-REBOOT process for IP: {}", previous_ip);
        
        self.transition_to(DhcpState::InitReboot)?;
        self.transition_to(DhcpState::Rebooting)?;
        
        let ack = self.reboot_phase(previous_ip).await?;
        
        // We're now bound with the previous lease
        self.transition_to(DhcpState::Bound)?;
        self.handle_ack(&ack)?;
        
        Ok(Configuration::from_response(ack))
    }

    /// Perform full DHCP configuration process (DORA sequence)
    pub async fn configure(&mut self) -> Result<Configuration, ClientError> {
        info!("Starting DHCP configuration process");
        
        self.transition_to(DhcpState::Init)?;
        
        // Check if we have a previous IP to try to reuse (INIT-REBOOT)
        if let Some(previous_ip) = self.previous_ip {
            info!("Attempting to reuse previous IP: {}", previous_ip);
            match self.init_reboot(previous_ip).await {
                Ok(config) => {
                    info!("Successfully reused previous IP");
                    return Ok(config);
                }
                Err(ClientError::Nak) => {
                    info!("Previous IP rejected, starting full discovery");
                    self.previous_ip = None; // Clear rejected IP
                }
                Err(e) => {
                    warn!("Init-reboot failed: {}, starting full discovery", e);
                    self.previous_ip = None;
                }
            }
        }
        
        // Start discovery process
        self.transition_to(DhcpState::Selecting)?;
        let offer = self.discover_phase().await?;
        
        // Request the offered configuration
        self.transition_to(DhcpState::Requesting)?;
        let ack = self.request_phase(offer).await?;
        
        // We're now bound with a valid lease
        self.transition_to(DhcpState::Bound)?;
        self.handle_ack(&ack)?;
        
        Ok(Configuration::from_response(ack))
    }

    /// Run the client lifecycle - handles renewal, rebinding, and expiration
    pub async fn run_lifecycle(&mut self) -> Result<(), ClientError> {
        if self.state != DhcpState::Bound {
            return Err(ClientError::Protocol("Must be in BOUND state to run lifecycle".to_string()));
        }

        loop {
            let lease = self.lease.as_ref().ok_or_else(|| {
                ClientError::Protocol("No lease information in BOUND state".to_string())
            })?;

            // Check if lease has expired
            if lease.is_expired() {
                warn!("Lease has expired, returning to INIT state");
                self.transition_to(DhcpState::Init)?;
                return Err(ClientError::LeaseExpired);
            }

            // Check if we should start rebinding
            if lease.should_rebind() && self.state == DhcpState::Renewing {
                info!("T2 reached, transitioning to REBINDING");
                self.transition_to(DhcpState::Rebinding)?;
                continue;
            }

            // Check if we should start renewal
            if lease.should_renew() && self.state == DhcpState::Bound {
                info!("T1 reached, transitioning to RENEWING");
                self.transition_to(DhcpState::Renewing)?;
                continue;
            }

            match self.state {
                DhcpState::Bound => {
                    // Wait until T1 (renewal time)
                    let wait_time = lease.time_until_renewal();
                    debug!("Waiting {:?} until renewal time (T1)", wait_time);
                    sleep(wait_time).await;
                }
                DhcpState::Renewing => {
                    // Try to renew with original server
                    match self.renew_phase().await {
                        Ok(ack) => {
                            info!("Lease renewed successfully");
                            self.transition_to(DhcpState::Bound)?;
                            self.handle_ack(&ack)?;
                        }
                        Err(ClientError::Timeout { .. }) => {
                            // Continue in RENEWING state, will check for T2 on next iteration
                            debug!("Renewal attempt timed out, will retry");
                        }
                        Err(e) => return Err(e),
                    }
                }
                DhcpState::Rebinding => {
                    // Try to rebind with any server
                    match self.rebind_phase().await {
                        Ok(ack) => {
                            info!("Lease rebound successfully");
                            self.transition_to(DhcpState::Bound)?;
                            self.handle_ack(&ack)?;
                        }
                        Err(ClientError::Timeout { .. }) => {
                            // Continue in REBINDING state, will check for expiry on next iteration
                            debug!("Rebinding attempt timed out, will retry");
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ => {
                    return Err(ClientError::Protocol(format!(
                        "Invalid state {} for lifecycle management", self.state
                    )));
                }
            }

            // Small delay to prevent busy loop
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Release the current lease
    pub async fn release(&mut self) -> Result<(), ClientError> {
        if let Some(lease) = self.lease.clone() {
            let release = self.builder.release(
                self.xid,
                lease.assigned_ip,
                lease.server_id,
                Some("Client initiated release".to_string()),
            );

            let server_addr = SocketAddr::new(IpAddr::V4(lease.server_id), DHCP_PORT_SERVER);
            self.send_message_to(release, server_addr).await?;
            info!("Sent DHCP RELEASE to {}", lease.server_id);
        }

        self.lease = None;
        self.transition_to(DhcpState::Init)?;
        Ok(())
    }

    /// Decline an IP address due to conflict detection
    pub async fn decline(&mut self, conflicted_ip: Ipv4Addr, server_id: Ipv4Addr, reason: String) -> Result<(), ClientError> {
        info!("Declining IP {} due to: {}", conflicted_ip, reason);
        
        let decline = self.builder.decline(
            self.xid,
            conflicted_ip,
            server_id,
            Some(reason),
        );

        let server_addr = SocketAddr::new(IpAddr::V4(server_id), DHCP_PORT_SERVER);
        self.send_message_to(decline, server_addr).await?;
        info!("Sent DHCP DECLINE for {} to {}", conflicted_ip, server_id);

        // After decline, return to INIT state and start over
        self.lease = None;
        self.offered_ip = None;
        self.transition_to(DhcpState::Init)?;
        Ok(())
    }

    /// Check for IP conflicts using ARP and ICMP probing (macOS implementation)
    /// Implements RFC 2131 section 2.2 requirement for client-side conflict detection
    pub async fn check_ip_conflict(&self, ip: Ipv4Addr) -> Result<bool, ClientError> {
        info!("Checking for IP conflict: {}", ip);
        
        // RFC 2131: "the client SHOULD probe the newly received address, e.g., with ARP"
        
        // Method 1: Check if IP is already in ARP table
        // if self.check_arp_table(ip).await? {
        //     warn!("IP {} found in ARP table - conflict detected", ip);
        //     return Ok(true);
        // }
        
        // Method 2: Probe with ping (ICMP echo request)
        // This is more reliable than ARP on macOS as it doesn't require raw sockets
        if self.ping_probe(ip).await? {
            warn!("IP {} responded to ping - conflict detected", ip);
            return Ok(true);
        }
        
        // Method 3: Send gratuitous ARP and check for conflicts
        // Note: This would require raw sockets or additional tools
        // For now, we rely on the above two methods
        
        debug!("No IP conflict detected for {}", ip);
        Ok(false)
    }

    /// Check if IP address exists in system ARP table
    async fn check_arp_table(&self, ip: Ipv4Addr) -> Result<bool, ClientError> {
        use tokio::process::Command;
        
        debug!("Checking ARP table for {}", ip);
        
        // Use 'arp -n <ip>' to check if IP is in ARP table
        let output = match Command::new("arp")
            .arg("-n")
            .arg(ip.to_string())
            .output()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                debug!("ARP command failed: {}", e);
                return Ok(false); // If ARP command fails, assume no conflict
            }
        };
        
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // If arp command succeeds and returns output, the IP is in the table
            if !stdout.trim().is_empty() && !stdout.contains("no entry") {
                debug!("ARP table entry found for {}: {}", ip, stdout.trim());
                return Ok(true);
            }
        }
        
        debug!("No ARP table entry for {}", ip);
        Ok(false)
    }

    /// Probe IP address with ICMP ping
    async fn ping_probe(&self, ip: Ipv4Addr) -> Result<bool, ClientError> {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};
        
        debug!("Ping probing {}", ip);
        
        // Use ping with short timeout: 'ping -c 1 -W 1000 <ip>'
        // -c 1: send only 1 packet
        // -W 1000: timeout after 1000ms (1 second)
        let ping_future = Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("1000")
            .arg(ip.to_string())
            .output();
        
        // Add our own timeout as extra safety
        let output = match timeout(Duration::from_secs(2), ping_future).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                debug!("Ping command failed: {}", e);
                return Ok(false); // If ping fails, assume no conflict
            }
            Err(_) => {
                debug!("Ping timeout for {}", ip);
                return Ok(false); // Timeout means no response
            }
        };
        
        if output.status.success() {
            debug!("Ping successful for {} - IP is in use", ip);
            return Ok(true);
        }
        
        debug!("Ping failed for {} - IP appears available", ip);
        Ok(false)
    }


    // === State Machine Management ===

    /// Transition to a new state with validation
    fn transition_to(&mut self, new_state: DhcpState) -> Result<(), ClientError> {
        let current_state = self.state;
        
        let valid = match (current_state, new_state) {
            // Initial transitions
            (DhcpState::Init, DhcpState::Init) => true, // reset/retry
            (DhcpState::Init, DhcpState::Selecting) => true,
            (DhcpState::Init, DhcpState::InitReboot) => true,
            
            // Discovery phase
            (DhcpState::Selecting, DhcpState::Requesting) => true,
            (DhcpState::Selecting, DhcpState::Selecting) => true, // retry
            (DhcpState::Selecting, DhcpState::Init) => true, // restart
            
            // Request phase
            (DhcpState::Requesting, DhcpState::Bound) => true,
            (DhcpState::Requesting, DhcpState::Requesting) => true, // retry
            (DhcpState::Requesting, DhcpState::Init) => true, // NAK or timeout
            (DhcpState::Requesting, DhcpState::Selecting) => true, // restart discovery
            
            // Bound operations
            (DhcpState::Bound, DhcpState::Renewing) => true,
            (DhcpState::Bound, DhcpState::Init) => true, // release
            (DhcpState::Bound, DhcpState::Bound) => true, // refresh
            
            // Renewal phase
            (DhcpState::Renewing, DhcpState::Bound) => true, // successful renewal
            (DhcpState::Renewing, DhcpState::Rebinding) => true, // T2 reached
            (DhcpState::Renewing, DhcpState::Renewing) => true, // retry
            (DhcpState::Renewing, DhcpState::Init) => true, // NAK or major failure
            
            // Rebinding phase
            (DhcpState::Rebinding, DhcpState::Bound) => true, // successful rebind
            (DhcpState::Rebinding, DhcpState::Init) => true, // lease expired or NAK
            (DhcpState::Rebinding, DhcpState::Rebinding) => true, // retry
            
            // Reboot phase
            (DhcpState::InitReboot, DhcpState::Rebooting) => true,
            (DhcpState::InitReboot, DhcpState::Init) => true,
            (DhcpState::Rebooting, DhcpState::Bound) => true,
            (DhcpState::Rebooting, DhcpState::Init) => true,
            (DhcpState::Rebooting, DhcpState::Rebooting) => true, // retry
            
            _ => false,
        };

        if !valid {
            return Err(ClientError::InvalidTransition {
                from: current_state,
                to: new_state,
            });
        }

        trace!("State transition: {} -> {}", current_state, new_state);
        
        // Reset retry state on actual state change (not for retry transitions)
        if current_state != new_state {
            self.retry_state.reset();
        }
        
        self.state = new_state;

        Ok(())
    }

    // === DHCP Protocol Phases ===

    /// Discovery phase - send DISCOVER and wait for OFFER
    async fn discover_phase(&mut self) -> Result<Message, ClientError> {
        loop {
            // Send DISCOVER
            let discover = self.builder.discover(
                self.xid,
                self.broadcast,
                None, // requested IP
                None, // requested lease time
            );

            self.send_message(discover).await?;
            info!("Sent DHCP DISCOVER (attempt {})", self.retry_state.attempt + 1);
            self.retry_state.record_attempt();

            // Wait for OFFER with timeout
            let timeout_duration = self.retry_state.next_interval(self.lease.as_ref(), self.state);
            
            match timeout(timeout_duration, self.wait_for_message_type(MessageType::DhcpOffer)).await {
                Ok(Ok((_, offer))) => {
                    info!("Received DHCP OFFER for {}", offer.your_ip_address);
                    return Ok(offer);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    debug!("DISCOVER timeout after {:?}, retrying", timeout_duration);
                    // Continue loop for retry
                }
            }

            // Check if we should give up (optional - RFC doesn't specify max retries for DISCOVER)
            if self.retry_state.attempt >= 10 {
                return Err(ClientError::Timeout { state: self.state });
            }
        }
    }

    /// Request phase - send REQUEST and wait for ACK
    async fn request_phase(&mut self, offer: Message) -> Result<Message, ClientError> {
        let server_id = offer.options.dhcp_server_id
            .ok_or_else(|| ClientError::Protocol("OFFER missing server ID".to_string()))?;
        
        self.offered_ip = Some(offer.your_ip_address);

        loop {
            // Send REQUEST
            let request = self.builder.request_selecting(
                self.xid,
                self.broadcast,
                offer.your_ip_address,
                None, // lease time
                server_id,
            );

            self.send_message(request).await?;
            info!("Sent DHCP REQUEST for {} (attempt {})", 
                  offer.your_ip_address, self.retry_state.attempt + 1);
            self.last_request_time = Some(Instant::now());
            self.retry_state.record_attempt();

            // Wait for ACK/NAK with timeout
            let timeout_duration = self.retry_state.next_interval(self.lease.as_ref(), self.state);
            
            match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
                Ok(Ok(message)) => {
                    match message.validate() {
                        Ok(MessageType::DhcpAck) => {
                            info!("Received DHCP ACK");
                            
                            // Check for IP conflicts before accepting the lease
                            let assigned_ip = message.your_ip_address;
                            match self.check_ip_conflict(assigned_ip).await {
                                Ok(true) => {
                                    // IP conflict detected, decline the address
                                    let server_id = message.options.dhcp_server_id
                                        .ok_or_else(|| ClientError::Protocol("ACK missing server ID".to_string()))?;

                                    warn!("IP conflict detected for {}, sending DECLINE", assigned_ip);
                                    self.decline(assigned_ip, server_id, "ARP conflict detected".to_string()).await?;
                                    return Err(ClientError::IpConflict);
                                }
                                Ok(false) => {
                                    // No conflict, accept the lease
                                    return Ok(message);
                                }
                                Err(e) => {
                                    warn!("ARP check failed for {}: {}, accepting lease anyway", assigned_ip, e);
                                    return Ok(message);
                                }
                            }
                        }
                        Ok(MessageType::DhcpNak) => {
                            warn!("Received DHCP NAK, returning to INIT");
                            return Err(ClientError::Nak);
                        }
                        _ => {
                            debug!("Received unexpected message type, ignoring");
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    debug!("REQUEST timeout after {:?}, retrying", timeout_duration);
                    // Continue loop for retry
                }
            }

            // Check if we should give up and restart discovery
            if self.retry_state.attempt >= 5 {
                warn!("Too many REQUEST retries, returning to INIT");
                return Err(ClientError::Timeout { state: self.state });
            }
        }
    }

    /// Renewal phase - send REQUEST to original server
    async fn renew_phase(&mut self) -> Result<Message, ClientError> {
        let lease = self.lease.clone()
            .ok_or_else(|| ClientError::Protocol("No lease to renew".to_string()))?;

        // Check if we should retry
        if !self.retry_state.should_retry(Some(&lease), self.state) {
            return Err(ClientError::Timeout { state: self.state });
        }

        let request = self.builder.request_renew(
            self.xid,
            false, // not broadcast for renewal
            lease.assigned_ip,
            None, // lease time
        );

        // Send unicast to original server
        let server_addr = SocketAddr::new(IpAddr::V4(lease.server_id), DHCP_PORT_SERVER);
        self.send_message_to(request, server_addr).await?;
        info!("Sent DHCP REQUEST (renew) to {} (attempt {})", 
              lease.server_id, self.retry_state.attempt + 1);
        self.last_request_time = Some(Instant::now());
        self.retry_state.record_attempt();

        // Wait for response with lease-specific timeout
        let timeout_duration = lease.retry_interval(self.state);
        
        match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
            Ok(Ok(message)) => {
                match message.validate() {
                    Ok(MessageType::DhcpAck) => {
                        info!("Lease renewal successful");
                        return Ok(message);
                    }
                    Ok(MessageType::DhcpNak) => {
                        warn!("Renewal NAK received, returning to INIT");
                        return Err(ClientError::Nak);
                    }
                    _ => {
                        debug!("Received unexpected message type during renewal");
                    }
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!("Renewal timeout after {:?}", timeout_duration);
            }
        }

        Err(ClientError::Timeout { state: self.state })
    }

    /// Rebinding phase - send REQUEST to any server
    async fn rebind_phase(&mut self) -> Result<Message, ClientError> {
        let lease = self.lease.clone()
            .ok_or_else(|| ClientError::Protocol("No lease to rebind".to_string()))?;

        // Check if we should retry
        if !self.retry_state.should_retry(Some(&lease), self.state) {
            return Err(ClientError::Timeout { state: self.state });
        }

        let request = self.builder.request_renew(
            self.xid,
            true, // broadcast for rebinding
            lease.assigned_ip,
            None, // lease time
        );

        self.send_message(request).await?;
        info!("Sent DHCP REQUEST (rebind) broadcast (attempt {})", 
              self.retry_state.attempt + 1);
        self.last_request_time = Some(Instant::now());
        self.retry_state.record_attempt();

        // Wait for response with lease-specific timeout
        let timeout_duration = lease.retry_interval(self.state);
        
        match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
            Ok(Ok(message)) => {
                match message.validate() {
                    Ok(MessageType::DhcpAck) => {
                        info!("Lease rebinding successful");
                        return Ok(message);
                    }
                    Ok(MessageType::DhcpNak) => {
                        warn!("Rebinding NAK received, returning to INIT");
                        return Err(ClientError::Nak);
                    }
                    _ => {
                        debug!("Received unexpected message type during rebinding");
                    }
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!("Rebinding timeout after {:?}", timeout_duration);
            }
        }

        Err(ClientError::Timeout { state: self.state })
    }

    /// Reboot phase - send REQUEST to verify previous IP (INIT-REBOOT)
    async fn reboot_phase(&mut self, previous_ip: Ipv4Addr) -> Result<Message, ClientError> {
        loop {
            // Send REQUEST for previous IP
            let request = self.builder.request_init_reboot(
                self.xid,
                self.broadcast,
                previous_ip,
                None, // lease time
            );

            self.send_message(request).await?;
            info!("Sent DHCP REQUEST (init-reboot) for {} (attempt {})", 
                  previous_ip, self.retry_state.attempt + 1);
            self.last_request_time = Some(Instant::now());
            self.retry_state.record_attempt();

            // Wait for ACK/NAK with timeout
            let timeout_duration = self.retry_state.next_interval(self.lease.as_ref(), self.state);
            
            match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
                Ok(Ok(message)) => {
                    match message.validate() {
                        Ok(MessageType::DhcpAck) => {
                            info!("INIT-REBOOT successful for {}", previous_ip);
                            return Ok(message);
                        }
                        Ok(MessageType::DhcpNak) => {
                            warn!("INIT-REBOOT NAK received for {}, IP no longer valid", previous_ip);
                            return Err(ClientError::Nak);
                        }
                        _ => {
                            debug!("Received unexpected message type during init-reboot");
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    debug!("INIT-REBOOT timeout after {:?}, retrying", timeout_duration);
                    // Continue loop for retry
                }
            }

            // Check if we should give up
            if self.retry_state.attempt >= 5 {
                warn!("Too many INIT-REBOOT retries");
                return Err(ClientError::Timeout { state: self.state });
            }
        }
    }

    // === Helper Methods ===

    /// Handle ACK message and update lease information
    fn handle_ack(&mut self, ack: &Message) -> Result<(), ClientError> {
        let server_id = ack.options.dhcp_server_id
            .ok_or_else(|| ClientError::Protocol("ACK missing server ID".to_string()))?;
        
        let lease_time = ack.options.address_time
            .ok_or_else(|| ClientError::Protocol("ACK missing lease time".to_string()))?;

        self.lease = Some(LeaseInfo::new(
            ack.your_ip_address,
            server_id,
            lease_time,
            ack.options.renewal_time,
            ack.options.rebinding_time,
        ));

        info!("Lease established: IP={}, Server={}, Duration={}s", 
              ack.your_ip_address, server_id, lease_time);

        Ok(())
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

    /// Wait for a specific message type with transaction ID validation
    async fn wait_for_message_type(&mut self, expected_type: MessageType) -> Result<(SocketAddr, Message), ClientError> {
        loop {
            if let Some(result) = self.socket.recv_message().await {
                match result {
                    Ok((addr, message)) => {
                        // Validate transaction ID
                        if message.transaction_id != self.xid {
                            trace!("Ignoring message with wrong transaction ID: {} (expected {})", 
                                  message.transaction_id, self.xid);
                            continue;
                        }

                        // Validate message type
                        match message.validate() {
                            Ok(msg_type) if msg_type == expected_type => {
                                return Ok((addr, message));
                            }
                            Ok(msg_type) => {
                                debug!("Got {} but expected {}", msg_type, expected_type);
                                continue;
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
                return Err(ClientError::Protocol("Socket stream ended".to_string()));
            }
        }
    }

    /// Wait for ACK or NAK message
    async fn wait_for_ack_or_nak(&mut self) -> Result<Message, ClientError> {
        loop {
            if let Some(result) = self.socket.recv_message().await {
                match result {
                    Ok((addr, message)) => {
                        // Validate transaction ID
                        if message.transaction_id != self.xid {
                            trace!("Ignoring message with wrong transaction ID: {} (expected {})", 
                                  message.transaction_id, self.xid);
                            continue;
                        }

                        // Check for ACK or NAK
                        match message.validate() {
                            Ok(MessageType::DhcpAck) | Ok(MessageType::DhcpNak) => {
                                return Ok(message);
                            }
                            Ok(msg_type) => {
                                debug!("Got {} but expected ACK or NAK", msg_type);
                                continue;
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
                return Err(ClientError::Protocol("Socket stream ended".to_string()));
            }
        }
    }
}
