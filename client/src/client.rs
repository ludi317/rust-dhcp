use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use arp::{announce_address, arp_probe, ArpProbeResult};
use dhcp_framed::DhcpFramed;
use dhcp_protocol::{Message, MessageType, DHCP_PORT_SERVER};
use eui48::MacAddress;
use log::{debug, error, info, trace, warn};
use tokio::time::{sleep, timeout};

use crate::builder::MessageBuilder;
use crate::dns::{apply_dns_config, restore_dns_config};
use crate::netlink::NetlinkHandle;
use crate::ntp::apply_ntp_config;
use crate::state::{DhcpState, LeaseInfo, RetryState};

#[cfg(target_os = "linux")]
use {libc::EEXIST, rtnetlink};

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
    #[error("IP address conflict detected for {assigned_ip} from server {server_id}")]
    IpConflict { assigned_ip: Ipv4Addr, server_id: Ipv4Addr },
    #[error("Lease is invalid")]
    InvalidLease,
    #[error("Failed to add ip address to interface")]
    FailedToAddIP,
}

pub struct Client {
    /// Network socket for DHCP communication
    socket: DhcpFramed,
    /// Message builder for creating DHCP messages
    builder: MessageBuilder,
    /// Current DHCP state
    state: DhcpState,
    /// Current lease information (if any)
    pub lease: Option<LeaseInfo>,
    /// Retry state for current operation
    retry_state: RetryState,
    /// Current transaction ID
    xid: u32,
    /// Last offered IP (for REQUEST messages)
    offered_ip: Option<Ipv4Addr>,
    /// Whether the IP address already existed when we tried to assign it
    ip_already_existed: bool,
}

impl Client {
    pub async fn new(interface_name: &str, client_hardware_address: MacAddress) -> Result<Self, ClientError> {
        let socket = DhcpFramed::bind(interface_name).await?;

        let hostname = hostname::get().ok().and_then(|s| s.into_string().ok());
        let builder = MessageBuilder::new(client_hardware_address, hostname);

        let xid = rand::random();
        let retry_state = RetryState::new();

        Ok(Client {
            socket,
            builder,
            state: DhcpState::Init,
            lease: None,
            retry_state,
            xid,
            offered_ip: None,
            ip_already_existed: false,
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

    /// Perform full DHCP configuration process (DORA sequence)
    pub async fn configure(&mut self, netlink_handle: &NetlinkHandle) -> Result<(), ClientError> {
        info!("Starting DHCP configuration process");
        let dora_start = Instant::now();

        self.transition_to(DhcpState::Init)?;

        // Start discovery process
        self.transition_to(DhcpState::Selecting)?;
        let offer = self.discover_phase().await?;

        // Request the offered configuration
        self.transition_to(DhcpState::Requesting)?;
        let ack = self.request_phase(offer).await?;

        let dora_duration = dora_start.elapsed().as_millis();
        info!("DORA sequence completed in {:?} ms", dora_duration);

        // We're now bound with a valid lease
        self.handle_ack(&ack, netlink_handle).await?;
        self.transition_to(DhcpState::Bound)?;

        Ok(())
    }

    /// Run the client lifecycle - handles renewal, rebinding, and expiration
    pub async fn run_lifecycle(&mut self, netlink_handle: &NetlinkHandle) -> Result<(), ClientError> {
        if self.state != DhcpState::Bound {
            return Err(ClientError::Protocol("Must be in BOUND state to run lifecycle".to_string()));
        }

        // Check for infinite lease - no renewal needed
        if let Some(lease) = &self.lease {
            if lease.is_infinite() {
                info!("Lease is infinite - no renewal required, exiting lifecycle");
                return Ok(());
            }
        }

        loop {
            let lease = self
                .lease
                .as_ref()
                .ok_or_else(|| ClientError::Protocol("No lease information in BOUND state".to_string()))?;

            // Check if lease has expired
            if lease.is_expired() {
                warn!("Lease has expired");
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
                DhcpState::Renewing | DhcpState::Rebinding => {
                    let result = match self.state {
                        DhcpState::Renewing => {
                            info!("Attempting lease renewal");
                            self.renew_phase().await
                        }
                        DhcpState::Rebinding => {
                            info!("Attempting lease rebinding");
                            self.rebind_phase().await
                        }
                        _ => unreachable!(),
                    };

                    match result {
                        Ok(ack) => match self.handle_ack(&ack, netlink_handle).await {
                            Ok(()) => {
                                let action = if self.state == DhcpState::Renewing { "renewed" } else { "rebound" };
                                info!("Lease {} successfully", action);
                                self.transition_to(DhcpState::Bound)?;
                            }
                            Err(e @ ClientError::InvalidLease) | Err(e @ ClientError::IpConflict{..}) => {
                                return Err(e)
                            }
                            Err(e) => {
                                warn!("Applying lease failed, will retry: {:?}", e);
                            }
                        },
                        Err(ClientError::Nak) => {
                            return Err(ClientError::Nak)
                        }
                        Err(e) => {
                            let phase = if self.state == DhcpState::Renewing { "Renewing" } else { "Rebinding" };
                            warn!("{} failed, will retry: {:?}", phase, e);
                        }
                    }
                }
                _ => {
                    return Err(ClientError::Protocol(format!(
                        "Invalid state {} for lifecycle management",
                        self.state
                    )));
                }
            }
        }
    }

    /// Release the current lease. Make sure to call undo_lease() after calling this.
    pub async fn release(&mut self, reason: String) -> Result<(), ClientError> {
        if let Some(lease) = self.lease.clone() {
            let release = self.builder.release(self.xid, lease.assigned_ip, lease.server_id, Some(reason));

            self.send_unicast(release, lease.server_id).await?;
            info!("Sent DHCP RELEASE to {}", lease.server_id);
        }

        Ok(())
    }

    /// Decline an IP address due to conflict detection
    pub async fn decline(&mut self, conflicted_ip: Ipv4Addr, server_id: Ipv4Addr, reason: String) -> Result<(), ClientError> {
        info!("Declining IP {} due to: {}", conflicted_ip, reason);

        let decline = self.builder.decline(self.xid, conflicted_ip, server_id, Some(reason));

        self.send_broadcast(decline).await?;
        info!("Sent DHCP DECLINE for {}", conflicted_ip);

        Ok(())
    }

    /// Send DHCP INFORM message to get additional configuration
    pub async fn inform(&mut self, client_ip: Ipv4Addr) -> Result<(), ClientError> {
        info!("Sending DHCP INFORM for IP: {}", client_ip);

        let inform = self.builder.inform(self.xid, client_ip);

        self.send_broadcast(inform).await?;
        info!("Sent DHCP INFORM");

        // Wait for ACK response
        let timeout_duration = Duration::from_secs(10);

        match timeout(timeout_duration, self.wait_for_message_type(MessageType::DhcpAck)).await {
            Ok(Ok((_, ack))) => {
                info!("Received DHCP ACK for INFORM");
                info!("✅ DHCP Configuration received:");
                if let Some(subnet_mask) = ack.options.subnet_mask {
                    info!("   📍 Subnet Mask: {}", subnet_mask);
                }
                if let Some(ref routers) = ack.options.routers {
                    if let Some(gateway) = routers.first() {
                        info!("   🚪 Gateway: {}", gateway);
                    }
                }
                if let Some(ref dns_servers) = ack.options.domain_name_servers {
                    info!("   🌐 DNS servers: {:?}", dns_servers);
                }

                if let Some(ref ntp_servers) = ack.options.ntp_servers {
                    info!("   🕰  NTP servers: {:?}", ntp_servers);
                }
                Ok(())
            }
            Ok(Err(e)) => {
                warn!("DHCP INFORM failed: {}", e);
                Err(e)
            }
            Err(_) => {
                warn!("INFORM timeout after {:?}", timeout_duration);
                Err(ClientError::Timeout { state: self.state })
            }
        }
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
            (DhcpState::Selecting, DhcpState::Init) => true,      // restart

            // Request phase
            (DhcpState::Requesting, DhcpState::Bound) => true,
            (DhcpState::Requesting, DhcpState::Requesting) => true, // retry
            (DhcpState::Requesting, DhcpState::Init) => true,       // NAK or timeout
            (DhcpState::Requesting, DhcpState::Selecting) => true,  // restart discovery

            // Bound operations
            (DhcpState::Bound, DhcpState::Renewing) => true,
            (DhcpState::Bound, DhcpState::Init) => true,  // release
            (DhcpState::Bound, DhcpState::Bound) => true, // refresh

            // Renewal phase
            (DhcpState::Renewing, DhcpState::Bound) => true,     // successful renewal
            (DhcpState::Renewing, DhcpState::Rebinding) => true, // T2 reached
            (DhcpState::Renewing, DhcpState::Renewing) => true,  // retry
            (DhcpState::Renewing, DhcpState::Init) => true,      // NAK or major failure

            // Rebinding phase
            (DhcpState::Rebinding, DhcpState::Bound) => true,     // successful rebind
            (DhcpState::Rebinding, DhcpState::Init) => true,      // lease expired or NAK
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
            let discover = self.builder.discover(self.xid, None, None);

            self.send_broadcast(discover).await?;
            self.retry_state.record_attempt();
            info!("Sent DHCP DISCOVER (attempt {})", self.retry_state.attempt);

            // Wait for OFFER with timeout
            let timeout_duration = self.retry_state.next_interval();

            match timeout(timeout_duration, self.wait_for_message_type(MessageType::DhcpOffer)).await {
                Ok(Ok((_, offer))) => {
                    info!("Received DHCP OFFER for {}", offer.your_ip_address);
                    return Ok(offer);
                }
                Ok(Err(e)) => {
                    debug!("DHCP OFFER failed, retrying: {}", e);
                }
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
        self.offered_ip = Some(offer.your_ip_address);

        loop {
            // Send REQUEST
            let request = self.builder.request_selecting(
                self.xid,
                offer.your_ip_address,
                None, // lease time
                offer.options.dhcp_server_id.unwrap(),
            );

            self.send_broadcast(request).await?;
            self.retry_state.record_attempt();

            info!(
                "Sent DHCP REQUEST for {} (attempt {})",
                offer.your_ip_address, self.retry_state.attempt
            );

            // Wait for ACK/NAK with timeout
            let timeout_duration = self.retry_state.next_interval();

            match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
                Ok(Ok(message)) => {
                    if message.options.dhcp_message_type == Some(MessageType::DhcpAck) {
                        info!("Received DHCP ACK");
                        return Ok(message);
                    } else {
                        warn!("Received DHCP NAK");
                        return Err(ClientError::Nak);
                    }
                },
                Ok(Err(e)) => {
                    debug!("REQUEST failed, retrying: {}", e);
                }
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
        let lease = self
            .lease
            .clone()
            .ok_or_else(|| ClientError::Protocol("No lease to renew".to_string()))?;

        let request = self.builder.request_renew(self.xid, lease.assigned_ip, None);

        // Send unicast to original server
        self.send_unicast(request, lease.server_id).await?;
        self.retry_state.record_attempt();

        info!(
            "Sent DHCP REQUEST (renew) to {} (attempt {})",
            lease.server_id, self.retry_state.attempt
        );

        // Wait for response with lease-specific timeout
        let timeout_duration = lease.retry_interval(self.state);

        match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
            Ok(Ok(message)) => {
                if message.options.dhcp_message_type == Some(MessageType::DhcpAck) {
                    Ok(message)
                } else {
                    warn!("Renewal NAK received");
                    Err(ClientError::Nak)
                }
            },
            Ok(Err(e)) => {
                debug!("Renewal failed: {}", e);
                Err(e)
            }
            Err(_) => {
                debug!("Renewal timeout after {:?}", timeout_duration);
                Err(ClientError::Timeout { state: self.state })
            }
        }
    }

    /// Rebinding phase - send REQUEST to any server
    async fn rebind_phase(&mut self) -> Result<Message, ClientError> {
        let lease = self
            .lease
            .clone()
            .ok_or_else(|| ClientError::Protocol("No lease to rebind".to_string()))?;

        let request = self.builder.request_renew(self.xid, lease.assigned_ip, None);

        self.send_broadcast(request).await?;
        self.retry_state.record_attempt();
        info!("Sent DHCP REQUEST (rebind) (attempt {})", self.retry_state.attempt);

        // Wait for response with lease-specific timeout
        let timeout_duration = lease.retry_interval(self.state);

        match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
            Ok(Ok(message)) => {
                if message.options.dhcp_message_type == Some(MessageType::DhcpAck) {
                    info!("Lease rebinding successful");
                    Ok(message)
                } else {
                    warn!("Rebinding NAK received");
                    Err(ClientError::Nak)
                }
            },
            Ok(Err(e)) => {
                debug!("Rebinding failed: {}", e);
                Err(e)
            }
            Err(_) => {
                debug!("Rebinding timeout after {:?}", timeout_duration);
                Err(ClientError::Timeout { state: self.state })
            }
        }


    }

    /// Reboot phase - send REQUEST to verify previous IP (INIT-REBOOT)
    async fn reboot_phase(&mut self, previous_ip: Ipv4Addr) -> Result<Message, ClientError> {
        loop {
            // Send REQUEST for previous IP
            let request = self.builder.request_init_reboot(
                self.xid,
                previous_ip,
                None, // lease time
            );

            self.send_broadcast(request).await?;
            self.retry_state.record_attempt();

            info!(
                "Sent DHCP REQUEST (init-reboot) for {} (attempt {})",
                previous_ip, self.retry_state.attempt
            );

            // Wait for ACK/NAK with timeout
            let timeout_duration = self.retry_state.next_interval();

            match timeout(timeout_duration, self.wait_for_ack_or_nak()).await {
                Ok(Ok(message)) => {
                    if message.options.dhcp_message_type == Some(MessageType::DhcpAck) {
                        info!("INIT-REBOOT successful for {}", previous_ip);
                        return Ok(message);
                    } else {
                        warn!("INIT-REBOOT NAK received for {}, IP no longer valid", previous_ip);
                        return Err(ClientError::Nak);
                    }
                },
                Ok(Err(e)) => {
                    debug!("INIT-REBOOT failed, retrying: {}", e);
                }
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

    /// Handle ACK message and update lease information
    /// Errors it may return: InvalidLease, IPConflict, FailedToAddIP
    async fn handle_ack(&mut self, ack: &Message, netlink_handle: &NetlinkHandle) -> Result<(), ClientError> {
        let server_id = ack.options.dhcp_server_id.unwrap();

        // validate parameters in ack

        // earlier offered ip must match acked ip
        if let Some(offered_ip) = self.offered_ip {
            if offered_ip != ack.your_ip_address {
                error!("Unexpected IP address. ACK gave {} but earlier we were offered {}", ack.your_ip_address, offered_ip);
                return Err(ClientError::InvalidLease);
            }
        }

        // ip must be unicast
        let ip = ack.your_ip_address;
        if !is_unicast(ip) {
            error!("ACK 'your_ip_address' is not unicast: {}", ip);
            return Err(ClientError::InvalidLease);
        }

        if ip.is_link_local() {
            warn!("IP Address in ACK from {} is a link-local unicast IP: {}", server_id, ip);
        }

        let lease_time = ack.options.address_time.unwrap();
        let renewal_time = ack.options.renewal_time.unwrap_or(lease_time / 2);
        let rebinding_time = ack.options.rebinding_time.unwrap_or(((lease_time as u64 * 7) / 8) as u32);

        let subnet: u8 = match ack.options.subnet_mask {
            Some(mask) => {
                let bits = u32::from(mask);
                let mask = bits.leading_ones();
                if mask == 0 || mask == 32 || mask + bits.trailing_zeros() != 32 {
                    error!("ACK contains invalid 'subnet_mask': {}", mask);
                    return Err(ClientError::InvalidLease);
                }
                mask as u8
            }
            None => {
                warn!("ACK from {} lacks subnet mask, using default class-based mask", server_id);
                let ip_bytes = ip.octets();
                match ip_bytes[0] {
                    0..=127 => 8,
                    128..=191 => 16,
                    _ => 24,
                }
            }
        };

        use crate::netlink;
        use std::collections::HashSet;
        let mut seen_destinations = HashSet::new();
        let mut cleaned_routes = Vec::new();
        let mut default_gw = None;

        // classless static routes validation
        if let Some(routes) = &ack.options.classless_static_routes {
            for route in routes {
                let (dest, mask, via) = route;

                // Skip if destination already seen or via address is not unicast
                if seen_destinations.contains(dest) || !is_unicast(*via) {
                    continue;
                }

                // Check for default gateway (mask == 0)
                if mask.is_unspecified() && default_gw.is_none() {
                    default_gw = Some(via.clone());
                    dbg!("using default gw {:?} from classless route option", via);
                }

                // Add to seen set and include in result
                seen_destinations.insert(dest.clone());
                cleaned_routes.push(route.clone());
            }
        }

        // if default gateway isn't defined in classless routes option, fall back to router option
        if default_gw.is_none() {
            if let Some(gateways) = &ack.options.routers {
                default_gw = gateways.iter().find(|&&gw| is_unicast(gw)).cloned();
            }
        }

        if default_gw.is_none() {
            error!("ACK from {} lacks a usable DEFAULT_GW or CLASSLESS_ROUTE default route", server_id);
            return Err(ClientError::InvalidLease);
        }

        let gw = default_gw.unwrap();

        if !netlink::is_same_subnet(ip, subnet, gw) {
            warn!(
                "Default gateway {} is not on the same subnet as assigned IP {} (/{} mask)",
                gw, ip, subnet
            );
        }

        // check if lease has changed
        if let Some(lease) = &mut self.lease {
            if lease.assigned_ip == ip
                && lease.subnet_prefix == subnet
                && lease.gateway_ip == gw
                && lease.routes == cleaned_routes
                && lease.ntp_servers.iter().collect::<HashSet<_>>() == ack.options.ntp_servers.iter().collect::<HashSet<_>>()
                && lease.dns_servers.iter().collect::<HashSet<_>>() == ack.options.domain_name_servers.iter().collect::<HashSet<_>>()
                && lease.domain_name == ack.options.domain_name
            {
                info!("🤝 No change in lease parameters");

                // update lease start time
                lease.lease_start = Instant::now();
                lease.server_id = server_id;
                lease.lease_time = lease_time;
                lease.renewal_time = renewal_time;
                lease.rebinding_time = rebinding_time;
                return Ok(());
            }
            info!("🆕 Lease has changed!");
            self.undo_lease(netlink_handle).await;
        }

        info!("✅ DHCP Lease received:");
        info!("   📍 Your IP: {}/{}", ip, subnet);
        info!("   🚪 Gateway: {}", gw);
        info!("   ⏰ Lease Duration: {}s", lease_time);

        if let Some(ref dns_servers) = ack.options.domain_name_servers {
            info!("   🌐 DNS servers: {:?}", dns_servers);
        }

        if let Some(ref domain_name) = ack.options.domain_name {
            info!("   🏷️ Domain name: {}", domain_name);
        }

        if let Some(ref ntp_servers) = ack.options.ntp_servers {
            info!("   🕰  NTP servers: {:?}", ntp_servers);
        }

        // Get interface details
        let interface_idx = netlink_handle.interface_idx;
        let our_mac = netlink_handle.interface_mac;

        // Perform ARP probe to make sure no one else is using this ip address
        match arp_probe(interface_idx, ip, our_mac).await {
            ArpProbeResult::Available => {
                info!("✅ ARP probe successful - IP address {} is available", ip);
            }
            ArpProbeResult::InUse => {
                warn!("❌ IP address {} is already in use (detected via ARP)", ip);
                return Err(ClientError::IpConflict { assigned_ip: ip, server_id });
            }
            ArpProbeResult::Error(e) => {
                warn!("⚠️  ARP probe failed: {} - proceeding anyway", e);
            }
        }

        // Send ARP announcements
        if let Err(e) = announce_address(interface_idx, ip, our_mac).await {
            warn!("⚠️  Failed to send gratuitous ARP announcement: {}", e);
        }

        info!(
            "🔧 Assigning IP address {}/{} to interface {}",
            ip, subnet, netlink_handle.interface_name
        );

        // Assign the IP address
        match netlink_handle.add_interface_ip(ip, subnet).await {
            Ok(()) => {
                info!("✅ Successfully assigned IP address to interface");
                self.ip_already_existed = false;
            }
            Err(e) => {
                if is_eexist_error(&e) {
                    info!("✋ IP address already assigned to interface");
                    self.ip_already_existed = true;
                } else {
                    warn!(
                        "❌  Failed to assign IP address to interface {}: {}",
                        netlink_handle.interface_name, e
                    );
                    return Err(ClientError::FailedToAddIP);
                }
            }
        }

        // add default gateway route
        match netlink_handle.add_route(Ipv4Addr::UNSPECIFIED, 0, gw, ip, subnet).await {
            Ok(()) => {
                info!("✅ Successfully added {} as default gateway", gw);
            }
            Err(e) => {
                warn!("⚠️  Failed to add {} as default gateway: {}", gw, e);
                // carry on
            }
        }

        // add classless static routes
        for route in &cleaned_routes {
            let (dst, mask, via) = route;
            let dst_prefix_len = netmask_to_prefix(*mask);
            if dst_prefix_len == 0 {
                continue;
            }
            match netlink_handle.add_route(*dst, dst_prefix_len, *via, ip, subnet).await {
                Ok(()) => {
                    info!("✅ Successfully added route: {}/{} via {}", dst, dst_prefix_len, gw);
                }
                Err(e) => {
                    warn!("⚠️  Failed to add route: {}/{} via {}: {}", dst, dst_prefix_len, gw, e);
                    // carry on
                }
            }
        }

        // Apply DNS configuration
        if let Some(ref dns_servers) = ack.options.domain_name_servers {
            if let Err(e) = apply_dns_config(dns_servers, ack.options.domain_name.as_deref()).await {
                warn!("⚠️  Failed to apply DNS configuration: {}", e);
            } else {
                info!("✅ Successfully applied DNS configuration");
            }
        }

        // Apply NTP servers
        if let Some(ref ntp_servers) = ack.options.ntp_servers {
            if let Err(e) = apply_ntp_config(ntp_servers).await {
                warn!("⚠️  Failed to apply NTP configuration: {}", e);
            } else {
                info!("✅ Successfully applied NTP configuration");
            }
        }

        self.lease = Some(LeaseInfo::new(
            ip,
            subnet,
            gw,
            cleaned_routes,
            server_id,
            lease_time,
            renewal_time,
            rebinding_time,
            ack.options.domain_name_servers.clone(),
            ack.options.domain_name.clone(),
            ack.options.ntp_servers.clone(),
        ));
        Ok(())
    }

    /// Send a message via broadcast
    async fn send_broadcast(&mut self, message: Message) -> Result<(), ClientError> {
        let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DHCP_PORT_SERVER);
        let item = (broadcast_addr, (message, None));
        self.socket.send_message(item).await?;
        Ok(())
    }

    /// Send a message via unicast to a specific server
    async fn send_unicast(&mut self, message: Message, server_ip: Ipv4Addr) -> Result<(), ClientError> {
        let server_addr = SocketAddr::new(IpAddr::V4(server_ip), DHCP_PORT_SERVER);
        let item = (server_addr, (message, None));
        self.socket.send_message(item).await?;
        Ok(())
    }

    /// Wait for one of the specified message types with transaction ID validation
    async fn wait_for_message_types(&mut self, expected_types: &[MessageType]) -> Result<(SocketAddr, Message), ClientError> {
        loop {
            if let Some(result) = self.socket.recv_message().await {
                match result {
                    Ok((addr, message)) => {
                        // Validate transaction ID
                        if message.transaction_id != self.xid {
                            trace!(
                                "Ignoring message with wrong transaction ID: {} (expected {})",
                                message.transaction_id,
                                self.xid
                            );
                            continue;
                        }

                        // Validate message type
                        match message.validate() {
                            Ok(msg_type) if expected_types.contains(&msg_type) => {
                                return Ok((addr, message));
                            }
                            Ok(msg_type) => {
                                debug!("Got {} but expected one of {:?}", msg_type, expected_types);
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

    /// Wait for a specific message type with transaction ID validation
    async fn wait_for_message_type(&mut self, expected_type: MessageType) -> Result<(SocketAddr, Message), ClientError> {
        self.wait_for_message_types(&[expected_type]).await
    }

    /// Wait for ACK or NAK message
    async fn wait_for_ack_or_nak(&mut self) -> Result<Message, ClientError> {
        let (_, message) = self.wait_for_message_types(&[MessageType::DhcpAck, MessageType::DhcpNak]).await?;
        Ok(message)
    }

    /// Remove all network configuration applied by the current DHCP lease
    pub async fn undo_lease(&mut self, netlink_handle: &NetlinkHandle) {
        if let Some(lease) = &self.lease {
            info!("🧹 Removing network configuration for lease");

            if lease.ntp_servers.is_some() {
                if let Err(e) = apply_ntp_config(&Vec::new()).await {
                    warn!("⚠️  Failed to remove NTP servers: {}", e);
                }
            }

            if lease.dns_servers.is_some() {
                if let Err(e) = restore_dns_config().await {
                    warn!("⚠️  Failed to restore original DNS configuration: {}", e);
                }
            }

            // remove static routes
            for (dest, mask, via) in &lease.routes {
                let prefix = netmask_to_prefix(*mask);
                if let Err(e) = netlink_handle
                    .delete_route(*dest, prefix, *via, lease.assigned_ip, lease.subnet_prefix)
                    .await
                {
                    warn!("⚠️  Failed to remove route {}/{} via {}: {}", dest, prefix, via, e);
                } else {
                    info!("✅ Removed route {}/{} via {}", dest, prefix, via);
                }
            }

            // remove default gateway route
            if let Err(e) = netlink_handle
                .delete_route(Ipv4Addr::UNSPECIFIED, 0, lease.gateway_ip, lease.assigned_ip, lease.subnet_prefix)
                .await
            {
                warn!("⚠️  Failed to remove default gateway route via {}: {}", lease.gateway_ip, e);
            } else {
                info!("✅ Removed default gateway route via {}", lease.gateway_ip);
            }

            // remove IP address from interface (only if we assigned it)
            if self.ip_already_existed {
                info!(
                    "✋ Leaving IP address {}/{} on interface (it already existed)",
                    lease.assigned_ip, lease.subnet_prefix
                );
            } else {
                if let Err(e) = netlink_handle.delete_interface_ip(lease.assigned_ip, lease.subnet_prefix).await {
                    warn!(
                        "⚠️  Failed to remove IP address {}/{} from interface: {}",
                        lease.assigned_ip, lease.subnet_prefix, e
                    );
                } else {
                    info!("✅ Removed IP address {}/{} from interface", lease.assigned_ip, lease.subnet_prefix);
                }
            }

            info!("🧹 Lease removal completed");
        } else {
            error!("Lease is none");
        }

        self.lease = None;
    }
}

fn is_unicast(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback())
}

#[cfg(target_os = "linux")]
fn is_eexist_error(e: &Box<dyn std::error::Error>) -> bool {
    if let Some(rtnetlink_error) = e.downcast_ref::<rtnetlink::Error>() {
        if let rtnetlink::Error::NetlinkError(error_msg) = rtnetlink_error {
            if let Some(code) = error_msg.code {
                return code.get() == -(EEXIST as i32);
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_eexist_error(_e: &Box<dyn std::error::Error>) -> bool {
    false
}

pub fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let octets = netmask.octets();
    let mask_u32 = ((octets[0] as u32) << 24) | ((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | (octets[3] as u32);
    mask_u32.count_ones() as u8
}
