//! DHCPv6 client orchestrator (RFC 8415).
//!
//! Phase 1 scope: stateful IA_NA only.

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use dhcproto::v6::{DhcpOption, IAAddr, Message, MessageType, OptionCode, Status, IANA};
use dhcproto::{Decodable, Decoder, Encodable};
use eui48::MacAddress;
use log::{debug, info, warn};
use thiserror::Error;
use tokio::time::sleep;

use crate::dns::{apply_dns_config, restore_dns_config};
use crate::netlink::NetlinkHandle;
use crate::v6::builder::{build_release, build_renew_or_rebind, build_request, build_solicit};
use crate::v6::duid::{self, DuidError};
use crate::v6::lifecycle::{elapsed_centis, first_rt, next_rt, DEFAULT_SOLICIT_TIMEOUT};
use crate::v6::socket::DhcpV6Framed;
use crate::v6::state::{
    ClientV6State, DhcpV6State, IaAddress, IaContents, IaLease, IaState, IaType, REB_MAX_RT, REB_TIMEOUT, REL_MAX_RC, REL_TIMEOUT,
    REN_MAX_RT, REN_TIMEOUT, REQ_MAX_RC, REQ_MAX_RT, REQ_TIMEOUT, SOL_MAX_RT, SOL_TIMEOUT,
};

const PRIMARY_IAID: u32 = 1;
const RECV_BUF_BYTES: usize = 4096;
/// Default IPv6 prefix used when no on-link information is available. The DHCPv6
/// server does not advertise the subnet — that comes from RAs. /128 keeps the
/// host route correct while leaving prefix learning to the kernel + RAs.
const DEFAULT_V6_PREFIX_LEN: u8 = 128;

#[derive(Debug, Error)]
pub enum ClientV6Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DUID error: {0}")]
    Duid(#[from] DuidError),
    #[error("SOLICIT timed out — no DHCPv6 server responded")]
    SolicitTimeout,
    #[error("REQUEST failed after {0} attempts")]
    RequestExhausted(u32),
    #[error("server replied with status {0:?}: {1}")]
    Status(Status, String),
    #[error("server sent a malformed reply: {0}")]
    BadReply(String),
    #[error("lease expired")]
    LeaseExpired,
    #[error("failed to install IPv6 address: {0}")]
    InstallFailed(String),
    #[error("encode error: {0}")]
    Encode(String),
}

pub struct ClientV6 {
    pub interface_name: String,
    pub interface_idx: u32,
    pub interface_mac: MacAddress,
    pub state_data: ClientV6State,
    socket: DhcpV6Framed,
    xid: [u8; 3],
    solicit_timeout: Duration,
    pub resolv_conf_path: PathBuf,
}

impl ClientV6 {
    /// Build a new client. Loads or generates the DUID at `duid_path`.
    pub async fn new(
        interface_name: &str, interface_idx: u32, interface_mac: MacAddress, duid_path: &Path, solicit_timeout: Option<Duration>,
        resolv_conf_path: Option<PathBuf>,
    ) -> Result<Self, ClientV6Error> {
        let duid = duid::load_or_generate(duid_path, interface_mac)?;
        let mut state_data = ClientV6State::new(duid);
        state_data.ias.insert(PRIMARY_IAID, IaState::new(PRIMARY_IAID, IaType::Na));

        let socket = DhcpV6Framed::bind(interface_name, interface_idx).await?;
        let xid = random_xid();

        Ok(Self {
            interface_name: interface_name.to_string(),
            interface_idx,
            interface_mac,
            state_data,
            socket,
            xid,
            solicit_timeout: solicit_timeout.unwrap_or(DEFAULT_SOLICIT_TIMEOUT),
            resolv_conf_path: resolv_conf_path.unwrap_or_else(|| PathBuf::from("/etc/resolv.conf")),
        })
    }

    pub fn state(&self) -> DhcpV6State {
        self.state_data
            .ias
            .get(&PRIMARY_IAID)
            .map(|i| i.state)
            .unwrap_or(DhcpV6State::Init)
    }

    pub fn lease(&self) -> Option<&IaLease> {
        self.state_data.ias.get(&PRIMARY_IAID).and_then(|i| i.lease.as_ref())
    }

    /// Full SOLICIT → ADVERTISE → REQUEST → REPLY exchange, then install the lease.
    pub async fn configure(&mut self, netlink: &NetlinkHandle) -> Result<(), ClientV6Error> {
        info!("Starting DHCPv6 configuration (SOLICIT → REQUEST)");
        let configure_start = Instant::now();

        let advertise = self.solicit_phase().await?;
        let reply = self.request_phase(&advertise).await?;

        info!("DHCPv6 exchange completed in {} ms", configure_start.elapsed().as_millis());
        self.handle_reply(&reply, netlink).await?;
        self.set_state(DhcpV6State::Bound);
        Ok(())
    }

    /// Drive the bound client through T1 (RENEW) and T2 (REBIND).
    pub async fn run_lifecycle(&mut self, netlink: &NetlinkHandle) -> Result<(), ClientV6Error> {
        loop {
            let lease = match self.lease() {
                Some(l) => l.clone(),
                None => return Err(ClientV6Error::BadReply("no lease in lifecycle".into())),
            };
            if lease.is_expired() {
                warn!("DHCPv6 lease expired");
                return Err(ClientV6Error::LeaseExpired);
            }

            if self.state() == DhcpV6State::Bound {
                let wait = lease.time_until_t1();
                info!("⏳ DHCPv6 waiting {:?} until T1 (renewal)", wait);
                sleep(wait).await;
                self.set_state(DhcpV6State::Renewing);
                continue;
            }

            match self.state() {
                DhcpV6State::Renewing => match self.renew_phase().await {
                    Ok(reply) => {
                        self.handle_reply(&reply, netlink).await?;
                        self.set_state(DhcpV6State::Bound);
                    }
                    Err(_) if lease.should_rebind() => {
                        info!("T2 reached during renewal; switching to REBIND");
                        self.set_state(DhcpV6State::Rebinding);
                    }
                    Err(e) => {
                        warn!("renew attempt failed: {}", e);
                        sleep(Duration::from_secs(5)).await;
                    }
                },
                DhcpV6State::Rebinding => match self.rebind_phase().await {
                    Ok(reply) => {
                        self.handle_reply(&reply, netlink).await?;
                        self.set_state(DhcpV6State::Bound);
                    }
                    Err(e) => {
                        warn!("rebind attempt failed: {}", e);
                        if lease.is_expired() {
                            return Err(ClientV6Error::LeaseExpired);
                        }
                        sleep(Duration::from_secs(5)).await;
                    }
                },
                other => {
                    return Err(ClientV6Error::BadReply(format!("unexpected state {} in lifecycle", other)));
                }
            }
        }
    }

    /// Send a multicast RELEASE for the bound lease (best-effort).
    pub async fn release(&mut self, reason: &str) -> Result<(), ClientV6Error> {
        let (ia, lease) = match self
            .state_data
            .ias
            .get(&PRIMARY_IAID)
            .and_then(|ia| ia.lease.as_ref().map(|l| (ia.clone(), l.clone())))
        {
            Some(p) => p,
            None => return Ok(()),
        };
        let server_duid = lease.server_duid.clone();
        info!("📤 DHCPv6 RELEASE ({})", reason);

        self.xid = random_xid();
        let mut attempts = 0u32;
        loop {
            let msg = build_release(&self.state_data.duid, &server_duid, self.xid, &ia, &lease);
            let bytes = encode_message(&msg)?;
            self.socket.send_multicast(&bytes).await?;
            attempts += 1;

            let mut buf = vec![0u8; RECV_BUF_BYTES];
            let rt = if attempts == 1 {
                first_rt(REL_TIMEOUT)
            } else {
                Duration::from_secs_f64(REL_TIMEOUT * (attempts as f64))
            };
            match self.socket.recv_with_timeout(&mut buf, rt).await {
                Ok(Some((n, _))) => {
                    if let Ok(reply) = Message::decode(&mut Decoder::new(&buf[..n])) {
                        if reply.xid() == self.xid && reply.msg_type() == MessageType::Reply {
                            debug!("RELEASE acknowledged");
                            break;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("RELEASE recv error: {}", e);
                }
            }

            if attempts >= REL_MAX_RC {
                debug!("RELEASE attempts exhausted; proceeding to teardown");
                break;
            }
        }
        self.set_state(DhcpV6State::Released);
        Ok(())
    }

    /// Manual renewal trigger (e.g. SIGHUP / SIGUSR1).
    pub async fn renew(&mut self, netlink: &NetlinkHandle) -> Result<(), ClientV6Error> {
        if self.state() != DhcpV6State::Bound {
            return Err(ClientV6Error::BadReply("not in BOUND state for renew".into()));
        }
        self.set_state(DhcpV6State::Renewing);
        let reply = self.renew_phase().await?;
        self.handle_reply(&reply, netlink).await?;
        self.set_state(DhcpV6State::Bound);
        Ok(())
    }

    /// Tear down anything installed by the last lease.
    pub async fn undo_lease(&mut self, netlink: &NetlinkHandle) {
        let path = v6_resolv_path(&self.resolv_conf_path);
        if let Err(e) = restore_dns_config(&path).await {
            warn!("⚠️  Failed to restore DNS at {}: {}", path.display(), e);
        }
        if let Some(ia) = self.state_data.ias.get_mut(&PRIMARY_IAID) {
            if let Some(lease) = ia.lease.take() {
                if let IaContents::Addresses(addrs) = &lease.contents {
                    for a in addrs {
                        if let Err(e) = netlink.delete_interface_ip_v6(a.addr, DEFAULT_V6_PREFIX_LEN).await {
                            warn!("⚠️  Failed to remove IPv6 {}: {}", a.addr, e);
                        } else {
                            info!("✅ Removed IPv6 {}", a.addr);
                        }
                    }
                }
            }
            ia.state = DhcpV6State::Init;
        }
        self.state_data.server_duid = None;
        self.state_data.dns_servers.clear();
        self.state_data.search_domains.clear();
    }

    // ---- internal phases ----

    async fn solicit_phase(&mut self) -> Result<Message, ClientV6Error> {
        self.xid = random_xid();
        self.set_state(DhcpV6State::Soliciting);
        let started = Instant::now();
        let mut rt = first_rt(SOL_TIMEOUT);
        let mut best_advertise: Option<(u8, Message)> = None;
        let mut attempts = 0u32;

        let deadline = started + self.solicit_timeout;

        loop {
            if Instant::now() >= deadline {
                if let Some((_pref, msg)) = best_advertise {
                    return Ok(msg);
                }
                return Err(ClientV6Error::SolicitTimeout);
            }

            let ia = self
                .state_data
                .ias
                .get(&PRIMARY_IAID)
                .cloned()
                .ok_or_else(|| ClientV6Error::BadReply("missing primary IA".into()))?;
            let msg = build_solicit(&self.state_data.duid, self.xid, &ia, elapsed_centis(started));
            let bytes = encode_message(&msg)?;
            self.socket.send_multicast(&bytes).await?;
            attempts += 1;
            info!("DHCPv6 → SOLICIT (attempt {}, RT {:?})", attempts, rt);

            let recv_deadline = (Instant::now() + rt).min(deadline);
            let mut buf = vec![0u8; RECV_BUF_BYTES];
            loop {
                let remaining = recv_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match self.socket.recv_with_timeout(&mut buf, remaining).await {
                    Ok(Some((n, _src))) => {
                        let parsed = match Message::decode(&mut Decoder::new(&buf[..n])) {
                            Ok(m) => m,
                            Err(e) => {
                                debug!("dropping malformed DHCPv6 datagram: {}", e);
                                continue;
                            }
                        };
                        if parsed.xid() != self.xid || parsed.msg_type() != MessageType::Advertise {
                            continue;
                        }
                        if let Some(status) = status_code(&parsed) {
                            if status.0 != Status::Success {
                                debug!("ignoring ADVERTISE with status {:?}: {}", status.0, status.1);
                                continue;
                            }
                        }
                        let preference = preference_value(&parsed);
                        info!("DHCPv6 ← ADVERTISE (preference={})", preference);
                        let take = best_advertise.as_ref().map(|(p, _)| preference > *p).unwrap_or(true);
                        if take {
                            best_advertise = Some((preference, parsed));
                        }
                        if preference == 255 {
                            return Ok(best_advertise.unwrap().1);
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("DHCPv6 recv error: {}", e);
                        break;
                    }
                }
            }

            if attempts >= 1 {
                if let Some((_, msg)) = best_advertise {
                    return Ok(msg);
                }
            }

            rt = next_rt(rt, SOL_MAX_RT);
        }
    }

    async fn request_phase(&mut self, advertise: &Message) -> Result<Message, ClientV6Error> {
        self.set_state(DhcpV6State::Requesting);
        self.xid = random_xid();

        let server_duid = extract_server_duid(advertise)?;
        let (_iaid, advertised) = extract_iana_addresses(advertise)?;
        self.state_data.server_duid = Some(server_duid.clone());

        let started = Instant::now();
        let mut rt = first_rt(REQ_TIMEOUT);
        let mut attempts = 0u32;

        loop {
            let ia = self
                .state_data
                .ias
                .get(&PRIMARY_IAID)
                .cloned()
                .ok_or_else(|| ClientV6Error::BadReply("missing primary IA".into()))?;
            let msg = build_request(
                &self.state_data.duid,
                &server_duid,
                self.xid,
                &ia,
                &advertised,
                elapsed_centis(started),
            );
            let bytes = encode_message(&msg)?;
            self.socket.send_multicast(&bytes).await?;
            attempts += 1;
            info!("DHCPv6 → REQUEST (attempt {}, RT {:?})", attempts, rt);

            let mut buf = vec![0u8; RECV_BUF_BYTES];
            match self.socket.recv_with_timeout(&mut buf, rt).await {
                Ok(Some((n, _))) => {
                    if let Ok(reply) = Message::decode(&mut Decoder::new(&buf[..n])) {
                        if reply.xid() == self.xid && reply.msg_type() == MessageType::Reply {
                            if let Some((status, msg)) = status_code(&reply) {
                                if status != Status::Success {
                                    return Err(ClientV6Error::Status(status, msg));
                                }
                            }
                            return Ok(reply);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!("REQUEST recv error: {}", e),
            }

            if attempts >= REQ_MAX_RC {
                return Err(ClientV6Error::RequestExhausted(attempts));
            }
            rt = next_rt(rt, REQ_MAX_RT);
        }
    }

    async fn renew_phase(&mut self) -> Result<Message, ClientV6Error> {
        self.send_lease_update(MessageType::Renew, true, REN_TIMEOUT, REN_MAX_RT).await
    }

    async fn rebind_phase(&mut self) -> Result<Message, ClientV6Error> {
        self.send_lease_update(MessageType::Rebind, false, REB_TIMEOUT, REB_MAX_RT).await
    }

    async fn send_lease_update(
        &mut self, msg_type: MessageType, include_server_duid: bool, irt: f64, mrt: f64,
    ) -> Result<Message, ClientV6Error> {
        self.xid = random_xid();
        let (ia, lease) = self
            .state_data
            .ias
            .get(&PRIMARY_IAID)
            .and_then(|ia| ia.lease.as_ref().map(|l| (ia.clone(), l.clone())))
            .ok_or_else(|| ClientV6Error::BadReply("no lease to renew/rebind".into()))?;
        let server_duid = if include_server_duid {
            Some(lease.server_duid.clone())
        } else {
            None
        };

        let started = Instant::now();
        let mut rt = first_rt(irt);
        let mut attempts = 0u32;

        loop {
            let msg = build_renew_or_rebind(
                msg_type,
                &self.state_data.duid,
                server_duid.as_deref(),
                self.xid,
                &ia,
                &lease,
                elapsed_centis(started),
            );
            let bytes = encode_message(&msg)?;
            // RENEW is normally unicast to the server, but RFC 8415 §18.2.4 allows clients
            // without unicast support to multicast. We always multicast to keep the socket
            // path uniform; REBIND is multicast by spec.
            self.socket.send_multicast(&bytes).await?;
            attempts += 1;

            let mut buf = vec![0u8; RECV_BUF_BYTES];
            match self.socket.recv_with_timeout(&mut buf, rt).await {
                Ok(Some((n, _))) => {
                    if let Ok(reply) = Message::decode(&mut Decoder::new(&buf[..n])) {
                        if reply.xid() == self.xid && reply.msg_type() == MessageType::Reply {
                            if let Some((Status::NoBinding, _)) = status_code(&reply) {
                                return Err(ClientV6Error::Status(Status::NoBinding, "server has no binding".into()));
                            }
                            return Ok(reply);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!("renew/rebind recv error: {}", e),
            }

            if lease.is_expired() {
                return Err(ClientV6Error::LeaseExpired);
            }
            if attempts >= 20 {
                return Err(ClientV6Error::RequestExhausted(attempts));
            }
            rt = next_rt(rt, mrt);
        }
    }

    async fn handle_reply(&mut self, reply: &Message, netlink: &NetlinkHandle) -> Result<(), ClientV6Error> {
        let server_duid = extract_server_duid(reply)?;
        let (iana_t1, iana_t2, addrs) = extract_iana_lease(reply)?;
        if addrs.is_empty() {
            return Err(ClientV6Error::BadReply("REPLY contained no IAADDR".into()));
        }

        let dns_servers = extract_dns_servers(reply);
        let search_domains = extract_domain_list(reply);

        // RFC 8415 §21.4: if server sends 0, the client picks. Use a sensible default.
        let valid_max = addrs.iter().map(|a| a.valid_lifetime).max().unwrap_or(Duration::ZERO);
        let t1 = if iana_t1 > 0 {
            Duration::from_secs(iana_t1 as u64)
        } else {
            valid_max / 2
        };
        let t2 = if iana_t2 > 0 {
            Duration::from_secs(iana_t2 as u64)
        } else {
            valid_max * 4 / 5
        };

        info!("✅ DHCPv6 lease received:");
        for a in &addrs {
            info!(
                "   📍 IPv6: {} (preferred {:?}, valid {:?})",
                a.addr, a.preferred_lifetime, a.valid_lifetime
            );
        }
        info!("   ⏰ T1={:?}, T2={:?}", t1, t2);
        if !dns_servers.is_empty() {
            info!("   🌐 DNS servers: {:?}", dns_servers);
        }
        if !search_domains.is_empty() {
            info!("   🔎 Search domains: {:?}", search_domains);
        }

        // Install addresses on the interface (new ones only).
        let existing: Option<&IaLease> = self
            .state_data
            .ias
            .get(&PRIMARY_IAID)
            .and_then(|ia| ia.lease.as_ref());
        let existing_addrs: Vec<Ipv6Addr> = existing
            .map(|l| match &l.contents {
                IaContents::Addresses(a) => a.iter().map(|x| x.addr).collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();

        for a in &addrs {
            if existing_addrs.contains(&a.addr) {
                continue;
            }
            match netlink.add_interface_ip_v6(a.addr, DEFAULT_V6_PREFIX_LEN).await {
                Ok(()) => info!("✅ Installed IPv6 {}", a.addr),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("File exists") || msg.contains("EEXIST") {
                        info!("✋ IPv6 {} already on interface", a.addr);
                    } else {
                        return Err(ClientV6Error::InstallFailed(format!("addr {}: {}", a.addr, e)));
                    }
                }
            }
        }

        // Remove any addresses that are no longer in the lease.
        let new_set: Vec<Ipv6Addr> = addrs.iter().map(|a| a.addr).collect();
        for old in &existing_addrs {
            if !new_set.contains(old) {
                if let Err(e) = netlink.delete_interface_ip_v6(*old, DEFAULT_V6_PREFIX_LEN).await {
                    warn!("⚠️  Failed to remove stale IPv6 {}: {}", old, e);
                }
            }
        }

        // DNS / search domains
        if !dns_servers.is_empty() || !search_domains.is_empty() {
            let path = v6_resolv_path(&self.resolv_conf_path);
            let nameservers: Vec<IpAddr> = dns_servers.iter().map(|a| IpAddr::V6(*a)).collect();
            if let Err(e) = apply_dns_config(&path, &nameservers, None, &search_domains, "v6").await {
                warn!("⚠️  Failed to apply DHCPv6 DNS configuration: {}", e);
            }
        }

        let lease = IaLease {
            server_duid,
            acquired: Instant::now(),
            t1,
            t2,
            contents: IaContents::Addresses(addrs),
        };
        if let Some(ia) = self.state_data.ias.get_mut(&PRIMARY_IAID) {
            ia.lease = Some(lease);
        }
        self.state_data.dns_servers = dns_servers;
        self.state_data.search_domains = search_domains;
        Ok(())
    }

    fn set_state(&mut self, new_state: DhcpV6State) {
        if let Some(ia) = self.state_data.ias.get_mut(&PRIMARY_IAID) {
            ia.state = new_state;
        }
    }
}

// ---- helpers ----

fn random_xid() -> [u8; 3] {
    let r: [u8; 4] = rand::random();
    [r[0], r[1], r[2]]
}

fn encode_message(msg: &Message) -> Result<Vec<u8>, ClientV6Error> {
    msg.to_vec().map_err(|e| ClientV6Error::Encode(e.to_string()))
}

fn status_code(msg: &Message) -> Option<(Status, String)> {
    if let Some(DhcpOption::StatusCode(sc)) = msg.opts().get(OptionCode::StatusCode) {
        return Some((sc.status, sc.msg.clone()));
    }
    None
}

fn preference_value(msg: &Message) -> u8 {
    if let Some(DhcpOption::Preference(p)) = msg.opts().get(OptionCode::Preference) {
        return *p;
    }
    0
}

fn extract_server_duid(msg: &Message) -> Result<Vec<u8>, ClientV6Error> {
    match msg.opts().get(OptionCode::ServerId) {
        Some(DhcpOption::ServerId(bytes)) => Ok(bytes.clone()),
        _ => Err(ClientV6Error::BadReply("missing ServerId".into())),
    }
}

fn extract_iana(msg: &Message) -> Result<&IANA, ClientV6Error> {
    match msg.opts().get(OptionCode::IANA) {
        Some(DhcpOption::IANA(iana)) => Ok(iana),
        _ => Err(ClientV6Error::BadReply("missing IA_NA".into())),
    }
}

/// (IPv6 address, preferred lifetime seconds, valid lifetime seconds) tuple extracted
/// from an IAADDR option, before being shaped into an `IaAddress`.
type AdvertisedAddr = (Ipv6Addr, u32, u32);

fn extract_iana_addresses(msg: &Message) -> Result<(u32, Vec<AdvertisedAddr>), ClientV6Error> {
    let iana = extract_iana(msg)?;
    if let Some((Status::NoAddrsAvail, m)) = iana_status(iana) {
        return Err(ClientV6Error::Status(Status::NoAddrsAvail, m));
    }
    let mut addrs = Vec::new();
    for opt in iana.opts.iter() {
        if let DhcpOption::IAAddr(IAAddr {
            addr, preferred_life, valid_life, ..
        }) = opt
        {
            addrs.push((*addr, *preferred_life, *valid_life));
        }
    }
    Ok((iana.id, addrs))
}

fn extract_iana_lease(msg: &Message) -> Result<(u32, u32, Vec<IaAddress>), ClientV6Error> {
    let iana = extract_iana(msg)?;
    if let Some((status, m)) = iana_status(iana) {
        if status != Status::Success {
            return Err(ClientV6Error::Status(status, m));
        }
    }
    let mut addrs = Vec::new();
    for opt in iana.opts.iter() {
        if let DhcpOption::IAAddr(IAAddr {
            addr,
            preferred_life,
            valid_life,
            ..
        }) = opt
        {
            if *valid_life == 0 {
                continue;
            }
            addrs.push(IaAddress {
                addr: *addr,
                preferred_lifetime: Duration::from_secs(*preferred_life as u64),
                valid_lifetime: Duration::from_secs(*valid_life as u64),
            });
        }
    }
    Ok((iana.t1, iana.t2, addrs))
}

fn iana_status(iana: &IANA) -> Option<(Status, String)> {
    for opt in iana.opts.iter() {
        if let DhcpOption::StatusCode(sc) = opt {
            return Some((sc.status, sc.msg.clone()));
        }
    }
    None
}

fn extract_dns_servers(msg: &Message) -> Vec<Ipv6Addr> {
    match msg.opts().get(OptionCode::DomainNameServers) {
        Some(DhcpOption::DomainNameServers(addrs)) => addrs.iter().copied().filter(|a| !a.is_unspecified()).collect(),
        _ => Vec::new(),
    }
}

fn extract_domain_list(msg: &Message) -> Vec<String> {
    match msg.opts().get(OptionCode::DomainSearchList) {
        Some(DhcpOption::DomainSearchList(names)) => names.iter().map(|n| n.to_utf8()).collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn v6_resolv_path(base: &Path) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(".ipv6");
    PathBuf::from(s)
}
