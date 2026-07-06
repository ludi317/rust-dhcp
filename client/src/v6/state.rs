//! DHCPv6 client state (IA-keyed).

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

/// DHCPv6 client states (RFC 8415).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpV6State {
    Init,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Released,
}

impl fmt::Display for DhcpV6State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpV6State::Init => write!(f, "INIT"),
            DhcpV6State::Soliciting => write!(f, "SOLICITING"),
            DhcpV6State::Requesting => write!(f, "REQUESTING"),
            DhcpV6State::Bound => write!(f, "BOUND"),
            DhcpV6State::Renewing => write!(f, "RENEWING"),
            DhcpV6State::Rebinding => write!(f, "REBINDING"),
            DhcpV6State::Released => write!(f, "RELEASED"),
        }
    }
}

/// Identity Association type. Phase 1 uses only `Na`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IaType {
    Na,
    #[allow(dead_code)]
    Ta,
    #[allow(dead_code)]
    Pd,
}

/// A single address inside an IA_NA.
#[derive(Debug, Clone)]
pub struct IaAddress {
    pub addr: Ipv6Addr,
    pub preferred_lifetime: Duration,
    pub valid_lifetime: Duration,
}

/// Reserved for future IA_PD support.
#[derive(Debug, Clone)]
pub struct IaPrefix {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred_lifetime: Duration,
    pub valid_lifetime: Duration,
}

#[derive(Debug, Clone)]
pub enum IaContents {
    Addresses(Vec<IaAddress>),
    #[allow(dead_code)]
    Prefixes(Vec<IaPrefix>),
}

#[derive(Debug, Clone)]
pub struct IaLease {
    pub server_duid: Vec<u8>,
    pub acquired: Instant,
    pub t1: Duration,
    pub t2: Duration,
    pub contents: IaContents,
}

impl IaLease {
    pub fn time_until_t1(&self) -> Duration {
        self.t1.saturating_sub(self.acquired.elapsed())
    }
    pub fn time_until_t2(&self) -> Duration {
        self.t2.saturating_sub(self.acquired.elapsed())
    }
    pub fn should_renew(&self) -> bool {
        self.time_until_t1().is_zero()
    }
    pub fn should_rebind(&self) -> bool {
        self.time_until_t2().is_zero()
    }
    pub fn longest_valid_lifetime(&self) -> Duration {
        match &self.contents {
            IaContents::Addresses(addrs) => addrs.iter().map(|a| a.valid_lifetime).max().unwrap_or(Duration::ZERO),
            IaContents::Prefixes(pxs) => pxs.iter().map(|p| p.valid_lifetime).max().unwrap_or(Duration::ZERO),
        }
    }
    pub fn is_expired(&self) -> bool {
        self.acquired.elapsed() >= self.longest_valid_lifetime()
    }
}

/// Retransmission state for an in-flight message (RFC 8415 §15).
#[derive(Debug, Clone)]
pub struct RetransmitState {
    pub attempts: u32,
    pub current_rt: Duration,
    pub started: Instant,
}

impl RetransmitState {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            current_rt: Duration::ZERO,
            started: Instant::now(),
        }
    }
}

impl Default for RetransmitState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct IaState {
    pub iaid: u32,
    pub ia_type: IaType,
    pub state: DhcpV6State,
    pub lease: Option<IaLease>,
    pub retransmit: RetransmitState,
}

impl IaState {
    pub fn new(iaid: u32, ia_type: IaType) -> Self {
        Self {
            iaid,
            ia_type,
            state: DhcpV6State::Init,
            lease: None,
            retransmit: RetransmitState::new(),
        }
    }
}

// RFC 8415 §7.6 message-type timing constants (seconds).
pub const SOL_TIMEOUT: f64 = 1.0;
pub const SOL_MAX_RT: f64 = 3600.0;
pub const REQ_TIMEOUT: f64 = 1.0;
pub const REQ_MAX_RT: f64 = 30.0;
pub const REQ_MAX_RC: u32 = 10;
pub const REN_TIMEOUT: f64 = 10.0;
pub const REN_MAX_RT: f64 = 600.0;
pub const REB_TIMEOUT: f64 = 10.0;
pub const REB_MAX_RT: f64 = 600.0;
pub const REL_TIMEOUT: f64 = 1.0;
pub const REL_MAX_RC: u32 = 4;

/// Shared bookkeeping for a `ClientV6` instance.
pub struct ClientV6State {
    pub ias: HashMap<u32, IaState>,
    pub duid: Vec<u8>,
    pub server_duid: Option<Vec<u8>>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub search_domains: Vec<String>,
}

impl ClientV6State {
    pub fn new(duid: Vec<u8>) -> Self {
        Self {
            ias: HashMap::new(),
            duid,
            server_duid: None,
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
        }
    }
}
