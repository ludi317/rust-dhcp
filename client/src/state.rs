//! RFC 2131 compliant DHCP client state machine

use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// DHCP client states as defined in RFC 2131
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    /// Initial state. Client has no network configuration.
    Init,
    /// Client has sent DHCPDISCOVER and is waiting for DHCPOFFER.
    Selecting,
    /// Client has sent DHCPREQUEST in response to DHCPOFFER.
    Requesting,
    /// Client has received DHCPACK and has a valid lease.
    Bound,
    /// Client is renewing its lease with the original server.
    Renewing,
    /// Client is rebinding its lease with any server.
    Rebinding,
    /// Client is rebooting and trying to verify previous configuration.
    InitReboot,
    /// Client has sent DHCPREQUEST to verify previous configuration.
    Rebooting,
}

impl fmt::Display for DhcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpState::Init => write!(f, "INIT"),
            DhcpState::Selecting => write!(f, "SELECTING"),
            DhcpState::Requesting => write!(f, "REQUESTING"),
            DhcpState::Bound => write!(f, "BOUND"),
            DhcpState::Renewing => write!(f, "RENEWING"),
            DhcpState::Rebinding => write!(f, "REBINDING"),
            DhcpState::InitReboot => write!(f, "INIT-REBOOT"),
            DhcpState::Rebooting => write!(f, "REBOOTING"),
        }
    }
}

/// DHCP lease information and timers
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    /// The IP address assigned to the client
    pub assigned_ip: Ipv4Addr,
    /// The DHCP server that assigned the lease
    pub server_id: Ipv4Addr,
    /// When the lease was acquired
    pub lease_start: Instant,
    /// Total lease duration in seconds
    pub lease_time: u32,
    /// Time to start renewal (T1) in seconds from lease start
    pub renewal_time: u32,
    /// Time to start rebinding (T2) in seconds from lease start  
    pub rebinding_time: u32,
    /// DNS servers provided by DHCP
    pub dns_servers: Option<Vec<Ipv4Addr>>,
    /// Domain name provided by DHCP
    pub domain_name: Option<String>,
    /// NTP servers provided by DHCP
    pub ntp_servers: Option<Vec<Ipv4Addr>>,
}

impl LeaseInfo {
    /// Create new lease information
    pub fn new(
        assigned_ip: Ipv4Addr, 
        server_id: Ipv4Addr, 
        lease_time: u32, 
        renewal_time: u32, 
        rebinding_time: u32,
        dns_servers: Option<Vec<Ipv4Addr>>,
        domain_name: Option<String>,
        ntp_servers: Option<Vec<Ipv4Addr>>,
    ) -> Self {
        Self {
            assigned_ip,
            server_id,
            lease_start: Instant::now(),
            lease_time,
            renewal_time,
            rebinding_time,
            dns_servers,
            domain_name,
            ntp_servers,
        }
    }

    /// Get the T1 time (when to start renewal)
    pub fn t1(&self) -> u32 {
        self.renewal_time
    }

    /// Get the T2 time (when to start rebinding)  
    pub fn t2(&self) -> u32 {
        self.rebinding_time
    }

    /// Time until renewal should start (T1)
    pub fn time_until_renewal(&self) -> Duration {
        let elapsed = self.lease_start.elapsed().as_secs() as u32;
        let t1 = self.renewal_time;
        if elapsed >= t1 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs((t1 - elapsed) as u64)
        }
    }

    /// Time until rebinding should start (T2)
    pub fn time_until_rebinding(&self) -> Duration {
        let elapsed = self.lease_start.elapsed().as_secs() as u32;
        let t2 = self.rebinding_time;
        if elapsed >= t2 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs((t2 - elapsed) as u64)
        }
    }

    /// Time until lease expires
    pub fn time_until_expiry(&self) -> Duration {
        let elapsed = self.lease_start.elapsed().as_secs() as u32;
        if elapsed >= self.lease_time {
            Duration::from_secs(0)
        } else {
            Duration::from_secs((self.lease_time - elapsed) as u64)
        }
    }

    /// Check if it's time to start renewal (T1 reached)
    pub fn should_renew(&self) -> bool {
        self.time_until_renewal().is_zero()
    }

    /// Check if it's time to start rebinding (T2 reached)
    pub fn should_rebind(&self) -> bool {
        self.time_until_rebinding().is_zero()
    }

    /// Check if lease has expired
    pub fn is_expired(&self) -> bool {
        self.time_until_expiry().is_zero()
    }

    /// Check if lease is infinite (never expires)
    pub fn is_infinite(&self) -> bool {
        self.lease_time == 0xffffffff
    }

    /// Calculate retry interval according to RFC 2131 section 4.4.5
    ///
    /// "In both RENEWING and REBINDING states, if the client receives no
    /// response to its DHCPREQUEST message, the client SHOULD wait one-half
    /// of the remaining time until T2 (in RENEWING state) and one-half of
    /// the remaining lease time (in REBINDING state), down to a minimum of
    /// 60 seconds, before retransmitting the DHCPREQUEST message."
    pub fn retry_interval(&self, state: DhcpState) -> Duration {
        let remaining = match state {
            DhcpState::Renewing => self.time_until_rebinding(),
            DhcpState::Rebinding => self.time_until_expiry(),
            _ => Duration::from_secs(0),
        };

        (remaining / 2).max(Duration::from_secs(60))
    }
}

/// Backoff strategy for retransmissions
#[derive(Debug, Clone)]
pub struct RetryState {
    /// Number of retries attempted
    pub attempt: u32,
    /// When the last attempt was made
    pub last_attempt: Instant,
    /// Base retry interval
    pub base_interval: Duration,
    /// Maximum retry interval
    pub max_interval: Duration,
}

impl RetryState {
    /// Create new retry state
    pub fn new() -> Self {
        Self {
            attempt: 0,
            last_attempt: Instant::now(),
            base_interval: Duration::from_secs(2),
            max_interval: Duration::from_secs(64), // RFC 2131 suggests 64s max for initial requests
        }
    }

    /// Reset retry state
    pub fn reset(&mut self) {
        self.attempt = 0;
        self.last_attempt = Instant::now();
    }

    /// Record a retry attempt
    pub fn record_attempt(&mut self) {
        self.attempt += 1;
        self.last_attempt = Instant::now();
    }

    /// Get the next retry interval using exponential backoff
    pub fn next_interval(&self) -> Duration {
        use rand::Rng;
        let base_interval = self.base_interval * 2_u32.pow(self.attempt.min(6)); // Cap at 2^6
        let interval = if base_interval > self.max_interval {
            self.max_interval
        } else {
            base_interval
        };

        let mut rng = rand::thread_rng();
        let randomized_interval = interval.as_millis() as i64 + rng.gen_range(-500..=500) as i64; // -0.5 to +0.5 seconds in milliseconds
        Duration::from_millis(randomized_interval as u64)
    }
}
