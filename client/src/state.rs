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
    pub renewal_time: Option<u32>,
    /// Time to start rebinding (T2) in seconds from lease start  
    pub rebinding_time: Option<u32>,
}

impl LeaseInfo {
    /// Create new lease information
    pub fn new(
        assigned_ip: Ipv4Addr,
        server_id: Ipv4Addr,
        lease_time: u32,
        renewal_time: Option<u32>,
        rebinding_time: Option<u32>,
    ) -> Self {
        Self {
            assigned_ip,
            server_id,
            lease_start: Instant::now(),
            lease_time,
            renewal_time,
            rebinding_time,
        }
    }

    /// Get the T1 time (when to start renewal)
    /// RFC 2131: defaults to 0.5 * lease_time if not provided
    pub fn t1(&self) -> u32 {
        self.renewal_time.unwrap_or(self.lease_time / 2)
    }

    /// Get the T2 time (when to start rebinding)  
    /// RFC 2131: defaults to 0.875 * lease_time if not provided
    pub fn t2(&self) -> u32 {
        self.rebinding_time.unwrap_or(self.lease_time * 7 / 8)
    }

    /// Time until renewal should start (T1)
    pub fn time_until_renewal(&self) -> Duration {
        let elapsed = self.lease_start.elapsed().as_secs() as u32;
        let t1 = self.t1();
        if elapsed >= t1 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs((t1 - elapsed) as u64)
        }
    }

    /// Time until rebinding should start (T2)
    pub fn time_until_rebinding(&self) -> Duration {
        let elapsed = self.lease_start.elapsed().as_secs() as u32;
        let t2 = self.t2();
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

    /// Get remaining time in current phase for retry calculation
    pub fn remaining_time_in_phase(&self, state: DhcpState) -> Duration {
        match state {
            DhcpState::Renewing => {
                // Time remaining until T2
                let time_to_rebind = self.time_until_rebinding();
                if time_to_rebind.is_zero() {
                    Duration::from_secs(0)
                } else {
                    time_to_rebind
                }
            }
            DhcpState::Rebinding => {
                // Time remaining until lease expiry
                self.time_until_expiry()
            }
            _ => Duration::from_secs(0),
        }
    }

    /// Calculate retry interval according to RFC 2131 section 4.4.3
    /// 
    /// "In both RENEWING and REBINDING states, if the client receives no
    /// response to its DHCPREQUEST message, the client SHOULD wait one-half
    /// of the remaining time until T2 (in RENEWING state) and one-half of
    /// the remaining lease time (in REBINDING state), down to a minimum of
    /// 60 seconds, before retransmitting the DHCPREQUEST message."
    pub fn retry_interval(&self, state: DhcpState) -> Duration {
        let remaining = self.remaining_time_in_phase(state);
        let half_remaining = remaining / 2;
        
        // Minimum 60 seconds as per RFC
        let min_interval = Duration::from_secs(60);
        
        if half_remaining < min_interval {
            min_interval
        } else {
            half_remaining
        }
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
    pub fn new(base_interval: Duration) -> Self {
        Self {
            attempt: 0,
            last_attempt: Instant::now(),
            base_interval,
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
    /// For initial DHCP requests (DISCOVER/REQUEST), uses exponential backoff
    /// For lease renewal/rebinding, uses RFC 2131 specific calculation
    pub fn next_interval(&self, lease_info: Option<&LeaseInfo>, state: DhcpState) -> Duration {
        match (lease_info, state) {
            // Use RFC 2131 specific retry logic for renewal/rebinding
            (Some(lease), DhcpState::Renewing) | (Some(lease), DhcpState::Rebinding) => {
                lease.retry_interval(state)
            }
            // Use exponential backoff for initial requests with randomization
            _ => {
                use rand::Rng;
                let base_interval = self.base_interval * 2_u32.pow(self.attempt.min(6)); // Cap at 2^6
                let interval = if base_interval > self.max_interval {
                    self.max_interval
                } else {
                    base_interval
                };
                
                // Add randomization: -0.5 to +0.5 seconds as per RFC suggestion
                let mut rng = rand::thread_rng();
                let randomization_ms = rng.gen_range(-500..=500); // -0.5 to +0.5 seconds in milliseconds
                let randomized_interval = interval.as_millis() as i64 + randomization_ms as i64;
                
                // Ensure we don't go negative
                let final_ms = randomized_interval.max(100) as u64; // Minimum 100ms
                Duration::from_millis(final_ms)
            }
        }
    }

    /// Check if enough time has passed for next retry
    pub fn should_retry(&self, lease_info: Option<&LeaseInfo>, state: DhcpState) -> bool {
        let interval = self.next_interval(lease_info, state);
        self.last_attempt.elapsed() >= interval
    }
}