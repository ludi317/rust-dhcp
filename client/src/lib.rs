//! Modern async DHCP client implementation.

mod builder;
mod client;
mod dns;
pub mod netlink;
mod ntp;
mod state;

use std::str::FromStr;
// Re-export the main types
pub use self::client::{Client, ClientError};
pub use self::state::{DhcpState, LeaseInfo};

