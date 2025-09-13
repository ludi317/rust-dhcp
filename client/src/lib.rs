//! Modern async DHCP client implementation.

mod builder;
mod client;
pub mod netlink;
mod state;
pub mod utils;

use std::str::FromStr;
// Re-export the main types
pub use self::client::{Client, ClientError};
pub use self::state::{DhcpState, LeaseInfo};

