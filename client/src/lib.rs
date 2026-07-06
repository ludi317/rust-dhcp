//! Modern async DHCP client implementation.

mod builder;
mod client;
mod dns;
pub mod netlink;
mod ntp;
mod state;
pub mod v6;

// Re-export the main types
pub use self::client::{Client, ClientError};
pub use self::state::{DhcpState, LeaseInfo};
pub use self::v6::{ClientV6, ClientV6Error, DhcpV6State};

