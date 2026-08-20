//! DHCPv6 client (RFC 8415) — stateful IA_NA only.

pub mod builder;
pub mod client;
pub mod duid;
pub mod lifecycle;
pub mod socket;
pub mod state;

pub use self::client::{ClientV6, ClientV6Error};
pub use self::state::{DhcpV6State, IaState, IaType};
