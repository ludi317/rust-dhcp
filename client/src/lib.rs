//! Modern async DHCP client implementation.

mod builder;
mod client;
mod state;
pub mod utils;
pub mod network;
pub mod config;

use std::net::Ipv4Addr;
use std::str::FromStr;
// Re-export the main types
pub use self::client::{Client, ClientError};
pub use self::state::{DhcpState, LeaseInfo};

/// DHCP configuration result from a successful lease.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub your_ip_address: std::net::Ipv4Addr,
    pub server_ip_address: std::net::Ipv4Addr,
    pub subnet_mask: Option<std::net::Ipv4Addr>,
    pub routers: Option<Vec<std::net::Ipv4Addr>>,
    pub domain_name_servers: Option<Vec<std::net::Ipv4Addr>>,
    pub static_routes: Option<Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)>>,
    pub classless_static_routes: Option<Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr, std::net::Ipv4Addr)>>,
}

impl Configuration {
    pub fn from_response(mut response: dhcp_protocol::Message) -> Self {
        /*
        RFC 3442
        If the DHCP server returns both a Classless Static Routes option and
        a Router option, the DHCP client MUST ignore the Router option.
        Similarly, if the DHCP server returns both a Classless Static Routes
        option and a Static Routes option, the DHCP client MUST ignore the
        Static Routes option.
        */
        if response.options.classless_static_routes.is_some() {
            response.options.routers = None;
            response.options.static_routes = None;
        }

        Configuration {
            // your_ip_address: response.your_ip_address,
            your_ip_address: Ipv4Addr::from_str("192.168.65.4").unwrap(),
            // Use DHCP server ID from options if available, otherwise fall back to server_ip_address
            server_ip_address: response.options.dhcp_server_id.unwrap_or(response.server_ip_address),
            subnet_mask: response.options.subnet_mask,
            routers: response.options.routers,
            domain_name_servers: response.options.domain_name_servers,
            static_routes: response.options.static_routes,
            classless_static_routes: response.options.classless_static_routes,
        }
    }
}