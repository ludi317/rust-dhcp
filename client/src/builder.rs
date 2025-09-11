//! A builder for common DHCP client messages.

use std::net::Ipv4Addr;

use eui48::{MacAddress, EUI48LEN};

use dhcp_protocol::*;

const MAX_MESSAGE_SIZE: Option<u16> = Some(1280);

/// Builds common client messages with some parameters.
pub struct MessageBuilder {
    /// Mandatory `MAC-48` address.
    client_hardware_address: MacAddress,
    /// The optional machine hostname.
    hostname: Option<String>,
}

impl MessageBuilder {
    /// Creates a builder with message parameters which will not be changed.
    pub fn new(client_hardware_address: MacAddress, hostname: Option<String>) -> Self {
        MessageBuilder {
            client_hardware_address,
            hostname,
        }
    }

    /// Creates a general `DHCPDISCOVER` message.
    pub fn discover(&self, transaction_id: u32, address_request: Option<Ipv4Addr>, address_time: Option<u32>) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpDiscover);
        options.dhcp_max_message_size = MAX_MESSAGE_SIZE;
        options.parameter_list = Some(Self::parameter_list());
        options.address_request = address_request;
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `SELECTING` state.
    pub fn request_selecting(
        &self, transaction_id: u32, address_request: Ipv4Addr, address_time: Option<u32>, dhcp_server_id: Ipv4Addr,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = MAX_MESSAGE_SIZE;
        options.dhcp_server_id = Some(dhcp_server_id);
        options.parameter_list = Some(Self::parameter_list());
        options.address_request = Some(address_request);
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `INIT-REBOOT` state.
    pub fn request_init_reboot(&self, transaction_id: u32, address_request: Ipv4Addr, address_time: Option<u32>) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = MAX_MESSAGE_SIZE;
        options.parameter_list = Some(Self::parameter_list());
        options.address_request = Some(address_request);
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a `DHCPREQUEST` in `BOUND`, `RENEWING` or `REBINDING` state.
    pub fn request_renew(&self, transaction_id: u32, client_ip_address: Ipv4Addr, address_time: Option<u32>) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = MAX_MESSAGE_SIZE;
        options.parameter_list = Some(Self::parameter_list());
        options.address_time = address_time;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address,
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a general `DHCPINFORM` message.
    pub fn inform(&self, transaction_id: u32, client_ip_address: Ipv4Addr) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpInform);
        options.dhcp_max_message_size = MAX_MESSAGE_SIZE;
        options.parameter_list = Some(Self::parameter_list());

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address,
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a general `DHCPRELEASE` message.
    pub fn release(
        &self, transaction_id: u32, client_ip_address: Ipv4Addr, dhcp_server_id: Ipv4Addr, dhcp_message: Option<String>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpRelease);
        options.dhcp_max_message_size = MAX_MESSAGE_SIZE;
        options.dhcp_server_id = Some(dhcp_server_id);
        options.dhcp_message = dhcp_message;

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address,
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    /// Creates a general `DHCPDECLINE` message.
    pub fn decline(
        &self, transaction_id: u32, requested_address: Ipv4Addr, dhcp_server_id: Ipv4Addr, dhcp_message: Option<String>,
    ) -> Message {
        let mut options = Options::default();
        self.append_default_options(&mut options);

        options.dhcp_message_type = Some(MessageType::DhcpDecline);
        options.dhcp_server_id = Some(dhcp_server_id);
        options.dhcp_message = dhcp_message;
        options.address_request = Some(requested_address);

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: EUI48LEN as u8,
            hardware_options: Default::default(),

            transaction_id,
            seconds: Default::default(),
            is_broadcast: false,

            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),

            client_hardware_address: self.client_hardware_address.to_owned(),
            server_name: Default::default(),
            boot_filename: Default::default(),

            options,
        }
    }

    fn append_default_options(&self, options: &mut Options) {
        options.hostname = self.hostname.to_owned();
    }

    fn parameter_list() -> Vec<u8> {
        vec![
            OptionTag::SubnetMask as u8,
            OptionTag::ClasslessStaticRoutes as u8,
            OptionTag::Routers as u8,
            OptionTag::DomainNameServers as u8,
            OptionTag::DomainName as u8,
            OptionTag::NtpServers as u8,
        ]
    }
}
