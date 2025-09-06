//! DHCP message serialization module.

use std::{io, mem, net::Ipv4Addr};

use bytes::{Buf, BufMut};

use super::{
    constants::*,
    options::{OptionTag, Overload as OverloadEnum},
    Message,
};

/// Checks if there is enough space in buffer to put a value.
macro_rules! check_remaining(
    ($cursor:expr, $distance:expr) => (
        if $cursor.remaining() < $distance {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "No more space left"));
        }
    )
);

/// The tag octet and the length octet.
const SIZE_OPTION_PREFIX: usize = 2;
/// The end octet which may occur after any option.
const SIZE_OPTION_SUFFIX: usize = 1;
/// Both of the above.
const SIZE_OPTION_AFFIXES: usize = SIZE_OPTION_PREFIX + SIZE_OPTION_SUFFIX;

/// The overload option which is written last by the main cursor.
const SIZE_OPTION_OVERLOAD: usize = mem::size_of::<u8>() * 3;
/// The above and the required space for the `overload` option, which is written last.
const SIZE_OPTION_MAIN_AFFIXES: usize = SIZE_OPTION_AFFIXES + SIZE_OPTION_OVERLOAD;

/// The maximal option size.
const SIZE_OPTION_MAX: usize = 255;

/// The boot filename cursor position in the cursors array.
const CURSOR_INDEX_FILE: usize = 0;
/// The server name cursor position in the cursors array.
const CURSOR_INDEX_SNAME: usize = 1;
/// The main cursor position in the cursors array.
const CURSOR_INDEX_MAIN: usize = 2;
/// The cursors array size.
const CURSOR_INDEX_TOTAL: usize = 3;

impl Message {
    /// DHCP message serialization.
    ///
    /// Options encoded with `put_opt_*` methods called with the `?`
    /// operator are mandatory and throw an error on unsuccessful write.
    /// Options encoded with `put_opt_*` methods called without the `?` operator are optional
    /// and are written to the packet only if there is enough space left.
    /// The order of options and behavior of the encoder may be changed in the future.
    ///
    /// If `max_size` is specified, `dst` is truncated to it.
    ///
    /// # Errors
    /// `io::Error` if the buffer is too small.
    pub fn to_bytes(&self, dst: &mut [u8], max_size: Option<u16>) -> io::Result<usize> {
        use OptionTag::*;

        // the slice is truncated to the maximal client message size
        let dst = if let Some(max_size) = max_size {
            &mut dst[..((max_size as usize) - SIZE_HEADER_IP - SIZE_HEADER_UDP)]
        } else {
            dst
        };

        // cursors are initialized in the way they must be filled
        let mut cursors: [io::Cursor<&mut [u8]>; CURSOR_INDEX_TOTAL] = [
            io::Cursor::new(unsafe { &mut *(&mut dst[OFFSET_BOOT_FILENAME..OFFSET_MAGIC_COOKIE] as *mut [u8]) }),
            io::Cursor::new(unsafe { &mut *(&mut dst[OFFSET_SERVER_NAME..OFFSET_BOOT_FILENAME] as *mut [u8]) }),
            io::Cursor::new(unsafe { &mut *(dst as *mut [u8]) }),
        ];

        check_remaining!(cursors[CURSOR_INDEX_MAIN], OFFSET_OPTIONS);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.operation_code as u8);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.hardware_type as u8);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.hardware_address_length);
        cursors[CURSOR_INDEX_MAIN].put_u8(self.hardware_options);
        cursors[CURSOR_INDEX_MAIN].put_u32_be(self.transaction_id);
        cursors[CURSOR_INDEX_MAIN].put_u16_be(self.seconds);
        // https://tools.ietf.org/html/rfc2131#section-2
        // https://tools.ietf.org/html/rfc1700#page-3
        // Leftmost bit (0 bit) is most significant
        cursors[CURSOR_INDEX_MAIN].put_u16_be(if self.is_broadcast { 0x8000 } else { 0x0000 });
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.client_ip_address));
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.your_ip_address));
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.server_ip_address));
        cursors[CURSOR_INDEX_MAIN].put_u32_be(u32::from(self.gateway_ip_address));
        cursors[CURSOR_INDEX_MAIN].put(self.client_hardware_address.as_bytes()); // 6 byte MAC-48
        cursors[CURSOR_INDEX_MAIN].put(vec![0u8; SIZE_HARDWARE_ADDRESS - self.client_hardware_address.as_bytes().len()]); // 10 byte padding
        cursors[CURSOR_INDEX_MAIN].put(&self.server_name);
        cursors[CURSOR_INDEX_MAIN].put(vec![0u8; SIZE_SERVER_NAME - self.server_name.len()]); // (64 - length) byte padding
        cursors[CURSOR_INDEX_MAIN].put(&self.boot_filename);
        cursors[CURSOR_INDEX_MAIN].put(vec![0u8; SIZE_BOOT_FILENAME - self.boot_filename.len()]); // (128 - length) byte padding
        cursors[CURSOR_INDEX_MAIN].put_u32_be(MAGIC_COOKIE);

        // the most important and required options are encoded first
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            DhcpMessageType,
            &self.options.dhcp_message_type.to_owned().map(|v| v as u8),
        )?;
        Self::put_opt_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            DhcpMaxMessageSize,
            &self.options.dhcp_max_message_size,
        )?;
        Self::put_opt_ipv4(&mut cursors[CURSOR_INDEX_MAIN], DhcpServerId, &self.options.dhcp_server_id)?;
        Self::put_opt_ipv4(&mut cursors[CURSOR_INDEX_MAIN], AddressRequest, &self.options.address_request)?;
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], AddressTime, &self.options.address_time)?;
        Self::put_opt_vec(&mut cursors[CURSOR_INDEX_MAIN], ParameterList, &self.options.parameter_list)?;
        Self::put_opt_vec(&mut cursors[CURSOR_INDEX_MAIN], ClientId, &self.options.client_id)?;

        // the mandatory implemented network configuration options are encoded next
        Self::put_opt_ipv4(&mut cursors[CURSOR_INDEX_MAIN], SubnetMask, &self.options.subnet_mask)?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            DomainNameServers,
            &self.options.domain_name_servers,
        )?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], Routers, &self.options.routers)?;
        Self::put_opt_vec_ipv4_pairs(&mut cursors[CURSOR_INDEX_MAIN], StaticRoutes, &self.options.static_routes)?;

        // the splittable options are encoded after, leaving space for the 'overload' option
        Self::put_opt_classless_static_routes(&mut cursors, ClasslessStaticRoutes, &self.options.classless_static_routes)?;

        // the overload options is written last by the main cursor
        let overload = if cursors[CURSOR_INDEX_FILE].position() > 0 && cursors[CURSOR_INDEX_SNAME].position() > 0 {
            Some(OverloadEnum::Both)
        } else if cursors[CURSOR_INDEX_FILE].position() > 0 {
            Some(OverloadEnum::File)
        } else if cursors[CURSOR_INDEX_SNAME].position() > 0 {
            Some(OverloadEnum::Sname)
        } else {
            None
        };
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], Overload, &overload.map(|v| v as u8))?;

        // some helpful and optional options are encoded next
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], RenewalTime, &self.options.renewal_time)?;
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], RebindingTime, &self.options.rebinding_time)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], Hostname, &self.options.hostname)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], DhcpMessage, &self.options.dhcp_message)?;

        // unimplemented options are encoded next
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], TimeOffset, &self.options.time_offset)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], TimeServers, &self.options.time_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], NameServers, &self.options.name_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], LogServers, &self.options.log_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], QuotesServers, &self.options.quotes_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], LprServers, &self.options.lpr_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], ImpressServers, &self.options.impress_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], RlpServers, &self.options.rlp_servers)?;
        Self::put_opt_u16(&mut cursors[CURSOR_INDEX_MAIN], BootFileSize, &self.options.boot_file_size)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], MeritDumpFile, &self.options.merit_dump_file)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], DomainName, &self.options.domain_name)?;
        Self::put_opt_ipv4(&mut cursors[CURSOR_INDEX_MAIN], SwapServer, &self.options.swap_server)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], RootPath, &self.options.root_path)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], ExtensionsPath, &self.options.extensions_path)?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], ForwardOnOff, &self.options.forward_on_off)?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            NonLocalSourceRouteOnOff,
            &self.options.non_local_source_route_on_off,
        )?;
        Self::put_opt_vec_ipv4_pairs(&mut cursors[CURSOR_INDEX_MAIN], PolicyFilters, &self.options.policy_filters)?;
        Self::put_opt_u16(
            &mut cursors[CURSOR_INDEX_MAIN],
            MaxDatagramReassemblySize,
            &self.options.max_datagram_reassembly_size,
        )?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], DefaultIpTtl, &self.options.default_ip_ttl)?;
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], MtuTimeout, &self.options.mtu_timeout)?;
        Self::put_opt_vec_u16(&mut cursors[CURSOR_INDEX_MAIN], MtuPlateau, &self.options.mtu_plateau)?;
        Self::put_opt_u16(&mut cursors[CURSOR_INDEX_MAIN], MtuInterface, &self.options.mtu_interface)?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], MtuSubnet, &self.options.mtu_subnet)?;
        Self::put_opt_ipv4(&mut cursors[CURSOR_INDEX_MAIN], BroadcastAddress, &self.options.broadcast_address)?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], MaskRecovery, &self.options.mask_recovery)?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], MaskSupplier, &self.options.mask_supplier)?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            PerformRouterDiscovery,
            &self.options.perform_router_discovery,
        )?;
        Self::put_opt_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            RouterSolicitationAddress,
            &self.options.router_solicitation_address,
        )?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            TrailerEncapsulation,
            &self.options.trailer_encapsulation,
        )?;
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], ArpTimeout, &self.options.arp_timeout)?;
        Self::put_opt_u8(
            &mut cursors[CURSOR_INDEX_MAIN],
            EthernetEncapsulation,
            &self.options.ethernet_encapsulation,
        )?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], DefaultTcpTtl, &self.options.default_tcp_ttl)?;
        Self::put_opt_u32(&mut cursors[CURSOR_INDEX_MAIN], KeepaliveTime, &self.options.keepalive_time)?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], KeepaliveData, &self.options.keepalive_data)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], NisDomain, &self.options.nis_domain)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], NisServers, &self.options.nis_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], NtpServers, &self.options.ntp_servers)?;
        Self::put_opt_vec(&mut cursors[CURSOR_INDEX_MAIN], VendorSpecific, &self.options.vendor_specific)?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetbiosNameServers,
            &self.options.netbios_name_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            NetbiosDistributionServers,
            &self.options.netbios_distribution_servers,
        )?;
        Self::put_opt_u8(&mut cursors[CURSOR_INDEX_MAIN], NetbiosNodeType, &self.options.netbios_node_type)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], NetbiosScope, &self.options.netbios_scope)?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            XWindowFontServers,
            &self.options.x_window_font_servers,
        )?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            XWindowManagerServers,
            &self.options.x_window_manager_servers,
        )?;
        Self::put_opt_vec(&mut cursors[CURSOR_INDEX_MAIN], ClassId, &self.options.class_id)?;
        Self::put_opt_vec(&mut cursors[CURSOR_INDEX_MAIN], NetwareIpDomain, &self.options.netware_ip_domain)?;
        Self::put_opt_vec(&mut cursors[CURSOR_INDEX_MAIN], NetwareIpOption, &self.options.netware_ip_option)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], NisDomainName, &self.options.nis_v3_domain_name)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], NisServerAddress, &self.options.nis_v3_servers)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], ServerName, &self.options.server_name)?;
        Self::put_opt_string(&mut cursors[CURSOR_INDEX_MAIN], BootfileName, &self.options.bootfile_name)?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            HomeAgentAddresses,
            &self.options.home_agent_addresses,
        )?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], SmtpServers, &self.options.smtp_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], Pop3Servers, &self.options.pop3_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], NntpServers, &self.options.nntp_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], WwwServers, &self.options.www_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], FingerServers, &self.options.finger_servers)?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], IrcServers, &self.options.irc_servers)?;
        Self::put_opt_vec_ipv4(
            &mut cursors[CURSOR_INDEX_MAIN],
            StreetTalkServers,
            &self.options.street_talk_servers,
        )?;
        Self::put_opt_vec_ipv4(&mut cursors[CURSOR_INDEX_MAIN], StdaServers, &self.options.stda_servers)?;

        check_remaining!(cursors[CURSOR_INDEX_MAIN], mem::size_of::<u8>());
        cursors[CURSOR_INDEX_MAIN].put_u8(End as u8);
        if cursors[CURSOR_INDEX_FILE].position() > 0 {
            cursors[CURSOR_INDEX_FILE].put_u8(End as u8);
        }
        if cursors[CURSOR_INDEX_SNAME].position() > 0 {
            cursors[CURSOR_INDEX_SNAME].put_u8(End as u8);
        }
        Ok(cursors[CURSOR_INDEX_MAIN].position() as usize)
    }

    /// Cannot be splitted.
    fn put_opt_u8(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<u8>) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u8>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u8(*value);
        }
        Ok(())
    }

    /// Cannot be splitted.
    fn put_opt_u16(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<u16>) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u16>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u16_be(*value);
        }
        Ok(())
    }

    /// Cannot be splitted.
    fn put_opt_u32(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<u32>) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u32_be(*value);
        }
        Ok(())
    }

    /// Cannot be splitted.
    fn put_opt_ipv4(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<Ipv4Addr>) -> io::Result<()> {
        if let Some(ref value) = value {
            let size = mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put_u32_be(u32::from(*value));
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_string(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<String>) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put(value);
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<Vec<u8>>) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            cursor.put(value);
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec_u16(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<Vec<u16>>) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len() * mem::size_of::<u16>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u16_be(*element);
            }
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec_ipv4(cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<Vec<Ipv4Addr>>) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len() * mem::size_of::<u32>();
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.to_owned()));
            }
        }
        Ok(())
    }

    /// Can be splitted.
    fn put_opt_vec_ipv4_pairs(
        cursor: &mut io::Cursor<&mut [u8]>, tag: OptionTag, value: &Option<Vec<(Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }
            let size = value.len() * mem::size_of::<u32>() * 2;
            check_remaining!(cursor, SIZE_OPTION_AFFIXES + size);
            cursor.put_u8(tag as u8);
            cursor.put_u8(size as u8);
            for element in value.iter() {
                cursor.put_u32_be(u32::from(element.0.to_owned()));
                cursor.put_u32_be(u32::from(element.1.to_owned()));
            }
        }
        Ok(())
    }

    /// Can be splitted.
    /// The encoding algorithm explained at [RFC 3442](https://tools.ietf.org/html/rfc3442).
    ///
    /// The option is splitted by default.
    fn put_opt_classless_static_routes(
        cursors: &mut [io::Cursor<&mut [u8]>; CURSOR_INDEX_TOTAL], tag: OptionTag, value: &Option<Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr)>>,
    ) -> io::Result<()> {
        if let Some(ref value) = value {
            if value.is_empty() {
                return Ok(());
            }

            const BITS_IN_BYTE: usize = 8;
            const IPV4_BITSIZE: usize = mem::size_of::<u32>() * BITS_IN_BYTE;
            const MAX_DESCRIPTOR_SIZE: usize = 1 + mem::size_of::<u32>();

            let mut descriptors = Vec::<Vec<u8>>::with_capacity(value.len());
            for element in value.iter() {
                let subnet_number = element.0;
                let i_subnet_mask = u32::from(element.1);
                let mut subnet_mask_size = 0;

                for i in 0..IPV4_BITSIZE {
                    if i_subnet_mask & (1 << i) != 0 {
                        subnet_mask_size = 32 - i;
                        break;
                    }
                }
                let mut descriptor = Vec::<u8>::with_capacity(MAX_DESCRIPTOR_SIZE);
                descriptor.push(subnet_mask_size as u8);
                for i in 0..mem::size_of::<u32>() {
                    if subnet_mask_size > i * BITS_IN_BYTE {
                        descriptor.push(subnet_number.octets()[i]);
                    }
                }
                descriptors.push(descriptor);
            }

            let (mut i, mut j, mut c) = (0, 0, 0); // iterators
            while c < cursors.len() {
                let cursor = &mut cursors[c];
                let affix_len = if c != CURSOR_INDEX_MAIN {
                    SIZE_OPTION_AFFIXES // only the tag, the length and the END
                } else {
                    SIZE_OPTION_MAIN_AFFIXES // also some space for the 'overload' option
                };

                let mut len: usize = 0; // the length to be written by each cursor
                let mut repeat = false;
                while j < descriptors.len() {
                    let size = descriptors.get(j).unwrap().len() + mem::size_of::<u32>();

                    // find the range that can be written to the current buffer and the current option instance
                    if cursor.remaining() >= affix_len + len + size && len + size <= SIZE_OPTION_MAX {
                        len += size;
                        j += 1;
                    } else {
                        repeat = len + size > SIZE_OPTION_MAX;
                        break;
                    }
                }

                if len > 0 {
                    cursor.put_u8(tag as u8);
                    cursor.put_u8(len as u8);
                    for k in i..j {
                        cursor.put(descriptors.get(k).unwrap());
                        cursor.put_u32_be(u32::from(value.get(k).unwrap().2.to_owned()));
                    }
                    i = j;
                    if !repeat {
                        c += 1;
                    }
                }

                if j >= descriptors.len() {
                    break;
                }
            }
            if j < descriptors.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "No more space left"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HardwareType, MessageType, OperationCode, Options};
    use eui48::MacAddress;
    use std::net::Ipv4Addr;

    fn create_test_message() -> Message {
        let mut options = Options::default();
        options.dhcp_message_type = Some(MessageType::DhcpDiscover);
        options.dhcp_max_message_size = Some(1500);

        Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: 6,
            hardware_options: 0,
            transaction_id: 0x12345678,
            seconds: 0,
            is_broadcast: true,
            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            server_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            client_hardware_address: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            server_name: vec![0; 64],
            boot_filename: vec![0; 128],
            options,
        }
    }

    #[test]
    fn test_to_bytes_basic_structure() {
        let message = create_test_message();
        let mut buffer = vec![0u8; 1024];

        let result = message.to_bytes(&mut buffer, None);
        assert!(result.is_ok());
        let bytes_written = result.unwrap();
        assert!(bytes_written > 0);

        // Test fixed header structure (240 bytes + options)
        // Operation code (1 byte)
        assert_eq!(buffer[0], OperationCode::BootRequest as u8);

        // Hardware type (1 byte)
        assert_eq!(buffer[1], HardwareType::Ethernet as u8);

        // Hardware address length (1 byte)
        assert_eq!(buffer[2], 6);

        // Hardware options (1 byte)
        assert_eq!(buffer[3], 0);

        // Transaction ID (4 bytes, big-endian)
        let xid_bytes = [
            (0x12345678u32 >> 24) as u8,
            (0x12345678u32 >> 16) as u8,
            (0x12345678u32 >> 8) as u8,
            (0x12345678u32 & 0xFF) as u8,
        ];
        assert_eq!(&buffer[4..8], &xid_bytes);

        // Seconds (2 bytes)
        assert_eq!(&buffer[8..10], &[0, 0]);

        // Broadcast flag (2 bytes, big-endian with leftmost bit set)
        assert_eq!(&buffer[10..12], &[0x80, 0x00]);

        // IP addresses (4 bytes each, all zeros in this test)
        assert_eq!(&buffer[12..16], &[0, 0, 0, 0]); // client_ip_address
        assert_eq!(&buffer[16..20], &[0, 0, 0, 0]); // your_ip_address
        assert_eq!(&buffer[20..24], &[0, 0, 0, 0]); // server_ip_address
        assert_eq!(&buffer[24..28], &[0, 0, 0, 0]); // gateway_ip_address

        // Client hardware address (16 bytes total, 6 bytes MAC + 10 bytes padding)
        assert_eq!(&buffer[28..34], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&buffer[34..44], &[0; 10]); // padding

        // Server name (64 bytes, all zeros)
        assert_eq!(&buffer[44..108], &[0; 64]);

        // Boot filename (128 bytes, all zeros)
        assert_eq!(&buffer[108..236], &[0; 128]);

        // Magic cookie (4 bytes)
        assert_eq!(&buffer[236..240], &[99, 130, 83, 99]);
    }

    #[test]
    fn test_to_bytes_dhcp_options() {
        let message = create_test_message();
        let mut buffer = vec![0u8; 1024];

        let result = message.to_bytes(&mut buffer, None);
        assert!(result.is_ok());

        // Look for DHCP message type option after magic cookie
        let options_start = 240; // After fixed header + magic cookie

        // Find DHCP Message Type option (tag 53)
        let mut found_message_type = false;
        let mut found_max_message_size = false;
        let mut pos = options_start;

        while pos < buffer.len() - 2 {
            let tag = buffer[pos];
            if tag == 255 {
                // End option
                break;
            }

            let length = buffer[pos + 1] as usize;

            match tag {
                53 => {
                    // DHCP Message Type
                    assert_eq!(length, 1);
                    assert_eq!(buffer[pos + 2], MessageType::DhcpDiscover as u8);
                    found_message_type = true;
                }
                57 => {
                    // DHCP Maximum Message Size
                    assert_eq!(length, 2);
                    let max_size = ((buffer[pos + 2] as u16) << 8) | (buffer[pos + 3] as u16);
                    assert_eq!(max_size, 1500);
                    found_max_message_size = true;
                }
                _ => {
                    // Skip other options
                }
            }

            pos += 2 + length;
        }

        assert!(found_message_type, "DHCP Message Type option not found");
        assert!(found_max_message_size, "DHCP Max Message Size option not found");
    }

    #[test]
    fn test_to_bytes_with_max_size_limit() {
        let message = create_test_message();
        let mut buffer = vec![0u8; 1024];

        // Test with size limit
        let result = message.to_bytes(&mut buffer, Some(300));
        assert!(result.is_ok());
        let bytes_written = result.unwrap();

        // Should fit within the limit (300 - IP header - UDP header)
        let effective_limit = 300 - SIZE_HEADER_IP - SIZE_HEADER_UDP;
        assert!(bytes_written <= effective_limit);
    }

    #[test]
    fn test_to_bytes_message_with_ip_addresses() {
        let mut message = create_test_message();
        message.client_ip_address = Ipv4Addr::new(192, 168, 1, 100);
        message.your_ip_address = Ipv4Addr::new(192, 168, 1, 101);
        message.server_ip_address = Ipv4Addr::new(192, 168, 1, 1);
        message.gateway_ip_address = Ipv4Addr::new(192, 168, 1, 1);

        let mut buffer = vec![0u8; 1024];
        let result = message.to_bytes(&mut buffer, None);
        assert!(result.is_ok());

        // Check IP addresses in the serialized output
        assert_eq!(&buffer[12..16], &[192, 168, 1, 100]); // client_ip_address
        assert_eq!(&buffer[16..20], &[192, 168, 1, 101]); // your_ip_address
        assert_eq!(&buffer[20..24], &[192, 168, 1, 1]); // server_ip_address
        assert_eq!(&buffer[24..28], &[192, 168, 1, 1]); // gateway_ip_address
    }

    #[test]
    fn test_to_bytes_request_message() {
        let mut message = create_test_message();
        message.operation_code = OperationCode::BootReply;
        message.options.dhcp_message_type = Some(MessageType::DhcpAck);
        message.options.dhcp_server_id = Some(Ipv4Addr::new(192, 168, 1, 1));
        message.options.address_time = Some(3600);
        message.your_ip_address = Ipv4Addr::new(192, 168, 1, 100);

        let mut buffer = vec![0u8; 1024];
        let result = message.to_bytes(&mut buffer, None);
        assert!(result.is_ok());

        // Verify operation code changed
        assert_eq!(buffer[0], OperationCode::BootReply as u8);

        // Verify your_ip_address is set
        assert_eq!(&buffer[16..20], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        // Create a comprehensive test message with various fields and options
        let mut options = Options::default();
        options.dhcp_message_type = Some(MessageType::DhcpRequest);
        options.dhcp_max_message_size = Some(1500);
        options.dhcp_server_id = Some(Ipv4Addr::new(192, 168, 1, 1));
        options.address_request = Some(Ipv4Addr::new(192, 168, 1, 100));
        options.address_time = Some(3600);
        options.renewal_time = Some(1800);
        options.rebinding_time = Some(3150);
        options.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
        options.routers = Some(vec![Ipv4Addr::new(192, 168, 1, 1)]);
        options.domain_name_servers = Some(vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]);

        let original_message = Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: 6,
            hardware_options: 0,
            transaction_id: 0xDEADBEEF,
            seconds: 42,
            is_broadcast: true,
            client_ip_address: Ipv4Addr::new(0, 0, 0, 0),
            your_ip_address: Ipv4Addr::new(192, 168, 1, 100),
            server_ip_address: Ipv4Addr::new(192, 168, 1, 1),
            gateway_ip_address: Ipv4Addr::new(192, 168, 1, 1),
            client_hardware_address: MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            server_name: b"test-server.example.com".to_vec(),
            boot_filename: b"/boot/pxelinux.0".to_vec(),
            options,
        };

        // Serialize to bytes
        let mut buffer = vec![0u8; 1024];
        let serialize_result = original_message.to_bytes(&mut buffer, None);
        assert!(serialize_result.is_ok());
        let bytes_written = serialize_result.unwrap();
        assert!(bytes_written > 0);

        // Deserialize back from bytes
        let deserialize_result = Message::from_bytes(&buffer[..bytes_written]);
        assert!(deserialize_result.is_ok());
        let deserialized_message = deserialize_result.unwrap();

        // Compare all fields
        assert_eq!(original_message.operation_code, deserialized_message.operation_code);
        assert_eq!(original_message.hardware_type, deserialized_message.hardware_type);
        assert_eq!(
            original_message.hardware_address_length,
            deserialized_message.hardware_address_length
        );
        assert_eq!(original_message.hardware_options, deserialized_message.hardware_options);
        assert_eq!(original_message.transaction_id, deserialized_message.transaction_id);
        assert_eq!(original_message.seconds, deserialized_message.seconds);
        assert_eq!(original_message.is_broadcast, deserialized_message.is_broadcast);
        assert_eq!(original_message.client_ip_address, deserialized_message.client_ip_address);
        assert_eq!(original_message.your_ip_address, deserialized_message.your_ip_address);
        assert_eq!(original_message.server_ip_address, deserialized_message.server_ip_address);
        assert_eq!(original_message.gateway_ip_address, deserialized_message.gateway_ip_address);
        assert_eq!(
            original_message.client_hardware_address,
            deserialized_message.client_hardware_address
        );

        // Compare server_name and boot_filename (Note: these might be padded with zeros)
        // We'll compare just the non-zero portions
        let original_server_name = original_message
            .server_name
            .iter()
            .take_while(|&&b| b != 0)
            .cloned()
            .collect::<Vec<u8>>();
        let deserialized_server_name = deserialized_message
            .server_name
            .iter()
            .take_while(|&&b| b != 0)
            .cloned()
            .collect::<Vec<u8>>();
        assert_eq!(original_server_name, deserialized_server_name);

        let original_boot_filename = original_message
            .boot_filename
            .iter()
            .take_while(|&&b| b != 0)
            .cloned()
            .collect::<Vec<u8>>();
        let deserialized_boot_filename = deserialized_message
            .boot_filename
            .iter()
            .take_while(|&&b| b != 0)
            .cloned()
            .collect::<Vec<u8>>();
        assert_eq!(original_boot_filename, deserialized_boot_filename);

        // Compare options
        assert_eq!(
            original_message.options.dhcp_message_type,
            deserialized_message.options.dhcp_message_type
        );
        assert_eq!(
            original_message.options.dhcp_max_message_size,
            deserialized_message.options.dhcp_max_message_size
        );
        assert_eq!(original_message.options.dhcp_server_id, deserialized_message.options.dhcp_server_id);
        assert_eq!(
            original_message.options.address_request,
            deserialized_message.options.address_request
        );
        assert_eq!(original_message.options.address_time, deserialized_message.options.address_time);
        assert_eq!(original_message.options.renewal_time, deserialized_message.options.renewal_time);
        assert_eq!(original_message.options.rebinding_time, deserialized_message.options.rebinding_time);
        assert_eq!(original_message.options.subnet_mask, deserialized_message.options.subnet_mask);
        assert_eq!(original_message.options.routers, deserialized_message.options.routers);
        assert_eq!(
            original_message.options.domain_name_servers,
            deserialized_message.options.domain_name_servers
        );
    }

    #[test]
    fn test_serialize_deserialize_minimal_message() {
        // Test with minimal message (only required fields)
        let mut options = Options::default();
        options.dhcp_message_type = Some(MessageType::DhcpDiscover);

        let original_message = Message {
            operation_code: OperationCode::BootRequest,
            hardware_type: HardwareType::Ethernet,
            hardware_address_length: 6,
            hardware_options: 0,
            transaction_id: 0x12345678,
            seconds: 0,
            is_broadcast: false,
            client_ip_address: Ipv4Addr::UNSPECIFIED,
            your_ip_address: Ipv4Addr::UNSPECIFIED,
            server_ip_address: Ipv4Addr::UNSPECIFIED,
            gateway_ip_address: Ipv4Addr::UNSPECIFIED,
            client_hardware_address: MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            server_name: vec![0; 64],
            boot_filename: vec![0; 128],
            options,
        };

        // Serialize to bytes
        let mut buffer = vec![0u8; 1024];
        let serialize_result = original_message.to_bytes(&mut buffer, None);
        assert!(serialize_result.is_ok());
        let bytes_written = serialize_result.unwrap();

        // Deserialize back from bytes
        let deserialize_result = Message::from_bytes(&buffer[..bytes_written]);
        assert!(deserialize_result.is_ok());
        let deserialized_message = deserialize_result.unwrap();

        // Key fields should match
        assert_eq!(original_message.operation_code, deserialized_message.operation_code);
        assert_eq!(original_message.transaction_id, deserialized_message.transaction_id);
        assert_eq!(
            original_message.client_hardware_address,
            deserialized_message.client_hardware_address
        );
        assert_eq!(
            original_message.options.dhcp_message_type,
            deserialized_message.options.dhcp_message_type
        );
    }

    #[test]
    fn test_serialize_deserialize_broadcast_flag() {
        // Test that broadcast flag is correctly preserved
        let mut options = Options::default();
        options.dhcp_message_type = Some(MessageType::DhcpDiscover);

        let mut original_message = create_test_message();
        original_message.is_broadcast = true;

        // Serialize to bytes
        let mut buffer = vec![0u8; 1024];
        let serialize_result = original_message.to_bytes(&mut buffer, None);
        assert!(serialize_result.is_ok());
        let bytes_written = serialize_result.unwrap();

        // Deserialize back from bytes
        let deserialize_result = Message::from_bytes(&buffer[..bytes_written]);
        assert!(deserialize_result.is_ok());
        let deserialized_message = deserialize_result.unwrap();

        // Broadcast flag should be preserved
        assert_eq!(original_message.is_broadcast, deserialized_message.is_broadcast);
        assert_eq!(true, deserialized_message.is_broadcast);

        // Test with broadcast = false
        original_message.is_broadcast = false;
        let serialize_result = original_message.to_bytes(&mut buffer, None);
        assert!(serialize_result.is_ok());
        let bytes_written = serialize_result.unwrap();

        let deserialize_result = Message::from_bytes(&buffer[..bytes_written]);
        assert!(deserialize_result.is_ok());
        let deserialized_message = deserialize_result.unwrap();

        assert_eq!(false, deserialized_message.is_broadcast);
    }
}
