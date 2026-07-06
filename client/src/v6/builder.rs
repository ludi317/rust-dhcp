//! DHCPv6 message construction via `dhcproto`.

use dhcproto::v6::{DhcpOption, IAAddr, Message, MessageType, OptionCode, IANA, ORO};
use std::net::Ipv6Addr;
use std::time::Duration;

use crate::v6::state::{IaContents, IaLease, IaState};

fn oro_dns_and_domain() -> ORO {
    ORO {
        opts: vec![OptionCode::DomainNameServers, OptionCode::DomainSearchList],
    }
}

/// Build a SOLICIT message for a fresh IA_NA acquisition.
pub fn build_solicit(client_duid: &[u8], xid: [u8; 3], ia: &IaState, elapsed_centis: u16) -> Message {
    let mut msg = Message::new_with_id(MessageType::Solicit, xid);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(client_duid.to_vec()));
    opts.insert(DhcpOption::ElapsedTime(elapsed_centis));
    opts.insert(DhcpOption::IANA(IANA {
        id: ia.iaid,
        t1: 0,
        t2: 0,
        opts: Default::default(),
    }));
    opts.insert(DhcpOption::ORO(oro_dns_and_domain()));
    msg
}

/// Build a REQUEST message that echoes a chosen server's IA_NA.
pub fn build_request(
    client_duid: &[u8], server_duid: &[u8], xid: [u8; 3], ia: &IaState, advertised_addrs: &[(Ipv6Addr, u32, u32)],
    elapsed_centis: u16,
) -> Message {
    let mut msg = Message::new_with_id(MessageType::Request, xid);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(client_duid.to_vec()));
    opts.insert(DhcpOption::ServerId(server_duid.to_vec()));
    opts.insert(DhcpOption::ElapsedTime(elapsed_centis));

    let mut iana = IANA {
        id: ia.iaid,
        t1: 0,
        t2: 0,
        opts: Default::default(),
    };
    for (addr, preferred, valid) in advertised_addrs {
        iana.opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: *addr,
            preferred_life: *preferred,
            valid_life: *valid,
            opts: Default::default(),
        }));
    }
    opts.insert(DhcpOption::IANA(iana));
    opts.insert(DhcpOption::ORO(oro_dns_and_domain()));
    msg
}

/// Build a RENEW or REBIND message for an existing lease.
pub fn build_renew_or_rebind(
    msg_type: MessageType, client_duid: &[u8], server_duid: Option<&[u8]>, xid: [u8; 3], ia: &IaState,
    lease: &IaLease, elapsed_centis: u16,
) -> Message {
    let mut msg = Message::new_with_id(msg_type, xid);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(client_duid.to_vec()));
    if let Some(sd) = server_duid {
        opts.insert(DhcpOption::ServerId(sd.to_vec()));
    }
    opts.insert(DhcpOption::ElapsedTime(elapsed_centis));

    let mut iana = IANA {
        id: ia.iaid,
        t1: 0,
        t2: 0,
        opts: Default::default(),
    };
    if let IaContents::Addresses(addrs) = &lease.contents {
        for a in addrs {
            iana.opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: a.addr,
                preferred_life: secs_u32(a.preferred_lifetime),
                valid_life: secs_u32(a.valid_lifetime),
                opts: Default::default(),
            }));
        }
    }
    opts.insert(DhcpOption::IANA(iana));
    msg
}

/// Build a RELEASE message echoing the bound IA_NA.
pub fn build_release(
    client_duid: &[u8], server_duid: &[u8], xid: [u8; 3], ia: &IaState, lease: &IaLease,
) -> Message {
    let mut msg = Message::new_with_id(MessageType::Release, xid);
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::ClientId(client_duid.to_vec()));
    opts.insert(DhcpOption::ServerId(server_duid.to_vec()));
    opts.insert(DhcpOption::ElapsedTime(0));

    let mut iana = IANA {
        id: ia.iaid,
        t1: 0,
        t2: 0,
        opts: Default::default(),
    };
    if let IaContents::Addresses(addrs) = &lease.contents {
        for a in addrs {
            iana.opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: a.addr,
                preferred_life: secs_u32(a.preferred_lifetime),
                valid_life: secs_u32(a.valid_lifetime),
                opts: Default::default(),
            }));
        }
    }
    opts.insert(DhcpOption::IANA(iana));
    msg
}

fn secs_u32(d: Duration) -> u32 {
    d.as_secs().min(u32::MAX as u64) as u32
}
