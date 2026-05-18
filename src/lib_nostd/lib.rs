// SPDX-License-Identifier: Apache-2.0

#![no_std]

mod error;
mod policy;
mod tcp;
mod udp;

pub use self::{
    error::EfenceErrorCode,
    policy::{
        ACTION_DROP, ACTION_PASS, CFG_BLOB_LEN, Ipv4Cidr, MAP_CFG, MAP_CFG_LEN,
        MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION, MAP_TCP_INGRESS_IFACE_TO_LPM,
        MAP_TCP_INGRESS_PORT_ACTION, MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION,
        MAP_UDP_INGRESS_IFACE_TO_LPM, MAP_UDP_INGRESS_PORT_ACTION, MAX_IFACES,
        MAX_PREFIX_PORT_ENTRIES, MAX_PREFIXES, PORT_ANY, PrefixPort,
    },
    tcp::{TCP4_EVENTS_RING_BUF_SIZE, Tcp4EventRaw},
    udp::{UDP4_EVENTS_RING_BUF_SIZE, Udp4EventRaw},
};
