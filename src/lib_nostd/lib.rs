// SPDX-License-Identifier: Apache-2.0

#![no_std]

mod error;
mod policy;
mod tcp;
mod udp;

pub use self::{
    error::EfenceErrorCode,
    policy::{
        ACTION_DROP, ACTION_PASS, ALLOW_OUTGOING_FLAG, CFG_BLOB_LEN,
        EVENT_MONITOR_BUF_SIZE, Ipv4Cidr, MAP_CFG, MAP_CFG_LEN,
        MAP_MONITOR_ENABLED, MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION,
        MAP_TCP_INGRESS_IFACE_TO_LPM, MAP_TCP_INGRESS_PORT_ACTION,
        MAP_TCP4_EVENTS, MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION,
        MAP_UDP_INGRESS_IFACE_TO_LPM, MAP_UDP_INGRESS_PORT_ACTION,
        MAP_UDP4_EVENTS, MAX_IFACES, MAX_PREFIX_PORT_ENTRIES, MAX_PREFIXES,
        PORT_ANY, PrefixPort,
    },
    tcp::Tcp4EventRaw,
    udp::Udp4EventRaw,
};
