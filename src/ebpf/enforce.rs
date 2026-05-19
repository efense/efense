// SPDX-License-Identifier: GPL-2.0-only

//! Enforcement XDP program — also handles event monitoring when the
//! [`MONITOR_ENABLED`] flag is set.
//!
//! The data path for each protocol is independent:
//!
//! **UDP:**
//!
//! 1. Look up the ingress interface index in the
//!    [`UDP_IN_IF2LPM`](UDP_IFACE_TO_LPM) hash-of-maps. If the interface has no
//!    UDP policy attached, pass.
//! 2. Run a longest-prefix match against the source IPv4 address on the
//!    per-interface LPM trie. The trie returns the canonical [`Ipv4Cidr`] of
//!    the matching rule (or `None` ⇒ default action).
//! 3. Look up `(matched_prefix, src_port)` in the flat
//!    [`UDP_IN_PORT_ACT`](UDP_PORT_ACTION) hash. If miss, try the
//!    `(matched_prefix, PORT_ANY)` "any source port" fallback.
//! 4. If everything missed, return the per-interface default action from
//!    [`UDP_IN_IFACE_DFLT`](UDP_IFACE_DEFAULT_ACTION), defaulting to `XDP_PASS`
//!    if even that map has no entry for this interface.
//!
//! **TCP:**
//!
//! 1. Look up the ingress interface index in the
//!    [`TCP_IN_IF2LPM`](TCP_IFACE_TO_LPM) hash-of-maps. If the interface has no
//!    TCP policy attached, pass.
//! 2. Run a longest-prefix match against the source IPv4 address on the
//!    per-interface LPM trie.
//! 3. Look up `(matched_prefix, dst_port)` in the flat
//!    [`TCP_IN_PORT_ACT`](TCP_PORT_ACTION) hash. If miss, try the
//!    `(matched_prefix, PORT_ANY)` "any destination port" fallback.
//! 4. If everything missed, return the per-interface TCP default action from
//!    [`TCP_IN_IFACE_DFLT`](TCP_IFACE_DEFAULT_ACTION), defaulting to
//!    `XDP_PASS`.

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{Array, HashOfMaps, LpmTrie, lpm_trie::Key as LpmKey},
    macros::{btf_map, map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use efence_core::{
    ACTION_PASS, ALLOW_OUTGOING_FLAG, CFG_BLOB_LEN, EfenceErrorCode, Ipv4Cidr,
    MAX_IFACES, MAX_PREFIX_PORT_ENTRIES, MAX_PREFIXES, PORT_ANY, PrefixPort,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::ptr_at;

// ---------------------------------------------------------------------------
// Maps
//
// Per-protocol maps follow the same pattern:
// - `*_IF2LPM` is a BTF hash-of-maps; its inner template is a BTF LPM trie.
// - `*_PORT_ACT` and `*_IFACE_DFLT` are legacy hash maps.
// ---------------------------------------------------------------------------

/// Per-interface UDP-ingress LPM trie.
#[btf_map(name = "UDP_IN_IF2LPM")]
static UDP_IFACE_TO_LPM: HashOfMaps<
    u32,
    LpmTrie<[u8; 4], Ipv4Cidr, { MAX_PREFIXES as usize }>,
    { MAX_IFACES as usize },
    0,
> = HashOfMaps::new();

/// `(matched_prefix, src_port)` → action lookup.
#[map(name = "UDP_IN_PORT_ACT")]
static UDP_PORT_ACTION: HashMap<PrefixPort, u32> =
    HashMap::<PrefixPort, u32>::with_max_entries(MAX_PREFIX_PORT_ENTRIES, 0);

/// Per-interface UDP default action.
#[map(name = "UDP_IN_IFACE_DFLT")]
static UDP_IFACE_DEFAULT_ACTION: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(MAX_IFACES, 0);

/// Per-interface TCP-ingress LPM trie.
#[btf_map(name = "TCP_IN_IF2LPM")]
static TCP_IFACE_TO_LPM: HashOfMaps<
    u32,
    LpmTrie<[u8; 4], Ipv4Cidr, { MAX_PREFIXES as usize }>,
    { MAX_IFACES as usize },
    0,
> = HashOfMaps::new();

/// `(matched_prefix, dst_port)` → action lookup.
#[map(name = "TCP_IN_PORT_ACT")]
static TCP_PORT_ACTION: HashMap<PrefixPort, u32> =
    HashMap::<PrefixPort, u32>::with_max_entries(MAX_PREFIX_PORT_ENTRIES, 0);

/// Per-interface TCP default action.
#[map(name = "TCP_IN_IFACE_DFLT")]
static TCP_IFACE_DEFAULT_ACTION: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(MAX_IFACES, 0);

/// Serialized JSON blob of the userspace `EfenceConfig`. Opaque to the
/// kernel program: it is only ever read by `efctl show`. Declared here
/// so the verifier-loaded program owns the pin lifetime.
#[btf_map(name = "CFG")]
static CFG: Array<u8, CFG_BLOB_LEN, 0> = Array::new();

/// Length in bytes of the meaningful prefix of [`CFG`].
#[btf_map(name = "CFG_LEN")]
static CFG_LEN: Array<u32, 1, 0> = Array::new();

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

#[xdp]
pub fn efence_net_ingress_apply(ctx: XdpContext) -> u32 {
    match try_efence_net_ingress_apply(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_efence_net_ingress_apply(
    ctx: &XdpContext,
) -> Result<u32, EfenceErrorCode> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|_| EfenceErrorCode::InvalidProtocol)?;
    let src_ip: [u8; 4] = unsafe { (*ipv4hdr).src_addr };

    let ifindex = ctx.ingress_ifindex() as u32;

    match proto {
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src_port: u16 = unsafe { (*udphdr).src_port() };
            let dst_port: u16 = unsafe { (*udphdr).dst_port() };
            let action = decide_udp(ifindex, src_ip, src_port);
            crate::monitor::try_monitor_udp(
                ctx, ipv4hdr, src_ip, src_port, dst_port,
            );
            Ok(action)
        }
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src_port: u16 = unsafe { u16::from_be_bytes((*tcphdr).source) };
            let dst_port: u16 = unsafe { u16::from_be_bytes((*tcphdr).dest) };
            let action = decide_tcp(ifindex, src_ip, dst_port, tcphdr);
            crate::monitor::try_monitor_tcp(
                ctx, ipv4hdr, src_ip, src_port, dst_port, tcphdr,
            );
            Ok(action)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// Decide the fate of a UDP packet using UDP-specific maps.
#[inline(always)]
fn decide_udp(ifindex: u32, src_ip: [u8; 4], src_port: u16) -> u32 {
    let inner_lpm = match unsafe { UDP_IFACE_TO_LPM.get(&ifindex) } {
        Some(t) => t,
        None => return xdp_action::XDP_PASS,
    };

    let lpm_key = LpmKey::new(32, src_ip);
    let matched_prefix: Ipv4Cidr = match inner_lpm.get(&lpm_key) {
        Some(p) => *p,
        None => return udp_iface_default_action(ifindex),
    };

    let key_exact = PrefixPort::new(matched_prefix, src_port);
    if let Some(action) = unsafe { UDP_PORT_ACTION.get(key_exact) } {
        return action_to_xdp(*action);
    }
    let key_any = PrefixPort::new(matched_prefix, PORT_ANY);
    if let Some(action) = unsafe { UDP_PORT_ACTION.get(key_any) } {
        return action_to_xdp(*action);
    }

    udp_iface_default_action(ifindex)
}

/// Decide the fate of a TCP packet using TCP-specific maps.
#[inline(always)]
fn decide_tcp(
    ifindex: u32,
    src_ip: [u8; 4],
    dst_port: u16,
    tcphdr: *const TcpHdr,
) -> u32 {
    let inner_lpm = match unsafe { TCP_IFACE_TO_LPM.get(&ifindex) } {
        Some(t) => t,
        None => return xdp_action::XDP_PASS,
    };

    // Check whether allow_outgoing is set for this interface.
    let iface_raw = unsafe { TCP_IFACE_DEFAULT_ACTION.get(&ifindex) }
        .map(|v| *v)
        .unwrap_or(ACTION_PASS);

    if (iface_raw & ALLOW_OUTGOING_FLAG) != 0 {
        let syn = unsafe { (*tcphdr).syn() };
        // Pass everything except pure SYNs (syn=1, ack=0), which are
        // new incoming connection requests and still get filtered.
        if syn == 0 {
            return xdp_action::XDP_PASS;
        }
        let ack = unsafe { (*tcphdr).ack() };
        if ack != 0 {
            // SYN-ACK – response to an outbound SYN from this host.
            return xdp_action::XDP_PASS;
        }
    }

    let lpm_key = LpmKey::new(32, src_ip);
    let matched_prefix: Ipv4Cidr = match inner_lpm.get(&lpm_key) {
        Some(p) => *p,
        None => return tcp_iface_default_action(ifindex),
    };

    let key_exact = PrefixPort::new(matched_prefix, dst_port);
    if let Some(action) = unsafe { TCP_PORT_ACTION.get(key_exact) } {
        return action_to_xdp(*action);
    }
    let key_any = PrefixPort::new(matched_prefix, PORT_ANY);
    if let Some(action) = unsafe { TCP_PORT_ACTION.get(key_any) } {
        return action_to_xdp(*action);
    }

    tcp_iface_default_action(ifindex)
}

#[inline(always)]
fn udp_iface_default_action(ifindex: u32) -> u32 {
    let action = match unsafe { UDP_IFACE_DEFAULT_ACTION.get(ifindex) } {
        Some(a) => *a,
        None => ACTION_PASS,
    };
    action_to_xdp(action)
}

#[inline(always)]
fn tcp_iface_default_action(ifindex: u32) -> u32 {
    let action = match unsafe { TCP_IFACE_DEFAULT_ACTION.get(ifindex) } {
        Some(a) => *a,
        None => ACTION_PASS,
    };
    action_to_xdp(action)
}

#[inline(always)]
fn action_to_xdp(action: u32) -> u32 {
    match action & 1 {
        0 => xdp_action::XDP_PASS, // ACTION_PASS
        1 => xdp_action::XDP_DROP, // ACTION_DROP
        _ => xdp_action::XDP_PASS,
    }
}
