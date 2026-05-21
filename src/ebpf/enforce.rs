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
//! 4. If everything missed, the packet is dropped (the default action is always
//!    `drop`).
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
//! 4. If everything missed, the packet is dropped (the default action is always
//!    `drop`).

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{Array, HashOfMaps, LpmTrie, lpm_trie::Key as LpmKey},
    macros::{btf_map, map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use efence_core::{
    ACTION_PASS, ALLOW_OUTGOING_FLAG, CFG_BLOB_LEN, EfenceErrorCode, Ipv4Cidr,
    MAX_IFACES, MAX_PORT_ALLOW_LIST_ENTRIES, MAX_PREFIX_PORT_ENTRIES,
    MAX_PREFIXES, PORT_ANY, PortKey, PrefixPort,
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

/// Per-interface TCP allow-outgoing flag.
///
/// Key: interface index (`u32`).  Value: `ALLOW_OUTGOING_FLAG` if outgoing
/// connections are permitted, `0` otherwise.
#[map(name = "TCP_IN_IFACE_DFLT")]
pub(crate) static TCP_IFACE_ALLOW_OUTGOING: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(MAX_IFACES, 0);

/// Early port allow-list.
///
/// Key: [`PortKey`] `(ifindex, port)`.  Value: `1` (present = allowed).
/// A SYN whose `(ifindex, dst_port)` is not in this map is dropped before
/// ACK flood protection runs.
#[map(name = "PORT_ALLOW_LIST")]
static PORT_ALLOW_LIST: HashMap<PortKey, u32> =
    HashMap::<PortKey, u32>::with_max_entries(MAX_PORT_ALLOW_LIST_ENTRIES, 0);

/// Per-protocol default action.
///
/// Index 0 = UDP default action, Index 1 = TCP default action.
/// When set to [`ACTION_PASS`] the eBPF program returns `XDP_PASS`
/// immediately, skipping all processing for that protocol.
#[btf_map(name = "PROTO_DFLT")]
static PROTO_DFLT: Array<u32, 2, 0> = Array::new();

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
pub fn efence_net_xdp_ingress_apply(ctx: XdpContext) -> u32 {
    match try_efence_net_xdp_ingress_apply(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_efence_net_xdp_ingress_apply(
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
            // Early skip: if the protocol-level default is PASS, allow all
            // UDP traffic without any further processing.
            if let Some(&v) = PROTO_DFLT.get(0)
                && v == ACTION_PASS
            {
                crate::monitor::try_monitor_udp(
                    ipv4hdr, src_ip, src_port, dst_port,
                );
                return Ok(xdp_action::XDP_PASS);
            }
            // Early port allow-list check for UDP.
            let udp_key = PortKey::new(ifindex, src_port);
            if unsafe { PORT_ALLOW_LIST.get(udp_key) }.is_none() {
                return Ok(xdp_action::XDP_DROP);
            }
            let (is_default_action, action) =
                decide_udp(ifindex, src_ip, src_port);
            if is_default_action {
                crate::monitor::try_monitor_udp(
                    ipv4hdr, src_ip, src_port, dst_port,
                );
            }
            Ok(action)
        }
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let src_port: u16 = unsafe { u16::from_be_bytes((*tcphdr).source) };
            let dst_port: u16 = unsafe { u16::from_be_bytes((*tcphdr).dest) };
            // Early skip: if the protocol-level default is PASS, allow all
            // TCP traffic without any further processing.
            if let Some(&v) = PROTO_DFLT.get(1)
                && v == ACTION_PASS
            {
                crate::monitor::try_monitor_tcp(
                    ipv4hdr, src_ip, src_port, dst_port, tcphdr,
                );
                return Ok(xdp_action::XDP_PASS);
            }

            // Early port allow-list check: drop SYN to non-allowed ports.
            let tcp_key = PortKey::new(ifindex, dst_port);
            let port_allowed =
                unsafe { PORT_ALLOW_LIST.get(tcp_key) }.is_some();
            if !port_allowed {
                let is_syn = unsafe { (*tcphdr).syn() } != 0;
                let is_ack = unsafe { (*tcphdr).ack() } != 0;
                if is_syn && !is_ack {
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // Run TCP ACK flood protection before the regular filter.
            if let Some(action) = crate::protect::protect_tcp_ack_flood(
                ctx, ifindex, src_ip, tcphdr,
            )? {
                return Ok(action);
            }

            let (is_default_action, action) =
                decide_tcp(ifindex, src_ip, dst_port, tcphdr);
            if is_default_action {
                crate::monitor::try_monitor_tcp(
                    ipv4hdr, src_ip, src_port, dst_port, tcphdr,
                );
            }
            Ok(action)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// Decide the fate of a UDP packet using UDP-specific maps.
/// Returns `(is_default_action, action)` where `is_default_action` is `true`
/// when no specific rule matched and the packet is handled by the default.
#[inline(always)]
fn decide_udp(ifindex: u32, src_ip: [u8; 4], src_port: u16) -> (bool, u32) {
    let inner_lpm = match unsafe { UDP_IFACE_TO_LPM.get(&ifindex) } {
        Some(t) => t,
        None => return (false, xdp_action::XDP_PASS),
    };

    let lpm_key = LpmKey::new(32, src_ip);
    let matched_prefix: Ipv4Cidr = match inner_lpm.get(&lpm_key) {
        Some(p) => *p,
        None => return (true, xdp_action::XDP_DROP),
    };

    let key_exact = PrefixPort::new(matched_prefix, src_port);
    if let Some(action) = unsafe { UDP_PORT_ACTION.get(key_exact) } {
        return (false, action_to_xdp(*action));
    }
    let key_any = PrefixPort::new(matched_prefix, PORT_ANY);
    if let Some(action) = unsafe { UDP_PORT_ACTION.get(key_any) } {
        return (false, action_to_xdp(*action));
    }

    (true, xdp_action::XDP_DROP)
}

/// Decide the fate of a TCP packet using TCP-specific maps.
/// Returns `(is_default_action, action)` where `is_default_action` is `true`
/// when no specific rule matched and the packet is handled by the default.
#[inline(always)]
fn decide_tcp(
    ifindex: u32,
    src_ip: [u8; 4],
    dst_port: u16,
    tcphdr: *const TcpHdr,
) -> (bool, u32) {
    let inner_lpm = match unsafe { TCP_IFACE_TO_LPM.get(&ifindex) } {
        Some(t) => t,
        None => return (false, xdp_action::XDP_PASS),
    };

    // Check whether allow_outgoing is set for this interface.
    let allow_outgoing = unsafe { TCP_IFACE_ALLOW_OUTGOING.get(ifindex) }
        .copied()
        .unwrap_or(0);

    if (allow_outgoing & ALLOW_OUTGOING_FLAG) != 0 {
        let syn = unsafe { (*tcphdr).syn() };
        // Pass everything except pure SYNs (syn=1, ack=0), which are
        // new incoming connection requests and still get filtered.
        if syn == 0 {
            return (false, xdp_action::XDP_PASS);
        }
        let ack = unsafe { (*tcphdr).ack() };
        if ack != 0 {
            // SYN-ACK – response to an outbound SYN from this host.
            return (false, xdp_action::XDP_PASS);
        }
    }

    let lpm_key = LpmKey::new(32, src_ip);
    let matched_prefix: Ipv4Cidr = match inner_lpm.get(&lpm_key) {
        Some(p) => *p,
        None => return (true, tcp_iface_default_action(ifindex)),
    };

    let key_exact = PrefixPort::new(matched_prefix, dst_port);
    if let Some(action) = unsafe { TCP_PORT_ACTION.get(key_exact) } {
        return (false, action_to_xdp(*action));
    }
    let key_any = PrefixPort::new(matched_prefix, PORT_ANY);
    if let Some(action) = unsafe { TCP_PORT_ACTION.get(key_any) } {
        return (false, action_to_xdp(*action));
    }

    (true, tcp_iface_default_action(ifindex))
}

#[inline(always)]
fn tcp_iface_default_action(_ifindex: u32) -> u32 {
    xdp_action::XDP_DROP
}

#[inline(always)]
fn action_to_xdp(action: u32) -> u32 {
    match action & 1 {
        0 => xdp_action::XDP_PASS, // ACTION_PASS
        1 => xdp_action::XDP_DROP, // ACTION_DROP
        _ => xdp_action::XDP_PASS,
    }
}
