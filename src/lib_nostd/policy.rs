// SPDX-License-Identifier: Apache-2.0

//! Shared policy definitions used by both the eBPF program and the
//! userspace CLI.
//!
//! These items intentionally live in the `no_std` crate so that the eBPF
//! program can reference exactly the same constants, map names, key/value
//! types and action values as the userspace loader.

/// Action value indicating the packet should be passed through.
pub const ACTION_PASS: u32 = 0;

/// Action value indicating the packet should be dropped.
pub const ACTION_DROP: u32 = 1;

/// Bit-flag (ORed into the per-interface default-action value) that
/// enables the "allow outgoing" behaviour for TCP: non-SYN packets are
/// passed so that connections initiated by the local host are allowed
/// through; only incoming pure-SYNs are subject to the allow list.
pub const ALLOW_OUTGOING_FLAG: u32 = 2;

// ---------------------------------------------------------------------------
// Map names
// ---------------------------------------------------------------------------

/// Map name holding the per-interface default action for UDP ingress.
///
/// `BPF_MAP_TYPE_HASH` keyed by interface index (`u32`), value [`u32`]
/// (`ACTION_PASS` / `ACTION_DROP`).
pub const MAP_UDP_INGRESS_IFACE_DEFAULT_ACTION: &str = "UDP_IN_IFACE_DFLT";

/// Map name of the outer hash-of-maps mapping interface index to the
/// per-interface source-IP LPM trie.
///
/// `BPF_MAP_TYPE_HASH_OF_MAPS`, keyed by interface index (`u32`). The
/// inner map is a `BPF_MAP_TYPE_LPM_TRIE` keyed by IPv4 source address
/// (4 bytes, network byte order) and storing an [`Ipv4Cidr`] (the
/// canonical prefix that gets fed into [`MAP_UDP_INGRESS_PORT_ACTION`]
/// to look up the action).
pub const MAP_UDP_INGRESS_IFACE_TO_LPM: &str = "UDP_IN_IF2LPM";

/// Map name of the flat hash table mapping
/// `(matched_src_prefix, src_port)` to an action.
///
/// `BPF_MAP_TYPE_HASH` keyed by [`PrefixPort`], value `u32`
/// (`ACTION_PASS` / `ACTION_DROP`). The reserved port `PORT_ANY` (`0`,
/// which never appears as a real UDP source port on the wire) is used
/// as the "any source port" bucket for a given prefix.
pub const MAP_UDP_INGRESS_PORT_ACTION: &str = "UDP_IN_PORT_ACT";

/// Map name holding the per-interface default action for TCP ingress.
///
/// `BPF_MAP_TYPE_HASH` keyed by interface index (`u32`), value [`u32`]
/// (`ACTION_PASS` / `ACTION_DROP`).
pub const MAP_TCP_INGRESS_IFACE_DEFAULT_ACTION: &str = "TCP_IN_IFACE_DFLT";

/// Map name of the outer hash-of-maps mapping interface index to the
/// per-interface source-IP LPM trie for TCP.
///
/// `BPF_MAP_TYPE_HASH_OF_MAPS`, keyed by interface index (`u32`). The
/// inner map is a `BPF_MAP_TYPE_LPM_TRIE` keyed by IPv4 source address
/// (4 bytes, network byte order) and storing an [`Ipv4Cidr`].
pub const MAP_TCP_INGRESS_IFACE_TO_LPM: &str = "TCP_IN_IF2LPM";

/// Map name of the flat hash table mapping
/// `(matched_src_prefix, dst_port)` to an action for TCP.
///
/// `BPF_MAP_TYPE_HASH` keyed by [`PrefixPort`], value `u32`
/// (`ACTION_PASS` / `ACTION_DROP`). The reserved port `PORT_ANY` (`0`)
/// is used as the "any destination port" bucket for a given prefix.
pub const MAP_TCP_INGRESS_PORT_ACTION: &str = "TCP_IN_PORT_ACT";

/// Map name holding the serialized [`EfenceConfig`] JSON blob.
///
/// `BPF_MAP_TYPE_ARRAY` of [`CFG_BLOB_LEN`] bytes. Only the first
/// [`MAP_CFG_LEN`] bytes are meaningful.
pub const MAP_CFG: &str = "CFG";

/// Map name holding the byte length of the JSON blob stored in
/// [`MAP_CFG`]. Single-entry `BPF_MAP_TYPE_ARRAY` with key `0` storing
/// a [`u32`].
pub const MAP_CFG_LEN: &str = "CFG_LEN";

// ---------------------------------------------------------------------------
// Map capacities (must match the BTF declarations in `src/ebpf/enforce.rs`)
// ---------------------------------------------------------------------------

/// Maximum number of interfaces with an attached UDP ingress policy.
pub const MAX_IFACES: u32 = 64;

/// Maximum number of distinct source-IP CIDR prefixes across all
/// interfaces.
pub const MAX_PREFIXES: u32 = 4096;

/// Maximum number of `(prefix, port)` entries in
/// [`MAP_UDP_INGRESS_PORT_ACTION`].
pub const MAX_PREFIX_PORT_ENTRIES: u32 = 16384;

/// Maximum size in bytes of the serialized [`EfenceConfig`] JSON blob.
pub const CFG_BLOB_LEN: usize = 65536;

/// Reserved inner-port-map key used to mean "any source port".
///
/// UDP source port `0` does not appear on the wire under normal
/// circumstances (it is the "no source port" sentinel per RFC 768), so
/// it is safe to repurpose as the per-prefix wildcard bucket.
pub const PORT_ANY: u16 = 0;

// ---------------------------------------------------------------------------
// IPv4 CIDR key
// ---------------------------------------------------------------------------

/// IPv4 CIDR prefix used as both a value (inside the LPM trie) and as a
/// key (into [`MAP_UDP_INGRESS_PREFIX_TO_PORT_MAP`]).
///
/// `addr` is stored in **network byte order** (the same order kernel
/// helpers use for `bpf_lpm_trie_key::data`); `prefix_len` is in bits
/// (`0..=32`). The trailing `_pad` byte makes the layout a stable
/// 8-byte POD so it can be used as an aya map key without surprises.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    pub addr: [u8; 4],
    pub prefix_len: u8,
    pub _pad: [u8; 3],
}

impl Ipv4Cidr {
    /// Build a canonical CIDR from a network-byte-order address and a
    /// prefix length. The address is masked so that any host bits below
    /// `prefix_len` are zeroed; this guarantees a single canonical form
    /// per prefix.
    #[inline]
    pub const fn new(addr: [u8; 4], prefix_len: u8) -> Self {
        let mut out = [0u8; 4];
        let mut bits_left = prefix_len as u32;
        let mut i = 0;
        while i < 4 {
            if bits_left >= 8 {
                out[i] = addr[i];
                bits_left -= 8;
            } else if bits_left == 0 {
                out[i] = 0;
            } else {
                let shift = 8 - bits_left;
                out[i] = addr[i] & (0xffu8 << shift);
                bits_left = 0;
            }
            i += 1;
        }
        Self {
            addr: out,
            prefix_len,
            _pad: [0; 3],
        }
    }

    /// Match-any prefix (`0.0.0.0/0`).
    #[inline]
    pub const fn any() -> Self {
        Self {
            addr: [0; 4],
            prefix_len: 0,
            _pad: [0; 3],
        }
    }
}

/// Composite key for [`MAP_UDP_INGRESS_PORT_ACTION`].
///
/// The `prefix` field must be the canonical [`Ipv4Cidr`] returned by
/// the per-interface LPM trie (i.e. the same byte pattern the userspace
/// inserted). `port` is the UDP source port in host byte order; the
/// reserved value [`PORT_ANY`] means "any source port for this prefix".
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrefixPort {
    pub prefix: Ipv4Cidr,
    pub port: u16,
    pub _pad: [u8; 2],
}

impl PrefixPort {
    #[inline]
    pub const fn new(prefix: Ipv4Cidr, port: u16) -> Self {
        Self {
            prefix,
            port,
            _pad: [0; 2],
        }
    }
}
