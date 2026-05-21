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

/// Map name holding the serialized [`EfenseConfig`] JSON blob.
///
/// `BPF_MAP_TYPE_ARRAY` of [`CFG_BLOB_LEN`] bytes. Only the first
/// [`MAP_CFG_LEN`] bytes are meaningful.
pub const MAP_CFG: &str = "CFG";

/// Map name holding the byte length of the JSON blob stored in
/// [`MAP_CFG`]. Single-entry `BPF_MAP_TYPE_ARRAY` with key `0` storing
/// a [`u32`].
pub const MAP_CFG_LEN: &str = "CFG_LEN";

/// Map name of the flat hash table used as a monitor-enable flag.
///
/// `BPF_MAP_TYPE_HASH` keyed by [`u32`] (always key `0`), value `u32`
/// (`0` = disabled, `1` = enabled).
pub const MAP_MONITOR_ENABLED: &str = "MONITOR_ENABLED";

/// Map name of the UDP4 event ring buffer.
pub const MAP_UDP4_EVENTS: &str = "UDP4_EVENTS";

/// Map name of the TCP4 event ring buffer.
pub const MAP_TCP4_EVENTS: &str = "TCP4_EVENTS";

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

/// Maximum size in bytes of the serialized [`EfenseConfig`] JSON blob.
pub const CFG_BLOB_LEN: usize = 65536;

/// Map name for the per-interface TCP ACK flood protection enabled flag.
///
/// `BPF_MAP_TYPE_HASH` keyed by interface index (`u32`), value `u32`
/// (`0` = disabled, `1` = enabled).
pub const MAP_TCP_ACK_FLOOD_PROTECTION_ENABLED: &str =
    "TCP_ACK_FLOOD_PROT_ENABLED";

/// Map name for the early port allow-list.
///
/// Key: [`PortKey`] `(ifindex, port)`.  Value: `1` (present = allowed).
/// Used to short-circuit the XDP pipeline: a SYN to a port that is not
/// in this map is dropped before ACK flood protection runs.
pub const MAP_PORT_ALLOW_LIST: &str = "PORT_ALLOW_LIST";

/// Array storing the per-protocol default action.
///
/// Index 0 = UDP, Index 1 = TCP.
/// When the entry is [`ACTION_PASS`] the eBPF program skips all processing
/// for that protocol and unconditionally passes the packet. When the entry
/// is [`ACTION_DROP`] the program proceeds with the normal policy filter.
///
/// `efctl apply` sets the entry to `ACTION_PASS` when no interface defines
/// the corresponding protocol section, and to `ACTION_DROP` when at least
/// one interface does.
pub const MAP_PROTO_DFLT: &str = "PROTO_DFLT";

/// Index of the UDP entry in [`MAP_PROTO_DFLT`].
pub const PROTO_DFLT_UDP: u32 = 0;

/// Index of the TCP entry in [`MAP_PROTO_DFLT`].
pub const PROTO_DFLT_TCP: u32 = 1;

/// Map name for the (source-IP, source-port) → SEQ tracker used by TCP
/// ACK flood protection.
///
/// `BPF_MAP_TYPE_HASH` keyed by [`AckTrackKey`], value `u32` (sequence
/// number from the completed handshake ACK, used as the SEQ baseline).
pub const MAP_TCP_ACK_SEQ_TRACKER: &str = "TCP_ACK_SEQ_TRACKER";

/// Maximum number of entries in [`MAP_TCP_ACK_SEQ_TRACKER`].
pub const MAX_TCP_ACK_SEQ_ENTRIES: u32 = 32768;

/// Ring buffer byte size for event monitoring (`UDP4_EVENTS` and
/// `TCP4_EVENTS`). Must be a power of 2 and page-aligned (multiple of 4096).
pub const EVENT_MONITOR_BUF_SIZE: usize = 128 * 1024;

/// Maximum number of entries in [`MAP_PORT_ALLOW_LIST`].
pub const MAX_PORT_ALLOW_LIST_ENTRIES: u32 = 16384;

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

/// Key for the early-port allow-list map [`MAP_PORT_ALLOW_LIST`].
///
/// `ifindex` is the network interface index; `port` is the transport-layer
/// port in host byte order.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PortKey {
    pub ifindex: u32,
    pub port: u16,
    pub _pad: [u8; 2],
}

impl PortKey {
    #[inline]
    pub const fn new(ifindex: u32, port: u16) -> Self {
        Self {
            ifindex,
            port,
            _pad: [0; 2],
        }
    }
}

/// Key for the TCP ACK SEQ tracker map [`MAP_TCP_ACK_SEQ_TRACKER`].
///
/// `src_ip` is the source IPv4 address in network byte order; `src_port`
/// is the source TCP port in host byte order.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AckTrackKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub _pad: [u8; 2],
}

impl AckTrackKey {
    #[inline]
    pub const fn new(src_ip: [u8; 4], src_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            _pad: [0; 2],
        }
    }
}
