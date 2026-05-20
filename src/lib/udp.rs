// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    time::{Duration, UNIX_EPOCH},
};

use efence_core::Udp4EventRaw;
use serde::{Deserialize, Serialize};

use crate::event::{BOOT_TIME, deserialize_timestamp, serialize_timestamp};

/// Policy for UDP ingress on a single interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpIngressPolicy {
    #[serde(default)]
    pub allow_list: Vec<Udp4IngressRule>,
}

/// A single rule entry inside a UDP ingress `allow_list`.
///
/// `src_ip_ranges` can be empty to match any source address. A missing
/// `src_port` is treated as "any source port" for the matched prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Udp4IngressRule {
    pub name: String,
    #[serde(default)]
    pub src_ip_ranges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Udp4Event {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    #[serde(
        serialize_with = "serialize_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub timestamp: Duration,
}

impl Udp4Event {
    pub fn new(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        timestamp: Duration,
    ) -> Self {
        Self {
            src,
            dst,
            src_port,
            dst_port,
            timestamp,
        }
    }
}

impl From<Udp4EventRaw> for Udp4Event {
    fn from(raw: Udp4EventRaw) -> Self {
        Self {
            src: Ipv4Addr::from(raw.src),
            dst: Ipv4Addr::from(raw.dst),
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            timestamp: BOOT_TIME
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .checked_add(Duration::from_nanos(raw.timestamp))
                .unwrap_or_default(),
        }
    }
}

/// `#[repr(transparent)]` userspace POD wrapper over
/// [`efence_core::PrefixPort`].
///
/// See [`crate::Ipv4CidrPod`] for the rationale: the orphan rule forbids
/// implementing [`aya::Pod`] directly on a type defined in `efence_core`,
/// so we wrap it. `repr(transparent)` keeps the wire layout identical
/// to the wrapped type.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrefixPortPod(pub efence_core::PrefixPort);

impl From<efence_core::PrefixPort> for PrefixPortPod {
    fn from(v: efence_core::PrefixPort) -> Self {
        Self(v)
    }
}

impl From<PrefixPortPod> for efence_core::PrefixPort {
    fn from(v: PrefixPortPod) -> Self {
        v.0
    }
}

// SAFETY: `efence_core::PrefixPort` is `#[repr(C)]` with only `Copy`
// integer / nested-POD fields plus explicit `_pad` bytes (so there is
// no implicit padding), and is `'static`. The wrapper adds nothing
// thanks to `repr(transparent)`.
unsafe impl aya::Pod for PrefixPortPod {}
