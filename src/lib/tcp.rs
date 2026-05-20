// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    time::{Duration, UNIX_EPOCH},
};

use efence_core::Tcp4EventRaw;
use serde::{Deserialize, Serialize};

use crate::{
    config::Protections,
    event::{BOOT_TIME, deserialize_timestamp, serialize_timestamp},
};

/// Represents a TCP event
///
/// To eliminate the noise, only trace TCP ACK packet during TCP handshake,
/// hence each Tcp4Event represents a established TCP connection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Tcp4Event {
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

impl Tcp4Event {
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

/// Policy for TCP ingress on a single interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpIngressPolicy {
    /// TCP ACK flood protection settings.
    #[serde(default)]
    pub protections: Protections,
    #[serde(default)]
    pub allow_list: Vec<Tcp4IngressRule>,
    /// When `true`, TCP packets that are not pure SYNs (i.e. not
    /// opening a new connection) are unconditionally passed. This lets
    /// the local host initiate outbound TCP connections even when the
    /// default action is `drop`.
    #[serde(default = "default_true")]
    pub allow_outgoing: bool,
}

fn default_true() -> bool {
    true
}

/// A single rule entry inside a TCP ingress `allow_list`.
///
/// `src_ip_ranges` can be empty to match any source address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tcp4IngressRule {
    pub name: String,
    #[serde(default)]
    pub src_ip_ranges: Vec<String>,
    pub port: u16,
}

impl From<Tcp4EventRaw> for Tcp4Event {
    fn from(raw: Tcp4EventRaw) -> Self {
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
