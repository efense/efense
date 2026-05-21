// SPDX-License-Identifier: Apache-2.0

use aya::Pod;
use serde::{Deserialize, Serialize};

use crate::{tcp::TcpIngressPolicy, udp::UdpIngressPolicy};

/// Top-level efense configuration applied via `efctl apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfenseConfig {
    pub interfaces: Vec<Interface>,
}

impl EfenseConfig {
    /// Merge `old` (the configuration currently loaded into the kernel)
    /// into `self` (the desired new configuration) in-place.
    ///
    /// Merge semantics: `self` always wins for fields it specifies. Any
    /// field or interface only present in `old` is preserved so that a
    /// partial `apply` does not implicitly drop unrelated existing state.
    ///
    /// Concretely:
    ///
    /// * For each interface in `old`:
    ///     * If `self` already contains an interface with the same name, its
    ///       per-protocol policies are merged (see [`Interface::merge`]).
    ///     * Otherwise the interface from `old` is appended to `self`.
    /// * The relative order of interfaces in `self` is preserved; interfaces
    ///   coming from `old` are appended at the end in their original order.
    pub fn merge(&mut self, old: &Self) {
        for old_iface in &old.interfaces {
            match self
                .interfaces
                .iter_mut()
                .find(|i| i.name == old_iface.name)
            {
                Some(new_iface) => new_iface.merge(old_iface),
                None => self.interfaces.push(old_iface.clone()),
            }
        }
    }
}

/// Per-interface policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        alias = "udp_ingress"
    )]
    pub udp: Option<UdpIngressPolicy>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        alias = "tcp_ingress"
    )]
    pub tcp: Option<TcpIngressPolicy>,
}

/// Per-interface protection features (e.g. flood detection).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Protections {
    /// Enable TCP ACK flood protection on this interface.
    #[serde(default)]
    pub tcp_ack_flood: bool,
}

impl Interface {
    /// Merge `old`'s per-protocol policies into `self`.
    ///
    /// For every protocol policy, the entry in `self` wins when present;
    /// otherwise the entry from `old` is preserved. The interface name
    /// is not modified.
    pub fn merge(&mut self, old: &Self) {
        if self.udp.is_none() {
            self.udp = old.udp.clone();
        }
        if self.tcp.is_none() {
            self.tcp = old.tcp.clone();
        }
    }
}

/// Top-level action taken on a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Pass,
    Drop,
}

/// Userspace POD wrapper over [`efense_core::PortKey`].
///
/// See [`Ipv4CidrPod`] for the rationale.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PortKeyPod(pub efense_core::PortKey);

impl From<efense_core::PortKey> for PortKeyPod {
    fn from(v: efense_core::PortKey) -> Self {
        Self(v)
    }
}

impl From<PortKeyPod> for efense_core::PortKey {
    fn from(v: PortKeyPod) -> Self {
        v.0
    }
}

// SAFETY: `efense_core::PortKey` is `#[repr(C)]` with only `Copy` integer
// fields plus explicit `_pad` bytes, and is `'static`. The wrapper adds
// nothing thanks to `repr(transparent)`.
unsafe impl Pod for PortKeyPod {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UdpIngressPolicy, udp::Udp4IngressRule};

    #[test]
    fn deserialize_example() {
        let yaml = "\
interfaces:
  - name: enp2s0
    udp:
      allow_list:
      - name: allow_dns_query
        src_port: 53
      - name: drop_subnet_80
        src_ip_ranges:
        - 10.0.0.0/24
        src_port: 80
";
        let cfg: EfenseConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        let iface = &cfg.interfaces[0];
        assert_eq!(iface.name, "enp2s0");
        let udp = iface.udp.as_ref().unwrap();
        assert_eq!(udp.allow_list.len(), 2);
        assert_eq!(udp.allow_list[0].name, "allow_dns_query");
        assert!(udp.allow_list[0].src_ip_ranges.is_empty());
        assert_eq!(udp.allow_list[0].src_port, Some(53));
        let r1 = &udp.allow_list[1];
        assert_eq!(r1.name, "drop_subnet_80");
        assert_eq!(r1.src_ip_ranges, vec!["10.0.0.0/24"]);
        assert_eq!(r1.src_port, Some(80));
    }

    fn udp_policy(rules: &[(&str, u16)]) -> UdpIngressPolicy {
        UdpIngressPolicy {
            allow_list: rules
                .iter()
                .map(|(n, p)| Udp4IngressRule {
                    name: (*n).to_string(),
                    src_ip_ranges: Vec::new(),
                    src_port: Some(*p),
                })
                .collect(),
        }
    }

    #[test]
    fn deserialize_tcp_example() {
        let yaml = "\
interfaces:
  - name: enp2s0
    tcp:
      allow_list:
      - name: allow_ssh
        src_ip_ranges:
        - 192.168.122.0/24
        port: 22
";
        let cfg: EfenseConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        let iface = &cfg.interfaces[0];
        assert_eq!(iface.name, "enp2s0");
        let tcp = iface.tcp.as_ref().unwrap();
        assert_eq!(tcp.allow_list.len(), 1);
        assert_eq!(tcp.allow_list[0].name, "allow_ssh");
        assert_eq!(
            tcp.allow_list[0].src_ip_ranges,
            vec!["192.168.122.0/24".to_string()]
        );
        assert_eq!(tcp.allow_list[0].port, 22);
    }

    #[test]
    fn merge_appends_interfaces_only_in_old() {
        let mut new = EfenseConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp: Some(udp_policy(&[])),
                tcp: None,
            }],
        };
        let old = EfenseConfig {
            interfaces: vec![Interface {
                name: "eth1".to_string(),
                udp: Some(udp_policy(&[("a", 1)])),
                tcp: None,
            }],
        };
        new.merge(&old);
        assert_eq!(new.interfaces.len(), 2);
        assert_eq!(new.interfaces[0].name, "eth0");
        assert_eq!(new.interfaces[1].name, "eth1");
        assert_eq!(
            new.interfaces[1].udp.as_ref().unwrap().allow_list[0].src_port,
            Some(1)
        );
    }

    #[test]
    fn merge_new_overrides_per_protocol_when_set() {
        let mut new = EfenseConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp: Some(udp_policy(&[("new", 53)])),
                tcp: None,
            }],
        };
        let old = EfenseConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp: Some(udp_policy(&[("old", 80)])),
                tcp: None,
            }],
        };
        new.merge(&old);
        assert_eq!(new.interfaces.len(), 1);
        let udp = new.interfaces[0].udp.as_ref().unwrap();
        assert_eq!(udp.allow_list.len(), 1);
        assert_eq!(udp.allow_list[0].name, "new");
    }

    #[test]
    fn merge_fills_missing_protocol_from_old() {
        let mut new = EfenseConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp: None,
                tcp: None,
            }],
        };
        let old = EfenseConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp: Some(udp_policy(&[("old", 80)])),
                tcp: None,
            }],
        };
        new.merge(&old);
        let udp = new.interfaces[0].udp.as_ref().unwrap();
        assert_eq!(udp.allow_list[0].name, "old");
    }
}
