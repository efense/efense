// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{tcp::TcpIngressPolicy, udp::UdpIngressPolicy};

/// Top-level efense configuration applied via `efctl apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfenceConfig {
    pub interfaces: Vec<Interface>,
}

impl EfenceConfig {
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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub udp_ingress: Option<UdpIngressPolicy>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tcp_ingress: Option<TcpIngressPolicy>,
}

impl Interface {
    /// Merge `old`'s per-protocol policies into `self`.
    ///
    /// For every protocol policy, the entry in `self` wins when present;
    /// otherwise the entry from `old` is preserved. The interface name
    /// is not modified.
    pub fn merge(&mut self, old: &Self) {
        if self.udp_ingress.is_none() {
            self.udp_ingress = old.udp_ingress.clone();
        }
        if self.tcp_ingress.is_none() {
            self.tcp_ingress = old.tcp_ingress.clone();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UdpIngressPolicy, udp::Udp4IngressRule};

    #[test]
    fn deserialize_example() {
        let yaml = "\
interfaces:
  - name: enp2s0
    udp_ingress:
      default_action: drop
      allow_list:
      - name: allow_dns_query
        src_port: 53
      - name: drop_subnet_80
        src_ip: 10.0.0.0/24
        src_port: 80
";
        let cfg: EfenceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        let iface = &cfg.interfaces[0];
        assert_eq!(iface.name, "enp2s0");
        let udp = iface.udp_ingress.as_ref().unwrap();
        assert_eq!(udp.default_action, Action::Drop);
        assert_eq!(udp.allow_list.len(), 2);
        assert_eq!(udp.allow_list[0].name, "allow_dns_query");
        assert_eq!(udp.allow_list[0].src_ip, None);
        assert_eq!(udp.allow_list[0].src_port, Some(53));
        let r1 = &udp.allow_list[1];
        assert_eq!(r1.name, "drop_subnet_80");
        let cidr = r1.src_ip.unwrap();
        assert_eq!(cidr.addr, std::net::Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(r1.src_port, Some(80));
    }

    fn udp_policy(default: Action, rules: &[(&str, u16)]) -> UdpIngressPolicy {
        UdpIngressPolicy {
            default_action: default,
            allow_list: rules
                .iter()
                .map(|(n, p)| Udp4IngressRule {
                    name: (*n).to_string(),
                    src_ip: None,
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
    tcp_ingress:
      default_action: drop
      allow_list:
      - name: allow_ssh
        src_ip: 192.168.122.0/24
        dst_port: 22
";
        let cfg: EfenceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        let iface = &cfg.interfaces[0];
        assert_eq!(iface.name, "enp2s0");
        let tcp = iface.tcp_ingress.as_ref().unwrap();
        assert_eq!(tcp.default_action, Action::Drop);
        assert_eq!(tcp.allow_list.len(), 1);
        assert_eq!(tcp.allow_list[0].name, "allow_ssh");
        let cidr = tcp.allow_list[0].src_ip.unwrap();
        assert_eq!(cidr.addr, std::net::Ipv4Addr::new(192, 168, 122, 0));
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(tcp.allow_list[0].dst_port, Some(22));
    }

    #[test]
    fn merge_appends_interfaces_only_in_old() {
        let mut new = EfenceConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp_ingress: Some(udp_policy(Action::Drop, &[])),
                tcp_ingress: None,
            }],
        };
        let old = EfenceConfig {
            interfaces: vec![Interface {
                name: "eth1".to_string(),
                udp_ingress: Some(udp_policy(Action::Pass, &[("a", 1)])),
                tcp_ingress: None,
            }],
        };
        new.merge(&old);
        assert_eq!(new.interfaces.len(), 2);
        assert_eq!(new.interfaces[0].name, "eth0");
        assert_eq!(new.interfaces[1].name, "eth1");
        assert_eq!(
            new.interfaces[1].udp_ingress.as_ref().unwrap().allow_list[0]
                .src_port,
            Some(1)
        );
    }

    #[test]
    fn merge_new_overrides_per_protocol_when_set() {
        let mut new = EfenceConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp_ingress: Some(udp_policy(Action::Drop, &[("new", 53)])),
                tcp_ingress: None,
            }],
        };
        let old = EfenceConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp_ingress: Some(udp_policy(Action::Pass, &[("old", 80)])),
                tcp_ingress: None,
            }],
        };
        new.merge(&old);
        assert_eq!(new.interfaces.len(), 1);
        let udp = new.interfaces[0].udp_ingress.as_ref().unwrap();
        assert_eq!(udp.default_action, Action::Drop);
        assert_eq!(udp.allow_list.len(), 1);
        assert_eq!(udp.allow_list[0].name, "new");
    }

    #[test]
    fn merge_fills_missing_protocol_from_old() {
        let mut new = EfenceConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp_ingress: None,
                tcp_ingress: None,
            }],
        };
        let old = EfenceConfig {
            interfaces: vec![Interface {
                name: "eth0".to_string(),
                udp_ingress: Some(udp_policy(Action::Pass, &[("old", 80)])),
                tcp_ingress: None,
            }],
        };
        new.merge(&old);
        let udp = new.interfaces[0].udp_ingress.as_ref().unwrap();
        assert_eq!(udp.default_action, Action::Pass);
        assert_eq!(udp.allow_list[0].name, "old");
    }
}
