// SPDX-License-Identifier: Apache-2.0

//! IP address types and related parsing/formatting helpers.

use std::{fmt, net::Ipv4Addr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// IPv4 address with an optional CIDR prefix length.
///
/// The on-wire representation in YAML / JSON is a single string:
///
/// * `192.168.0.1` is parsed as `192.168.0.1/32` (single-host match).
/// * `192.168.0.0/16` is parsed as a `/16` prefix.
///
/// The host bits below `prefix_len` are accepted as written and
/// preserved here; canonicalization (masking) is performed downstream
/// when the value is inserted into the LPM trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix_len == 32 {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix_len)
        }
    }
}

impl Ipv4Cidr {
    /// Parse the textual `A.B.C.D` or `A.B.C.D/N` form. A bare address
    /// without `/N` is treated as `/32`. `N` must be `0..=32`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_part, prefix_len) = match s.split_once('/') {
            None => (s, 32u8),
            Some((a, p)) => {
                let n: u8 = p.parse().map_err(|_| {
                    format!("invalid prefix length {p:?} in {s:?}")
                })?;
                if n > 32 {
                    return Err(format!(
                        "prefix length {n} out of range 0..=32 in {s:?}"
                    ));
                }
                (a, n)
            }
        };
        let addr: Ipv4Addr = addr_part.parse().map_err(|_| {
            format!("invalid IPv4 address {addr_part:?} in {s:?}")
        })?;
        Ok(Self { addr, prefix_len })
    }
}

impl Serialize for Ipv4Cidr {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ipv4Cidr {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Ipv4Cidr;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    "an IPv4 address or CIDR string (e.g. \"192.168.0.1\" or \
                     \"192.168.0.0/16\")",
                )
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Ipv4Cidr, E> {
                Ipv4Cidr::parse(s).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// `#[repr(transparent)]` userspace POD wrapper over
/// [`efense_core::Ipv4Cidr`].
///
/// The orphan rule forbids implementing [`aya::Pod`] directly on a type
/// defined in `efense_core`, so we wrap it here. Because the wrapper is
/// `repr(transparent)`, it has the exact same memory layout, size and
/// alignment as the wrapped type, so a BPF map declared with
/// `Ipv4CidrPod` as its key/value type sees the same wire bytes as a
/// kernel-side map declared with `efense_core::Ipv4Cidr`.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4CidrPod(pub efense_core::Ipv4Cidr);

impl From<efense_core::Ipv4Cidr> for Ipv4CidrPod {
    fn from(v: efense_core::Ipv4Cidr) -> Self {
        Self(v)
    }
}

impl From<Ipv4CidrPod> for efense_core::Ipv4Cidr {
    fn from(v: Ipv4CidrPod) -> Self {
        v.0
    }
}

// SAFETY: `efense_core::Ipv4Cidr` is `#[repr(C)]` with only `Copy`
// integer fields plus explicit `_pad` bytes (so there is no implicit
// padding), and is `'static`. The wrapper adds nothing thanks to
// `repr(transparent)`.
unsafe impl aya::Pod for Ipv4CidrPod {}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Ipv4Cidr {
        Ipv4Cidr {
            addr: Ipv4Addr::new(a, b, c, d),
            prefix_len,
        }
    }

    // -- parse / Display --------------------------------------------------

    #[test]
    fn parse_bare_address_defaults_to_slash_32() {
        let c = Ipv4Cidr::parse("192.168.0.1").unwrap();
        assert_eq!(c, cidr(192, 168, 0, 1, 32));
    }

    #[test]
    fn parse_cidr() {
        let c = Ipv4Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(c, cidr(10, 0, 0, 0, 8));
    }

    #[test]
    fn parse_slash_zero() {
        let c = Ipv4Cidr::parse("0.0.0.0/0").unwrap();
        assert_eq!(c, cidr(0, 0, 0, 0, 0));
    }

    #[test]
    fn parse_slash_thirty_two() {
        let c = Ipv4Cidr::parse("192.168.0.1/32").unwrap();
        assert_eq!(c, cidr(192, 168, 0, 1, 32));
    }

    #[test]
    fn parse_preserves_host_bits() {
        // The parser does not canonicalize: host bits below the prefix
        // are preserved exactly as written.
        let c = Ipv4Cidr::parse("192.168.0.1/16").unwrap();
        assert_eq!(c, cidr(192, 168, 0, 1, 16));
    }

    #[test]
    fn parse_rejects_invalid_address() {
        assert!(Ipv4Cidr::parse("not-an-ip").is_err());
        assert!(Ipv4Cidr::parse("999.0.0.0").is_err());
        assert!(Ipv4Cidr::parse("1.2.3").is_err());
        assert!(Ipv4Cidr::parse("/24").is_err());
    }

    #[test]
    fn parse_rejects_invalid_prefix_length() {
        // Prefix length must parse as `u8` and be in `0..=32`.
        assert!(Ipv4Cidr::parse("10.0.0.0/33").is_err());
        assert!(Ipv4Cidr::parse("10.0.0.0/256").is_err());
        assert!(Ipv4Cidr::parse("10.0.0.0/abc").is_err());
        assert!(Ipv4Cidr::parse("10.0.0.0/-1").is_err());
    }

    #[test]
    fn display_slash_32_omits_prefix_len() {
        assert_eq!(cidr(192, 168, 0, 1, 32).to_string(), "192.168.0.1");
    }

    #[test]
    fn display_other_prefix_len_includes_it() {
        assert_eq!(cidr(10, 0, 0, 0, 8).to_string(), "10.0.0.0/8");
        assert_eq!(cidr(0, 0, 0, 0, 0).to_string(), "0.0.0.0/0");
        assert_eq!(cidr(172, 16, 0, 0, 12).to_string(), "172.16.0.0/12");
    }

    // -- Serialize --------------------------------------------------------

    #[test]
    fn serialize_json_slash_32_is_bare_address() {
        let c = cidr(192, 168, 0, 1, 32);
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"192.168.0.1\"");
    }

    #[test]
    fn serialize_json_cidr_form() {
        let c = cidr(10, 0, 0, 0, 8);
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"10.0.0.0/8\"");
    }

    #[test]
    fn serialize_yaml_cidr_form() {
        let c = cidr(192, 168, 122, 0, 24);
        let yaml = serde_yaml::to_string(&c).unwrap();
        // serde_yaml appends a trailing newline.
        assert_eq!(yaml, "192.168.122.0/24\n");
    }

    // -- Deserialize ------------------------------------------------------

    #[test]
    fn deserialize_json_bare_address() {
        let c: Ipv4Cidr = serde_json::from_str("\"192.168.0.1\"").unwrap();
        assert_eq!(c, cidr(192, 168, 0, 1, 32));
    }

    #[test]
    fn deserialize_json_cidr_form() {
        let c: Ipv4Cidr = serde_json::from_str("\"10.0.0.0/8\"").unwrap();
        assert_eq!(c, cidr(10, 0, 0, 0, 8));
    }

    #[test]
    fn deserialize_yaml_cidr_form() {
        let c: Ipv4Cidr = serde_yaml::from_str("192.168.122.0/24").unwrap();
        assert_eq!(c, cidr(192, 168, 122, 0, 24));
    }

    #[test]
    fn deserialize_rejects_non_string() {
        // The deserializer asks for a string explicitly; numbers / maps
        // must fail rather than be coerced.
        assert!(serde_json::from_str::<Ipv4Cidr>("42").is_err());
        assert!(serde_json::from_str::<Ipv4Cidr>("{}").is_err());
        assert!(serde_json::from_str::<Ipv4Cidr>("null").is_err());
    }

    #[test]
    fn deserialize_rejects_invalid_string() {
        assert!(serde_json::from_str::<Ipv4Cidr>("\"\"").is_err());
        assert!(serde_json::from_str::<Ipv4Cidr>("\"nope\"").is_err());
        assert!(serde_json::from_str::<Ipv4Cidr>("\"10.0.0.0/33\"").is_err());
    }

    // -- Round-trip -------------------------------------------------------

    #[test]
    fn roundtrip_json_all_prefix_lens() {
        for prefix_len in 0u8..=32 {
            let c = cidr(192, 168, 0, 1, prefix_len);
            let json = serde_json::to_string(&c).unwrap();
            let back: Ipv4Cidr = serde_json::from_str(&json).unwrap();
            assert_eq!(back, c, "round-trip failed for /{prefix_len}");
        }
    }

    #[test]
    fn roundtrip_yaml() {
        let c = cidr(172, 16, 0, 0, 12);
        let yaml = serde_yaml::to_string(&c).unwrap();
        let back: Ipv4Cidr = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back, c);
    }
}
