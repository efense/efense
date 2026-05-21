// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{Tcp4Event, Udp4Event};

pub(crate) static BOOT_TIME: LazyLock<SystemTime> = LazyLock::new(|| {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                line.strip_prefix("btime ")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
            })
        })
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH)
});

pub(crate) fn serialize_timestamp<S: serde::Serializer>(
    ts: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let utc_dt = OffsetDateTime::from(UNIX_EPOCH + *ts);
    let formatted =
        utc_dt.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&formatted)
}

pub(crate) fn deserialize_timestamp<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Duration, D::Error> {
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    let dt = OffsetDateTime::parse(&s, &Rfc3339)
        .map_err(serde::de::Error::custom)?;
    let wall_clock = SystemTime::from(dt);
    wall_clock
        .duration_since(UNIX_EPOCH)
        .map_err(|_| serde::de::Error::custom("timestamp before UNIX_EPOCH"))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EfenseEvent {
    #[serde(rename = "udp4_ingress")]
    Udp4Ingress(Udp4Event),
    #[serde(rename = "tcp4_ingress")]
    Tcp4Ingress(Tcp4Event),
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use super::BOOT_TIME;
    use crate::{EfenseEvent, Tcp4Event, Udp4Event};

    #[test]
    fn serialize_deserialize_udp_event() {
        let udp = Udp4Event::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            12345,
            80,
            BOOT_TIME
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                + Duration::from_nanos(1_000_000_000_001),
        );
        let event = EfenseEvent::Udp4Ingress(udp);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EfenseEvent = serde_json::from_str(&json).unwrap();

        match deserialized {
            EfenseEvent::Udp4Ingress(d) => {
                assert_eq!(d.src, udp.src);
                assert_eq!(d.dst, udp.dst);
                assert_eq!(d.src_port, udp.src_port);
                assert_eq!(d.dst_port, udp.dst_port);
                assert_eq!(d.timestamp, udp.timestamp);
            }
            _ => panic!("expected Udp4Ingress"),
        }
    }

    #[test]
    fn serialize_deserialize_tcp_event() {
        let tcp = Tcp4Event::new(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(192, 168, 1, 2),
            54321,
            443,
            BOOT_TIME
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                + Duration::from_nanos(2_000_000_000_002),
        );
        let event = EfenseEvent::Tcp4Ingress(tcp);

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EfenseEvent = serde_json::from_str(&json).unwrap();

        match deserialized {
            EfenseEvent::Tcp4Ingress(d) => {
                assert_eq!(d.src, tcp.src);
                assert_eq!(d.dst, tcp.dst);
                assert_eq!(d.src_port, tcp.src_port);
                assert_eq!(d.dst_port, tcp.dst_port);
                assert_eq!(d.timestamp, tcp.timestamp);
            }
            _ => panic!("expected Tcp4Ingress"),
        }
    }
}
