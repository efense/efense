// SPDX-License-Identifier: GPL-2.0-only

//! Monitor helpers invoked by the enforce XDP program when the
//! [`MONITOR_ENABLED`] flag is set.

use aya_ebpf::{
    btf_maps::{Array, ring_buf::RingBuf},
    helpers::bpf_ktime_get_boot_ns,
    macros::btf_map,
};
use efence_core::{EVENT_MONITOR_BUF_SIZE, Tcp4EventRaw, Udp4EventRaw};
use network_types::{ip::Ipv4Hdr, tcp::TcpHdr};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

#[btf_map]
static UDP4_EVENTS: RingBuf<Udp4EventRaw, EVENT_MONITOR_BUF_SIZE, 0> =
    RingBuf::new();

#[btf_map]
static TCP4_EVENTS: RingBuf<Tcp4EventRaw, EVENT_MONITOR_BUF_SIZE, 0> =
    RingBuf::new();

/// Monitor-enabled flag (single-element array).
///
/// Value `0` = disabled, `1` = enabled. Written by the userspace
/// `efctl monitor` command.
#[btf_map(name = "MONITOR_ENABLED")]
static MONITOR_ENABLED: Array<u32, 1, 0> = Array::new();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn is_monitor_enabled() -> bool {
    MONITOR_ENABLED.get(0).is_some_and(|v| *v != 0)
}

fn submit_udp4_event(event: Udp4EventRaw) {
    match UDP4_EVENTS.reserve(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {
            disable_monitor();
        }
    }
}

fn submit_tcp4_event(event: Tcp4EventRaw) {
    match TCP4_EVENTS.reserve(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {
            disable_monitor();
        }
    }
}

// ---------------------------------------------------------------------------
// Public API – called from enforce.rs after the filter decision
// ---------------------------------------------------------------------------

pub fn try_monitor_udp(
    ipv4hdr: *const Ipv4Hdr,
    src_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) {
    if !is_monitor_enabled() {
        return;
    }
    let src = u32::from_be_bytes(src_ip);
    let dst = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let tstamp = unsafe { bpf_ktime_get_boot_ns() };
    submit_udp4_event(Udp4EventRaw::new(src, dst, src_port, dst_port, tstamp));
}

pub fn try_monitor_tcp(
    ipv4hdr: *const Ipv4Hdr,
    src_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcphdr: *const TcpHdr,
) {
    if !is_monitor_enabled() {
        return;
    }
    let ack = unsafe { (*tcphdr).ack() };
    let syn = unsafe { (*tcphdr).syn() };
    if ack != 0 && syn == 0 {
        let ip_hdr_len = unsafe { (*ipv4hdr).ihl() as u16 };
        let tcp_hdr_len = unsafe { (*tcphdr).doff() * 4 };
        let ip_tot_len = unsafe { (*ipv4hdr).tot_len() };
        if ip_tot_len == ip_hdr_len + tcp_hdr_len {
            let src = u32::from_be_bytes(src_ip);
            let dst = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
            let tstamp = unsafe { bpf_ktime_get_boot_ns() };
            submit_tcp4_event(Tcp4EventRaw::new(
                src, dst, src_port, dst_port, tstamp,
            ));
        }
    }
}

#[inline(always)]
fn disable_monitor() {
    let _ = MONITOR_ENABLED.set(0, 0u32, 0);
}
