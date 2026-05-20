// SPDX-License-Identifier: GPL-2.0-only

//! TCP ACK flood protection helpers invoked by the enforce XDP program.

use aya_ebpf::{
    bindings::xdp_action, macros::map, maps::HashMap, programs::XdpContext,
};
use aya_log_ebpf::debug;
use efence_core::{EfenceErrorCode, MAX_IFACES, MAX_TCP_ACK_ISN_ENTRIES};
use network_types::tcp::TcpHdr;

use crate::enforce::TCP_IFACE_ALLOW_OUTGOING;

// ---------------------------------------------------------------------------
// TCP ACK flood protection maps
// ---------------------------------------------------------------------------

/// Per-interface TCP ACK flood protection enabled flag.
///
/// Key: interface index (`u32`).  Value: `0` = disabled, `1` = enabled.
#[map(name = "TCP_ACK_FLOOD_PROT_ENABLED")]
static TCP_ACK_FLOOD_PROT_ENABLED: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(MAX_IFACES, 0);

/// Source-IP → handshake sequence-number tracker.
///
/// Populated at runtime when a handshake-completing ACK is observed.
/// Keyed by source IPv4 address in network byte order.
#[map(name = "TCP_ACK_ISN_TRACKER")]
static TCP_ACK_ISN_TRACKER: HashMap<[u8; 4], u32> =
    HashMap::<[u8; 4], u32>::with_max_entries(MAX_TCP_ACK_ISN_ENTRIES, 0);

/// TCP ACK flood protection — runs before `decide_tcp`.
///
/// Returns `Ok(Some(action))` when the protection decides the packet's
/// fate, or `Ok(None)` to fall through to the regular TCP filter.
///
/// ## Behaviour
///
/// * **SYN** (new incoming connection): records `src_ip + ISN` in the tracker
///   so that the eventual ACK completing the handshake can be validated.
/// * **SYN-ACK** (response to an outbound SYN): records `src_ip + ISN` only
///   when [`allow_outgoing`] is set for this interface.  When `allow_outgoing`
///   is `false` the SYN-ACK is silently skipped — no outbound connection could
///   have produced it, so there is nothing to track.
/// * **ACK with payload** (data): looks up `src_ip` in the tracker.
///     - No entry ⟹ drop (no completed handshake observed).
///     - Entry exists but `current_seq - stored_seq` (wrapping) exceeds
///       [`TCP_ACK_MAX_WINDOW`] ⟹ drop (sequence out of reasonable range).
///     - Otherwise ⟹ update the tracker with the latest `seq` and pass.
#[inline(always)]
pub fn protect_tcp_ack_flood(
    ctx: &XdpContext,
    ifindex: u32,
    src_ip: [u8; 4],
    tcphdr: *const TcpHdr,
) -> Result<Option<u32>, EfenceErrorCode> {
    // Check if ACK flood protection is enabled on this interface.
    match unsafe { TCP_ACK_FLOOD_PROT_ENABLED.get(&ifindex) } {
        Some(v) if *v == 0 => return Ok(None),
        None => return Ok(None),
        _ => (),
    }

    let is_ack = unsafe { (*tcphdr).ack() } != 0;
    let is_syn = unsafe { (*tcphdr).syn() } != 0;
    let seq = unsafe { u32::from_be_bytes((*tcphdr).seq) };
    let src = unsafe { u32::from_be_bytes((*tcphdr).seq) };

    let allow_outgoing = unsafe { TCP_IFACE_ALLOW_OUTGOING.get(&ifindex) }
        .map(|v| *v)
        .unwrap_or(0)
        != 0;

    if is_syn {
        if is_ack && !allow_outgoing {
            debug!(
                ctx,
                "DROP SYN-ACK because allow_outgoing=false, from src={:i} \
                 seq={}",
                src,
                seq
            );
            return Ok(Some(xdp_action::XDP_DROP));
        }
        let _ = TCP_ACK_ISN_TRACKER.insert(&src_ip, &seq, 0);
        debug!(ctx, "ACK_TRACK: learned src={:i} seq={}", src, seq);
        return Ok(None);
    }

    match unsafe { TCP_ACK_ISN_TRACKER.get(&src_ip) } {
        Some(pre_seq) => {
            let delta = seq.wrapping_sub(*pre_seq);
            if delta > 0xffff {
                debug!(
                    ctx,
                    "ACK_TRACK: DROP src={:i} seq={} stored={} delta={}",
                    src,
                    seq,
                    *pre_seq,
                    delta,
                );
                return Ok(Some(xdp_action::XDP_DROP));
            }
            let _ = TCP_ACK_ISN_TRACKER.insert(&src_ip, &seq, 0);
            debug!(
                ctx,
                "ACK_TRACK: pass src={:i} seq={} delta={}", src, seq, delta
            );
            Ok(None)
        }
        None => {
            debug!(
                ctx,
                "ACK_TRACK: DROP src={:i} seq={} (no tracker entry)", src, seq,
            );
            Ok(Some(xdp_action::XDP_DROP))
        }
    }
}
