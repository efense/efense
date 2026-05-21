// SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]

use aya_ebpf::programs::XdpContext;
use efense_core::EfenseErrorCode;

mod enforce;
mod monitor;
mod protect;

#[inline(always)]
pub(crate) fn ptr_at<T>(
    ctx: &XdpContext,
    offset: usize,
) -> Result<*const T, EfenseErrorCode> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(EfenseErrorCode::PacketTooSmall);
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
