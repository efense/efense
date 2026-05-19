// SPDX-License-Identifier: Apache-2.0

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Udp4EventRaw {
    /// native endianness IPv4 source address.
    pub src: u32,
    /// native endianness IPv4 destination address.
    pub dst: u32,
    /// native endianness UDP source port.
    pub src_port: u16,
    /// native endianness UDP destination port.
    pub dst_port: u16,
    /// Padding to align the struct to 8 bytes for efficient ring buffer
    /// storage.
    pub _pad: u32,
    /// Kernel timestamp in nanoseconds (from bpf_ktime_get_boot_ns).
    pub timestamp: u64,
}

impl Udp4EventRaw {
    pub fn new(
        src: u32,
        dst: u32,
        src_port: u16,
        dst_port: u16,
        timestamp: u64,
    ) -> Self {
        Self {
            src,
            dst,
            src_port,
            dst_port,
            _pad: 0,
            timestamp,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != core::mem::size_of::<Self>() {
            return Err("invalid UDP4 event size");
        }
        Ok(Self {
            src: u32::from_ne_bytes(
                bytes[0..4].try_into().map_err(|_| "bad src bytes")?,
            ),
            dst: u32::from_ne_bytes(
                bytes[4..8].try_into().map_err(|_| "bad dst bytes")?,
            ),
            src_port: u16::from_ne_bytes(
                bytes[8..10].try_into().map_err(|_| "bad src_port bytes")?,
            ),
            dst_port: u16::from_ne_bytes(
                bytes[10..12].try_into().map_err(|_| "bad dst_port bytes")?,
            ),
            _pad: 0,
            timestamp: u64::from_ne_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| "bad timestamp bytes")?,
            ),
        })
    }
}
