// SPDX-License-Identifier: Apache-2.0

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum EfenseErrorCode {
    PacketTooSmall,
    InvalidProtocol,
}

impl core::fmt::Display for EfenseErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EfenseErrorCode::PacketTooSmall => "packet too small",
                EfenseErrorCode::InvalidProtocol => "invalid protocol",
            }
        )
    }
}
