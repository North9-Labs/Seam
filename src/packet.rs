use crate::error::ApexError;

pub const HEADER_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const MIN_PACKET_LEN: usize = HEADER_LEN + TAG_LEN;

/// Minimum output buffer size for encoding `plaintext_len` bytes.
pub fn encode_buf_len(plaintext_len: usize) -> usize {
    HEADER_LEN + plaintext_len + TAG_LEN
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PktType {
    Initial   = 0x00,
    Handshake = 0x01,
    Data      = 0x02,
    Ack       = 0x03,
    FecRepair = 0x04,
    Chaff     = 0x05,
    PathProbe = 0x06,
    Close     = 0x07,
}

impl TryFrom<u8> for PktType {
    type Error = ApexError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(Self::Initial),
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Ack),
            0x04 => Ok(Self::FecRepair),
            0x05 => Ok(Self::Chaff),
            0x06 => Ok(Self::PathProbe),
            0x07 => Ok(Self::Close),
            other => Err(ApexError::InvalidPktType(other)),
        }
    }
}
