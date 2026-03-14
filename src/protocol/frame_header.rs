use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;
use super::constants::{FRAME_FLAG_NEEDS_BAS, FRAME_FLAG_SPLIT};
use super::reliability::Reliability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub reliability: Reliability,
    pub is_split: bool,
    pub needs_bas: bool,
}

impl FrameHeader {
    pub fn new(reliability: Reliability, is_split: bool, needs_bas: bool) -> Self {
        Self {
            reliability,
            is_split,
            needs_bas,
        }
    }

    pub fn from_byte(raw: u8) -> Result<Self, DecodeError> {
        let reliability = Reliability::try_from(raw >> 5)?;
        let is_split = (raw & FRAME_FLAG_SPLIT) != 0;
        let needs_bas = (raw & FRAME_FLAG_NEEDS_BAS) != 0;
        Ok(Self {
            reliability,
            is_split,
            needs_bas,
        })
    }

    pub fn to_byte(self) -> u8 {
        let mut raw = (self.reliability as u8) << 5;
        if self.is_split {
            raw |= FRAME_FLAG_SPLIT;
        }
        if self.needs_bas {
            raw |= FRAME_FLAG_NEEDS_BAS;
        }
        raw
    }
}

impl RaknetCodec for FrameHeader {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        dst.put_u8(self.to_byte());
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if !src.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        Self::from_byte(src.get_u8())
    }
}
