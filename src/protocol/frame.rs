use bytes::{Buf, BufMut, Bytes};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;
use super::constants::MAX_SPLIT_PARTS;
use super::frame_header::FrameHeader;
use super::sequence24::Sequence24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitInfo {
    pub part_count: u32,
    pub part_id: u16,
    pub part_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub bit_length: u16,
    pub reliable_index: Option<Sequence24>,
    pub sequence_index: Option<Sequence24>,
    pub ordering_index: Option<Sequence24>,
    pub ordering_channel: Option<u8>,
    pub split: Option<SplitInfo>,
    pub payload: Bytes,
}

impl Frame {
    pub fn payload_len(&self) -> usize {
        ((self.bit_length as usize) + 7) >> 3
    }

    pub fn encoded_size(&self) -> usize {
        let mut size = 3usize;
        let rel = self.header.reliability;

        if rel.is_reliable() {
            size += 3;
        }
        if rel.is_sequenced() {
            size += 3;
        }
        if rel.is_ordered() || rel.is_sequenced() {
            size += 4;
        }
        if self.header.is_split {
            size += 10;
        }

        size + self.payload_len()
    }
}

impl RaknetCodec for Frame {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        if self.payload_len() != self.payload.len() {
            return Err(EncodeError::FrameBitLengthMismatch);
        }

        self.header.encode_raknet(dst)?;
        self.bit_length.encode_raknet(dst)?;

        let rel = self.header.reliability;
        if rel.is_reliable() {
            self.reliable_index
                .ok_or(EncodeError::MissingReliableIndex)?
                .encode_raknet(dst)?;
        }
        if rel.is_sequenced() {
            self.sequence_index
                .ok_or(EncodeError::MissingSequenceIndex)?
                .encode_raknet(dst)?;
        }
        if rel.is_ordered() || rel.is_sequenced() {
            self.ordering_index
                .ok_or(EncodeError::MissingOrderingIndex)?
                .encode_raknet(dst)?;
            self.ordering_channel
                .ok_or(EncodeError::MissingOrderingChannel)?
                .encode_raknet(dst)?;
        }

        if self.header.is_split {
            let split = self.split.as_ref().ok_or(EncodeError::MissingSplitInfo)?;
            split.part_count.encode_raknet(dst)?;
            split.part_id.encode_raknet(dst)?;
            split.part_index.encode_raknet(dst)?;
        }

        dst.put_slice(&self.payload);
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        let header = FrameHeader::decode_raknet(src)?;
        let bit_length = u16::decode_raknet(src)?;
        let payload_len = ((bit_length as usize) + 7) >> 3;
        if payload_len == 0 {
            return Err(DecodeError::InvalidFrameBitLength(bit_length));
        }

        let rel = header.reliability;

        let reliable_index = if rel.is_reliable() {
            Some(Sequence24::decode_raknet(src)?)
        } else {
            None
        };

        let sequence_index = if rel.is_sequenced() {
            Some(Sequence24::decode_raknet(src)?)
        } else {
            None
        };

        let (ordering_index, ordering_channel) = if rel.is_ordered() || rel.is_sequenced() {
            (
                Some(Sequence24::decode_raknet(src)?),
                Some(u8::decode_raknet(src)?),
            )
        } else {
            (None, None)
        };

        let split = if header.is_split {
            let part_count = u32::decode_raknet(src)?;
            if part_count == 0 {
                return Err(DecodeError::SplitCountZero);
            }
            if part_count > MAX_SPLIT_PARTS {
                return Err(DecodeError::SplitIndexOutOfRange);
            }

            let part_id = u16::decode_raknet(src)?;
            let part_index = u32::decode_raknet(src)?;
            if part_index >= part_count {
                return Err(DecodeError::SplitIndexOutOfRange);
            }

            Some(SplitInfo {
                part_count,
                part_id,
                part_index,
            })
        } else {
            None
        };

        if src.remaining() < payload_len {
            return Err(DecodeError::UnexpectedEof);
        }
        let payload = src.copy_to_bytes(payload_len);

        Ok(Self {
            header,
            bit_length,
            reliable_index,
            sequence_index,
            ordering_index,
            ordering_channel,
            split,
            payload,
        })
    }
}
