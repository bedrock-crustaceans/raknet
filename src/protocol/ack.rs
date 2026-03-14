use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;
use super::constants::MAX_ACK_SEQUENCES;
use super::sequence24::Sequence24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceRange {
    pub start: Sequence24,
    pub end: Sequence24,
}

impl SequenceRange {
    pub fn wraps(self) -> bool {
        self.start != self.end && self.start.value() > self.end.value()
    }

    pub fn split_wrapping(self) -> Option<(SequenceRange, SequenceRange)> {
        if !self.wraps() {
            return None;
        }

        let tail = SequenceRange {
            start: self.start,
            end: Sequence24::new(0x00FF_FFFF),
        };

        let head = SequenceRange {
            start: Sequence24::new(0),
            end: self.end,
        };

        Some((tail, head))
    }

    pub fn record_count(self) -> usize {
        if self.wraps() { 2 } else { 1 }
    }

    pub fn encoded_size(self) -> usize {
        if self.start == self.end {
            1 + 3
        } else {
            1 + 3 + 3
        }
    }
}

impl RaknetCodec for SequenceRange {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        let singleton = self.start == self.end;
        singleton.encode_raknet(dst)?;
        self.start.encode_raknet(dst)?;
        if !singleton {
            self.end.encode_raknet(dst)?;
        }
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        let singleton = bool::decode_raknet(src)?;
        let start = Sequence24::decode_raknet(src)?;
        let end = if singleton {
            start
        } else {
            Sequence24::decode_raknet(src)?
        };

        Ok(Self { start, end })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AckNackPayload {
    pub ranges: Vec<SequenceRange>,
}

impl AckNackPayload {
    pub fn encoded_size(&self) -> usize {
        let mut size = 2usize;
        for r in &self.ranges {
            if let Some((a, b)) = r.split_wrapping() {
                size += a.encoded_size() + b.encoded_size();
            } else {
                size += r.encoded_size();
            }
        }
        size
    }
}

impl RaknetCodec for AckNackPayload {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        let record_count: usize = self.ranges.iter().map(|r| r.record_count()).sum();
        if record_count > MAX_ACK_SEQUENCES as usize {
            return Err(EncodeError::AckRecordOverflow(record_count));
        }

        (record_count as u16).encode_raknet(dst)?;
        for range in &self.ranges {
            if let Some((left, right)) = range.split_wrapping() {
                left.encode_raknet(dst)?;
                right.encode_raknet(dst)?;
            } else {
                range.encode_raknet(dst)?;
            }
        }
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        let count = u16::decode_raknet(src)?;
        if count > MAX_ACK_SEQUENCES {
            return Err(DecodeError::InvalidAckRangeCount(count));
        }

        let mut ranges = Vec::with_capacity(count as usize);
        for _ in 0..count {
            ranges.push(SequenceRange::decode_raknet(src)?);
        }

        Ok(Self { ranges })
    }
}
