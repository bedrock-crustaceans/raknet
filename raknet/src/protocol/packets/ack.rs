use crate::protocol::codec::RakCodec;
use crate::protocol::error::RakCodecError;
use crate::util::flags::{ACK, NACK, VALID};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Error, Read, Write};
use std::mem::take;

pub const MAX_ACK_ENTRIES: usize = 8192;

const HEADER_SIZE: usize = size_of::<u8>() + size_of::<u16>();
const SINGLE_SIZE: usize = size_of::<u8>() + 3;
const RANGE_SIZE: usize = size_of::<u8>() + 3 + 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub is_nack: bool,
    pub sequences: Vec<u32>,
}

impl Ack {
    pub fn new(mut sequences: Vec<u32>, is_nack: bool) -> Self {
        sequences.sort_unstable();
        sequences.dedup();
        Self { is_nack, sequences }
    }
    
    pub fn split(sequences: Vec<u32>, is_nack: bool, max_size: usize) -> Vec<Self> {
        let sequences = Self::new(sequences, is_nack).sequences;

        let mut acks = Vec::new();
        let mut current: Vec<u32> = Vec::new();
        let mut size = HEADER_SIZE;
        let mut range_start = 0;

        for seq in sequences {
            let extends = current.last().is_some_and(|&last| seq == last + 1);
            let growth = match (extends, current.last() == Some(&range_start)) {
                (false, _) => SINGLE_SIZE,
                (true, true) => RANGE_SIZE - SINGLE_SIZE,
                (true, false) => 0,
            };

            if !current.is_empty() && (current.len() == MAX_ACK_ENTRIES || size + growth > max_size)
            {
                acks.push(Self {
                    is_nack,
                    sequences: take(&mut current),
                });
                size = HEADER_SIZE;
            }

            match current.is_empty() || !extends {
                true => {
                    range_start = seq;
                    size += SINGLE_SIZE;
                }
                false => size += growth,
            }
            current.push(seq);
        }

        if !current.is_empty() {
            acks.push(Self {
                is_nack,
                sequences: current,
            });
        }
        acks
    }

    #[inline(always)]
    fn serialize_range<W: Write>(start: u32, end: u32, writer: &mut W) -> Result<(), Error> {
        if start == end {
            writer.write_u8(1)?;
            writer.write_u24::<LittleEndian>(start)?;
        } else {
            writer.write_u8(0)?;
            writer.write_u24::<LittleEndian>(start)?;
            writer.write_u24::<LittleEndian>(end)?;
        }
        Ok(())
    }

    #[inline(always)]
    fn range_size_hint(start: u32, end: u32) -> usize {
        match start == end {
            true => SINGLE_SIZE,
            false => RANGE_SIZE,
        }
    }
}

impl RakCodec for Ack {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), RakCodecError> {
        if self.sequences.len() > MAX_ACK_ENTRIES {
            return Err(RakCodecError::TooManyAckEntries);
        }

        writer.write_u8(VALID | if self.is_nack { NACK } else { ACK })?;

        let (&first, rest) = match self.sequences.split_first() {
            Some(pair) => pair,
            None => {
                writer.write_u16::<BigEndian>(0)?;
                return Ok(());
            }
        };

        // in worst case each sequence is written as a 4 byte single-value range
        let mut buf: Vec<u8> = Vec::with_capacity(self.sequences.len() * 4);
        let mut count: u16 = 0;

        let mut start: u32 = first;
        let mut end: u32 = start;
        for &i in rest {
            if i == end + 1 {
                end = i
            } else {
                Self::serialize_range(start, end, &mut buf)?;
                count += 1;
                start = i;
                end = i;
            }
        }
        Self::serialize_range(start, end, &mut buf)?;
        count += 1;

        writer.write_u16::<BigEndian>(count)?;
        writer.write_all(&buf)?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, RakCodecError> {
        let id = reader.read_u8()?;
        if id & VALID == 0 || (id & (ACK | NACK)).count_ones() != 1 {
            return Err(RakCodecError::UnexpectedHeader(id));
        }

        let is_nack = id & NACK != 0;

        let count = reader.read_u16::<BigEndian>()?;

        let mut sequences: Vec<u32> = Vec::new();
        for _ in 0..count {
            let (start, end) = if reader.read_u8()? != 0 {
                let single = reader.read_u24::<LittleEndian>()?;
                (single, single)
            } else {
                (
                    reader.read_u24::<LittleEndian>()?,
                    reader.read_u24::<LittleEndian>()?,
                )
            };
            if end < start {
                return Err(RakCodecError::Malformed("ack range invalid, end < start"));
            }
            if sequences.len() + (end - start) as usize >= MAX_ACK_ENTRIES {
                return Err(RakCodecError::TooManyAckEntries);
            }
            sequences.extend(start..=end);
        }

        Ok(Self::new(sequences, is_nack))
    }

    fn size_hint(&self) -> usize {
        let mut size = HEADER_SIZE;

        let (&first, rest) = match self.sequences.split_first() {
            Some(pair) => pair,
            None => {
                return size;
            }
        };

        let mut start: u32 = first;
        let mut end: u32 = start;
        for &i in rest {
            if i == end + 1 {
                end = i
            } else {
                size += Self::range_size_hint(start, end);
                start = i;
                end = i;
            }
        }
        size += Self::range_size_hint(start, end);

        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_contiguous_range() {
        let ack = Ack::new(vec![5, 6, 7], false);

        let mut buf = Vec::with_capacity(ack.size_hint());
        ack.serialize(&mut buf).unwrap();

        let decoded = Ack::deserialize(&mut buf.as_slice()).unwrap();

        assert_eq!(decoded.sequences, vec![5, 6, 7]);
    }

    fn range_ack(start: u32, end: u32) -> Vec<u8> {
        let mut buf = vec![VALID | ACK];
        buf.write_u16::<BigEndian>(1).unwrap();
        buf.write_u8(0).unwrap();
        buf.write_u24::<LittleEndian>(start).unwrap();
        buf.write_u24::<LittleEndian>(end).unwrap();
        buf
    }

    #[test]
    fn rejects_ranges_expanding_past_the_entry_cap() {
        let buf = range_ack(0, MAX_ACK_ENTRIES as u32);

        let decoded = Ack::deserialize(&mut buf.as_slice());

        assert!(
            matches!(decoded, Err(RakCodecError::TooManyAckEntries)),
            "an ACK expanding to more than {MAX_ACK_ENTRIES} entries must be rejected, got {decoded:?}"
        );
    }

    #[test]
    fn accepts_ranges_at_the_entry_cap() {
        let buf = range_ack(0, MAX_ACK_ENTRIES as u32 - 1);

        let decoded = Ack::deserialize(&mut buf.as_slice()).unwrap();

        assert_eq!(decoded.sequences.len(), MAX_ACK_ENTRIES);
    }

    #[test]
    fn serialize_rejects_more_entries_than_the_cap() {
        let ack = Ack::new((0..=MAX_ACK_ENTRIES as u32).collect(), false);

        let encoded = ack.serialize(&mut Vec::new());

        assert!(
            matches!(encoded, Err(RakCodecError::TooManyAckEntries)),
            "encoding {} entries must be rejected like decoding them is, got {encoded:?}",
            ack.sequences.len()
        );
    }

    #[test]
    fn serialize_does_not_overflow_the_range_count() {
        let ack = Ack::new((0..70_000u32).map(|i| i * 2).collect(), true);

        let encoded = ack.serialize(&mut Vec::new());

        assert!(matches!(encoded, Err(RakCodecError::TooManyAckEntries)));
    }

    #[test]
    fn split_starts_a_new_ack_when_the_next_record_would_not_fit() {
        let acks = Ack::split(vec![10, 0, 1, 2], false, HEADER_SIZE + RANGE_SIZE);

        let sequences: Vec<Vec<u32>> = acks.into_iter().map(|ack| ack.sequences).collect();
        assert_eq!(sequences, vec![vec![0, 1, 2], vec![10]]);
    }

    #[test]
    fn split_acks_encode_within_their_size_hint() {
        let sequences = (0..3000u32).filter(|i| i % 3 != 0).collect();

        for ack in Ack::split(sequences, true, 100) {
            let mut buf = Vec::new();
            ack.serialize(&mut buf).unwrap();
            assert!(buf.len() <= 100, "ACK of {} bytes", buf.len());
            assert_eq!(buf.len(), ack.size_hint());
        }
    }
}
