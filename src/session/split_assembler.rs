use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use crate::error::DecodeError;
use crate::protocol::frame::Frame;

struct SplitEntry {
    header: crate::protocol::frame_header::FrameHeader,
    reliable_index: Option<crate::protocol::sequence24::Sequence24>,
    sequence_index: Option<crate::protocol::sequence24::Sequence24>,
    ordering_index: Option<crate::protocol::sequence24::Sequence24>,
    ordering_channel: Option<u8>,
    part_count: u32,
    received: usize,
    parts: Vec<Option<Bytes>>,
    last_update: Instant,
}

pub struct SplitAssembler {
    entries: HashMap<u16, SplitEntry>,
    ttl: Duration,
    max_parts: u32,
    max_concurrent: usize,
}

impl SplitAssembler {
    pub fn new(ttl: Duration, max_parts: u32, max_concurrent: usize) -> Self {
        let effective_ttl = if ttl.is_zero() {
            Duration::from_secs(30)
        } else {
            ttl
        };

        Self {
            entries: HashMap::new(),
            ttl: effective_ttl,
            max_parts: max_parts.max(1),
            max_concurrent: max_concurrent.max(1),
        }
    }

    pub fn add(&mut self, frame: Frame, now: Instant) -> Result<Option<Frame>, DecodeError> {
        if !frame.header.is_split {
            return Ok(Some(frame));
        }

        // Opportunistically reclaim stale compounds before applying capacity checks.
        let _ = self.prune(now);

        let split = frame.split.as_ref().ok_or(DecodeError::MissingSplitInfo)?;
        if split.part_count == 0 {
            return Err(DecodeError::SplitCountZero);
        }
        if split.part_count > self.max_parts {
            return Err(DecodeError::SplitTooLarge);
        }
        if split.part_index >= split.part_count {
            return Err(DecodeError::SplitIndexOutOfRange);
        }
        let part_count =
            usize::try_from(split.part_count).map_err(|_| DecodeError::SplitTooLarge)?;

        if self.entries.len() >= self.max_concurrent && !self.entries.contains_key(&split.part_id) {
            return Err(DecodeError::SplitBufferFull);
        }

        let entry = self
            .entries
            .entry(split.part_id)
            .or_insert_with(|| SplitEntry {
                header: frame.header,
                reliable_index: frame.reliable_index,
                sequence_index: frame.sequence_index,
                ordering_index: frame.ordering_index,
                ordering_channel: frame.ordering_channel,
                part_count: split.part_count,
                received: 0,
                parts: vec![None; part_count],
                last_update: now,
            });

        if entry.part_count != split.part_count {
            return Err(DecodeError::SplitCountMismatch);
        }
        if entry.parts.len() != part_count {
            return Err(DecodeError::SplitCountMismatch);
        }

        let index = split.part_index as usize;
        if index >= entry.parts.len() {
            return Err(DecodeError::SplitIndexOutOfRange);
        }

        if entry.parts[index].is_some() {
            return Ok(None);
        }

        entry.parts[index] = Some(frame.payload.clone());
        entry.received += 1;
        entry.last_update = now;

        if entry.received != entry.parts.len() {
            return Ok(None);
        }

        let mut merged = BytesMut::new();
        for part in &entry.parts {
            let bytes = part.as_ref().ok_or(DecodeError::SplitCountMismatch)?;
            merged.extend_from_slice(bytes);
        }
        let payload = merged.freeze();

        let assembled = Frame {
            header: crate::protocol::frame_header::FrameHeader {
                reliability: entry.header.reliability,
                is_split: false,
                needs_bas: entry.header.needs_bas,
            },
            bit_length: (payload.len() as u16) << 3,
            reliable_index: entry.reliable_index,
            sequence_index: entry.sequence_index,
            ordering_index: entry.ordering_index,
            ordering_channel: entry.ordering_channel,
            split: None,
            payload,
        };

        self.entries.remove(&split.part_id);
        Ok(Some(assembled))
    }

    pub fn prune(&mut self, now: Instant) -> usize {
        let mut dropped = 0usize;
        self.entries.retain(|_, entry| {
            if now.duration_since(entry.last_update) >= self.ttl {
                dropped += 1;
                false
            } else {
                true
            }
        });
        dropped
    }

    pub fn drain_buffered_parts(&mut self) -> Vec<Bytes> {
        let mut out = Vec::new();
        for (_, entry) in self.entries.drain() {
            out.extend(entry.parts.into_iter().flatten());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;

    use super::SplitAssembler;
    use crate::error::DecodeError;
    use crate::protocol::frame::{Frame, SplitInfo};
    use crate::protocol::frame_header::FrameHeader;
    use crate::protocol::reliability::Reliability;

    fn split_frame(
        part_id: u16,
        part_count: u32,
        part_index: u32,
        payload: &'static [u8],
    ) -> Frame {
        Frame {
            header: FrameHeader::new(Reliability::ReliableOrdered, true, false),
            bit_length: (payload.len() as u16) << 3,
            reliable_index: None,
            sequence_index: None,
            ordering_index: None,
            ordering_channel: None,
            split: Some(SplitInfo {
                part_count,
                part_id,
                part_index,
            }),
            payload: Bytes::from_static(payload),
        }
    }

    #[test]
    fn add_rejects_split_part_count_over_limit() {
        let mut assembler = SplitAssembler::new(Duration::from_secs(5), 2, 8);
        let now = Instant::now();
        let frame = split_frame(1, 3, 0, b"a");
        let err = assembler
            .add(frame, now)
            .expect_err("part_count above max_parts must be rejected");
        assert!(matches!(err, DecodeError::SplitTooLarge));
    }

    #[test]
    fn add_enforces_max_concurrent_compounds_but_allows_existing_id() {
        let mut assembler = SplitAssembler::new(Duration::from_secs(5), 4, 2);
        let now = Instant::now();

        assert!(matches!(
            assembler.add(split_frame(1, 2, 0, b"a"), now),
            Ok(None)
        ));
        assert!(matches!(
            assembler.add(split_frame(2, 2, 0, b"b"), now),
            Ok(None)
        ));

        let err = assembler
            .add(split_frame(3, 2, 0, b"c"), now)
            .expect_err("new split compound must fail when buffer is full");
        assert!(matches!(err, DecodeError::SplitBufferFull));

        let assembled = assembler
            .add(split_frame(1, 2, 1, b"d"), now)
            .expect("existing compound should still accept remaining part");
        assert!(
            assembled.is_some(),
            "compound with existing part_id should complete"
        );
    }

    #[test]
    fn add_rejects_split_count_mismatch_for_same_part_id() {
        let mut assembler = SplitAssembler::new(Duration::from_secs(5), 8, 8);
        let now = Instant::now();

        assert!(matches!(
            assembler.add(split_frame(9, 2, 0, b"a"), now),
            Ok(None)
        ));
        let err = assembler
            .add(split_frame(9, 3, 1, b"b"), now)
            .expect_err("same part_id with different part_count must be rejected");
        assert!(matches!(err, DecodeError::SplitCountMismatch));
    }

    #[test]
    fn add_assembles_payload_and_ignores_duplicate_part() {
        let mut assembler = SplitAssembler::new(Duration::from_secs(5), 4, 8);
        let now = Instant::now();

        assert!(matches!(
            assembler.add(split_frame(5, 2, 0, b"hello "), now),
            Ok(None)
        ));
        assert!(matches!(
            assembler.add(split_frame(5, 2, 0, b"duplicate"), now),
            Ok(None)
        ));

        let assembled = assembler
            .add(split_frame(5, 2, 1, b"world"), now)
            .expect("final split part should be accepted")
            .expect("compound should assemble");
        assert_eq!(assembled.payload.as_ref(), b"hello world");
        assert!(!assembled.header.is_split);
        assert!(
            assembler.entries.is_empty(),
            "assembled compound must be removed"
        );
    }

    #[test]
    fn prune_drops_only_expired_compounds() {
        let mut assembler = SplitAssembler::new(Duration::from_millis(30), 8, 8);
        let start = Instant::now();

        assert!(matches!(
            assembler.add(split_frame(11, 2, 0, b"a"), start),
            Ok(None)
        ));
        assert!(matches!(
            assembler.add(
                split_frame(12, 2, 0, b"b"),
                start + Duration::from_millis(20)
            ),
            Ok(None)
        ));

        let dropped_first = assembler.prune(start + Duration::from_millis(35));
        assert_eq!(dropped_first, 1, "only oldest compound should expire first");
        assert_eq!(assembler.entries.len(), 1);

        let dropped_second = assembler.prune(start + Duration::from_millis(60));
        assert_eq!(
            dropped_second, 1,
            "remaining compound should expire on later prune"
        );
        assert!(assembler.entries.is_empty());
    }

    #[test]
    fn add_prunes_expired_compounds_before_capacity_check() {
        let mut assembler = SplitAssembler::new(Duration::from_millis(20), 4, 1);
        let start = Instant::now();

        assert!(matches!(
            assembler.add(split_frame(30, 2, 0, b"x"), start),
            Ok(None)
        ));

        let result = assembler.add(
            split_frame(31, 2, 0, b"y"),
            start + Duration::from_millis(25),
        );
        assert!(
            result.is_ok(),
            "expired compound should be pruned before checking max_concurrent"
        );
    }
}
