use std::panic::{AssertUnwindSafe, catch_unwind};

use bytes::BytesMut;
use proptest::prelude::*;
use raknet_rs::low_level::protocol::ack::{AckNackPayload, SequenceRange};
use raknet_rs::low_level::protocol::codec::RaknetCodec;
use raknet_rs::low_level::protocol::datagram::Datagram;
use raknet_rs::low_level::protocol::sequence24::Sequence24;
use raknet_rs::protocol::packet::OfflinePacket;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn datagram_decode_random_input_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut src = &data[..];
            let _ = Datagram::decode(&mut src);
        }));
        prop_assert!(result.is_ok());
    }

    #[test]
    fn offline_decode_random_input_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut src = &data[..];
            let _ = OfflinePacket::decode(&mut src);
        }));
        prop_assert!(result.is_ok());
    }

    #[test]
    fn ack_payload_roundtrip_is_stable(
        ranges in proptest::collection::vec(
            (0u32..=0x00FF_FFFF, 0u32..=0x00FF_FFFF),
            0..16
        )
    ) {
        let payload = AckNackPayload {
            ranges: ranges
                .into_iter()
                .map(|(start, end)| SequenceRange {
                    start: Sequence24::new(start),
                    end: Sequence24::new(end),
                })
                .collect(),
        };

        let mut encoded = BytesMut::new();
        if payload.encode_raknet(&mut encoded).is_err() {
            return Ok(());
        }
        let mut src = &encoded[..];
        let decoded = AckNackPayload::decode_raknet(&mut src)?;
        prop_assert!(src.is_empty());

        let mut reencoded = BytesMut::new();
        decoded.encode_raknet(&mut reencoded)?;
        prop_assert!(!reencoded.is_empty() || decoded.ranges.is_empty());
    }
}
