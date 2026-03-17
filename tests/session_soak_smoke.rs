use std::time::{Duration, Instant};

use bytes::Bytes;
use raknet_rs::low_level::protocol::ack::{AckNackPayload, SequenceRange};
use raknet_rs::low_level::protocol::datagram::DatagramPayload;
use raknet_rs::low_level::protocol::reliability::Reliability;
use raknet_rs::low_level::session::tunables::SessionTunables;
use raknet_rs::low_level::session::{QueuePayloadResult, RakPriority, Session};

#[test]
fn multi_session_loss_and_reorder_soak_smoke_stays_bounded() {
    let session_count = 128usize;
    let tick_count = 180usize;
    let mut sessions = Vec::with_capacity(session_count);
    let tunables = SessionTunables::default();
    for _ in 0..session_count {
        sessions.push(Session::with_tunables(1400, tunables.clone()));
    }

    let start = Instant::now();
    let mut total_acks = 0usize;
    let mut total_nacks = 0usize;
    let mut max_pending_bytes = 0usize;

    for tick in 0..tick_count {
        let now = start + Duration::from_millis((tick as u64) * 20);
        for session in &mut sessions {
            let queue_result = session.queue_payload(
                Bytes::from_static(b"soak-payload"),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High,
            );
            assert!(
                matches!(
                    queue_result,
                    QueuePayloadResult::Enqueued { .. } | QueuePayloadResult::Deferred
                ),
                "unexpected queue result during soak: {queue_result:?}"
            );

            let outbound = session.on_tick(now, 6, 64 * 1024, 6, 64 * 1024);
            for datagram in outbound {
                if !matches!(datagram.payload, DatagramPayload::Frames(_)) {
                    continue;
                }

                let seq = datagram.header.sequence;
                let signal = (seq.value() as usize).wrapping_add(tick);
                if signal % 7 == 0 {
                    if signal % 13 == 0 {
                        session.handle_nack_payload(AckNackPayload {
                            ranges: vec![SequenceRange {
                                start: seq,
                                end: seq,
                            }],
                        });
                    }
                    continue;
                }

                session.handle_ack_payload(AckNackPayload {
                    ranges: vec![SequenceRange {
                        start: seq,
                        end: seq,
                    }],
                });
            }

            let progress = session.process_incoming_receipts(now + Duration::from_millis(1));
            total_acks = total_acks.saturating_add(progress.acked);
            total_nacks = total_nacks.saturating_add(progress.nacked);

            max_pending_bytes = max_pending_bytes.max(session.pending_outgoing_bytes());
            assert!(
                session.pending_outgoing_bytes() <= tunables.outgoing_queue_max_bytes,
                "pending bytes exceeded configured hard budget"
            );
            assert!(
                session.pending_outgoing_frames() <= tunables.outgoing_queue_max_frames,
                "pending frames exceeded configured hard budget"
            );
            assert!(
                !session.take_backpressure_disconnect(),
                "soak smoke should not trigger hard backpressure disconnect"
            );
        }
    }

    assert!(total_acks > 0, "soak should produce at least one ACK");
    assert!(
        max_pending_bytes < tunables.outgoing_queue_max_bytes,
        "queue should stay bounded below hard limit"
    );
    assert!(
        total_nacks > 0,
        "soak profile should exercise at least one NACK branch"
    );
}
