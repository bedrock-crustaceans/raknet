use std::time::{Duration, Instant};

use bytes::Bytes;
use raknet_rust::low_level::protocol::ack::{AckNackPayload, SequenceRange};
use raknet_rust::low_level::protocol::reliability::Reliability;
use raknet_rust::low_level::session::tunables::{CongestionProfile, SessionTunables};
use raknet_rust::low_level::session::{QueuePayloadResult, RakPriority, Session};

fn default_tick(session: &mut Session, now: Instant, max_new_datagrams: usize) -> usize {
    session
        .on_tick(now, max_new_datagrams, 64 * 1024, 0, 0)
        .len()
}

#[test]
fn reliable_send_is_throttled_by_congestion_window_until_ack() {
    let tunables = SessionTunables {
        congestion_profile: CongestionProfile::Custom,
        initial_congestion_window: 1.0,
        min_congestion_window: 1.0,
        max_congestion_window: 1.0,
        ..SessionTunables::default()
    };

    let mut session = Session::with_tunables(200, tunables);
    let payload = Bytes::from(vec![0xAA; 150]);

    assert!(matches!(
        session.queue_payload(
            payload.clone(),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High
        ),
        QueuePayloadResult::Enqueued { .. }
    ));
    assert!(matches!(
        session.queue_payload(payload, Reliability::ReliableOrdered, 0, RakPriority::High),
        QueuePayloadResult::Enqueued { .. }
    ));

    let now = Instant::now();
    let first = session.on_tick(now, 2, 64 * 1024, 0, 0);
    assert_eq!(
        first.len(),
        1,
        "cwnd=1 must allow only one reliable datagram"
    );
    let seq = first[0].header.sequence;

    let blocked = default_tick(&mut session, now + Duration::from_millis(1), 2);
    assert_eq!(blocked, 0, "second datagram must wait for ACK");

    session.handle_ack_payload(AckNackPayload {
        ranges: vec![SequenceRange {
            start: seq,
            end: seq,
        }],
    });
    let _ = session.process_incoming_receipts(now + Duration::from_millis(30));

    let after_ack = default_tick(&mut session, now + Duration::from_millis(31), 2);
    assert_eq!(
        after_ack, 1,
        "after ACK, queued reliable datagram must flow"
    );
}

#[test]
fn karn_rule_skips_srtt_update_for_retransmitted_datagram() {
    let mut session = Session::new(200);
    let now = Instant::now();

    assert!(matches!(
        session.queue_payload(
            Bytes::from(vec![0xBB; 150]),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High
        ),
        QueuePayloadResult::Enqueued { .. }
    ));

    let sent = session.on_tick(now, 1, 64 * 1024, 0, 0);
    assert_eq!(sent.len(), 1);
    let seq = sent[0].header.sequence;

    let resent = session.collect_resendable(now + Duration::from_secs(2), 4, usize::MAX);
    assert_eq!(resent.len(), 1, "timeout should produce one resend");

    session.handle_ack_payload(AckNackPayload {
        ranges: vec![SequenceRange {
            start: seq,
            end: seq,
        }],
    });
    let _ =
        session.process_incoming_receipts(now + Duration::from_secs(2) + Duration::from_millis(20));

    let snapshot = session.metrics_snapshot();
    assert_eq!(
        snapshot.srtt_ms, 0.0,
        "Karn rule: retransmitted packet ACK must not sample RTT"
    );
}

#[test]
fn resend_rto_is_clamped_to_configured_max() {
    let tunables = SessionTunables {
        congestion_profile: CongestionProfile::Custom,
        resend_rto: Duration::from_millis(100),
        min_resend_rto: Duration::from_millis(80),
        max_resend_rto: Duration::from_millis(500),
        ..SessionTunables::default()
    };

    let mut session = Session::with_tunables(200, tunables);
    let start = Instant::now();

    assert!(matches!(
        session.queue_payload(
            Bytes::from(vec![0xCC; 150]),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High
        ),
        QueuePayloadResult::Enqueued { .. }
    ));
    let _ = session.on_tick(start, 1, 64 * 1024, 0, 0);

    for step in 1..=6 {
        let now = start + Duration::from_secs(step * 2);
        let resent = session.collect_resendable(now, 8, usize::MAX);
        assert_eq!(resent.len(), 1);
    }

    let snapshot = session.metrics_snapshot();
    assert!(
        snapshot.resend_rto_ms <= 500.0,
        "RTO must stay under configured max: {}",
        snapshot.resend_rto_ms
    );
}

#[test]
fn resend_rto_is_clamped_to_configured_min_after_fast_ack_samples() {
    let tunables = SessionTunables {
        congestion_profile: CongestionProfile::Custom,
        resend_rto: Duration::from_millis(400),
        min_resend_rto: Duration::from_millis(200),
        max_resend_rto: Duration::from_millis(2_000),
        ..SessionTunables::default()
    };

    let mut session = Session::with_tunables(200, tunables);
    let start = Instant::now();

    for i in 0..5 {
        assert!(matches!(
            session.queue_payload(
                Bytes::from(vec![0xCD; 120]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));
        let send_at = start + Duration::from_millis((i * 10) as u64);
        let sent = session.on_tick(send_at, 1, 64 * 1024, 0, 0);
        assert_eq!(sent.len(), 1, "payload must be emitted for RTT sample");
        let seq = sent[0].header.sequence;

        session.handle_ack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq,
                end: seq,
            }],
        });
        let _ = session.process_incoming_receipts(send_at + Duration::from_millis(4));
    }

    let snapshot = session.metrics_snapshot();
    assert!(
        snapshot.resend_rto_ms >= 200.0,
        "RTO must stay above configured min: {}",
        snapshot.resend_rto_ms
    );
}

#[test]
fn high_latency_profile_is_less_aggressive_on_nack_loss_than_conservative() {
    let now = Instant::now();

    let mut conservative = Session::with_tunables(
        200,
        SessionTunables {
            congestion_profile: CongestionProfile::Conservative,
            ..SessionTunables::default()
        },
    );

    let mut high_latency = Session::with_tunables(
        200,
        SessionTunables {
            congestion_profile: CongestionProfile::HighLatency,
            ..SessionTunables::default()
        },
    );

    for session in [&mut conservative, &mut high_latency] {
        assert!(matches!(
            session.queue_payload(
                Bytes::from(vec![0xCE; 120]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));
    }

    let conservative_sent = conservative.on_tick(now, 1, 64 * 1024, 0, 0);
    let high_latency_sent = high_latency.on_tick(now, 1, 64 * 1024, 0, 0);
    assert_eq!(conservative_sent.len(), 1);
    assert_eq!(high_latency_sent.len(), 1);

    let conservative_before = conservative.metrics_snapshot().congestion_window_packets;
    let high_latency_before = high_latency.metrics_snapshot().congestion_window_packets;

    conservative.handle_nack_payload(AckNackPayload {
        ranges: vec![SequenceRange {
            start: conservative_sent[0].header.sequence,
            end: conservative_sent[0].header.sequence,
        }],
    });
    let _ = conservative.process_incoming_receipts(now + Duration::from_millis(1));
    let conservative_after = conservative.metrics_snapshot().congestion_window_packets;

    high_latency.handle_nack_payload(AckNackPayload {
        ranges: vec![SequenceRange {
            start: high_latency_sent[0].header.sequence,
            end: high_latency_sent[0].header.sequence,
        }],
    });
    let _ = high_latency.process_incoming_receipts(now + Duration::from_millis(1));
    let high_latency_after = high_latency.metrics_snapshot().congestion_window_packets;

    let conservative_ratio = conservative_after / conservative_before.max(1.0);
    let high_latency_ratio = high_latency_after / high_latency_before.max(1.0);
    assert!(
        high_latency_ratio >= conservative_ratio,
        "high-latency profile should be at least as conservative on NACK loss (high={}, conservative={})",
        high_latency_ratio,
        conservative_ratio
    );
}

#[test]
fn pending_outgoing_bytes_return_to_zero_after_flush() {
    let mut session = Session::new(200);
    let payload = Bytes::from(vec![0xDD; 150]);

    let _ = session.queue_payload(
        payload.clone(),
        Reliability::ReliableOrdered,
        0,
        RakPriority::High,
    );
    let _ = session.queue_payload(payload, Reliability::ReliableOrdered, 0, RakPriority::High);

    assert!(
        session.pending_outgoing_bytes() > 0,
        "queued bytes must increase after enqueue"
    );

    let sent = session.on_tick(Instant::now(), 8, 64 * 1024, 0, 0);
    assert!(!sent.is_empty());
    assert_eq!(session.pending_outgoing_frames(), 0);
    assert_eq!(session.pending_outgoing_bytes(), 0);
}

#[test]
fn soft_backpressure_defers_low_priority_reliable() {
    let tunables = SessionTunables {
        outgoing_queue_max_frames: 4,
        outgoing_queue_max_bytes: 8 * 1024,
        outgoing_queue_soft_ratio: 0.5,
        ..SessionTunables::default()
    };

    let mut session = Session::with_tunables(200, tunables);

    let _ = session.queue_payload(
        Bytes::from_static(b"a"),
        Reliability::Reliable,
        0,
        RakPriority::High,
    );
    let _ = session.queue_payload(
        Bytes::from_static(b"b"),
        Reliability::Reliable,
        0,
        RakPriority::High,
    );

    assert!(matches!(
        session.queue_payload(
            Bytes::from_static(b"c"),
            Reliability::Reliable,
            0,
            RakPriority::Low
        ),
        QueuePayloadResult::Deferred
    ));

    let snapshot = session.metrics_snapshot();
    assert_eq!(snapshot.outgoing_queue_defers, 1);
}

#[test]
fn nack_for_reliable_datagram_triggers_resend_before_timeout() {
    let mut session = Session::new(200);
    let now = Instant::now();

    assert!(matches!(
        session.queue_payload(
            Bytes::from(vec![0xEE; 150]),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High
        ),
        QueuePayloadResult::Enqueued { .. }
    ));

    let sent = session.on_tick(now, 1, 64 * 1024, 0, 0);
    assert_eq!(sent.len(), 1);
    let seq = sent[0].header.sequence;

    session.handle_nack_payload(AckNackPayload {
        ranges: vec![SequenceRange {
            start: seq,
            end: seq,
        }],
    });
    let progress = session.process_incoming_receipts(now + Duration::from_millis(5));
    assert_eq!(progress.nacked, 1);

    let resent = session.on_tick(now + Duration::from_millis(5), 0, 0, 4, usize::MAX);
    assert!(
        resent.iter().any(|d| d.header.sequence == seq),
        "nack should schedule immediate resend of the same datagram sequence"
    );
}

#[test]
fn unreliable_with_ack_receipt_reports_receipt_completion_on_ack() {
    let mut session = Session::new(200);
    let now = Instant::now();

    assert!(matches!(
        session.queue_payload_with_receipt(
            Bytes::from_static(b"hello"),
            Reliability::UnreliableWithAckReceipt,
            0,
            RakPriority::Normal,
            Some(555)
        ),
        QueuePayloadResult::Enqueued { .. }
    ));

    let sent = session.on_tick(now, 1, 64 * 1024, 0, 0);
    assert_eq!(sent.len(), 1);
    let seq = sent[0].header.sequence;

    session.handle_ack_payload(AckNackPayload {
        ranges: vec![SequenceRange {
            start: seq,
            end: seq,
        }],
    });
    let progress = session.process_incoming_receipts(now + Duration::from_millis(15));
    assert_eq!(progress.acked, 1);
    assert_eq!(progress.acked_receipt_ids, vec![555]);
}
