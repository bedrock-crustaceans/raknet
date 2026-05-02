use std::env;
use std::time::{Duration, Instant};

use bytes::Bytes;
use raknet::low_level::protocol::ack::{AckNackPayload, SequenceRange};
use raknet::low_level::protocol::datagram::DatagramPayload;
use raknet::low_level::protocol::reliability::Reliability;
use raknet::low_level::session::tunables::SessionTunables;
use raknet::low_level::session::{QueuePayloadResult, RakPriority, Session};

fn parse_arg(args: &[String], key: &str, default: usize) -> usize {
    let prefix = format!("--{key}=");
    for arg in args {
        if let Some(raw) = arg.strip_prefix(&prefix)
            && let Ok(v) = raw.parse::<usize>()
        {
            return v;
        }
    }
    default
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let session_count = parse_arg(&args, "sessions", 512);
    let tick_count = parse_arg(&args, "ticks", 2_000);
    let payload_size = parse_arg(&args, "payload-bytes", 180).max(1);

    let tunables = SessionTunables::default();
    let mut sessions = Vec::with_capacity(session_count);
    for _ in 0..session_count {
        sessions.push(Session::with_tunables(1400, tunables.clone()));
    }

    let start = Instant::now();
    let mut total_acks = 0usize;
    let mut total_nacks = 0usize;
    let mut max_pending_bytes = 0usize;
    let mut queue_drops = 0usize;
    let mut queue_defers = 0usize;
    let mut queue_disconnects = 0usize;

    let payload = Bytes::from(vec![0xAB; payload_size]);

    for tick in 0..tick_count {
        let now = start + Duration::from_millis((tick as u64) * 20);
        for session in &mut sessions {
            match session.queue_payload(
                payload.clone(),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High,
            ) {
                QueuePayloadResult::Enqueued { .. } => {}
                QueuePayloadResult::Dropped => queue_drops = queue_drops.saturating_add(1),
                QueuePayloadResult::Deferred => queue_defers = queue_defers.saturating_add(1),
                QueuePayloadResult::DisconnectRequested => {
                    queue_disconnects = queue_disconnects.saturating_add(1)
                }
            }

            let outbound = session.on_tick(now, 6, 64 * 1024, 6, 64 * 1024);
            for datagram in outbound {
                if !matches!(datagram.payload, DatagramPayload::Frames(_)) {
                    continue;
                }

                let seq = datagram.header.sequence;
                let signal = (seq.value() as usize).wrapping_add(tick);
                if signal % 9 == 0 {
                    if signal % 17 == 0 {
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
            if session.take_backpressure_disconnect() {
                queue_disconnects = queue_disconnects.saturating_add(1);
            }
        }
    }

    println!("RakNet soak summary");
    println!("sessions={session_count}");
    println!("ticks={tick_count}");
    println!("payload_bytes={payload_size}");
    println!("acked={total_acks}");
    println!("nacked={total_nacks}");
    println!("max_pending_bytes={max_pending_bytes}");
    println!("queue_drops={queue_drops}");
    println!("queue_defers={queue_defers}");
    println!("queue_disconnects={queue_disconnects}");
}
