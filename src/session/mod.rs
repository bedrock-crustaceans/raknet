pub mod ack_queue;
pub mod ordering_channels;
pub mod priority;
pub mod reliable_tracker;
pub mod split_assembler;
pub mod state;
pub mod tunables;

pub use priority::RakPriority;
pub use state::SessionState;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use zeroize::Zeroize;

use ack_queue::AckQueue;
use ordering_channels::{OrderedResult, OrderingChannels, SequencedResult};
use split_assembler::SplitAssembler;

use crate::error::DecodeError;
use crate::protocol::ack::{AckNackPayload, SequenceRange};
use crate::protocol::constants::{DatagramFlags, MAX_ACK_SEQUENCES, RAKNET_DATAGRAM_HEADER_SIZE};
use crate::protocol::datagram::{Datagram, DatagramHeader, DatagramPayload};
use crate::protocol::frame::Frame;
use crate::protocol::frame_header::FrameHeader;
use crate::protocol::reliability::Reliability;
use crate::protocol::sequence24::Sequence24;

use self::reliable_tracker::ReliableTracker;
use self::tunables::{AckNackPriority, BackpressureMode, SessionTunables};

#[derive(Debug, Clone)]
pub struct TrackedDatagram {
    pub datagram: Datagram,
    pub send_time: Instant,
    pub next_send: Instant,
    pub retries: u32,
    pub nack_resend_pending: bool,
    pub resendable: bool,
    pub receipt_ids: Vec<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct ReceiptProgress {
    pub acked: usize,
    pub nacked: usize,
    pub acked_receipt_ids: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePayloadResult {
    Enqueued { reliable_bytes: usize },
    Dropped,
    Deferred,
    DisconnectRequested,
}

#[derive(Debug, Default, Clone, Copy)]
struct SessionMetrics {
    ingress_datagrams: u64,
    ingress_frames: u64,
    duplicate_reliable_drops: u64,
    ordered_stale_drops: u64,
    ordered_buffer_full_drops: u64,
    sequenced_stale_drops: u64,
    sequenced_missing_index_drops: u64,
    reliable_sent_datagrams: u64,
    resent_datagrams: u64,
    ack_out_datagrams: u64,
    nack_out_datagrams: u64,
    acked_datagrams: u64,
    nacked_datagrams: u64,
    split_ttl_drops: u64,
    outgoing_queue_drops: u64,
    outgoing_queue_defers: u64,
    outgoing_queue_disconnects: u64,
    backpressure_delays: u64,
    backpressure_drops: u64,
    backpressure_disconnects: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SessionMetricsSnapshot {
    pub ingress_datagrams: u64,
    pub ingress_frames: u64,
    pub duplicate_reliable_drops: u64,
    pub ordered_stale_drops: u64,
    pub ordered_buffer_full_drops: u64,
    pub sequenced_stale_drops: u64,
    pub sequenced_missing_index_drops: u64,
    pub reliable_sent_datagrams: u64,
    pub resent_datagrams: u64,
    pub ack_out_datagrams: u64,
    pub nack_out_datagrams: u64,
    pub acked_datagrams: u64,
    pub nacked_datagrams: u64,
    pub split_ttl_drops: u64,
    pub pending_outgoing_frames: usize,
    pub pending_outgoing_bytes: usize,
    pub outgoing_queue_drops: u64,
    pub outgoing_queue_defers: u64,
    pub outgoing_queue_disconnects: u64,
    pub backpressure_delays: u64,
    pub backpressure_drops: u64,
    pub backpressure_disconnects: u64,
    pub srtt_ms: f64,
    pub rttvar_ms: f64,
    pub resend_rto_ms: f64,
    pub congestion_window_packets: f64,
    pub resend_ratio: f64,
    pub pacing_budget_bytes: f64,
    pub pacing_rate_bytes_per_sec: f64,
}

#[derive(Debug, Clone)]
struct QueuedFrame {
    weight: u64,
    encoded_size: usize,
    is_reliable: bool,
    priority: RakPriority,
    receipt_id: Option<u64>,
    frame: Frame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackpressureAction {
    Allow,
    Drop,
    Defer,
    Disconnect,
}

impl PartialEq for QueuedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.weight == other.weight
    }
}

impl Eq for QueuedFrame {}

impl PartialOrd for QueuedFrame {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedFrame {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower weight is higher priority.
        other.weight.cmp(&self.weight)
    }
}

pub struct Session {
    state: SessionState,
    mtu: usize,
    last_activity: Instant,
    last_keepalive_sent: Instant,
    datagram_read_index: Sequence24,
    datagram_write_index: Sequence24,
    reliable_write_index: Sequence24,
    split_write_index: u16,
    ordering_write_index: Vec<Sequence24>,
    sequencing_write_index: Vec<Sequence24>,
    reliable_tracker: ReliableTracker,
    split_assembler: SplitAssembler,
    ordering: OrderingChannels,
    outgoing_heap: BinaryHeap<QueuedFrame>,
    outgoing_next_weights: [u64; 4],
    last_min_weight: u64,
    outgoing_acks: AckQueue,
    outgoing_nacks: AckQueue,
    ack_flush_interval: Duration,
    nack_flush_interval: Duration,
    ack_max_ranges_per_datagram: usize,
    nack_max_ranges_per_datagram: usize,
    ack_nack_priority: AckNackPriority,
    next_ack_flush_at: Instant,
    next_nack_flush_at: Instant,
    incoming_acks: VecDeque<SequenceRange>,
    incoming_nacks: VecDeque<SequenceRange>,
    sent_datagrams: BTreeMap<Sequence24, TrackedDatagram>,
    receipt_tracking: HashMap<u64, usize>,
    resend_rto: Duration,
    min_resend_rto: Duration,
    max_resend_rto: Duration,
    srtt_ms: Option<f64>,
    rttvar_ms: f64,
    congestion_window_packets: f64,
    min_congestion_window_packets: f64,
    max_congestion_window_packets: f64,
    slow_start_threshold_packets: f64,
    congestion_additive_gain: f64,
    congestion_multiplicative_decrease_nack: f64,
    congestion_multiplicative_decrease_timeout: f64,
    high_rtt_threshold_ms: f64,
    high_rtt_additive_scale: f64,
    nack_loss_backoff_cooldown: Duration,
    next_nack_loss_backoff: Instant,
    pacing_enabled: bool,
    pacing_gain: f64,
    pacing_min_rate_bytes_per_sec: f64,
    pacing_max_rate_bytes_per_sec: f64,
    pacing_budget_max_bytes: f64,
    pacing_budget_bytes: f64,
    pacing_rate_bytes_per_sec: f64,
    last_pacing_update: Instant,
    outgoing_queued_bytes: usize,
    outgoing_queue_max_frames: usize,
    outgoing_queue_max_bytes: usize,
    outgoing_queue_soft_ratio: f64,
    backpressure_mode: BackpressureMode,
    best_effort_zeroize_dropped_payloads: bool,
    disconnect_requested_by_backpressure: bool,
    metrics: SessionMetrics,
}

impl Session {
    pub fn new(mtu: usize) -> Self {
        Self::with_tunables(mtu, SessionTunables::default())
    }

    pub fn with_tunables(mtu: usize, tunables: SessionTunables) -> Self {
        let now = Instant::now();
        let congestion = tunables.resolved_congestion_settings();
        let min_cwnd = congestion.min_congestion_window.max(1.0);
        let max_cwnd = congestion.max_congestion_window.max(min_cwnd);
        let initial_cwnd = congestion
            .initial_congestion_window
            .clamp(min_cwnd, max_cwnd)
            .max(1.0);
        let slow_start_threshold = congestion
            .congestion_slow_start_threshold
            .clamp(min_cwnd, max_cwnd);
        let pacing_min_rate = tunables.pacing_min_rate_bytes_per_sec.max(1.0);
        let pacing_max_rate = tunables.pacing_max_rate_bytes_per_sec.max(pacing_min_rate);
        let pacing_budget_max = tunables.pacing_max_burst_bytes.max(1) as f64;
        let initial_pacing_budget = if tunables.pacing_start_full {
            pacing_budget_max
        } else {
            0.0
        };
        let ack_nack_flush = tunables.resolved_ack_nack_flush_settings();
        let mut s = Self {
            state: SessionState::Offline,
            mtu,
            last_activity: now,
            last_keepalive_sent: now,
            datagram_read_index: Sequence24::new(0),
            datagram_write_index: Sequence24::new(0),
            reliable_write_index: Sequence24::new(0),
            split_write_index: 0,
            ordering_write_index: vec![Sequence24::new(0); 16],
            sequencing_write_index: vec![Sequence24::new(0); 16],
            reliable_tracker: ReliableTracker::new(tunables.reliable_window),
            split_assembler: SplitAssembler::new(
                tunables.split_ttl,
                tunables.max_split_parts,
                tunables.max_concurrent_splits,
            ),
            ordering: OrderingChannels::new(
                tunables.max_ordering_channels,
                tunables.max_ordered_pending_per_channel,
                tunables.max_order_gap,
            ),
            outgoing_heap: BinaryHeap::new(),
            outgoing_next_weights: [0; 4],
            last_min_weight: 0,
            outgoing_acks: AckQueue::new(tunables.ack_queue_capacity),
            outgoing_nacks: AckQueue::new(tunables.ack_queue_capacity),
            ack_flush_interval: ack_nack_flush.ack_flush_interval,
            nack_flush_interval: ack_nack_flush.nack_flush_interval,
            ack_max_ranges_per_datagram: ack_nack_flush.ack_max_ranges_per_datagram,
            nack_max_ranges_per_datagram: ack_nack_flush.nack_max_ranges_per_datagram,
            ack_nack_priority: ack_nack_flush.ack_nack_priority,
            next_ack_flush_at: now,
            next_nack_flush_at: now,
            incoming_acks: VecDeque::new(),
            incoming_nacks: VecDeque::new(),
            sent_datagrams: BTreeMap::new(),
            receipt_tracking: HashMap::new(),
            resend_rto: congestion
                .resend_rto
                .clamp(congestion.min_resend_rto, congestion.max_resend_rto),
            min_resend_rto: congestion.min_resend_rto,
            max_resend_rto: congestion.max_resend_rto,
            srtt_ms: None,
            rttvar_ms: 0.0,
            congestion_window_packets: initial_cwnd,
            min_congestion_window_packets: min_cwnd,
            max_congestion_window_packets: max_cwnd,
            slow_start_threshold_packets: slow_start_threshold,
            congestion_additive_gain: congestion.congestion_additive_gain.max(0.01),
            congestion_multiplicative_decrease_nack: congestion
                .congestion_multiplicative_decrease_nack
                .clamp(0.1, 0.99),
            congestion_multiplicative_decrease_timeout: congestion
                .congestion_multiplicative_decrease_timeout
                .clamp(0.1, 0.99),
            high_rtt_threshold_ms: congestion.congestion_high_rtt_threshold_ms.max(1.0),
            high_rtt_additive_scale: congestion
                .congestion_high_rtt_additive_scale
                .clamp(0.05, 1.0),
            nack_loss_backoff_cooldown: congestion
                .congestion_nack_backoff_cooldown
                .max(Duration::from_millis(1)),
            next_nack_loss_backoff: now,
            pacing_enabled: tunables.pacing_enabled,
            pacing_gain: tunables.pacing_gain.max(0.05),
            pacing_min_rate_bytes_per_sec: pacing_min_rate,
            pacing_max_rate_bytes_per_sec: pacing_max_rate,
            pacing_budget_max_bytes: pacing_budget_max,
            pacing_budget_bytes: initial_pacing_budget,
            pacing_rate_bytes_per_sec: pacing_min_rate,
            last_pacing_update: now,
            outgoing_queued_bytes: 0,
            outgoing_queue_max_frames: tunables.outgoing_queue_max_frames.max(1),
            outgoing_queue_max_bytes: tunables.outgoing_queue_max_bytes.max(1),
            outgoing_queue_soft_ratio: tunables.outgoing_queue_soft_ratio.clamp(0.05, 0.99),
            backpressure_mode: tunables.backpressure_mode,
            best_effort_zeroize_dropped_payloads: tunables.best_effort_zeroize_dropped_payloads,
            disconnect_requested_by_backpressure: false,
            metrics: SessionMetrics::default(),
        };

        for level in 0..4 {
            s.outgoing_next_weights[level] = ((1u64 << level) * level as u64) + level as u64;
        }

        s
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn transition_to(&mut self, next: SessionState) -> bool {
        if self.state.can_transition_to(next) {
            self.state = next;
            true
        } else {
            false
        }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    pub fn touch_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_activity)
    }

    pub fn should_send_keepalive(&self, now: Instant, interval: Duration) -> bool {
        if self.state != SessionState::Connected || interval.is_zero() {
            return false;
        }

        self.idle_for(now) >= interval
            && now.saturating_duration_since(self.last_keepalive_sent) >= interval
    }

    pub fn mark_keepalive_sent(&mut self, now: Instant) {
        self.last_keepalive_sent = now;
    }

    pub fn next_datagram_sequence(&mut self) -> Sequence24 {
        let seq = self.datagram_write_index;
        self.datagram_write_index = self.datagram_write_index.next();
        seq
    }

    pub fn pending_outgoing_frames(&self) -> usize {
        self.outgoing_heap.len()
    }

    pub fn pending_outgoing_bytes(&self) -> usize {
        self.outgoing_queued_bytes
    }

    pub fn force_control_flush_deadlines(&mut self, now: Instant) {
        if !self.outgoing_acks.is_empty() {
            self.next_ack_flush_at = now;
        }
        if !self.outgoing_nacks.is_empty() {
            self.next_nack_flush_at = now;
        }
    }

    pub fn take_backpressure_disconnect(&mut self) -> bool {
        let should_disconnect = self.disconnect_requested_by_backpressure;
        self.disconnect_requested_by_backpressure = false;
        should_disconnect
    }

    pub fn metrics_snapshot(&self) -> SessionMetricsSnapshot {
        let resend_ratio = if self.metrics.reliable_sent_datagrams == 0 {
            0.0
        } else {
            self.metrics.resent_datagrams as f64 / self.metrics.reliable_sent_datagrams as f64
        };

        SessionMetricsSnapshot {
            ingress_datagrams: self.metrics.ingress_datagrams,
            ingress_frames: self.metrics.ingress_frames,
            duplicate_reliable_drops: self.metrics.duplicate_reliable_drops,
            ordered_stale_drops: self.metrics.ordered_stale_drops,
            ordered_buffer_full_drops: self.metrics.ordered_buffer_full_drops,
            sequenced_stale_drops: self.metrics.sequenced_stale_drops,
            sequenced_missing_index_drops: self.metrics.sequenced_missing_index_drops,
            reliable_sent_datagrams: self.metrics.reliable_sent_datagrams,
            resent_datagrams: self.metrics.resent_datagrams,
            ack_out_datagrams: self.metrics.ack_out_datagrams,
            nack_out_datagrams: self.metrics.nack_out_datagrams,
            acked_datagrams: self.metrics.acked_datagrams,
            nacked_datagrams: self.metrics.nacked_datagrams,
            split_ttl_drops: self.metrics.split_ttl_drops,
            pending_outgoing_frames: self.pending_outgoing_frames(),
            pending_outgoing_bytes: self.pending_outgoing_bytes(),
            outgoing_queue_drops: self.metrics.outgoing_queue_drops,
            outgoing_queue_defers: self.metrics.outgoing_queue_defers,
            outgoing_queue_disconnects: self.metrics.outgoing_queue_disconnects,
            backpressure_delays: self.metrics.backpressure_delays,
            backpressure_drops: self.metrics.backpressure_drops,
            backpressure_disconnects: self.metrics.backpressure_disconnects,
            srtt_ms: self.srtt_ms.unwrap_or(0.0),
            rttvar_ms: self.rttvar_ms,
            resend_rto_ms: self.resend_rto.as_secs_f64() * 1000.0,
            congestion_window_packets: self.congestion_window_packets,
            resend_ratio,
            pacing_budget_bytes: self.pacing_budget_bytes,
            pacing_rate_bytes_per_sec: self.pacing_rate_bytes_per_sec,
        }
    }

    pub fn process_datagram_sequence(&mut self, seq: Sequence24, now: Instant) {
        let expected = self.datagram_read_index;

        if expected > seq {
            let ack_was_empty = self.outgoing_acks.is_empty();
            self.outgoing_acks.push(SequenceRange {
                start: seq,
                end: seq,
            });
            if ack_was_empty {
                self.next_ack_flush_at = now + self.ack_flush_interval;
            }
            return;
        }

        self.datagram_read_index = seq.next();

        if seq == expected {
            let ack_was_empty = self.outgoing_acks.is_empty();
            self.outgoing_acks.push(SequenceRange {
                start: seq,
                end: seq,
            });
            if ack_was_empty {
                self.next_ack_flush_at = now + self.ack_flush_interval;
            }
            return;
        }

        let mut nack_start = expected;
        let nack_end = seq.prev();

        loop {
            let mut chunk_end = nack_start;
            let mut count = 0;

            while count < (MAX_ACK_SEQUENCES - 1) && chunk_end < nack_end {
                chunk_end = chunk_end.next();
                count += 1;
            }

            let nack_was_empty = self.outgoing_nacks.is_empty();
            self.outgoing_nacks.push(SequenceRange {
                start: nack_start,
                end: chunk_end,
            });
            if nack_was_empty {
                self.next_nack_flush_at = now + self.nack_flush_interval;
            }

            if chunk_end == nack_end {
                break;
            }

            nack_start = chunk_end.next();
        }

        let ack_was_empty = self.outgoing_acks.is_empty();
        self.outgoing_acks.push(SequenceRange {
            start: seq,
            end: seq,
        });
        if ack_was_empty {
            self.next_ack_flush_at = now + self.ack_flush_interval;
        }
    }

    pub fn ingest_datagram(
        &mut self,
        datagram: Datagram,
        now: Instant,
    ) -> Result<Vec<Frame>, DecodeError> {
        self.metrics.ingress_datagrams = self.metrics.ingress_datagrams.saturating_add(1);

        match datagram.payload {
            DatagramPayload::Ack(payload) => {
                self.handle_ack_payload(payload);
                Ok(Vec::new())
            }
            DatagramPayload::Nack(payload) => {
                self.handle_nack_payload(payload);
                Ok(Vec::new())
            }
            DatagramPayload::Frames(frames) => {
                self.metrics.ingress_frames = self
                    .metrics
                    .ingress_frames
                    .saturating_add(frames.len() as u64);
                self.process_datagram_sequence(datagram.header.sequence, now);
                self.handle_frames(frames, now)
            }
        }
    }

    pub fn handle_ack_payload(&mut self, payload: AckNackPayload) {
        self.incoming_acks.extend(payload.ranges);
    }

    pub fn handle_nack_payload(&mut self, payload: AckNackPayload) {
        self.incoming_nacks.extend(payload.ranges);
    }

    fn handle_frames(
        &mut self,
        frames: Vec<Frame>,
        now: Instant,
    ) -> Result<Vec<Frame>, DecodeError> {
        let mut out = Vec::new();

        for frame in frames {
            let is_split = frame.header.is_split;
            let should_drop_duplicate = frame.header.reliability.is_reliable() && !is_split;

            if should_drop_duplicate
                && let Some(ridx) = frame.reliable_index
                && self.reliable_tracker.has_seen(ridx)
            {
                self.metrics.duplicate_reliable_drops =
                    self.metrics.duplicate_reliable_drops.saturating_add(1);
                continue;
            }

            let assembled = self.split_assembler.add(frame, now)?;
            let Some(frame) = assembled else {
                continue;
            };

            if !is_split
                && frame.header.reliability.is_reliable()
                && let Some(ridx) = frame.reliable_index
            {
                let _ = self.reliable_tracker.see(ridx);
            }

            if frame.header.reliability.is_sequenced() {
                match self.ordering.handle_sequenced(&frame) {
                    SequencedResult::Accept => out.push(frame),
                    SequencedResult::DropMissingSequence => {
                        self.metrics.sequenced_missing_index_drops =
                            self.metrics.sequenced_missing_index_drops.saturating_add(1);
                    }
                    SequencedResult::DropStale => {
                        self.metrics.sequenced_stale_drops =
                            self.metrics.sequenced_stale_drops.saturating_add(1);
                    }
                }
                continue;
            }

            if frame.header.reliability.is_ordered() {
                match self.ordering.handle_ordered(frame) {
                    OrderedResult::Ready(mut ready) => out.append(&mut ready),
                    OrderedResult::Buffered => {}
                    OrderedResult::DroppedStale => {
                        self.metrics.ordered_stale_drops =
                            self.metrics.ordered_stale_drops.saturating_add(1);
                    }
                    OrderedResult::DroppedBufferFull => {
                        self.metrics.ordered_buffer_full_drops =
                            self.metrics.ordered_buffer_full_drops.saturating_add(1);
                    }
                }
                continue;
            }

            out.push(frame);
        }

        Ok(out)
    }

    pub fn drain_ack_datagram(&mut self, now: Instant) -> Option<Datagram> {
        let ranges = self
            .outgoing_acks
            .pop_for_mtu(self.mtu, 3, self.ack_max_ranges_per_datagram);
        if ranges.is_empty() {
            return None;
        }
        self.next_ack_flush_at = now + self.ack_flush_interval;
        self.metrics.ack_out_datagrams = self.metrics.ack_out_datagrams.saturating_add(1);

        Some(Datagram {
            header: DatagramHeader {
                flags: DatagramFlags::VALID | DatagramFlags::ACK,
                sequence: Sequence24::new(0),
            },
            payload: DatagramPayload::Ack(AckNackPayload { ranges }),
        })
    }

    pub fn drain_nack_datagram(&mut self, now: Instant) -> Option<Datagram> {
        let ranges =
            self.outgoing_nacks
                .pop_for_mtu(self.mtu, 3, self.nack_max_ranges_per_datagram);
        if ranges.is_empty() {
            return None;
        }
        self.next_nack_flush_at = now + self.nack_flush_interval;
        self.metrics.nack_out_datagrams = self.metrics.nack_out_datagrams.saturating_add(1);

        Some(Datagram {
            header: DatagramHeader {
                flags: DatagramFlags::VALID | DatagramFlags::NACK,
                sequence: Sequence24::new(0),
            },
            payload: DatagramPayload::Nack(AckNackPayload { ranges }),
        })
    }

    pub fn track_sent_reliable_datagram(
        &mut self,
        datagram: Datagram,
        now: Instant,
        receipt_ids: Vec<u64>,
    ) {
        let seq = datagram.header.sequence;
        let has_reliable = match &datagram.payload {
            DatagramPayload::Frames(frames) => {
                frames.iter().any(|f| f.header.reliability.is_reliable())
            }
            DatagramPayload::Ack(_) | DatagramPayload::Nack(_) => false,
        };
        let has_ack_receipt = match &datagram.payload {
            DatagramPayload::Frames(frames) => frames
                .iter()
                .any(|f| f.header.reliability.is_with_ack_receipt()),
            DatagramPayload::Ack(_) | DatagramPayload::Nack(_) => false,
        };

        if !has_reliable && !has_ack_receipt && receipt_ids.is_empty() {
            return;
        }

        if has_reliable {
            self.metrics.reliable_sent_datagrams =
                self.metrics.reliable_sent_datagrams.saturating_add(1);
        }

        for receipt_id in &receipt_ids {
            let counter = self.receipt_tracking.entry(*receipt_id).or_insert(0);
            *counter = counter.saturating_add(1);
        }

        self.sent_datagrams.insert(
            seq,
            TrackedDatagram {
                datagram,
                send_time: now,
                next_send: now + self.resend_rto,
                retries: 0,
                nack_resend_pending: false,
                resendable: has_reliable,
                receipt_ids,
            },
        );
    }

    pub fn queue_payload(
        &mut self,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
    ) -> QueuePayloadResult {
        self.queue_payload_with_receipt(payload, reliability, channel, priority, None)
    }

    pub fn queue_payload_with_receipt(
        &mut self,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: Option<u64>,
    ) -> QueuePayloadResult {
        let (estimated_frames, estimated_bytes, effective_reliability) =
            self.estimate_queue_impact(payload.len(), reliability);

        match self.evaluate_backpressure(
            estimated_frames,
            estimated_bytes,
            effective_reliability,
            priority,
        ) {
            BackpressureAction::Allow => {}
            BackpressureAction::Drop => {
                if self.best_effort_zeroize_dropped_payloads {
                    let _ = best_effort_zeroize_bytes(payload);
                }
                self.metrics.outgoing_queue_drops =
                    self.metrics.outgoing_queue_drops.saturating_add(1);
                self.metrics.backpressure_drops = self.metrics.backpressure_drops.saturating_add(1);
                return QueuePayloadResult::Dropped;
            }
            BackpressureAction::Defer => {
                if self.best_effort_zeroize_dropped_payloads {
                    let _ = best_effort_zeroize_bytes(payload);
                }
                self.metrics.outgoing_queue_defers =
                    self.metrics.outgoing_queue_defers.saturating_add(1);
                self.metrics.backpressure_delays =
                    self.metrics.backpressure_delays.saturating_add(1);
                return QueuePayloadResult::Deferred;
            }
            BackpressureAction::Disconnect => {
                if self.best_effort_zeroize_dropped_payloads {
                    let _ = best_effort_zeroize_bytes(payload);
                }
                self.metrics.outgoing_queue_disconnects =
                    self.metrics.outgoing_queue_disconnects.saturating_add(1);
                self.metrics.backpressure_disconnects =
                    self.metrics.backpressure_disconnects.saturating_add(1);
                self.disconnect_requested_by_backpressure = true;
                return QueuePayloadResult::DisconnectRequested;
            }
        }

        let max_single = self.max_payload_for(reliability, false);
        if payload.len() <= max_single {
            let reliable_bytes =
                self.enqueue_single_frame(payload, reliability, channel, priority, receipt_id);
            return QueuePayloadResult::Enqueued { reliable_bytes };
        }

        let reliable_bytes =
            self.enqueue_split_frames(payload, reliability, channel, priority, receipt_id);
        QueuePayloadResult::Enqueued { reliable_bytes }
    }

    pub fn process_incoming_receipts(&mut self, now: Instant) -> ReceiptProgress {
        let mut progress = ReceiptProgress::default();

        while let Some(range) = self.incoming_acks.pop_front() {
            Self::for_each_sequence(range, |seq| {
                if let Some(acked) = self.sent_datagrams.remove(&seq) {
                    progress.acked += 1;
                    self.on_reliable_ack();
                    if acked.retries == 0 {
                        let rtt_sample = now.saturating_duration_since(acked.send_time);
                        self.observe_rtt_sample(rtt_sample);
                    }

                    for receipt_id in acked.receipt_ids {
                        if let Some(pending) = self.receipt_tracking.get_mut(&receipt_id) {
                            if *pending > 1 {
                                *pending -= 1;
                            } else {
                                self.receipt_tracking.remove(&receipt_id);
                                progress.acked_receipt_ids.push(receipt_id);
                            }
                        }
                    }
                }
            });
        }
        self.metrics.acked_datagrams = self
            .metrics
            .acked_datagrams
            .saturating_add(progress.acked as u64);

        while let Some(range) = self.incoming_nacks.pop_front() {
            Self::for_each_sequence(range, |seq| {
                if let Some(entry) = self.sent_datagrams.get_mut(&seq)
                    && entry.resendable
                    && entry.next_send > now
                {
                    entry.next_send = now;
                    entry.nack_resend_pending = true;
                    progress.nacked += 1;
                }
            });
        }
        if progress.nacked > 0 {
            self.on_nack_loss(now);
        }
        self.metrics.nacked_datagrams = self
            .metrics
            .nacked_datagrams
            .saturating_add(progress.nacked as u64);

        progress
    }

    pub fn collect_resendable(
        &mut self,
        now: Instant,
        max_count: usize,
        max_bytes: usize,
    ) -> Vec<Datagram> {
        let mut total_bytes = 0usize;
        let mut selected = Vec::new();
        let mut timeout_loss_observed = false;

        for (&seq, tracked) in &self.sent_datagrams {
            if selected.len() >= max_count {
                break;
            }
            if !tracked.resendable {
                continue;
            }
            if tracked.next_send > now {
                continue;
            }

            let size = tracked.datagram.encoded_size();
            if total_bytes + size > max_bytes {
                break;
            }

            total_bytes += size;
            timeout_loss_observed |= !tracked.nack_resend_pending;
            selected.push(seq);
        }

        if selected.is_empty() {
            return Vec::new();
        }

        if timeout_loss_observed {
            self.on_timeout(now);
        }

        let next_send_at = now + self.resend_rto;
        let mut out = Vec::with_capacity(selected.len());
        for seq in selected {
            let Some(tracked) = self.sent_datagrams.get_mut(&seq) else {
                continue;
            };
            tracked.send_time = now;
            tracked.next_send = next_send_at;
            tracked.retries = tracked.retries.saturating_add(1);
            tracked.nack_resend_pending = false;
            out.push(tracked.datagram.clone());
            self.metrics.resent_datagrams = self.metrics.resent_datagrams.saturating_add(1);
        }

        out
    }

    pub fn build_data_datagram(
        &mut self,
        now: Instant,
        remaining_bytes_budget: &mut usize,
    ) -> Option<Datagram> {
        if self.outgoing_heap.is_empty() || *remaining_bytes_budget == 0 {
            return None;
        }

        let mut frames = Vec::new();
        let mut datagram_receipt_ids = Vec::new();
        let mut datagram_size = RAKNET_DATAGRAM_HEADER_SIZE;
        let mut has_reliable = false;
        let mut has_split = false;

        loop {
            let allow_reliable = has_reliable || self.can_emit_new_reliable_datagram();
            let Some(queued) = self.pop_next_frame_for_datagram(
                allow_reliable,
                datagram_size,
                *remaining_bytes_budget,
            ) else {
                break;
            };

            datagram_size += queued.encoded_size;
            *remaining_bytes_budget = remaining_bytes_budget.saturating_sub(queued.encoded_size);
            self.outgoing_queued_bytes = self
                .outgoing_queued_bytes
                .saturating_sub(queued.encoded_size);

            has_reliable |= queued.is_reliable;
            has_split |= queued.frame.header.is_split;
            if let Some(receipt_id) = queued.receipt_id
                && !datagram_receipt_ids.contains(&receipt_id)
            {
                datagram_receipt_ids.push(receipt_id);
            }
            frames.push(queued.frame);
        }

        if frames.is_empty() {
            return None;
        }

        let flags = if !self.outgoing_heap.is_empty() || has_split {
            DatagramFlags::VALID | DatagramFlags::CONTINUOUS_SEND
        } else {
            DatagramFlags::VALID | DatagramFlags::HAS_B_AND_AS
        };

        let datagram = Datagram {
            header: DatagramHeader {
                flags,
                sequence: self.next_datagram_sequence(),
            },
            payload: DatagramPayload::Frames(frames),
        };

        if has_reliable || !datagram_receipt_ids.is_empty() {
            self.track_sent_reliable_datagram(datagram.clone(), now, datagram_receipt_ids);
        }

        Some(datagram)
    }

    pub fn on_tick(
        &mut self,
        now: Instant,
        max_new_datagrams: usize,
        max_new_bytes: usize,
        max_resend_datagrams: usize,
        max_resend_bytes: usize,
    ) -> Vec<Datagram> {
        let mut out = Vec::new();
        self.refresh_pacing_budget(now);

        match self.ack_nack_priority {
            AckNackPriority::NackFirst => {
                self.flush_nack_if_due(now, &mut out);
                self.flush_ack_if_due(now, &mut out);
            }
            AckNackPriority::AckFirst => {
                self.flush_ack_if_due(now, &mut out);
                self.flush_nack_if_due(now, &mut out);
            }
        }

        let pacing_budget = if self.pacing_enabled {
            self.pacing_budget_bytes.floor() as usize
        } else {
            usize::MAX
        };
        let resend_bytes_budget = max_resend_bytes.min(pacing_budget);
        let resend_datagrams =
            self.collect_resendable(now, max_resend_datagrams, resend_bytes_budget);
        let resend_bytes_used = resend_datagrams
            .iter()
            .map(Datagram::encoded_size)
            .sum::<usize>();
        self.consume_pacing_budget(resend_bytes_used);
        out.extend(resend_datagrams);

        let available_pacing_for_new = if self.pacing_enabled {
            self.pacing_budget_bytes.floor() as usize
        } else {
            usize::MAX
        };
        let mut remaining_new_bytes = max_new_bytes.min(available_pacing_for_new);
        let budget_too_small_for_frame = self
            .min_queued_frame_size()
            .is_some_and(|min_frame| remaining_new_bytes < min_frame);
        let allow_immediate_bypass = self.pacing_enabled
            && (remaining_new_bytes == 0 || budget_too_small_for_frame)
            && max_new_bytes > 0
            && self.has_immediate_outgoing_frame();
        if allow_immediate_bypass {
            remaining_new_bytes = self.mtu.min(max_new_bytes).max(1);
        }

        let mut new_bytes_used = 0usize;
        let mut new_datagram_count = 0usize;
        while new_datagram_count < max_new_datagrams {
            let Some(datagram) = self.build_data_datagram(now, &mut remaining_new_bytes) else {
                break;
            };
            new_bytes_used = new_bytes_used.saturating_add(datagram.encoded_size());
            out.push(datagram);
            new_datagram_count += 1;
            if remaining_new_bytes == 0 {
                break;
            }
        }
        self.consume_pacing_budget(new_bytes_used);

        self.prune_split_state(now);
        out
    }

    fn flush_ack_if_due(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        if self.outgoing_acks.is_empty() || now < self.next_ack_flush_at {
            return;
        }
        if let Some(ack) = self.drain_ack_datagram(now) {
            out.push(ack);
        }
    }

    fn flush_nack_if_due(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        if self.outgoing_nacks.is_empty() || now < self.next_nack_flush_at {
            return;
        }
        if let Some(nack) = self.drain_nack_datagram(now) {
            out.push(nack);
        }
    }

    pub fn prune_split_state(&mut self, now: Instant) -> usize {
        let dropped = self.split_assembler.prune(now);
        self.metrics.split_ttl_drops = self.metrics.split_ttl_drops.saturating_add(dropped as u64);
        dropped
    }

    fn enqueue_single_frame(
        &mut self,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: Option<u64>,
    ) -> usize {
        let ordering_index = self.next_ordering_index_if_needed(reliability, channel);
        let sequence_index = self.next_sequence_index_if_needed(reliability, channel);
        let reliable_index = if reliability.is_reliable() {
            Some(self.next_reliable_index())
        } else {
            None
        };

        let frame = Frame {
            header: FrameHeader::new(reliability, false, false),
            bit_length: (payload.len() as u16) << 3,
            reliable_index,
            sequence_index,
            ordering_index,
            ordering_channel: ordering_index.map(|_| channel),
            split: None,
            payload,
        };

        let size = frame.encoded_size();
        self.push_outgoing_frame(frame, priority, receipt_id);
        if reliability.is_reliable() { size } else { 0 }
    }

    fn enqueue_split_frames(
        &mut self,
        mut payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: Option<u64>,
    ) -> usize {
        let reliability = Self::normalize_reliability_for_split(reliability);
        let max_split_payload = self.max_payload_for(reliability, true).max(1);
        let part_count = payload.len().div_ceil(max_split_payload);
        let split_id = self.split_write_index;
        self.split_write_index = self.split_write_index.wrapping_add(1);
        let ordering_index = self.next_ordering_index_if_needed(reliability, channel);
        let sequence_index = self.next_sequence_index_if_needed(reliability, channel);

        let mut reliable_bytes = 0usize;

        for idx in 0..part_count {
            let take = payload.len().min(max_split_payload);
            let part = payload.split_to(take);
            let reliable_index = if reliability.is_reliable() {
                Some(self.next_reliable_index())
            } else {
                None
            };

            let frame = Frame {
                header: FrameHeader::new(reliability, true, false),
                bit_length: (part.len() as u16) << 3,
                reliable_index,
                sequence_index,
                ordering_index,
                ordering_channel: ordering_index.map(|_| channel),
                split: Some(crate::protocol::frame::SplitInfo {
                    part_count: part_count as u32,
                    part_id: split_id,
                    part_index: idx as u32,
                }),
                payload: part,
            };

            let size = frame.encoded_size();
            self.push_outgoing_frame(frame, priority, receipt_id);
            if reliability.is_reliable() {
                reliable_bytes += size;
            }
        }

        reliable_bytes
    }

    fn max_payload_for(&self, reliability: Reliability, is_split: bool) -> usize {
        let frame_overhead = self.frame_overhead(reliability, is_split);
        self.mtu
            .saturating_sub(RAKNET_DATAGRAM_HEADER_SIZE + frame_overhead)
            .max(1)
    }

    fn frame_overhead(&self, reliability: Reliability, is_split: bool) -> usize {
        let mut size = 3usize;
        if reliability.is_reliable() {
            size += 3;
        }
        if reliability.is_sequenced() {
            size += 3;
        }
        if reliability.is_ordered() || reliability.is_sequenced() {
            size += 4;
        }
        if is_split {
            size += 10;
        }
        size
    }

    fn next_reliable_index(&mut self) -> Sequence24 {
        let idx = self.reliable_write_index;
        self.reliable_write_index = self.reliable_write_index.next();
        idx
    }

    fn next_ordering_index_if_needed(
        &mut self,
        reliability: Reliability,
        channel: u8,
    ) -> Option<Sequence24> {
        if !(reliability.is_ordered() || reliability.is_sequenced()) {
            return None;
        }

        let ch = channel as usize;
        if ch >= self.ordering_write_index.len() {
            self.ordering_write_index.resize(ch + 1, Sequence24::new(0));
        }

        let idx = self.ordering_write_index[ch];
        self.ordering_write_index[ch] = idx.next();
        Some(idx)
    }

    fn next_sequence_index_if_needed(
        &mut self,
        reliability: Reliability,
        channel: u8,
    ) -> Option<Sequence24> {
        if !reliability.is_sequenced() {
            return None;
        }

        let ch = channel as usize;
        if ch >= self.sequencing_write_index.len() {
            self.sequencing_write_index
                .resize(ch + 1, Sequence24::new(0));
        }

        let idx = self.sequencing_write_index[ch];
        self.sequencing_write_index[ch] = idx.next();
        Some(idx)
    }

    fn push_outgoing_frame(
        &mut self,
        frame: Frame,
        priority: RakPriority,
        receipt_id: Option<u64>,
    ) {
        let weight = self.next_weight(priority);
        let encoded_size = frame.encoded_size();
        let is_reliable = frame.header.reliability.is_reliable();
        self.outgoing_queued_bytes = self.outgoing_queued_bytes.saturating_add(encoded_size);
        self.outgoing_heap.push(QueuedFrame {
            weight,
            encoded_size,
            is_reliable,
            priority,
            receipt_id,
            frame,
        });
    }

    fn next_weight(&mut self, priority: RakPriority) -> u64 {
        let level = priority.as_index();
        let mut next = self.outgoing_next_weights[level];

        if !self.outgoing_heap.is_empty() {
            if next >= self.last_min_weight {
                next = self.last_min_weight + ((1u64 << level) * level as u64) + level as u64;
                self.outgoing_next_weights[level] =
                    next + ((1u64 << level) * (level as u64 + 1)) + level as u64;
            }
        } else {
            for p in 0..4 {
                self.outgoing_next_weights[p] = ((1u64 << p) * p as u64) + p as u64;
            }
        }

        self.last_min_weight = next - ((1u64 << level) * level as u64) + level as u64;
        next
    }

    fn normalize_reliability_for_split(reliability: Reliability) -> Reliability {
        match reliability {
            Reliability::Unreliable => Reliability::Reliable,
            Reliability::UnreliableSequenced => Reliability::ReliableSequenced,
            Reliability::UnreliableWithAckReceipt => Reliability::ReliableWithAckReceipt,
            v => v,
        }
    }

    fn estimate_queue_impact(
        &self,
        payload_len: usize,
        reliability: Reliability,
    ) -> (usize, usize, Reliability) {
        let max_single = self.max_payload_for(reliability, false);
        if payload_len <= max_single {
            let bytes = self
                .frame_overhead(reliability, false)
                .saturating_add(payload_len);
            return (1, bytes, reliability);
        }

        let effective = Self::normalize_reliability_for_split(reliability);
        let max_split_payload = self.max_payload_for(effective, true).max(1);
        let part_count = payload_len.div_ceil(max_split_payload);
        let bytes = payload_len
            .saturating_add(part_count.saturating_mul(self.frame_overhead(effective, true)));

        (part_count, bytes, effective)
    }

    fn evaluate_backpressure(
        &self,
        added_frames: usize,
        added_bytes: usize,
        reliability: Reliability,
        priority: RakPriority,
    ) -> BackpressureAction {
        let projected_frames = self.pending_outgoing_frames().saturating_add(added_frames);
        let projected_bytes = self.pending_outgoing_bytes().saturating_add(added_bytes);

        let hard_frames = self.outgoing_queue_max_frames.max(1);
        let hard_bytes = self.outgoing_queue_max_bytes.max(1);

        let soft_frames = ((hard_frames as f64) * self.outgoing_queue_soft_ratio)
            .floor()
            .max(1.0) as usize;
        let soft_bytes = ((hard_bytes as f64) * self.outgoing_queue_soft_ratio)
            .floor()
            .max(1.0) as usize;

        let exceeds_hard = projected_frames > hard_frames || projected_bytes > hard_bytes;
        let exceeds_soft = projected_frames > soft_frames || projected_bytes > soft_bytes;
        let reliable = reliability.is_reliable();

        if exceeds_hard {
            return match self.backpressure_mode {
                BackpressureMode::Delay => BackpressureAction::Defer,
                BackpressureMode::Shed => {
                    if !reliable || matches!(priority, RakPriority::Normal | RakPriority::Low) {
                        BackpressureAction::Drop
                    } else {
                        BackpressureAction::Defer
                    }
                }
                BackpressureMode::Disconnect => BackpressureAction::Disconnect,
            };
        }

        if exceeds_soft {
            return BackpressureAction::Defer;
        }

        BackpressureAction::Allow
    }

    fn best_effort_zeroize_buffered_payloads(&mut self) {
        for queued in self.outgoing_heap.drain() {
            let _ = best_effort_zeroize_bytes(queued.frame.payload);
        }

        for tracked in self.sent_datagrams.values_mut() {
            if let DatagramPayload::Frames(frames) = &mut tracked.datagram.payload {
                for frame in frames {
                    let payload = std::mem::take(&mut frame.payload);
                    let _ = best_effort_zeroize_bytes(payload);
                }
            }
        }

        for frame in self.ordering.drain_pending_ordered_frames() {
            let _ = best_effort_zeroize_bytes(frame.payload);
        }

        for part in self.split_assembler.drain_buffered_parts() {
            let _ = best_effort_zeroize_bytes(part);
        }
    }

    fn can_emit_new_reliable_datagram(&self) -> bool {
        let in_flight = self.sent_datagrams.len() as f64;
        in_flight < self.congestion_window_packets.max(1.0).floor()
    }

    fn refresh_pacing_budget(&mut self, now: Instant) {
        if !self.pacing_enabled {
            return;
        }

        let elapsed = now
            .saturating_duration_since(self.last_pacing_update)
            .as_secs_f64();
        self.last_pacing_update = now;

        let rate = self.compute_pacing_rate_bytes_per_sec();
        self.pacing_rate_bytes_per_sec = rate;

        if elapsed > 0.0 {
            self.pacing_budget_bytes = (self.pacing_budget_bytes + elapsed * rate)
                .clamp(0.0, self.pacing_budget_max_bytes);
        }
    }

    fn compute_pacing_rate_bytes_per_sec(&self) -> f64 {
        if !self.pacing_enabled {
            return f64::INFINITY;
        }

        let reference_rtt_ms = self
            .srtt_ms
            .unwrap_or_else(|| (self.resend_rto.as_secs_f64() * 1000.0).max(1.0));
        let rtt_secs = (reference_rtt_ms.max(1.0)) / 1000.0;
        let cwnd_bytes = self.congestion_window_packets.max(1.0) * self.mtu as f64;
        let raw_rate = (cwnd_bytes / rtt_secs) * self.pacing_gain;
        raw_rate.clamp(
            self.pacing_min_rate_bytes_per_sec,
            self.pacing_max_rate_bytes_per_sec,
        )
    }

    fn consume_pacing_budget(&mut self, bytes: usize) {
        if !self.pacing_enabled {
            return;
        }
        self.pacing_budget_bytes = (self.pacing_budget_bytes - bytes as f64).max(0.0);
    }

    fn has_immediate_outgoing_frame(&self) -> bool {
        self.outgoing_heap
            .iter()
            .any(|entry| entry.priority == RakPriority::Immediate)
    }

    fn min_queued_frame_size(&self) -> Option<usize> {
        self.outgoing_heap
            .iter()
            .map(|entry| entry.encoded_size)
            .min()
    }

    fn pop_next_frame_for_datagram(
        &mut self,
        allow_reliable: bool,
        datagram_size: usize,
        remaining_bytes_budget: usize,
    ) -> Option<QueuedFrame> {
        let mut deferred = Vec::new();
        let mut selected = None;

        while let Some(candidate) = self.outgoing_heap.pop() {
            let fits_mtu = datagram_size.saturating_add(candidate.encoded_size) <= self.mtu;
            let fits_budget = candidate.encoded_size <= remaining_bytes_budget;
            let reliability_ok = allow_reliable || !candidate.is_reliable;

            if fits_mtu && fits_budget && reliability_ok {
                selected = Some(candidate);
                break;
            }

            deferred.push(candidate);
        }

        for item in deferred {
            self.outgoing_heap.push(item);
        }

        selected
    }

    fn observe_rtt_sample(&mut self, sample: Duration) {
        let sample_ms = (sample.as_secs_f64() * 1000.0).max(1.0);
        match self.srtt_ms {
            None => {
                self.srtt_ms = Some(sample_ms);
                self.rttvar_ms = sample_ms / 2.0;
            }
            Some(srtt) => {
                let alpha = 0.125;
                let beta = 0.25;
                let variation = (srtt - sample_ms).abs();
                self.rttvar_ms = (1.0 - beta) * self.rttvar_ms + beta * variation;
                let next_srtt = (1.0 - alpha) * srtt + alpha * sample_ms;
                self.srtt_ms = Some(next_srtt);
            }
        }

        self.recompute_rto_from_rtt();
    }

    fn recompute_rto_from_rtt(&mut self) {
        let Some(srtt_ms) = self.srtt_ms else {
            return;
        };

        let rto_ms = srtt_ms + (4.0 * self.rttvar_ms).max(10.0);
        let clamped = rto_ms.clamp(
            self.min_resend_rto.as_secs_f64() * 1000.0,
            self.max_resend_rto.as_secs_f64() * 1000.0,
        );
        self.resend_rto = Duration::from_secs_f64(clamped / 1000.0);
    }

    fn on_reliable_ack(&mut self) {
        let mut additive = if self.congestion_window_packets < self.slow_start_threshold_packets {
            self.congestion_additive_gain.max(1.0)
        } else {
            self.congestion_additive_gain / self.congestion_window_packets.max(1.0)
        };

        if let Some(srtt_ms) = self.srtt_ms
            && srtt_ms >= self.high_rtt_threshold_ms
        {
            additive *= self.high_rtt_additive_scale;
        }

        additive = additive.max(0.001);
        self.congestion_window_packets = (self.congestion_window_packets + additive).clamp(
            self.min_congestion_window_packets,
            self.max_congestion_window_packets,
        );
    }

    fn on_timeout(&mut self, now: Instant) {
        self.apply_loss_backoff(self.congestion_multiplicative_decrease_timeout);
        let backed_off = self.resend_rto.saturating_mul(2);
        self.resend_rto = backed_off.min(self.max_resend_rto);
        self.next_nack_loss_backoff = now + self.nack_loss_backoff_cooldown;
    }

    fn on_nack_loss(&mut self, now: Instant) {
        if now < self.next_nack_loss_backoff {
            return;
        }

        self.apply_loss_backoff(self.congestion_multiplicative_decrease_nack);
        self.next_nack_loss_backoff = now + self.nack_loss_backoff_cooldown;
    }

    fn apply_loss_backoff(&mut self, factor: f64) {
        let factor = factor.clamp(0.1, 0.99);
        let reduced = (self.congestion_window_packets * factor).clamp(
            self.min_congestion_window_packets,
            self.max_congestion_window_packets,
        );
        self.slow_start_threshold_packets = reduced;
        self.congestion_window_packets = reduced;
    }

    fn for_each_sequence<F>(range: SequenceRange, mut f: F)
    where
        F: FnMut(Sequence24),
    {
        let mut seq = range.start;
        loop {
            f(seq);
            if seq == range.end {
                break;
            }
            seq = seq.next();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.best_effort_zeroize_dropped_payloads {
            self.best_effort_zeroize_buffered_payloads();
        }
    }
}

fn best_effort_zeroize_bytes(payload: Bytes) -> bool {
    match payload.try_into_mut() {
        Ok(mut writable) => {
            writable.as_mut().zeroize();
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;

    use super::{QueuePayloadResult, RakPriority, Session, SessionState};
    use crate::protocol::ack::{AckNackPayload, SequenceRange};
    use crate::protocol::datagram::DatagramPayload;
    use crate::protocol::frame::{Frame, SplitInfo};
    use crate::protocol::frame_header::FrameHeader;
    use crate::protocol::reliability::Reliability;
    use crate::protocol::sequence24::Sequence24;
    use crate::session::tunables::{
        AckNackFlushProfile, AckNackPriority, BackpressureMode, CongestionProfile, SessionTunables,
    };

    fn transition_to_connected(session: &mut Session) {
        assert!(session.transition_to(SessionState::Req1Recv));
        assert!(session.transition_to(SessionState::Reply1Sent));
        assert!(session.transition_to(SessionState::Req2Recv));
        assert!(session.transition_to(SessionState::Reply2Sent));
        assert!(session.transition_to(SessionState::ConnReqRecv));
        assert!(session.transition_to(SessionState::ConnReqAcceptedSent));
        assert!(session.transition_to(SessionState::NewIncomingRecv));
        assert!(session.transition_to(SessionState::Connected));
    }

    #[test]
    fn idle_tracking_updates_when_activity_touched() {
        let mut session = Session::new(1400);
        let now = Instant::now();
        let old = now
            .checked_sub(Duration::from_secs(8))
            .expect("instant subtraction must succeed");
        session.touch_activity(old);
        assert!(session.idle_for(now) >= Duration::from_secs(8));

        session.touch_activity(now);
        assert!(session.idle_for(now) <= Duration::from_millis(1));
    }

    #[test]
    fn keepalive_is_emitted_only_for_connected_idle_sessions() {
        let mut session = Session::new(1400);
        let now = Instant::now() + Duration::from_secs(6);
        let interval = Duration::from_secs(5);

        let old = now
            .checked_sub(Duration::from_secs(6))
            .expect("instant subtraction must succeed");
        session.touch_activity(old);
        assert!(!session.should_send_keepalive(now, interval));

        transition_to_connected(&mut session);
        assert!(session.should_send_keepalive(now, interval));

        session.mark_keepalive_sent(now);
        assert!(!session.should_send_keepalive(now, interval));
    }

    #[test]
    fn soft_backpressure_delays_unreliable_payloads() {
        let tunables = SessionTunables {
            outgoing_queue_max_frames: 4,
            outgoing_queue_max_bytes: 8 * 1024,
            outgoing_queue_soft_ratio: 0.5,
            ..SessionTunables::default()
        };

        let mut session = Session::with_tunables(1400, tunables);

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"a"),
                Reliability::Reliable,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));
        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"b"),
                Reliability::Reliable,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"u"),
                Reliability::Unreliable,
                0,
                RakPriority::Low
            ),
            QueuePayloadResult::Deferred
        ));

        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.outgoing_queue_defers, 1);
        assert_eq!(snapshot.backpressure_delays, 1);
    }

    #[test]
    fn hard_backpressure_disconnects_in_disconnect_mode() {
        let tunables = SessionTunables {
            outgoing_queue_max_frames: 1,
            outgoing_queue_max_bytes: 8 * 1024,
            outgoing_queue_soft_ratio: 0.5,
            backpressure_mode: BackpressureMode::Disconnect,
            ..SessionTunables::default()
        };

        let mut session = Session::with_tunables(1400, tunables);

        let _ = session.queue_payload(
            Bytes::from_static(b"a"),
            Reliability::Reliable,
            0,
            RakPriority::High,
        );

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"b"),
                Reliability::Reliable,
                0,
                RakPriority::Immediate
            ),
            QueuePayloadResult::DisconnectRequested
        ));
        assert!(session.take_backpressure_disconnect());
        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.backpressure_disconnects, 1);
    }

    #[test]
    fn hard_backpressure_sheds_low_priority_in_shed_mode() {
        let tunables = SessionTunables {
            outgoing_queue_max_frames: 1,
            outgoing_queue_max_bytes: 8 * 1024,
            outgoing_queue_soft_ratio: 0.5,
            backpressure_mode: BackpressureMode::Shed,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);

        let _ = session.queue_payload(
            Bytes::from_static(b"a"),
            Reliability::Reliable,
            0,
            RakPriority::High,
        );

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"b"),
                Reliability::Unreliable,
                0,
                RakPriority::Low
            ),
            QueuePayloadResult::Dropped
        ));
        assert!(!session.take_backpressure_disconnect());
        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.backpressure_drops, 1);
    }

    #[test]
    fn hard_backpressure_shed_mode_defers_high_priority_reliable() {
        let tunables = SessionTunables {
            outgoing_queue_max_frames: 1,
            outgoing_queue_max_bytes: 8 * 1024,
            outgoing_queue_soft_ratio: 0.5,
            backpressure_mode: BackpressureMode::Shed,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);

        let _ = session.queue_payload(
            Bytes::from_static(b"a"),
            Reliability::Reliable,
            0,
            RakPriority::High,
        );

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"b"),
                Reliability::Reliable,
                0,
                RakPriority::Immediate
            ),
            QueuePayloadResult::Deferred
        ));
        assert!(!session.take_backpressure_disconnect());
        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.backpressure_delays, 1);
        assert_eq!(snapshot.backpressure_drops, 0);
    }

    #[test]
    fn hard_backpressure_delays_in_delay_mode() {
        let tunables = SessionTunables {
            outgoing_queue_max_frames: 1,
            outgoing_queue_max_bytes: 8 * 1024,
            outgoing_queue_soft_ratio: 0.5,
            backpressure_mode: BackpressureMode::Delay,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);

        let _ = session.queue_payload(
            Bytes::from_static(b"a"),
            Reliability::Reliable,
            0,
            RakPriority::High,
        );

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"b"),
                Reliability::Reliable,
                0,
                RakPriority::Low
            ),
            QueuePayloadResult::Deferred
        ));
        assert!(!session.take_backpressure_disconnect());
        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.backpressure_delays, 1);
    }

    #[test]
    fn ack_updates_rtt_and_timeout_reduces_congestion() {
        let mut session = Session::new(1400);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"payload"),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session
            .on_tick(now, 1, 1400, 0, 0)
            .into_iter()
            .next()
            .expect("data datagram must be produced");
        let seq = sent.header.sequence;

        session.handle_ack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq,
                end: seq,
            }],
        });
        let _ = session.process_incoming_receipts(now + Duration::from_millis(120));

        let after_ack = session.metrics_snapshot();
        assert!(after_ack.srtt_ms > 0.0);
        assert!(after_ack.resend_rto_ms >= 80.0);

        let before_timeout_cwnd = after_ack.congestion_window_packets;

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"resend"),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));
        let _ = session.on_tick(now + Duration::from_millis(125), 1, 1400, 0, 0);

        let _ = session.collect_resendable(now + Duration::from_millis(1000), 8, usize::MAX);
        let after_timeout = session.metrics_snapshot();
        assert!(after_timeout.congestion_window_packets < before_timeout_cwnd);
    }

    #[test]
    fn nack_backoff_cooldown_prevents_repeated_window_cuts() {
        let tunables = SessionTunables {
            congestion_profile: CongestionProfile::Custom,
            initial_congestion_window: 64.0,
            min_congestion_window: 8.0,
            max_congestion_window: 512.0,
            congestion_multiplicative_decrease_nack: 0.8,
            congestion_nack_backoff_cooldown: Duration::from_millis(200),
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(200, tunables);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload(
                Bytes::from(vec![0xA1; 150]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));
        assert!(matches!(
            session.queue_payload(
                Bytes::from(vec![0xA2; 150]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session.on_tick(now, 2, 64 * 1024, 0, 0);
        assert_eq!(
            sent.len(),
            2,
            "mtu=200 should emit one payload per datagram"
        );
        let seq_a = sent[0].header.sequence;
        let seq_b = sent[1].header.sequence;

        let before = session.metrics_snapshot().congestion_window_packets;

        session.handle_nack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq_a,
                end: seq_a,
            }],
        });
        let first = session.process_incoming_receipts(now + Duration::from_millis(1));
        assert_eq!(first.nacked, 1);
        let after_first = session.metrics_snapshot().congestion_window_packets;
        assert!(
            after_first < before,
            "first nack must reduce congestion window"
        );

        session.handle_nack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq_b,
                end: seq_b,
            }],
        });
        let second = session.process_incoming_receipts(now + Duration::from_millis(10));
        assert_eq!(second.nacked, 1);
        let after_second = session.metrics_snapshot().congestion_window_packets;
        assert!(
            (after_second - after_first).abs() < 0.0001,
            "second nack within cooldown must not cut cwnd again"
        );
    }

    #[test]
    fn timeout_backoff_is_stronger_than_nack_backoff() {
        let tunables = SessionTunables {
            congestion_profile: CongestionProfile::Custom,
            initial_congestion_window: 100.0,
            min_congestion_window: 8.0,
            max_congestion_window: 512.0,
            congestion_multiplicative_decrease_nack: 0.9,
            congestion_multiplicative_decrease_timeout: 0.5,
            ..SessionTunables::default()
        };
        let now = Instant::now();

        let mut nack_session = Session::with_tunables(200, tunables.clone());
        let _ = nack_session.queue_payload(
            Bytes::from(vec![0xB1; 150]),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High,
        );
        let sent_nack = nack_session.on_tick(now, 1, 64 * 1024, 0, 0);
        let seq_nack = sent_nack[0].header.sequence;
        nack_session.handle_nack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq_nack,
                end: seq_nack,
            }],
        });
        let _ = nack_session.process_incoming_receipts(now + Duration::from_millis(1));
        let cwnd_after_nack = nack_session.metrics_snapshot().congestion_window_packets;

        let mut timeout_session = Session::with_tunables(200, tunables);
        let _ = timeout_session.queue_payload(
            Bytes::from(vec![0xC1; 150]),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High,
        );
        let _ = timeout_session.on_tick(now, 1, 64 * 1024, 0, 0);
        let _ = timeout_session.collect_resendable(now + Duration::from_secs(2), 8, usize::MAX);
        let cwnd_after_timeout = timeout_session.metrics_snapshot().congestion_window_packets;

        assert!(
            cwnd_after_timeout < cwnd_after_nack,
            "timeout loss must reduce cwnd more aggressively than nack loss"
        );
    }

    #[test]
    fn pacing_budget_throttles_non_immediate_send_until_budget_refills() {
        let tunables = SessionTunables {
            pacing_enabled: true,
            pacing_start_full: false,
            pacing_min_rate_bytes_per_sec: 1024.0,
            pacing_max_rate_bytes_per_sec: 1024.0,
            pacing_max_burst_bytes: 1024,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(200, tunables);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload(
                Bytes::from(vec![0xD1; 150]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let blocked = session.on_tick(now, 1, 64 * 1024, 0, 0);
        assert!(
            blocked.is_empty(),
            "with almost zero burst budget, first send must be paced"
        );

        let resumed = session.on_tick(now + Duration::from_millis(250), 1, 64 * 1024, 0, 0);
        assert_eq!(
            resumed.len(),
            1,
            "after budget refill, datagram must be sent"
        );
        let snapshot = session.metrics_snapshot();
        assert!(
            snapshot.pacing_rate_bytes_per_sec >= 1000.0,
            "pacing rate should be active in snapshot"
        );
    }

    #[test]
    fn immediate_priority_can_bypass_empty_pacing_budget() {
        let tunables = SessionTunables {
            pacing_enabled: true,
            pacing_start_full: false,
            pacing_min_rate_bytes_per_sec: 1.0,
            pacing_max_rate_bytes_per_sec: 1.0,
            pacing_max_burst_bytes: 1,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(200, tunables);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload(
                Bytes::from(vec![0xD2; 150]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::Immediate
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session.on_tick(now, 1, 64 * 1024, 0, 0);
        assert_eq!(
            sent.len(),
            1,
            "immediate packet should bypass drained pacing budget once"
        );
    }

    #[test]
    fn ack_receipt_id_is_reported_once_after_all_datagrams_are_acked() {
        let mut session = Session::new(1400);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload_with_receipt(
                Bytes::from(vec![0xAA; 6000]),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High,
                Some(42)
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session.on_tick(now, 16, usize::MAX, 0, 0);
        let mut data_sequences = Vec::new();
        for datagram in &sent {
            if matches!(
                datagram.payload,
                crate::protocol::datagram::DatagramPayload::Frames(_)
            ) {
                data_sequences.push(datagram.header.sequence);
            }
        }
        assert!(
            data_sequences.len() > 1,
            "split payload should span multiple datagrams"
        );

        session.handle_ack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: data_sequences[0],
                end: data_sequences[0],
            }],
        });
        let first_progress = session.process_incoming_receipts(now + Duration::from_millis(100));
        assert!(first_progress.acked_receipt_ids.is_empty());

        for seq in data_sequences.iter().skip(1) {
            session.handle_ack_payload(AckNackPayload {
                ranges: vec![SequenceRange {
                    start: *seq,
                    end: *seq,
                }],
            });
        }
        let second_progress = session.process_incoming_receipts(now + Duration::from_millis(120));
        assert_eq!(second_progress.acked_receipt_ids, vec![42]);
    }

    #[test]
    fn prune_split_state_increments_split_ttl_drop_metrics() {
        let tunables = SessionTunables {
            split_ttl: Duration::from_millis(20),
            max_split_parts: 8,
            max_concurrent_splits: 8,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);
        let now = Instant::now();

        let split_frame = Frame {
            header: FrameHeader::new(Reliability::ReliableOrdered, true, false),
            bit_length: 8,
            reliable_index: None,
            sequence_index: None,
            ordering_index: None,
            ordering_channel: None,
            split: Some(SplitInfo {
                part_count: 2,
                part_id: 77,
                part_index: 0,
            }),
            payload: Bytes::from_static(b"a"),
        };

        assert!(matches!(
            session.split_assembler.add(split_frame, now),
            Ok(None)
        ));
        assert_eq!(
            session.prune_split_state(now + Duration::from_millis(10)),
            0
        );
        assert_eq!(session.metrics_snapshot().split_ttl_drops, 0);

        assert_eq!(
            session.prune_split_state(now + Duration::from_millis(30)),
            1
        );
        assert_eq!(session.metrics_snapshot().split_ttl_drops, 1);
    }

    #[test]
    fn nack_marks_reliable_datagram_for_immediate_resend() {
        let mut session = Session::new(1400);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload(
                Bytes::from_static(b"resend-me"),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session
            .on_tick(now, 1, usize::MAX, 0, 0)
            .into_iter()
            .next()
            .expect("reliable datagram should be emitted");
        let seq = sent.header.sequence;

        session.handle_nack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq,
                end: seq,
            }],
        });
        let progress = session.process_incoming_receipts(now + Duration::from_millis(1));
        assert_eq!(progress.nacked, 1);

        let resent = session.collect_resendable(now + Duration::from_millis(1), 8, usize::MAX);
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].header.sequence, seq);
    }

    #[test]
    fn nack_does_not_resend_unreliable_ack_receipt_datagrams() {
        let mut session = Session::new(1400);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload_with_receipt(
                Bytes::from_static(b"fire-and-forget"),
                Reliability::UnreliableWithAckReceipt,
                0,
                RakPriority::Normal,
                Some(77)
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session
            .on_tick(now, 1, usize::MAX, 0, 0)
            .into_iter()
            .next()
            .expect("datagram should be emitted");
        let seq = sent.header.sequence;

        session.handle_nack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq,
                end: seq,
            }],
        });
        let nack_progress = session.process_incoming_receipts(now + Duration::from_millis(1));
        assert_eq!(nack_progress.nacked, 0);

        let resent = session.collect_resendable(now + Duration::from_millis(1), 8, usize::MAX);
        assert!(resent.is_empty());

        session.handle_ack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq,
                end: seq,
            }],
        });
        let ack_progress = session.process_incoming_receipts(now + Duration::from_millis(10));
        assert_eq!(ack_progress.acked, 1);
        assert_eq!(ack_progress.acked_receipt_ids, vec![77]);
    }

    #[test]
    fn multiple_receipt_ids_from_single_datagram_are_reported_once_each() {
        let mut session = Session::new(1400);
        let now = Instant::now();

        assert!(matches!(
            session.queue_payload_with_receipt(
                Bytes::from_static(b"first"),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High,
                Some(10)
            ),
            QueuePayloadResult::Enqueued { .. }
        ));
        assert!(matches!(
            session.queue_payload_with_receipt(
                Bytes::from_static(b"second"),
                Reliability::ReliableOrdered,
                0,
                RakPriority::High,
                Some(20)
            ),
            QueuePayloadResult::Enqueued { .. }
        ));

        let sent = session
            .on_tick(now, 1, usize::MAX, 0, 0)
            .into_iter()
            .next()
            .expect("datagram should be emitted");
        let seq = sent.header.sequence;

        session.handle_ack_payload(AckNackPayload {
            ranges: vec![SequenceRange {
                start: seq,
                end: seq,
            }],
        });
        let mut receipts = session
            .process_incoming_receipts(now + Duration::from_millis(5))
            .acked_receipt_ids;
        receipts.sort_unstable();
        assert_eq!(receipts, vec![10, 20]);
    }

    #[test]
    fn ack_flush_interval_defers_ack_until_deadline() {
        let tunables = SessionTunables {
            ack_nack_flush_profile: AckNackFlushProfile::Custom,
            ack_flush_interval: Duration::from_millis(50),
            nack_flush_interval: Duration::from_millis(1),
            ack_max_ranges_per_datagram: 64,
            nack_max_ranges_per_datagram: 64,
            ack_nack_priority: AckNackPriority::NackFirst,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);
        let now = Instant::now();

        session.process_datagram_sequence(Sequence24::new(0), now);
        let early = session.on_tick(now + Duration::from_millis(10), 0, 0, 0, 0);
        assert!(
            early.is_empty(),
            "ack must not flush before configured interval"
        );

        let due = session.on_tick(now + Duration::from_millis(50), 0, 0, 0, 0);
        assert_eq!(due.len(), 1, "ack should flush at deadline");
        assert!(
            matches!(due[0].payload, DatagramPayload::Ack(_)),
            "flushed control packet must be ACK"
        );
    }

    #[test]
    fn ack_batch_max_ranges_splits_large_ack_queue_across_ticks() {
        let tunables = SessionTunables {
            ack_nack_flush_profile: AckNackFlushProfile::Custom,
            ack_flush_interval: Duration::from_millis(1),
            nack_flush_interval: Duration::from_millis(1),
            ack_max_ranges_per_datagram: 2,
            nack_max_ranges_per_datagram: 64,
            ack_nack_priority: AckNackPriority::NackFirst,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);
        let now = Instant::now();

        session.outgoing_acks.push(SequenceRange {
            start: Sequence24::new(1),
            end: Sequence24::new(1),
        });
        session.outgoing_acks.push(SequenceRange {
            start: Sequence24::new(3),
            end: Sequence24::new(3),
        });
        session.outgoing_acks.push(SequenceRange {
            start: Sequence24::new(5),
            end: Sequence24::new(5),
        });

        let first = session.on_tick(now, 0, 0, 0, 0);
        assert_eq!(first.len(), 1);
        match &first[0].payload {
            DatagramPayload::Ack(payload) => assert_eq!(payload.ranges.len(), 2),
            _ => panic!("expected ACK payload"),
        }

        let second = session.on_tick(now + Duration::from_millis(1), 0, 0, 0, 0);
        assert_eq!(second.len(), 1);
        match &second[0].payload {
            DatagramPayload::Ack(payload) => assert_eq!(payload.ranges.len(), 1),
            _ => panic!("expected ACK payload"),
        }
    }

    #[test]
    fn nack_first_priority_flushes_nack_before_ack() {
        let mut session = Session::new(1400);
        let now = Instant::now();

        session.process_datagram_sequence(Sequence24::new(2), now);
        let out = session.on_tick(now + Duration::from_millis(10), 0, 0, 0, 0);
        assert_eq!(out.len(), 2, "both NACK and ACK must be flushed");
        assert!(
            matches!(out[0].payload, DatagramPayload::Nack(_)),
            "NACK must be emitted before ACK when priority is NackFirst"
        );
        assert!(
            matches!(out[1].payload, DatagramPayload::Ack(_)),
            "ACK must be emitted after NACK"
        );

        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.ack_out_datagrams, 1);
        assert_eq!(snapshot.nack_out_datagrams, 1);
    }

    #[test]
    fn ack_first_priority_flushes_ack_before_nack_in_custom_policy() {
        let tunables = SessionTunables {
            ack_nack_flush_profile: AckNackFlushProfile::Custom,
            ack_flush_interval: Duration::from_millis(1),
            nack_flush_interval: Duration::from_millis(1),
            ack_max_ranges_per_datagram: 64,
            nack_max_ranges_per_datagram: 64,
            ack_nack_priority: AckNackPriority::AckFirst,
            ..SessionTunables::default()
        };
        let mut session = Session::with_tunables(1400, tunables);
        let now = Instant::now();

        session.process_datagram_sequence(Sequence24::new(2), now);
        let out = session.on_tick(now + Duration::from_millis(1), 0, 0, 0, 0);
        assert_eq!(out.len(), 2, "both ACK and NACK must be flushed");
        assert!(
            matches!(out[0].payload, DatagramPayload::Ack(_)),
            "ACK must be emitted before NACK when priority is AckFirst"
        );
        assert!(
            matches!(out[1].payload, DatagramPayload::Nack(_)),
            "NACK must be emitted after ACK"
        );

        let snapshot = session.metrics_snapshot();
        assert_eq!(snapshot.ack_out_datagrams, 1);
        assert_eq!(snapshot.nack_out_datagrams, 1);
    }

    #[test]
    fn best_effort_zeroize_bytes_reports_success_for_unique_buffer() {
        let payload = Bytes::from(vec![0xAA, 0xBB, 0xCC]);
        assert!(
            super::best_effort_zeroize_bytes(payload),
            "uniquely-owned buffer should be writable for zeroize"
        );
    }

    #[test]
    fn best_effort_zeroize_bytes_reports_failure_for_shared_buffer() {
        let payload = Bytes::from(vec![0xAA, 0xBB, 0xCC]);
        let shared = payload.clone();
        assert!(
            !super::best_effort_zeroize_bytes(payload),
            "shared buffer cannot be zeroized in-place without unique ownership"
        );
        drop(shared);
    }
}
