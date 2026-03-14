use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::server::RaknetServerEvent;
use crate::transport::TransportMetricsSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryMetricKind {
    Counter,
    Gauge,
}

impl TelemetryMetricKind {
    fn as_prometheus_type(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TelemetryRecord {
    pub name: String,
    pub help: &'static str,
    pub kind: TelemetryMetricKind,
    pub value: f64,
    pub labels: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ShardTelemetrySnapshot {
    pub snapshot: TransportMetricsSnapshot,
    pub dropped_non_critical_events: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AggregatedTelemetrySnapshot {
    pub snapshot: TransportMetricsSnapshot,
    pub dropped_non_critical_events: u64,
}

#[derive(Debug, Clone, Copy)]
struct MetricFamilySpec<'a> {
    prefix: &'a str,
    name: &'a str,
    help: &'static str,
    kind: TelemetryMetricKind,
    total_value: f64,
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryRegistry {
    shards: BTreeMap<usize, ShardTelemetrySnapshot>,
}

impl TelemetryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.shards.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub fn shard_snapshot(&self, shard_id: usize) -> Option<&ShardTelemetrySnapshot> {
        self.shards.get(&shard_id)
    }

    pub fn iter_shards(&self) -> impl Iterator<Item = (usize, &ShardTelemetrySnapshot)> {
        self.shards.iter().map(|(id, snapshot)| (*id, snapshot))
    }

    pub fn ingest_snapshot(
        &mut self,
        shard_id: usize,
        snapshot: TransportMetricsSnapshot,
        dropped_non_critical_events: u64,
    ) {
        self.shards.insert(
            shard_id,
            ShardTelemetrySnapshot {
                snapshot,
                dropped_non_critical_events,
            },
        );
    }

    pub fn ingest_server_event(&mut self, event: &RaknetServerEvent) -> bool {
        let Some((shard_id, snapshot, dropped_non_critical_events)) = event.metrics_snapshot()
        else {
            return false;
        };
        self.ingest_snapshot(shard_id, *snapshot, dropped_non_critical_events);
        true
    }

    pub fn aggregate(&self) -> AggregatedTelemetrySnapshot {
        let mut total = TransportMetricsSnapshot::default();
        let mut dropped_non_critical_events = 0u64;

        let mut weighted_srtt_sum = 0.0;
        let mut weighted_rttvar_sum = 0.0;
        let mut weighted_resend_rto_sum = 0.0;
        let mut weighted_cwnd_sum = 0.0;

        for shard in self.shards.values() {
            let s = shard.snapshot;
            dropped_non_critical_events =
                dropped_non_critical_events.saturating_add(shard.dropped_non_critical_events);

            total.session_count = total.session_count.saturating_add(s.session_count);
            total.sessions_started_total = total
                .sessions_started_total
                .saturating_add(s.sessions_started_total);
            total.sessions_closed_total = total
                .sessions_closed_total
                .saturating_add(s.sessions_closed_total);
            total.packets_forwarded_total = total
                .packets_forwarded_total
                .saturating_add(s.packets_forwarded_total);
            total.bytes_forwarded_total = total
                .bytes_forwarded_total
                .saturating_add(s.bytes_forwarded_total);
            total.pending_outgoing_frames = total
                .pending_outgoing_frames
                .saturating_add(s.pending_outgoing_frames);
            total.pending_outgoing_bytes = total
                .pending_outgoing_bytes
                .saturating_add(s.pending_outgoing_bytes);
            total.pending_unhandled_frames = total
                .pending_unhandled_frames
                .saturating_add(s.pending_unhandled_frames);
            total.pending_unhandled_bytes = total
                .pending_unhandled_bytes
                .saturating_add(s.pending_unhandled_bytes);
            total.ingress_datagrams = total.ingress_datagrams.saturating_add(s.ingress_datagrams);
            total.ingress_frames = total.ingress_frames.saturating_add(s.ingress_frames);
            total.duplicate_reliable_drops = total
                .duplicate_reliable_drops
                .saturating_add(s.duplicate_reliable_drops);
            total.ordered_stale_drops = total
                .ordered_stale_drops
                .saturating_add(s.ordered_stale_drops);
            total.ordered_buffer_full_drops = total
                .ordered_buffer_full_drops
                .saturating_add(s.ordered_buffer_full_drops);
            total.sequenced_stale_drops = total
                .sequenced_stale_drops
                .saturating_add(s.sequenced_stale_drops);
            total.sequenced_missing_index_drops = total
                .sequenced_missing_index_drops
                .saturating_add(s.sequenced_missing_index_drops);
            total.reliable_sent_datagrams = total
                .reliable_sent_datagrams
                .saturating_add(s.reliable_sent_datagrams);
            total.resent_datagrams = total.resent_datagrams.saturating_add(s.resent_datagrams);
            total.ack_out_total = total.ack_out_total.saturating_add(s.ack_out_total);
            total.nack_out_total = total.nack_out_total.saturating_add(s.nack_out_total);
            total.acked_datagrams = total.acked_datagrams.saturating_add(s.acked_datagrams);
            total.nacked_datagrams = total.nacked_datagrams.saturating_add(s.nacked_datagrams);
            total.split_ttl_drops = total.split_ttl_drops.saturating_add(s.split_ttl_drops);
            total.outgoing_queue_drops = total
                .outgoing_queue_drops
                .saturating_add(s.outgoing_queue_drops);
            total.outgoing_queue_defers = total
                .outgoing_queue_defers
                .saturating_add(s.outgoing_queue_defers);
            total.outgoing_queue_disconnects = total
                .outgoing_queue_disconnects
                .saturating_add(s.outgoing_queue_disconnects);
            total.backpressure_delays = total
                .backpressure_delays
                .saturating_add(s.backpressure_delays);
            total.backpressure_drops = total
                .backpressure_drops
                .saturating_add(s.backpressure_drops);
            total.backpressure_disconnects = total
                .backpressure_disconnects
                .saturating_add(s.backpressure_disconnects);
            total.local_requested_disconnects = total
                .local_requested_disconnects
                .saturating_add(s.local_requested_disconnects);
            total.remote_disconnect_notifications = total
                .remote_disconnect_notifications
                .saturating_add(s.remote_disconnect_notifications);
            total.remote_detect_lost_disconnects = total
                .remote_detect_lost_disconnects
                .saturating_add(s.remote_detect_lost_disconnects);
            total.illegal_state_transitions = total
                .illegal_state_transitions
                .saturating_add(s.illegal_state_transitions);
            total.timed_out_sessions = total
                .timed_out_sessions
                .saturating_add(s.timed_out_sessions);
            total.keepalive_pings_sent = total
                .keepalive_pings_sent
                .saturating_add(s.keepalive_pings_sent);
            total.unhandled_frames_queued = total
                .unhandled_frames_queued
                .saturating_add(s.unhandled_frames_queued);
            total.unhandled_frames_flushed = total
                .unhandled_frames_flushed
                .saturating_add(s.unhandled_frames_flushed);
            total.unhandled_frames_dropped = total
                .unhandled_frames_dropped
                .saturating_add(s.unhandled_frames_dropped);
            total.rate_global_limit_hits = total
                .rate_global_limit_hits
                .saturating_add(s.rate_global_limit_hits);
            total.rate_ip_block_hits = total
                .rate_ip_block_hits
                .saturating_add(s.rate_ip_block_hits);
            total.rate_ip_block_hits_rate_exceeded = total
                .rate_ip_block_hits_rate_exceeded
                .saturating_add(s.rate_ip_block_hits_rate_exceeded);
            total.rate_ip_block_hits_manual = total
                .rate_ip_block_hits_manual
                .saturating_add(s.rate_ip_block_hits_manual);
            total.rate_ip_block_hits_handshake_heuristic = total
                .rate_ip_block_hits_handshake_heuristic
                .saturating_add(s.rate_ip_block_hits_handshake_heuristic);
            total.rate_ip_block_hits_cookie_mismatch_guard = total
                .rate_ip_block_hits_cookie_mismatch_guard
                .saturating_add(s.rate_ip_block_hits_cookie_mismatch_guard);
            total.rate_addresses_blocked = total
                .rate_addresses_blocked
                .saturating_add(s.rate_addresses_blocked);
            total.rate_addresses_blocked_rate_exceeded = total
                .rate_addresses_blocked_rate_exceeded
                .saturating_add(s.rate_addresses_blocked_rate_exceeded);
            total.rate_addresses_blocked_manual = total
                .rate_addresses_blocked_manual
                .saturating_add(s.rate_addresses_blocked_manual);
            total.rate_addresses_blocked_handshake_heuristic = total
                .rate_addresses_blocked_handshake_heuristic
                .saturating_add(s.rate_addresses_blocked_handshake_heuristic);
            total.rate_addresses_blocked_cookie_mismatch_guard = total
                .rate_addresses_blocked_cookie_mismatch_guard
                .saturating_add(s.rate_addresses_blocked_cookie_mismatch_guard);
            total.rate_addresses_unblocked = total
                .rate_addresses_unblocked
                .saturating_add(s.rate_addresses_unblocked);
            total.rate_blocked_addresses = total
                .rate_blocked_addresses
                .saturating_add(s.rate_blocked_addresses);
            total.rate_exception_addresses = total
                .rate_exception_addresses
                .saturating_add(s.rate_exception_addresses);
            total.processing_budget_drops_total = total
                .processing_budget_drops_total
                .saturating_add(s.processing_budget_drops_total);
            total.processing_budget_drops_ip_exhausted_total = total
                .processing_budget_drops_ip_exhausted_total
                .saturating_add(s.processing_budget_drops_ip_exhausted_total);
            total.processing_budget_drops_global_exhausted_total = total
                .processing_budget_drops_global_exhausted_total
                .saturating_add(s.processing_budget_drops_global_exhausted_total);
            total.processing_budget_consumed_units_total = total
                .processing_budget_consumed_units_total
                .saturating_add(s.processing_budget_consumed_units_total);
            total.processing_budget_active_ip_buckets = total
                .processing_budget_active_ip_buckets
                .saturating_add(s.processing_budget_active_ip_buckets);
            total.cookie_rotations = total.cookie_rotations.saturating_add(s.cookie_rotations);
            total.cookie_mismatch_drops = total
                .cookie_mismatch_drops
                .saturating_add(s.cookie_mismatch_drops);
            total.cookie_mismatch_blocks = total
                .cookie_mismatch_blocks
                .saturating_add(s.cookie_mismatch_blocks);
            total.handshake_stage_cancel_drops = total
                .handshake_stage_cancel_drops
                .saturating_add(s.handshake_stage_cancel_drops);
            total.handshake_req1_req2_timeouts = total
                .handshake_req1_req2_timeouts
                .saturating_add(s.handshake_req1_req2_timeouts);
            total.handshake_reply2_connect_timeouts = total
                .handshake_reply2_connect_timeouts
                .saturating_add(s.handshake_reply2_connect_timeouts);
            total.handshake_missing_req1_drops = total
                .handshake_missing_req1_drops
                .saturating_add(s.handshake_missing_req1_drops);
            total.handshake_auto_blocks = total
                .handshake_auto_blocks
                .saturating_add(s.handshake_auto_blocks);
            total.handshake_already_connected_rejects = total
                .handshake_already_connected_rejects
                .saturating_add(s.handshake_already_connected_rejects);
            total.handshake_ip_recently_connected_rejects = total
                .handshake_ip_recently_connected_rejects
                .saturating_add(s.handshake_ip_recently_connected_rejects);
            total.request2_server_addr_mismatch_drops = total
                .request2_server_addr_mismatch_drops
                .saturating_add(s.request2_server_addr_mismatch_drops);
            total.request2_legacy_parse_hits = total
                .request2_legacy_parse_hits
                .saturating_add(s.request2_legacy_parse_hits);
            total.request2_legacy_drops = total
                .request2_legacy_drops
                .saturating_add(s.request2_legacy_drops);
            total.request2_ambiguous_parse_hits = total
                .request2_ambiguous_parse_hits
                .saturating_add(s.request2_ambiguous_parse_hits);
            total.request2_ambiguous_drops = total
                .request2_ambiguous_drops
                .saturating_add(s.request2_ambiguous_drops);
            total.proxy_inbound_reroutes = total
                .proxy_inbound_reroutes
                .saturating_add(s.proxy_inbound_reroutes);
            total.proxy_inbound_drops = total
                .proxy_inbound_drops
                .saturating_add(s.proxy_inbound_drops);
            total.proxy_outbound_reroutes = total
                .proxy_outbound_reroutes
                .saturating_add(s.proxy_outbound_reroutes);
            total.proxy_outbound_drops = total
                .proxy_outbound_drops
                .saturating_add(s.proxy_outbound_drops);

            let weight = s.session_count as f64;
            weighted_srtt_sum += s.avg_srtt_ms * weight;
            weighted_rttvar_sum += s.avg_rttvar_ms * weight;
            weighted_resend_rto_sum += s.avg_resend_rto_ms * weight;
            weighted_cwnd_sum += s.avg_congestion_window_packets * weight;
        }

        if total.session_count > 0 {
            let weight_sum = total.session_count as f64;
            total.avg_srtt_ms = weighted_srtt_sum / weight_sum;
            total.avg_rttvar_ms = weighted_rttvar_sum / weight_sum;
            total.avg_resend_rto_ms = weighted_resend_rto_sum / weight_sum;
            total.avg_congestion_window_packets = weighted_cwnd_sum / weight_sum;
        }

        total.resend_ratio = if total.reliable_sent_datagrams == 0 {
            0.0
        } else {
            total.resent_datagrams as f64 / total.reliable_sent_datagrams as f64
        };

        AggregatedTelemetrySnapshot {
            snapshot: total,
            dropped_non_critical_events,
        }
    }

    pub fn to_records(&self) -> Vec<TelemetryRecord> {
        self.to_records_with_prefix("raknet")
    }

    pub fn to_records_with_prefix(&self, prefix: &str) -> Vec<TelemetryRecord> {
        let mut records = Vec::new();
        let aggregated = self.aggregate();

        macro_rules! push_snapshot_counter {
            ($name:literal, $help:literal, $field:ident) => {
                self.push_metric_records(
                    &mut records,
                    MetricFamilySpec {
                        prefix,
                        name: $name,
                        help: $help,
                        kind: TelemetryMetricKind::Counter,
                        total_value: aggregated.snapshot.$field as f64,
                    },
                    |shard| shard.snapshot.$field as f64,
                );
            };
        }

        macro_rules! push_snapshot_gauge {
            ($name:literal, $help:literal, $field:ident) => {
                self.push_metric_records(
                    &mut records,
                    MetricFamilySpec {
                        prefix,
                        name: $name,
                        help: $help,
                        kind: TelemetryMetricKind::Gauge,
                        total_value: aggregated.snapshot.$field as f64,
                    },
                    |shard| shard.snapshot.$field as f64,
                );
            };
        }

        macro_rules! push_snapshot_gauge_f64 {
            ($name:literal, $help:literal, $field:ident) => {
                self.push_metric_records(
                    &mut records,
                    MetricFamilySpec {
                        prefix,
                        name: $name,
                        help: $help,
                        kind: TelemetryMetricKind::Gauge,
                        total_value: aggregated.snapshot.$field,
                    },
                    |shard| shard.snapshot.$field,
                );
            };
        }

        // P2.3 canonical metric dictionary.
        push_snapshot_gauge!("sessions_active", "Active RakNet sessions", session_count);
        push_snapshot_counter!(
            "sessions_started_total",
            "Total sessions that reached connected state",
            sessions_started_total
        );
        push_snapshot_counter!(
            "sessions_closed_total",
            "Total connected sessions closed",
            sessions_closed_total
        );
        push_snapshot_counter!(
            "packets_forwarded_total",
            "Total app frames forwarded to upper layer",
            packets_forwarded_total
        );
        push_snapshot_counter!(
            "bytes_forwarded_total",
            "Total app payload bytes forwarded to upper layer",
            bytes_forwarded_total
        );
        push_snapshot_counter!(
            "ack_out_total",
            "Total outbound ACK datagrams",
            ack_out_total
        );
        push_snapshot_counter!(
            "nack_out_total",
            "Total outbound NACK datagrams",
            nack_out_total
        );
        push_snapshot_counter!(
            "resend_total",
            "Total datagrams resent after loss/timeout",
            resent_datagrams
        );
        push_snapshot_gauge!(
            "rtt_srtt_ms",
            "Average smoothed RTT in milliseconds",
            avg_srtt_ms
        );
        push_snapshot_gauge!(
            "rtt_rttvar_ms",
            "Average RTT variance in milliseconds",
            avg_rttvar_ms
        );
        push_snapshot_gauge!(
            "rto_ms",
            "Average resend RTO in milliseconds",
            avg_resend_rto_ms
        );
        push_snapshot_gauge!(
            "cwnd_packets",
            "Average congestion window (datagram packets)",
            avg_congestion_window_packets
        );
        push_snapshot_counter!(
            "duplicate_drop_total",
            "Dropped duplicate reliable frames",
            duplicate_reliable_drops
        );
        push_snapshot_counter!(
            "split_ttl_drop_total",
            "Dropped split compounds due to TTL expiry",
            split_ttl_drops
        );

        // Legacy names kept for backward compatibility.
        push_snapshot_gauge!("session_count", "Active RakNet sessions", session_count);
        push_snapshot_gauge!(
            "pending_outgoing_frames",
            "Queued outgoing frames before datagram packaging",
            pending_outgoing_frames
        );
        push_snapshot_gauge!(
            "pending_outgoing_bytes",
            "Queued outgoing bytes before datagram packaging",
            pending_outgoing_bytes
        );
        push_snapshot_gauge!(
            "pending_unhandled_frames",
            "Unhandled app frames waiting for connected state",
            pending_unhandled_frames
        );
        push_snapshot_gauge!(
            "pending_unhandled_bytes",
            "Unhandled app frame bytes waiting for connected state",
            pending_unhandled_bytes
        );

        push_snapshot_counter!(
            "ingress_datagrams_total",
            "Total datagrams received",
            ingress_datagrams
        );
        push_snapshot_counter!(
            "ingress_frames_total",
            "Total frames received",
            ingress_frames
        );
        push_snapshot_counter!(
            "duplicate_reliable_drops_total",
            "Dropped duplicate reliable frames",
            duplicate_reliable_drops
        );
        push_snapshot_counter!(
            "ordered_stale_drops_total",
            "Dropped stale ordered frames",
            ordered_stale_drops
        );
        push_snapshot_counter!(
            "ordered_buffer_full_drops_total",
            "Dropped ordered frames due to reorder buffer overflow",
            ordered_buffer_full_drops
        );
        push_snapshot_counter!(
            "sequenced_stale_drops_total",
            "Dropped stale sequenced frames",
            sequenced_stale_drops
        );
        push_snapshot_counter!(
            "sequenced_missing_index_drops_total",
            "Dropped sequenced frames missing sequence index",
            sequenced_missing_index_drops
        );
        push_snapshot_counter!(
            "reliable_sent_datagrams_total",
            "Total reliable datagrams sent",
            reliable_sent_datagrams
        );
        push_snapshot_counter!(
            "resent_datagrams_total",
            "Total datagrams resent after loss/timeout",
            resent_datagrams
        );
        push_snapshot_counter!(
            "acked_datagrams_total",
            "Total datagrams acknowledged",
            acked_datagrams
        );
        push_snapshot_counter!(
            "nacked_datagrams_total",
            "Total datagrams negatively acknowledged",
            nacked_datagrams
        );
        push_snapshot_counter!(
            "split_ttl_drops_total",
            "Dropped split compounds due to TTL expiry",
            split_ttl_drops
        );
        push_snapshot_counter!(
            "outgoing_queue_drops_total",
            "Dropped payloads due to outgoing queue soft pressure",
            outgoing_queue_drops
        );
        push_snapshot_counter!(
            "outgoing_queue_defers_total",
            "Deferred payloads due to outgoing queue soft pressure",
            outgoing_queue_defers
        );
        push_snapshot_counter!(
            "outgoing_queue_disconnects_total",
            "Disconnects triggered by outgoing queue hard pressure",
            outgoing_queue_disconnects
        );
        push_snapshot_counter!(
            "backpressure_delay_total",
            "Backpressure delay actions (deferred packets)",
            backpressure_delays
        );
        push_snapshot_counter!(
            "backpressure_drop_total",
            "Backpressure shed actions (dropped packets)",
            backpressure_drops
        );
        push_snapshot_counter!(
            "backpressure_disconnect_total",
            "Backpressure disconnect actions",
            backpressure_disconnects
        );
        push_snapshot_counter!(
            "local_requested_disconnects_total",
            "Disconnects explicitly requested by local control path",
            local_requested_disconnects
        );
        push_snapshot_counter!(
            "remote_disconnect_notifications_total",
            "Remote disconnect notifications received",
            remote_disconnect_notifications
        );
        push_snapshot_counter!(
            "remote_detect_lost_disconnects_total",
            "Remote detect-lost disconnect signals received",
            remote_detect_lost_disconnects
        );
        push_snapshot_counter!(
            "illegal_state_transitions_total",
            "Illegal session state transitions detected",
            illegal_state_transitions
        );
        push_snapshot_counter!(
            "timed_out_sessions_total",
            "Sessions closed due to idle timeout",
            timed_out_sessions
        );
        push_snapshot_counter!(
            "keepalive_pings_sent_total",
            "Connected keepalive pings sent",
            keepalive_pings_sent
        );
        push_snapshot_counter!(
            "unhandled_frames_queued_total",
            "Unhandled app frames queued before connected state",
            unhandled_frames_queued
        );
        push_snapshot_counter!(
            "unhandled_frames_flushed_total",
            "Unhandled app frames flushed after connection",
            unhandled_frames_flushed
        );
        push_snapshot_counter!(
            "unhandled_frames_dropped_total",
            "Unhandled app frames dropped due to pipeline overflow",
            unhandled_frames_dropped
        );
        push_snapshot_counter!(
            "rate_global_limit_hits_total",
            "Global rate limit hits",
            rate_global_limit_hits
        );
        push_snapshot_counter!(
            "rate_ip_block_hits_total",
            "Per-IP rate limiter block hits",
            rate_ip_block_hits
        );
        push_snapshot_counter!(
            "rate_ip_block_hits_rate_exceeded_total",
            "Per-IP block hits caused by packet rate exceeding threshold",
            rate_ip_block_hits_rate_exceeded
        );
        push_snapshot_counter!(
            "rate_ip_block_hits_manual_total",
            "Per-IP block hits caused by manual address blocks",
            rate_ip_block_hits_manual
        );
        push_snapshot_counter!(
            "rate_ip_block_hits_handshake_heuristic_total",
            "Per-IP block hits caused by handshake heuristic guard",
            rate_ip_block_hits_handshake_heuristic
        );
        push_snapshot_counter!(
            "rate_ip_block_hits_cookie_mismatch_guard_total",
            "Per-IP block hits caused by cookie mismatch guard",
            rate_ip_block_hits_cookie_mismatch_guard
        );
        push_snapshot_counter!(
            "rate_addresses_blocked_total",
            "Addresses blocked by rate limiter",
            rate_addresses_blocked
        );
        push_snapshot_counter!(
            "rate_addresses_blocked_rate_exceeded_total",
            "Addresses blocked due to packet rate exceeding threshold",
            rate_addresses_blocked_rate_exceeded
        );
        push_snapshot_counter!(
            "rate_addresses_blocked_manual_total",
            "Addresses blocked manually",
            rate_addresses_blocked_manual
        );
        push_snapshot_counter!(
            "rate_addresses_blocked_handshake_heuristic_total",
            "Addresses blocked by handshake heuristic guard",
            rate_addresses_blocked_handshake_heuristic
        );
        push_snapshot_counter!(
            "rate_addresses_blocked_cookie_mismatch_guard_total",
            "Addresses blocked by cookie mismatch guard",
            rate_addresses_blocked_cookie_mismatch_guard
        );
        push_snapshot_counter!(
            "rate_addresses_unblocked_total",
            "Addresses unblocked by rate limiter",
            rate_addresses_unblocked
        );
        push_snapshot_gauge!(
            "rate_blocked_addresses",
            "Currently blocked addresses in rate limiter",
            rate_blocked_addresses
        );
        push_snapshot_gauge!(
            "rate_exception_addresses",
            "Rate limiter exception addresses",
            rate_exception_addresses
        );
        push_snapshot_counter!(
            "processing_budget_drops_total",
            "Connected datagrams dropped by processing budget limiter",
            processing_budget_drops_total
        );
        push_snapshot_counter!(
            "processing_budget_drops_ip_exhausted_total",
            "Connected datagrams dropped because per-IP processing budget was exhausted",
            processing_budget_drops_ip_exhausted_total
        );
        push_snapshot_counter!(
            "processing_budget_drops_global_exhausted_total",
            "Connected datagrams dropped because global processing budget was exhausted",
            processing_budget_drops_global_exhausted_total
        );
        push_snapshot_counter!(
            "processing_budget_consumed_units_total",
            "Total processing budget units consumed by connected datagrams",
            processing_budget_consumed_units_total
        );
        push_snapshot_gauge!(
            "processing_budget_active_ip_buckets",
            "Active per-IP processing budget buckets",
            processing_budget_active_ip_buckets
        );
        push_snapshot_counter!(
            "cookie_rotations_total",
            "Cookie key rotations",
            cookie_rotations
        );
        push_snapshot_counter!(
            "cookie_mismatch_drops_total",
            "Dropped handshakes due to cookie mismatch",
            cookie_mismatch_drops
        );
        push_snapshot_counter!(
            "cookie_mismatch_blocks_total",
            "Addresses blocked by cookie mismatch guard",
            cookie_mismatch_blocks
        );
        push_snapshot_counter!(
            "handshake_stage_cancel_drops_total",
            "Dropped handshakes due to stage cancel",
            handshake_stage_cancel_drops
        );
        push_snapshot_counter!(
            "handshake_req1_req2_timeouts_total",
            "REQ1->REQ2 handshake timeout drops",
            handshake_req1_req2_timeouts
        );
        push_snapshot_counter!(
            "handshake_reply2_connect_timeouts_total",
            "REPLY2->CONNECT handshake timeout drops",
            handshake_reply2_connect_timeouts
        );
        push_snapshot_counter!(
            "handshake_missing_req1_drops_total",
            "Dropped REQ2 packets without pending REQ1",
            handshake_missing_req1_drops
        );
        push_snapshot_counter!(
            "handshake_auto_blocks_total",
            "Automatic rate blocks triggered by handshake heuristics",
            handshake_auto_blocks
        );
        push_snapshot_counter!(
            "handshake_already_connected_rejects_total",
            "REQ1/REQ2 rejects answered with AlreadyConnected",
            handshake_already_connected_rejects
        );
        push_snapshot_counter!(
            "handshake_ip_recently_connected_rejects_total",
            "REQ1/REQ2 rejects answered with IpRecentlyConnected",
            handshake_ip_recently_connected_rejects
        );
        push_snapshot_counter!(
            "request2_server_addr_mismatch_drops_total",
            "Dropped REQ2 packets due to request2_server_addr_policy mismatch",
            request2_server_addr_mismatch_drops
        );
        push_snapshot_counter!(
            "request2_legacy_parse_hits_total",
            "Legacy Request2 parse path hits",
            request2_legacy_parse_hits
        );
        push_snapshot_counter!(
            "request2_legacy_drops_total",
            "Drops caused by legacy Request2 parse path",
            request2_legacy_drops
        );
        push_snapshot_counter!(
            "request2_ambiguous_parse_hits_total",
            "Ambiguous Request2 parse path hits",
            request2_ambiguous_parse_hits
        );
        push_snapshot_counter!(
            "request2_ambiguous_drops_total",
            "Drops caused by ambiguous Request2 parse path",
            request2_ambiguous_drops
        );
        push_snapshot_counter!(
            "proxy_inbound_reroutes_total",
            "Inbound packets rerouted by proxy routing",
            proxy_inbound_reroutes
        );
        push_snapshot_counter!(
            "proxy_inbound_drops_total",
            "Inbound packets dropped by proxy routing",
            proxy_inbound_drops
        );
        push_snapshot_counter!(
            "proxy_outbound_reroutes_total",
            "Outbound packets rerouted by proxy routing",
            proxy_outbound_reroutes
        );
        push_snapshot_counter!(
            "proxy_outbound_drops_total",
            "Outbound packets dropped by proxy routing",
            proxy_outbound_drops
        );
        push_snapshot_gauge_f64!(
            "avg_srtt_ms",
            "Average smoothed RTT in milliseconds",
            avg_srtt_ms
        );
        push_snapshot_gauge_f64!(
            "avg_rttvar_ms",
            "Average RTT variance in milliseconds",
            avg_rttvar_ms
        );
        push_snapshot_gauge_f64!(
            "avg_resend_rto_ms",
            "Average resend RTO in milliseconds",
            avg_resend_rto_ms
        );
        push_snapshot_gauge_f64!(
            "avg_congestion_window_packets",
            "Average congestion window (datagram packets)",
            avg_congestion_window_packets
        );
        push_snapshot_gauge_f64!(
            "resend_ratio",
            "Resend ratio (resent/reliable_sent)",
            resend_ratio
        );

        self.push_metric_records(
            &mut records,
            MetricFamilySpec {
                prefix,
                name: "dropped_non_critical_events_total",
                help: "Dropped non-critical runtime events due to overflow policy",
                kind: TelemetryMetricKind::Counter,
                total_value: aggregated.dropped_non_critical_events as f64,
            },
            |shard| shard.dropped_non_critical_events as f64,
        );

        records
    }

    pub fn render_prometheus(&self) -> String {
        self.render_prometheus_with_prefix("raknet")
    }

    pub fn render_prometheus_with_prefix(&self, prefix: &str) -> String {
        let mut out = String::new();
        let aggregated = self.aggregate();

        macro_rules! write_snapshot_counter {
            ($name:literal, $help:literal, $field:ident) => {
                self.write_metric_family(
                    &mut out,
                    MetricFamilySpec {
                        prefix,
                        name: $name,
                        help: $help,
                        kind: TelemetryMetricKind::Counter,
                        total_value: aggregated.snapshot.$field as f64,
                    },
                    |shard| shard.snapshot.$field as f64,
                );
            };
        }

        macro_rules! write_snapshot_gauge {
            ($name:literal, $help:literal, $field:ident) => {
                self.write_metric_family(
                    &mut out,
                    MetricFamilySpec {
                        prefix,
                        name: $name,
                        help: $help,
                        kind: TelemetryMetricKind::Gauge,
                        total_value: aggregated.snapshot.$field as f64,
                    },
                    |shard| shard.snapshot.$field as f64,
                );
            };
        }

        macro_rules! write_snapshot_gauge_f64 {
            ($name:literal, $help:literal, $field:ident) => {
                self.write_metric_family(
                    &mut out,
                    MetricFamilySpec {
                        prefix,
                        name: $name,
                        help: $help,
                        kind: TelemetryMetricKind::Gauge,
                        total_value: aggregated.snapshot.$field,
                    },
                    |shard| shard.snapshot.$field,
                );
            };
        }

        // P2.3 canonical metric dictionary.
        write_snapshot_gauge!("sessions_active", "Active RakNet sessions", session_count);
        write_snapshot_counter!(
            "sessions_started_total",
            "Total sessions that reached connected state",
            sessions_started_total
        );
        write_snapshot_counter!(
            "sessions_closed_total",
            "Total connected sessions closed",
            sessions_closed_total
        );
        write_snapshot_counter!(
            "packets_forwarded_total",
            "Total app frames forwarded to upper layer",
            packets_forwarded_total
        );
        write_snapshot_counter!(
            "bytes_forwarded_total",
            "Total app payload bytes forwarded to upper layer",
            bytes_forwarded_total
        );
        write_snapshot_counter!(
            "ack_out_total",
            "Total outbound ACK datagrams",
            ack_out_total
        );
        write_snapshot_counter!(
            "nack_out_total",
            "Total outbound NACK datagrams",
            nack_out_total
        );
        write_snapshot_counter!(
            "resend_total",
            "Total datagrams resent after loss/timeout",
            resent_datagrams
        );
        write_snapshot_gauge!(
            "rtt_srtt_ms",
            "Average smoothed RTT in milliseconds",
            avg_srtt_ms
        );
        write_snapshot_gauge!(
            "rtt_rttvar_ms",
            "Average RTT variance in milliseconds",
            avg_rttvar_ms
        );
        write_snapshot_gauge!(
            "rto_ms",
            "Average resend RTO in milliseconds",
            avg_resend_rto_ms
        );
        write_snapshot_gauge!(
            "cwnd_packets",
            "Average congestion window (datagram packets)",
            avg_congestion_window_packets
        );
        write_snapshot_counter!(
            "duplicate_drop_total",
            "Dropped duplicate reliable frames",
            duplicate_reliable_drops
        );
        write_snapshot_counter!(
            "split_ttl_drop_total",
            "Dropped split compounds due to TTL expiry",
            split_ttl_drops
        );

        // Legacy names kept for backward compatibility.
        write_snapshot_gauge!("session_count", "Active RakNet sessions", session_count);
        write_snapshot_gauge!(
            "pending_outgoing_frames",
            "Queued outgoing frames before datagram packaging",
            pending_outgoing_frames
        );
        write_snapshot_gauge!(
            "pending_outgoing_bytes",
            "Queued outgoing bytes before datagram packaging",
            pending_outgoing_bytes
        );
        write_snapshot_gauge!(
            "pending_unhandled_frames",
            "Unhandled app frames waiting for connected state",
            pending_unhandled_frames
        );
        write_snapshot_gauge!(
            "pending_unhandled_bytes",
            "Unhandled app frame bytes waiting for connected state",
            pending_unhandled_bytes
        );

        write_snapshot_counter!(
            "ingress_datagrams_total",
            "Total datagrams received",
            ingress_datagrams
        );
        write_snapshot_counter!(
            "ingress_frames_total",
            "Total frames received",
            ingress_frames
        );
        write_snapshot_counter!(
            "duplicate_reliable_drops_total",
            "Dropped duplicate reliable frames",
            duplicate_reliable_drops
        );
        write_snapshot_counter!(
            "ordered_stale_drops_total",
            "Dropped stale ordered frames",
            ordered_stale_drops
        );
        write_snapshot_counter!(
            "ordered_buffer_full_drops_total",
            "Dropped ordered frames due to reorder buffer overflow",
            ordered_buffer_full_drops
        );
        write_snapshot_counter!(
            "sequenced_stale_drops_total",
            "Dropped stale sequenced frames",
            sequenced_stale_drops
        );
        write_snapshot_counter!(
            "sequenced_missing_index_drops_total",
            "Dropped sequenced frames missing sequence index",
            sequenced_missing_index_drops
        );
        write_snapshot_counter!(
            "reliable_sent_datagrams_total",
            "Total reliable datagrams sent",
            reliable_sent_datagrams
        );
        write_snapshot_counter!(
            "resent_datagrams_total",
            "Total datagrams resent after loss/timeout",
            resent_datagrams
        );
        write_snapshot_counter!(
            "acked_datagrams_total",
            "Total datagrams acknowledged",
            acked_datagrams
        );
        write_snapshot_counter!(
            "nacked_datagrams_total",
            "Total datagrams negatively acknowledged",
            nacked_datagrams
        );
        write_snapshot_counter!(
            "split_ttl_drops_total",
            "Dropped split compounds due to TTL expiry",
            split_ttl_drops
        );
        write_snapshot_counter!(
            "outgoing_queue_drops_total",
            "Dropped payloads due to outgoing queue soft pressure",
            outgoing_queue_drops
        );
        write_snapshot_counter!(
            "outgoing_queue_defers_total",
            "Deferred payloads due to outgoing queue soft pressure",
            outgoing_queue_defers
        );
        write_snapshot_counter!(
            "outgoing_queue_disconnects_total",
            "Disconnects triggered by outgoing queue hard pressure",
            outgoing_queue_disconnects
        );
        write_snapshot_counter!(
            "backpressure_delay_total",
            "Backpressure delay actions (deferred packets)",
            backpressure_delays
        );
        write_snapshot_counter!(
            "backpressure_drop_total",
            "Backpressure shed actions (dropped packets)",
            backpressure_drops
        );
        write_snapshot_counter!(
            "backpressure_disconnect_total",
            "Backpressure disconnect actions",
            backpressure_disconnects
        );
        write_snapshot_counter!(
            "local_requested_disconnects_total",
            "Disconnects explicitly requested by local control path",
            local_requested_disconnects
        );
        write_snapshot_counter!(
            "remote_disconnect_notifications_total",
            "Remote disconnect notifications received",
            remote_disconnect_notifications
        );
        write_snapshot_counter!(
            "remote_detect_lost_disconnects_total",
            "Remote detect-lost disconnect signals received",
            remote_detect_lost_disconnects
        );
        write_snapshot_counter!(
            "illegal_state_transitions_total",
            "Illegal session state transitions detected",
            illegal_state_transitions
        );
        write_snapshot_counter!(
            "timed_out_sessions_total",
            "Sessions closed due to idle timeout",
            timed_out_sessions
        );
        write_snapshot_counter!(
            "keepalive_pings_sent_total",
            "Connected keepalive pings sent",
            keepalive_pings_sent
        );
        write_snapshot_counter!(
            "unhandled_frames_queued_total",
            "Unhandled app frames queued before connected state",
            unhandled_frames_queued
        );
        write_snapshot_counter!(
            "unhandled_frames_flushed_total",
            "Unhandled app frames flushed after connection",
            unhandled_frames_flushed
        );
        write_snapshot_counter!(
            "unhandled_frames_dropped_total",
            "Unhandled app frames dropped due to pipeline overflow",
            unhandled_frames_dropped
        );
        write_snapshot_counter!(
            "rate_global_limit_hits_total",
            "Global rate limit hits",
            rate_global_limit_hits
        );
        write_snapshot_counter!(
            "rate_ip_block_hits_total",
            "Per-IP rate limiter block hits",
            rate_ip_block_hits
        );
        write_snapshot_counter!(
            "rate_ip_block_hits_rate_exceeded_total",
            "Per-IP block hits caused by packet rate exceeding threshold",
            rate_ip_block_hits_rate_exceeded
        );
        write_snapshot_counter!(
            "rate_ip_block_hits_manual_total",
            "Per-IP block hits caused by manual address blocks",
            rate_ip_block_hits_manual
        );
        write_snapshot_counter!(
            "rate_ip_block_hits_handshake_heuristic_total",
            "Per-IP block hits caused by handshake heuristic guard",
            rate_ip_block_hits_handshake_heuristic
        );
        write_snapshot_counter!(
            "rate_ip_block_hits_cookie_mismatch_guard_total",
            "Per-IP block hits caused by cookie mismatch guard",
            rate_ip_block_hits_cookie_mismatch_guard
        );
        write_snapshot_counter!(
            "rate_addresses_blocked_total",
            "Addresses blocked by rate limiter",
            rate_addresses_blocked
        );
        write_snapshot_counter!(
            "rate_addresses_blocked_rate_exceeded_total",
            "Addresses blocked due to packet rate exceeding threshold",
            rate_addresses_blocked_rate_exceeded
        );
        write_snapshot_counter!(
            "rate_addresses_blocked_manual_total",
            "Addresses blocked manually",
            rate_addresses_blocked_manual
        );
        write_snapshot_counter!(
            "rate_addresses_blocked_handshake_heuristic_total",
            "Addresses blocked by handshake heuristic guard",
            rate_addresses_blocked_handshake_heuristic
        );
        write_snapshot_counter!(
            "rate_addresses_blocked_cookie_mismatch_guard_total",
            "Addresses blocked by cookie mismatch guard",
            rate_addresses_blocked_cookie_mismatch_guard
        );
        write_snapshot_counter!(
            "rate_addresses_unblocked_total",
            "Addresses unblocked by rate limiter",
            rate_addresses_unblocked
        );
        write_snapshot_gauge!(
            "rate_blocked_addresses",
            "Currently blocked addresses in rate limiter",
            rate_blocked_addresses
        );
        write_snapshot_gauge!(
            "rate_exception_addresses",
            "Rate limiter exception addresses",
            rate_exception_addresses
        );
        write_snapshot_counter!(
            "processing_budget_drops_total",
            "Connected datagrams dropped by processing budget limiter",
            processing_budget_drops_total
        );
        write_snapshot_counter!(
            "processing_budget_drops_ip_exhausted_total",
            "Connected datagrams dropped because per-IP processing budget was exhausted",
            processing_budget_drops_ip_exhausted_total
        );
        write_snapshot_counter!(
            "processing_budget_drops_global_exhausted_total",
            "Connected datagrams dropped because global processing budget was exhausted",
            processing_budget_drops_global_exhausted_total
        );
        write_snapshot_counter!(
            "processing_budget_consumed_units_total",
            "Total processing budget units consumed by connected datagrams",
            processing_budget_consumed_units_total
        );
        write_snapshot_gauge!(
            "processing_budget_active_ip_buckets",
            "Active per-IP processing budget buckets",
            processing_budget_active_ip_buckets
        );
        write_snapshot_counter!(
            "cookie_rotations_total",
            "Cookie key rotations",
            cookie_rotations
        );
        write_snapshot_counter!(
            "cookie_mismatch_drops_total",
            "Dropped handshakes due to cookie mismatch",
            cookie_mismatch_drops
        );
        write_snapshot_counter!(
            "cookie_mismatch_blocks_total",
            "Addresses blocked by cookie mismatch guard",
            cookie_mismatch_blocks
        );
        write_snapshot_counter!(
            "handshake_stage_cancel_drops_total",
            "Dropped handshakes due to stage cancel",
            handshake_stage_cancel_drops
        );
        write_snapshot_counter!(
            "handshake_req1_req2_timeouts_total",
            "REQ1->REQ2 handshake timeout drops",
            handshake_req1_req2_timeouts
        );
        write_snapshot_counter!(
            "handshake_reply2_connect_timeouts_total",
            "REPLY2->CONNECT handshake timeout drops",
            handshake_reply2_connect_timeouts
        );
        write_snapshot_counter!(
            "handshake_missing_req1_drops_total",
            "Dropped REQ2 packets without pending REQ1",
            handshake_missing_req1_drops
        );
        write_snapshot_counter!(
            "handshake_auto_blocks_total",
            "Automatic rate blocks triggered by handshake heuristics",
            handshake_auto_blocks
        );
        write_snapshot_counter!(
            "handshake_already_connected_rejects_total",
            "REQ1/REQ2 rejects answered with AlreadyConnected",
            handshake_already_connected_rejects
        );
        write_snapshot_counter!(
            "handshake_ip_recently_connected_rejects_total",
            "REQ1/REQ2 rejects answered with IpRecentlyConnected",
            handshake_ip_recently_connected_rejects
        );
        write_snapshot_counter!(
            "request2_server_addr_mismatch_drops_total",
            "Dropped REQ2 packets due to request2_server_addr_policy mismatch",
            request2_server_addr_mismatch_drops
        );
        write_snapshot_counter!(
            "request2_legacy_parse_hits_total",
            "Legacy Request2 parse path hits",
            request2_legacy_parse_hits
        );
        write_snapshot_counter!(
            "request2_legacy_drops_total",
            "Drops caused by legacy Request2 parse path",
            request2_legacy_drops
        );
        write_snapshot_counter!(
            "request2_ambiguous_parse_hits_total",
            "Ambiguous Request2 parse path hits",
            request2_ambiguous_parse_hits
        );
        write_snapshot_counter!(
            "request2_ambiguous_drops_total",
            "Drops caused by ambiguous Request2 parse path",
            request2_ambiguous_drops
        );
        write_snapshot_counter!(
            "proxy_inbound_reroutes_total",
            "Inbound packets rerouted by proxy routing",
            proxy_inbound_reroutes
        );
        write_snapshot_counter!(
            "proxy_inbound_drops_total",
            "Inbound packets dropped by proxy routing",
            proxy_inbound_drops
        );
        write_snapshot_counter!(
            "proxy_outbound_reroutes_total",
            "Outbound packets rerouted by proxy routing",
            proxy_outbound_reroutes
        );
        write_snapshot_counter!(
            "proxy_outbound_drops_total",
            "Outbound packets dropped by proxy routing",
            proxy_outbound_drops
        );
        write_snapshot_gauge_f64!(
            "avg_srtt_ms",
            "Average smoothed RTT in milliseconds",
            avg_srtt_ms
        );
        write_snapshot_gauge_f64!(
            "avg_rttvar_ms",
            "Average RTT variance in milliseconds",
            avg_rttvar_ms
        );
        write_snapshot_gauge_f64!(
            "avg_resend_rto_ms",
            "Average resend RTO in milliseconds",
            avg_resend_rto_ms
        );
        write_snapshot_gauge_f64!(
            "avg_congestion_window_packets",
            "Average congestion window (datagram packets)",
            avg_congestion_window_packets
        );
        write_snapshot_gauge_f64!(
            "resend_ratio",
            "Resend ratio (resent/reliable_sent)",
            resend_ratio
        );

        self.write_metric_family(
            &mut out,
            MetricFamilySpec {
                prefix,
                name: "dropped_non_critical_events_total",
                help: "Dropped non-critical runtime events due to overflow policy",
                kind: TelemetryMetricKind::Counter,
                total_value: aggregated.dropped_non_critical_events as f64,
            },
            |shard| shard.dropped_non_critical_events as f64,
        );

        out
    }

    fn push_metric_records<F>(
        &self,
        records: &mut Vec<TelemetryRecord>,
        spec: MetricFamilySpec<'_>,
        extract: F,
    ) where
        F: Fn(&ShardTelemetrySnapshot) -> f64,
    {
        for (shard_id, shard) in &self.shards {
            records.push(TelemetryRecord {
                name: format!("{}_{}", spec.prefix, spec.name),
                help: spec.help,
                kind: spec.kind,
                value: extract(shard),
                labels: vec![
                    ("scope".to_string(), "shard".to_string()),
                    ("shard".to_string(), shard_id.to_string()),
                ],
            });
        }

        records.push(TelemetryRecord {
            name: format!("{}_{}", spec.prefix, spec.name),
            help: spec.help,
            kind: spec.kind,
            value: spec.total_value,
            labels: vec![
                ("scope".to_string(), "all".to_string()),
                ("shard".to_string(), "all".to_string()),
            ],
        });
    }

    fn write_metric_family<F>(&self, out: &mut String, spec: MetricFamilySpec<'_>, extract: F)
    where
        F: Fn(&ShardTelemetrySnapshot) -> f64,
    {
        let _ = writeln!(out, "# HELP {}_{} {}", spec.prefix, spec.name, spec.help);
        let _ = writeln!(
            out,
            "# TYPE {}_{} {}",
            spec.prefix,
            spec.name,
            spec.kind.as_prometheus_type()
        );
        for (shard_id, shard) in &self.shards {
            let _ = writeln!(
                out,
                "{}_{}{{scope=\"shard\",shard=\"{shard_id}\"}} {}",
                spec.prefix,
                spec.name,
                extract(shard)
            );
        }
        let _ = writeln!(
            out,
            "{}_{}{{scope=\"all\",shard=\"all\"}} {}",
            spec.prefix, spec.name, spec.total_value
        );
    }
}

#[derive(Debug, Clone)]
pub struct TelemetryExporter {
    registry: TelemetryRegistry,
    prefix: String,
}

impl Default for TelemetryExporter {
    fn default() -> Self {
        Self {
            registry: TelemetryRegistry::new(),
            prefix: "raknet".to_string(),
        }
    }
}

impl TelemetryExporter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            ..Self::default()
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn set_prefix(&mut self, prefix: impl Into<String>) {
        self.prefix = prefix.into();
    }

    pub fn clear(&mut self) {
        self.registry.clear();
    }

    pub fn shard_count(&self) -> usize {
        self.registry.shard_count()
    }

    pub fn ingest_snapshot(
        &mut self,
        shard_id: usize,
        snapshot: TransportMetricsSnapshot,
        dropped_non_critical_events: u64,
    ) {
        self.registry
            .ingest_snapshot(shard_id, snapshot, dropped_non_critical_events);
    }

    pub fn ingest_server_event(&mut self, event: &RaknetServerEvent) -> bool {
        self.registry.ingest_server_event(event)
    }

    pub fn aggregate(&self) -> AggregatedTelemetrySnapshot {
        self.registry.aggregate()
    }

    pub fn render_prometheus(&self) -> String {
        self.registry.render_prometheus_with_prefix(&self.prefix)
    }

    pub fn records(&self) -> Vec<TelemetryRecord> {
        self.registry.to_records_with_prefix(&self.prefix)
    }

    pub fn registry(&self) -> &TelemetryRegistry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::{TelemetryExporter, TelemetryMetricKind, TelemetryRegistry};
    use crate::server::RaknetServerEvent;
    use crate::transport::TransportMetricsSnapshot;

    fn metrics_event(
        shard_id: usize,
        snapshot: TransportMetricsSnapshot,
        dropped_non_critical_events: u64,
    ) -> RaknetServerEvent {
        RaknetServerEvent::Metrics {
            shard_id,
            snapshot: Box::new(snapshot),
            dropped_non_critical_events,
        }
    }

    #[test]
    fn ingest_server_event_updates_shard_snapshot() {
        let mut registry = TelemetryRegistry::new();
        let snapshot = TransportMetricsSnapshot {
            session_count: 2,
            ingress_datagrams: 11,
            ..TransportMetricsSnapshot::default()
        };

        assert!(registry.ingest_server_event(&metrics_event(3, snapshot, 9)));
        assert_eq!(registry.shard_count(), 1);

        let shard = registry
            .shard_snapshot(3)
            .expect("shard snapshot should exist");
        assert_eq!(shard.snapshot.session_count, 2);
        assert_eq!(shard.snapshot.ingress_datagrams, 11);
        assert_eq!(shard.dropped_non_critical_events, 9);
    }

    #[test]
    fn aggregate_recomputes_weighted_averages_and_resend_ratio() {
        let mut registry = TelemetryRegistry::new();

        let shard0 = TransportMetricsSnapshot {
            session_count: 2,
            ingress_datagrams: 100,
            resent_datagrams: 20,
            reliable_sent_datagrams: 200,
            processing_budget_drops_total: 3,
            processing_budget_consumed_units_total: 10_000,
            avg_srtt_ms: 10.0,
            avg_rttvar_ms: 3.0,
            avg_resend_rto_ms: 25.0,
            avg_congestion_window_packets: 8.0,
            ..TransportMetricsSnapshot::default()
        };
        let shard1 = TransportMetricsSnapshot {
            session_count: 1,
            ingress_datagrams: 50,
            resent_datagrams: 10,
            reliable_sent_datagrams: 100,
            processing_budget_drops_total: 5,
            processing_budget_consumed_units_total: 20_000,
            avg_srtt_ms: 40.0,
            avg_rttvar_ms: 6.0,
            avg_resend_rto_ms: 55.0,
            avg_congestion_window_packets: 4.0,
            ..TransportMetricsSnapshot::default()
        };

        registry.ingest_snapshot(0, shard0, 2);
        registry.ingest_snapshot(1, shard1, 7);

        let total = registry.aggregate();
        assert_eq!(total.snapshot.session_count, 3);
        assert_eq!(total.snapshot.ingress_datagrams, 150);
        assert_eq!(total.snapshot.resent_datagrams, 30);
        assert_eq!(total.snapshot.reliable_sent_datagrams, 300);
        assert_eq!(total.snapshot.processing_budget_drops_total, 8);
        assert_eq!(
            total.snapshot.processing_budget_consumed_units_total,
            30_000
        );
        assert_eq!(total.dropped_non_critical_events, 9);

        assert!((total.snapshot.avg_srtt_ms - 20.0).abs() < 1e-9);
        assert!((total.snapshot.avg_rttvar_ms - 4.0).abs() < 1e-9);
        assert!((total.snapshot.avg_resend_rto_ms - 35.0).abs() < 1e-9);
        assert!((total.snapshot.avg_congestion_window_packets - (20.0 / 3.0)).abs() < 1e-9);
        assert!((total.snapshot.resend_ratio - 0.1).abs() < 1e-9);
    }

    #[test]
    fn prometheus_render_contains_shard_and_all_labels() {
        let mut registry = TelemetryRegistry::new();
        let snapshot = TransportMetricsSnapshot {
            session_count: 1,
            ingress_datagrams: 9,
            sessions_started_total: 2,
            sessions_closed_total: 1,
            packets_forwarded_total: 7,
            bytes_forwarded_total: 321,
            ack_out_total: 4,
            nack_out_total: 1,
            processing_budget_drops_total: 2,
            ..TransportMetricsSnapshot::default()
        };
        registry.ingest_snapshot(2, snapshot, 5);

        let body = registry.render_prometheus_with_prefix("raknet");
        assert!(body.contains("# HELP raknet_sessions_active Active RakNet sessions"));
        assert!(body.contains("# TYPE raknet_sessions_active gauge"));
        assert!(body.contains("raknet_sessions_active{scope=\"shard\",shard=\"2\"} 1"));
        assert!(body.contains("raknet_sessions_started_total{scope=\"all\",shard=\"all\"} 2"));
        assert!(body.contains("raknet_packets_forwarded_total{scope=\"all\",shard=\"all\"} 7"));
        assert!(body.contains("raknet_bytes_forwarded_total{scope=\"all\",shard=\"all\"} 321"));
        assert!(body.contains("raknet_ack_out_total{scope=\"all\",shard=\"all\"} 4"));
        assert!(body.contains("raknet_nack_out_total{scope=\"all\",shard=\"all\"} 1"));
        assert!(
            body.contains("raknet_processing_budget_drops_total{scope=\"all\",shard=\"all\"} 2")
        );
        assert!(body.contains("# HELP raknet_session_count Active RakNet sessions"));
        assert!(body.contains("# TYPE raknet_session_count gauge"));
        assert!(body.contains("raknet_session_count{scope=\"shard\",shard=\"2\"} 1"));
        assert!(body.contains("raknet_session_count{scope=\"all\",shard=\"all\"} 1"));
        assert!(
            body.contains(
                "raknet_dropped_non_critical_events_total{scope=\"shard\",shard=\"2\"} 5"
            )
        );
        assert!(
            body.contains(
                "raknet_dropped_non_critical_events_total{scope=\"all\",shard=\"all\"} 5"
            )
        );
    }

    #[test]
    fn record_export_marks_metric_kind_and_scope_labels() {
        let mut registry = TelemetryRegistry::new();
        let snapshot = TransportMetricsSnapshot {
            session_count: 4,
            sessions_started_total: 10,
            ..TransportMetricsSnapshot::default()
        };
        registry.ingest_snapshot(1, snapshot, 0);

        let records = registry.to_records_with_prefix("demo");
        let canonical = records
            .iter()
            .find(|record| {
                record.name == "demo_sessions_active"
                    && record
                        .labels
                        .iter()
                        .any(|(k, v)| k == "scope" && v == "shard")
                    && record.labels.iter().any(|(k, v)| k == "shard" && v == "1")
            })
            .expect("sessions_active shard record should exist");

        assert_eq!(canonical.kind, TelemetryMetricKind::Gauge);
        assert!((canonical.value - 4.0).abs() < 1e-9);

        let target = records
            .iter()
            .find(|record| {
                record.name == "demo_session_count"
                    && record
                        .labels
                        .iter()
                        .any(|(k, v)| k == "scope" && v == "shard")
                    && record.labels.iter().any(|(k, v)| k == "shard" && v == "1")
            })
            .expect("session_count shard record should exist");

        assert_eq!(target.kind, TelemetryMetricKind::Gauge);
        assert!((target.value - 4.0).abs() < 1e-9);
    }

    #[test]
    fn telemetry_exporter_uses_prefix_and_ingests_metrics_events() {
        let mut exporter = TelemetryExporter::with_prefix("demo");
        let snapshot = TransportMetricsSnapshot {
            session_count: 2,
            sessions_started_total: 5,
            ..TransportMetricsSnapshot::default()
        };
        assert!(exporter.ingest_server_event(&metrics_event(0, snapshot, 0)));
        assert_eq!(exporter.shard_count(), 1);

        let body = exporter.render_prometheus();
        assert!(body.contains("demo_sessions_active"));
        assert!(body.contains("demo_sessions_started_total"));
    }
}
