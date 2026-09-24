use crate::util::constants::{CC_ADDITIONAL_VARIANCE, CC_MAX_THRESHOLD};
use std::cmp::max;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug)]
pub struct RakCongestionController {
    mtu: usize,

    congestion_window: f64,
    congestion_recovery_sequence: Option<u32>,

    slow_start_threshold: f64,

    rtt_estimate_ms: f64,
    rtt_deviation_ms: f64,

    bytes_not_acknowledged: usize,

    sent_times: HashMap<u32, SystemTime>,
}

/// [`RakCongestionController`] in a serializable form.
///
/// The RTT fields are `INFINITY` until the first round trip is measured, which JSON
/// cannot represent, so they are `None` here rather than arriving back as zero.
#[derive(Clone, Debug, facet::Facet)]
pub struct RakCongestionSnapshot {
    pub mtu: usize,
    pub congestion_window: f64,
    pub congestion_recovery_sequence: Option<u32>,
    pub slow_start_threshold: f64,
    pub rtt_estimate_ms: Option<f64>,
    pub rtt_deviation_ms: Option<f64>,
    pub bytes_not_acknowledged: usize,
    pub sent_times: Vec<(u32, u64)>,
}

impl RakCongestionController {
    pub fn snapshot(&self, epoch: SystemTime) -> RakCongestionSnapshot {
        RakCongestionSnapshot {
            mtu: self.mtu,
            congestion_window: self.congestion_window,
            congestion_recovery_sequence: self.congestion_recovery_sequence,
            slow_start_threshold: self.slow_start_threshold,
            rtt_estimate_ms: finite(self.rtt_estimate_ms),
            rtt_deviation_ms: finite(self.rtt_deviation_ms),
            bytes_not_acknowledged: self.bytes_not_acknowledged,
            sent_times: self
                .sent_times
                .iter()
                .map(|(seq, at)| (*seq, millis_since(epoch, *at)))
                .collect(),
        }
    }

    pub fn restore(snapshot: RakCongestionSnapshot, epoch: SystemTime) -> Self {
        Self {
            mtu: snapshot.mtu,
            congestion_window: snapshot.congestion_window,
            congestion_recovery_sequence: snapshot.congestion_recovery_sequence,
            slow_start_threshold: snapshot.slow_start_threshold,
            rtt_estimate_ms: snapshot.rtt_estimate_ms.unwrap_or(f64::INFINITY),
            rtt_deviation_ms: snapshot.rtt_deviation_ms.unwrap_or(f64::INFINITY),
            bytes_not_acknowledged: snapshot.bytes_not_acknowledged,
            sent_times: snapshot
                .sent_times
                .into_iter()
                .map(|(seq, offset)| (seq, epoch + Duration::from_millis(offset)))
                .collect(),
        }
    }
}

fn finite(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

fn millis_since(epoch: SystemTime, at: SystemTime) -> u64 {
    at.duration_since(epoch).unwrap_or_default().as_millis() as u64
}

impl RakCongestionController {
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu,
            congestion_window: mtu as f64,
            congestion_recovery_sequence: None,

            slow_start_threshold: 0.0,

            rtt_estimate_ms: f64::INFINITY,
            rtt_deviation_ms: f64::INFINITY,

            bytes_not_acknowledged: 0,

            sent_times: HashMap::new(),
        }
    }

    pub fn transmission_bandwidth(&self) -> usize {
        let cwnd = self.congestion_window as isize;
        let used = self.bytes_not_acknowledged as isize;
        max(0, cwnd - used) as usize
    }

    pub fn retransmission_bandwidth(&self) -> usize {
        self.bytes_not_acknowledged
    }

    pub fn retransmission_timeout(&self) -> Duration {
        if self.rtt_estimate_ms.is_infinite() {
            return Duration::from_millis(CC_MAX_THRESHOLD as u64);
        }

        let threshold_ms = 2.0 * self.rtt_estimate_ms
            + 4.0 * self.rtt_deviation_ms
            + CC_ADDITIONAL_VARIANCE as f64;

        Duration::from_millis(threshold_ms.min(CC_MAX_THRESHOLD as f64) as u64)
    }

    pub fn rtt(&self) -> Duration {
        if self.rtt_estimate_ms.is_infinite() {
            Duration::from_millis(0)
        } else {
            Duration::from_millis(self.rtt_estimate_ms as u64)
        }
    }

    pub fn slow_start(&self) -> bool {
        self.congestion_window <= self.slow_start_threshold || self.slow_start_threshold == 0.0
    }

    pub fn resent(&mut self, sequence: u32) {
        if self.congestion_recovery_sequence.is_none() {
            self.slow_start_threshold = (self.congestion_window * 0.5).max(self.mtu as f64);
            self.congestion_window = self.mtu as f64;

            self.congestion_recovery_sequence = Some(sequence);
        }
    }

    pub fn nacked(&mut self) {
        if self.congestion_recovery_sequence.is_some() {
            self.slow_start_threshold = self.congestion_window * 0.75;
        }
    }

    pub fn acked(&mut self, now: SystemTime, seq: u32, size: usize, last_sequence: u32) {
        if let Some(sent_at) = self.sent_times.remove(&seq) {
            let rtt_ms = now
                .duration_since(sent_at)
                .unwrap_or_default()
                .as_secs_f64()
                * 1000.0;
            self.bytes_not_acknowledged -= size;

            if self.rtt_estimate_ms.is_infinite() {
                self.rtt_estimate_ms = rtt_ms;
                self.rtt_deviation_ms = rtt_ms;
            } else {
                let d = 0.05;
                let diff = rtt_ms - self.rtt_estimate_ms;

                self.rtt_estimate_ms += d * diff;
                self.rtt_deviation_ms += d * (diff.abs() - self.rtt_deviation_ms);
            }

            let in_recovery_period = match self.congestion_recovery_sequence {
                Some(rec_seq) => seq < rec_seq,
                None => false,
            };

            if in_recovery_period {
                self.congestion_recovery_sequence = Some(last_sequence);
            }

            if self.slow_start() {
                self.congestion_window += self.mtu as f64;

                if self.congestion_window > self.slow_start_threshold
                    && self.slow_start_threshold != 0.0
                {
                    self.congestion_window = self.slow_start_threshold
                        + (self.mtu as f64).powi(2) / self.congestion_window;
                }
            } else if in_recovery_period {
                self.congestion_window += (self.mtu as f64).powi(2) / self.congestion_window;
            }
        }
    }

    pub fn sent(&mut self, seq: u32, size: usize, now: SystemTime) {
        self.bytes_not_acknowledged += size;
        self.sent_times.insert(seq, now);
    }
}
