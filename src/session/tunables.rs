use std::time::Duration;

use crate::error::ConfigValidationError;
use crate::protocol::constants;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckNackFlushProfile {
    LowLatency,
    Balanced,
    Throughput,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckNackPriority {
    NackFirst,
    AckFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureMode {
    Delay,
    Shed,
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionProfile {
    Conservative,
    HighLatency,
    Custom,
}

#[derive(Debug, Clone, Copy)]
pub struct AckNackFlushSettings {
    pub ack_flush_interval: Duration,
    pub nack_flush_interval: Duration,
    pub ack_max_ranges_per_datagram: usize,
    pub nack_max_ranges_per_datagram: usize,
    pub ack_nack_priority: AckNackPriority,
}

#[derive(Debug, Clone, Copy)]
pub struct CongestionSettings {
    pub resend_rto: Duration,
    pub min_resend_rto: Duration,
    pub max_resend_rto: Duration,
    pub initial_congestion_window: f64,
    pub min_congestion_window: f64,
    pub max_congestion_window: f64,
    pub congestion_slow_start_threshold: f64,
    pub congestion_additive_gain: f64,
    pub congestion_multiplicative_decrease_nack: f64,
    pub congestion_multiplicative_decrease_timeout: f64,
    pub congestion_high_rtt_threshold_ms: f64,
    pub congestion_high_rtt_additive_scale: f64,
    pub congestion_nack_backoff_cooldown: Duration,
}

impl AckNackFlushProfile {
    pub fn settings(self) -> AckNackFlushSettings {
        match self {
            Self::LowLatency => AckNackFlushSettings {
                ack_flush_interval: Duration::from_millis(4),
                nack_flush_interval: Duration::from_millis(1),
                ack_max_ranges_per_datagram: 24,
                nack_max_ranges_per_datagram: 64,
                ack_nack_priority: AckNackPriority::NackFirst,
            },
            Self::Balanced => AckNackFlushSettings {
                ack_flush_interval: Duration::from_millis(10),
                nack_flush_interval: Duration::from_millis(2),
                ack_max_ranges_per_datagram: 48,
                nack_max_ranges_per_datagram: 96,
                ack_nack_priority: AckNackPriority::NackFirst,
            },
            Self::Throughput => AckNackFlushSettings {
                ack_flush_interval: Duration::from_millis(24),
                nack_flush_interval: Duration::from_millis(4),
                ack_max_ranges_per_datagram: 96,
                nack_max_ranges_per_datagram: 128,
                ack_nack_priority: AckNackPriority::NackFirst,
            },
            Self::Custom => AckNackFlushSettings {
                ack_flush_interval: Duration::from_millis(10),
                nack_flush_interval: Duration::from_millis(2),
                ack_max_ranges_per_datagram: 48,
                nack_max_ranges_per_datagram: 96,
                ack_nack_priority: AckNackPriority::NackFirst,
            },
        }
    }
}

impl CongestionProfile {
    pub fn settings(self) -> CongestionSettings {
        match self {
            Self::Conservative => CongestionSettings {
                resend_rto: Duration::from_millis(250),
                min_resend_rto: Duration::from_millis(80),
                max_resend_rto: Duration::from_millis(2_000),
                initial_congestion_window: 64.0,
                min_congestion_window: 8.0,
                max_congestion_window: 1024.0,
                congestion_slow_start_threshold: 128.0,
                congestion_additive_gain: 1.0,
                congestion_multiplicative_decrease_nack: 0.85,
                congestion_multiplicative_decrease_timeout: 0.6,
                congestion_high_rtt_threshold_ms: 180.0,
                congestion_high_rtt_additive_scale: 0.6,
                congestion_nack_backoff_cooldown: Duration::from_millis(50),
            },
            Self::HighLatency => CongestionSettings {
                resend_rto: Duration::from_millis(350),
                min_resend_rto: Duration::from_millis(120),
                max_resend_rto: Duration::from_millis(3_000),
                initial_congestion_window: 48.0,
                min_congestion_window: 8.0,
                max_congestion_window: 768.0,
                congestion_slow_start_threshold: 96.0,
                congestion_additive_gain: 0.85,
                congestion_multiplicative_decrease_nack: 0.92,
                congestion_multiplicative_decrease_timeout: 0.75,
                congestion_high_rtt_threshold_ms: 140.0,
                congestion_high_rtt_additive_scale: 0.85,
                congestion_nack_backoff_cooldown: Duration::from_millis(100),
            },
            Self::Custom => Self::Conservative.settings(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionTunables {
    pub ack_nack_flush_profile: AckNackFlushProfile,
    pub congestion_profile: CongestionProfile,
    pub ack_flush_interval: Duration,
    pub nack_flush_interval: Duration,
    pub ack_max_ranges_per_datagram: usize,
    pub nack_max_ranges_per_datagram: usize,
    pub ack_nack_priority: AckNackPriority,
    pub ack_queue_capacity: usize,
    pub backpressure_mode: BackpressureMode,
    pub reliable_window: usize,
    pub split_ttl: Duration,
    pub max_split_parts: u32,
    pub max_concurrent_splits: usize,
    pub max_ordering_channels: usize,
    pub max_ordered_pending_per_channel: usize,
    pub max_order_gap: u32,
    pub resend_rto: Duration,
    pub min_resend_rto: Duration,
    pub max_resend_rto: Duration,
    pub initial_congestion_window: f64,
    pub min_congestion_window: f64,
    pub max_congestion_window: f64,
    pub congestion_slow_start_threshold: f64,
    pub congestion_additive_gain: f64,
    pub congestion_multiplicative_decrease_nack: f64,
    pub congestion_multiplicative_decrease_timeout: f64,
    pub congestion_high_rtt_threshold_ms: f64,
    pub congestion_high_rtt_additive_scale: f64,
    pub congestion_nack_backoff_cooldown: Duration,
    pub pacing_enabled: bool,
    pub pacing_start_full: bool,
    pub pacing_gain: f64,
    pub pacing_min_rate_bytes_per_sec: f64,
    pub pacing_max_rate_bytes_per_sec: f64,
    pub pacing_max_burst_bytes: usize,
    pub outgoing_queue_max_frames: usize,
    pub outgoing_queue_max_bytes: usize,
    pub outgoing_queue_soft_ratio: f64,
    /// Best-effort zeroize for payload buffers that are dropped or abandoned
    /// before successful delivery. This may add CPU cost under heavy shedding.
    pub best_effort_zeroize_dropped_payloads: bool,
}

impl Default for SessionTunables {
    fn default() -> Self {
        let ack_nack_profile = AckNackFlushProfile::Balanced;
        let ack_nack_settings = ack_nack_profile.settings();
        let congestion_profile = CongestionProfile::Conservative;
        let congestion_settings = congestion_profile.settings();
        Self {
            ack_nack_flush_profile: ack_nack_profile,
            congestion_profile,
            ack_flush_interval: ack_nack_settings.ack_flush_interval,
            nack_flush_interval: ack_nack_settings.nack_flush_interval,
            ack_max_ranges_per_datagram: ack_nack_settings.ack_max_ranges_per_datagram,
            nack_max_ranges_per_datagram: ack_nack_settings.nack_max_ranges_per_datagram,
            ack_nack_priority: ack_nack_settings.ack_nack_priority,
            ack_queue_capacity: 1024,
            backpressure_mode: BackpressureMode::Shed,
            reliable_window: constants::MAX_ACK_SEQUENCES as usize,
            split_ttl: Duration::from_millis(constants::SPLIT_REASSEMBLY_TTL_MS),
            max_split_parts: constants::MAX_SPLIT_PARTS,
            max_concurrent_splits: constants::MAX_INFLIGHT_SPLIT_COMPOUNDS_PER_PEER,
            max_ordering_channels: 16,
            max_ordered_pending_per_channel: 2048,
            max_order_gap: constants::MAX_ACK_SEQUENCES as u32,
            resend_rto: congestion_settings.resend_rto,
            min_resend_rto: congestion_settings.min_resend_rto,
            max_resend_rto: congestion_settings.max_resend_rto,
            initial_congestion_window: congestion_settings.initial_congestion_window,
            min_congestion_window: congestion_settings.min_congestion_window,
            max_congestion_window: congestion_settings.max_congestion_window,
            congestion_slow_start_threshold: congestion_settings.congestion_slow_start_threshold,
            congestion_additive_gain: congestion_settings.congestion_additive_gain,
            congestion_multiplicative_decrease_nack: congestion_settings
                .congestion_multiplicative_decrease_nack,
            congestion_multiplicative_decrease_timeout: congestion_settings
                .congestion_multiplicative_decrease_timeout,
            congestion_high_rtt_threshold_ms: congestion_settings.congestion_high_rtt_threshold_ms,
            congestion_high_rtt_additive_scale: congestion_settings
                .congestion_high_rtt_additive_scale,
            congestion_nack_backoff_cooldown: congestion_settings.congestion_nack_backoff_cooldown,
            pacing_enabled: true,
            pacing_start_full: true,
            pacing_gain: 1.0,
            pacing_min_rate_bytes_per_sec: 24.0 * 1024.0,
            pacing_max_rate_bytes_per_sec: 32.0 * 1024.0 * 1024.0,
            pacing_max_burst_bytes: 128 * 1024,
            outgoing_queue_max_frames: 8192,
            outgoing_queue_max_bytes: 8 * 1024 * 1024,
            outgoing_queue_soft_ratio: 0.85,
            best_effort_zeroize_dropped_payloads: false,
        }
    }
}

impl SessionTunables {
    pub fn resolved_ack_nack_flush_settings(&self) -> AckNackFlushSettings {
        match self.ack_nack_flush_profile {
            AckNackFlushProfile::LowLatency
            | AckNackFlushProfile::Balanced
            | AckNackFlushProfile::Throughput => self.ack_nack_flush_profile.settings(),
            AckNackFlushProfile::Custom => AckNackFlushSettings {
                ack_flush_interval: self.ack_flush_interval,
                nack_flush_interval: self.nack_flush_interval,
                ack_max_ranges_per_datagram: self.ack_max_ranges_per_datagram,
                nack_max_ranges_per_datagram: self.nack_max_ranges_per_datagram,
                ack_nack_priority: self.ack_nack_priority,
            },
        }
    }

    pub fn resolved_congestion_settings(&self) -> CongestionSettings {
        match self.congestion_profile {
            CongestionProfile::Conservative | CongestionProfile::HighLatency => {
                self.congestion_profile.settings()
            }
            CongestionProfile::Custom => CongestionSettings {
                resend_rto: self.resend_rto,
                min_resend_rto: self.min_resend_rto,
                max_resend_rto: self.max_resend_rto,
                initial_congestion_window: self.initial_congestion_window,
                min_congestion_window: self.min_congestion_window,
                max_congestion_window: self.max_congestion_window,
                congestion_slow_start_threshold: self.congestion_slow_start_threshold,
                congestion_additive_gain: self.congestion_additive_gain,
                congestion_multiplicative_decrease_nack: self
                    .congestion_multiplicative_decrease_nack,
                congestion_multiplicative_decrease_timeout: self
                    .congestion_multiplicative_decrease_timeout,
                congestion_high_rtt_threshold_ms: self.congestion_high_rtt_threshold_ms,
                congestion_high_rtt_additive_scale: self.congestion_high_rtt_additive_scale,
                congestion_nack_backoff_cooldown: self.congestion_nack_backoff_cooldown,
            },
        }
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        let ack_nack = self.resolved_ack_nack_flush_settings();
        let congestion = self.resolved_congestion_settings();
        if ack_nack.ack_flush_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "ack_flush_interval",
                "must be > 0",
            ));
        }
        if ack_nack.nack_flush_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "nack_flush_interval",
                "must be > 0",
            ));
        }
        if ack_nack.ack_max_ranges_per_datagram == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "ack_max_ranges_per_datagram",
                "must be >= 1",
            ));
        }
        if ack_nack.nack_max_ranges_per_datagram == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "nack_max_ranges_per_datagram",
                "must be >= 1",
            ));
        }

        if self.ack_queue_capacity == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "ack_queue_capacity",
                "must be >= 1",
            ));
        }
        if self.reliable_window == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "reliable_window",
                "must be >= 1",
            ));
        }
        if self.split_ttl.is_zero() {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "split_ttl",
                "must be > 0",
            ));
        }
        if self.max_split_parts == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "max_split_parts",
                "must be >= 1",
            ));
        }
        if self.max_concurrent_splits == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "max_concurrent_splits",
                "must be >= 1",
            ));
        }
        if self.max_ordering_channels == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "max_ordering_channels",
                "must be >= 1",
            ));
        }
        if self.max_ordered_pending_per_channel == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "max_ordered_pending_per_channel",
                "must be >= 1",
            ));
        }
        if self.max_order_gap == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "max_order_gap",
                "must be >= 1",
            ));
        }
        if congestion.min_resend_rto.is_zero() {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "min_resend_rto",
                "must be > 0",
            ));
        }
        if congestion.max_resend_rto.is_zero() {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "max_resend_rto",
                "must be > 0",
            ));
        }
        if congestion.min_resend_rto > congestion.max_resend_rto {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "min_resend_rto",
                "must be <= max_resend_rto",
            ));
        }
        if congestion.resend_rto < congestion.min_resend_rto
            || congestion.resend_rto > congestion.max_resend_rto
        {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "resend_rto",
                "must be within [min_resend_rto, max_resend_rto]",
            ));
        }

        validate_positive_f64(
            congestion.initial_congestion_window,
            "initial_congestion_window",
        )?;
        validate_positive_f64(congestion.min_congestion_window, "min_congestion_window")?;
        validate_positive_f64(congestion.max_congestion_window, "max_congestion_window")?;
        if congestion.min_congestion_window > congestion.max_congestion_window {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "min_congestion_window",
                "must be <= max_congestion_window",
            ));
        }
        if congestion.initial_congestion_window < congestion.min_congestion_window
            || congestion.initial_congestion_window > congestion.max_congestion_window
        {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "initial_congestion_window",
                "must be within [min_congestion_window, max_congestion_window]",
            ));
        }
        if congestion.congestion_slow_start_threshold < congestion.min_congestion_window
            || congestion.congestion_slow_start_threshold > congestion.max_congestion_window
        {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "congestion_slow_start_threshold",
                "must be within [min_congestion_window, max_congestion_window]",
            ));
        }
        validate_positive_f64(
            congestion.congestion_additive_gain,
            "congestion_additive_gain",
        )?;
        validate_fraction(
            congestion.congestion_multiplicative_decrease_nack,
            "congestion_multiplicative_decrease_nack",
        )?;
        validate_fraction(
            congestion.congestion_multiplicative_decrease_timeout,
            "congestion_multiplicative_decrease_timeout",
        )?;
        validate_positive_f64(
            congestion.congestion_high_rtt_threshold_ms,
            "congestion_high_rtt_threshold_ms",
        )?;
        if !congestion.congestion_high_rtt_additive_scale.is_finite()
            || congestion.congestion_high_rtt_additive_scale <= 0.0
            || congestion.congestion_high_rtt_additive_scale > 1.0
        {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "congestion_high_rtt_additive_scale",
                "must be finite and within (0, 1]",
            ));
        }
        if congestion.congestion_nack_backoff_cooldown.is_zero() {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "congestion_nack_backoff_cooldown",
                "must be > 0",
            ));
        }

        validate_positive_f64(self.pacing_gain, "pacing_gain")?;
        validate_positive_f64(
            self.pacing_min_rate_bytes_per_sec,
            "pacing_min_rate_bytes_per_sec",
        )?;
        validate_positive_f64(
            self.pacing_max_rate_bytes_per_sec,
            "pacing_max_rate_bytes_per_sec",
        )?;
        if self.pacing_min_rate_bytes_per_sec > self.pacing_max_rate_bytes_per_sec {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "pacing_min_rate_bytes_per_sec",
                "must be <= pacing_max_rate_bytes_per_sec",
            ));
        }
        if self.pacing_max_burst_bytes == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "pacing_max_burst_bytes",
                "must be >= 1",
            ));
        }
        if self.outgoing_queue_max_frames == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "outgoing_queue_max_frames",
                "must be >= 1",
            ));
        }
        if self.outgoing_queue_max_bytes == 0 {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "outgoing_queue_max_bytes",
                "must be >= 1",
            ));
        }
        if !self.outgoing_queue_soft_ratio.is_finite()
            || self.outgoing_queue_soft_ratio <= 0.0
            || self.outgoing_queue_soft_ratio >= 1.0
        {
            return Err(ConfigValidationError::new(
                "SessionTunables",
                "outgoing_queue_soft_ratio",
                "must be finite and within (0, 1)",
            ));
        }

        Ok(())
    }
}

fn validate_positive_f64(value: f64, field: &'static str) -> Result<(), ConfigValidationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(ConfigValidationError::new(
            "SessionTunables",
            field,
            "must be finite and > 0",
        ));
    }
    Ok(())
}

fn validate_fraction(value: f64, field: &'static str) -> Result<(), ConfigValidationError> {
    if !value.is_finite() || value <= 0.0 || value >= 1.0 {
        return Err(ConfigValidationError::new(
            "SessionTunables",
            field,
            "must be finite and within (0, 1)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{AckNackFlushProfile, AckNackPriority, CongestionProfile, SessionTunables};

    #[test]
    fn validate_accepts_default_values() {
        SessionTunables::default()
            .validate()
            .expect("default tunables must be valid");
    }

    #[test]
    fn validate_rejects_zero_ack_queue_capacity() {
        let tunables = SessionTunables {
            ack_queue_capacity: 0,
            ..SessionTunables::default()
        };
        let err = tunables
            .validate()
            .expect_err("ack_queue_capacity=0 must be rejected");
        assert_eq!(err.config, "SessionTunables");
        assert_eq!(err.field, "ack_queue_capacity");
    }

    #[test]
    fn validate_rejects_zero_custom_ack_flush_interval() {
        let tunables = SessionTunables {
            ack_nack_flush_profile: AckNackFlushProfile::Custom,
            ack_flush_interval: Duration::ZERO,
            ..SessionTunables::default()
        };
        let err = tunables
            .validate()
            .expect_err("ack_flush_interval=0 must be rejected for custom policy");
        assert_eq!(err.config, "SessionTunables");
        assert_eq!(err.field, "ack_flush_interval");
    }

    #[test]
    fn profile_resolution_uses_profile_defaults_when_not_custom() {
        let tunables = SessionTunables {
            ack_nack_flush_profile: AckNackFlushProfile::LowLatency,
            ack_flush_interval: Duration::from_secs(99),
            nack_flush_interval: Duration::from_secs(99),
            ack_max_ranges_per_datagram: 1,
            nack_max_ranges_per_datagram: 1,
            ack_nack_priority: AckNackPriority::AckFirst,
            ..SessionTunables::default()
        };

        let resolved = tunables.resolved_ack_nack_flush_settings();
        assert_eq!(resolved.ack_flush_interval, Duration::from_millis(4));
        assert_eq!(resolved.nack_flush_interval, Duration::from_millis(1));
        assert_eq!(resolved.ack_max_ranges_per_datagram, 24);
        assert_eq!(resolved.nack_max_ranges_per_datagram, 64);
        assert_eq!(resolved.ack_nack_priority, AckNackPriority::NackFirst);
    }

    #[test]
    fn congestion_profile_resolution_uses_profile_defaults_when_not_custom() {
        let tunables = SessionTunables {
            congestion_profile: CongestionProfile::HighLatency,
            resend_rto: Duration::from_millis(10),
            min_resend_rto: Duration::from_millis(5),
            max_resend_rto: Duration::from_millis(20),
            initial_congestion_window: 1.0,
            min_congestion_window: 1.0,
            max_congestion_window: 2.0,
            congestion_slow_start_threshold: 1.0,
            congestion_additive_gain: 9.0,
            congestion_multiplicative_decrease_nack: 0.2,
            congestion_multiplicative_decrease_timeout: 0.2,
            congestion_high_rtt_threshold_ms: 9.0,
            congestion_high_rtt_additive_scale: 0.2,
            congestion_nack_backoff_cooldown: Duration::from_millis(1),
            ..SessionTunables::default()
        };

        let resolved = tunables.resolved_congestion_settings();
        assert_eq!(resolved.resend_rto, Duration::from_millis(350));
        assert_eq!(resolved.min_resend_rto, Duration::from_millis(120));
        assert_eq!(resolved.max_resend_rto, Duration::from_millis(3_000));
        assert!((resolved.congestion_multiplicative_decrease_nack - 0.92).abs() < f64::EPSILON);
        assert!((resolved.congestion_multiplicative_decrease_timeout - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_ignores_manual_congestion_fields_when_profile_is_not_custom() {
        let tunables = SessionTunables {
            congestion_profile: CongestionProfile::Conservative,
            min_resend_rto: Duration::from_millis(500),
            max_resend_rto: Duration::from_millis(100),
            ..SessionTunables::default()
        };

        tunables
            .validate()
            .expect("manual congestion fields must be ignored for non-custom congestion profile");
    }

    #[test]
    fn validate_rejects_invalid_custom_congestion_ranges() {
        let tunables = SessionTunables {
            congestion_profile: CongestionProfile::Custom,
            min_resend_rto: Duration::from_millis(500),
            max_resend_rto: Duration::from_millis(100),
            ..SessionTunables::default()
        };
        let err = tunables
            .validate()
            .expect_err("custom congestion profile must reject invalid ranges");
        assert_eq!(err.config, "SessionTunables");
        assert_eq!(err.field, "min_resend_rto");
    }
}
