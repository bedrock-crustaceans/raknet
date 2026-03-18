use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::error::ConfigValidationError;
use crate::protocol::constants::{
    DEFAULT_UNCONNECTED_MAGIC, MAXIMUM_MTU_SIZE, Magic, RAKNET_PROTOCOL_VERSION,
};
use crate::protocol::packet::MAX_UNCONNECTED_PONG_MOTD_BYTES;
use crate::session::tunables::SessionTunables;

#[derive(Debug, Clone, Copy)]
pub struct HandshakeHeuristicsConfig {
    pub enabled: bool,
    pub event_window: Duration,
    pub block_duration: Duration,
    pub score_threshold: u32,
    pub req1_req2_timeout_score: u32,
    pub reply2_connect_timeout_score: u32,
    pub missing_req1_score: u32,
    pub cookie_mismatch_score: u32,
    pub parse_anomaly_score: u32,
}

impl Default for HandshakeHeuristicsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            event_window: Duration::from_secs(30),
            block_duration: Duration::from_secs(30),
            score_threshold: 16,
            req1_req2_timeout_score: 4,
            reply2_connect_timeout_score: 4,
            missing_req1_score: 3,
            cookie_mismatch_score: 6,
            parse_anomaly_score: 2,
        }
    }
}

impl HandshakeHeuristicsConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.enabled {
            return Ok(());
        }
        if self.event_window.is_zero() {
            return Err(ConfigValidationError::new(
                "HandshakeHeuristicsConfig",
                "event_window",
                "must be > 0 when enabled",
            ));
        }
        if self.block_duration.is_zero() {
            return Err(ConfigValidationError::new(
                "HandshakeHeuristicsConfig",
                "block_duration",
                "must be > 0 when enabled",
            ));
        }
        if self.score_threshold == 0 {
            return Err(ConfigValidationError::new(
                "HandshakeHeuristicsConfig",
                "score_threshold",
                "must be >= 1 when enabled",
            ));
        }
        let score_sum = self
            .req1_req2_timeout_score
            .saturating_add(self.reply2_connect_timeout_score)
            .saturating_add(self.missing_req1_score)
            .saturating_add(self.cookie_mismatch_score)
            .saturating_add(self.parse_anomaly_score);
        if score_sum == 0 {
            return Err(ConfigValidationError::new(
                "HandshakeHeuristicsConfig",
                "req1_req2_timeout_score",
                "at least one heuristic score must be > 0 when enabled",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CookieMismatchGuardConfig {
    pub enabled: bool,
    pub event_window: Duration,
    pub mismatch_threshold: u32,
    pub block_duration: Duration,
}

impl Default for CookieMismatchGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            event_window: Duration::from_secs(20),
            mismatch_threshold: 3,
            block_duration: Duration::from_secs(30),
        }
    }
}

impl CookieMismatchGuardConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.enabled {
            return Ok(());
        }
        if self.event_window.is_zero() {
            return Err(ConfigValidationError::new(
                "CookieMismatchGuardConfig",
                "event_window",
                "must be > 0 when enabled",
            ));
        }
        if self.mismatch_threshold == 0 {
            return Err(ConfigValidationError::new(
                "CookieMismatchGuardConfig",
                "mismatch_threshold",
                "must be >= 1 when enabled",
            ));
        }
        if self.block_duration.is_zero() {
            return Err(ConfigValidationError::new(
                "CookieMismatchGuardConfig",
                "block_duration",
                "must be > 0 when enabled",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessingBudgetConfig {
    pub enabled: bool,
    pub per_ip_refill_units_per_sec: u32,
    pub per_ip_burst_units: u32,
    pub global_refill_units_per_sec: u32,
    pub global_burst_units: u32,
    pub bucket_idle_ttl: Duration,
}

impl Default for ProcessingBudgetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_refill_units_per_sec: 3_000_000,
            per_ip_burst_units: 1_500_000,
            global_refill_units_per_sec: 128_000_000,
            global_burst_units: 32_000_000,
            bucket_idle_ttl: Duration::from_secs(30),
        }
    }
}

impl ProcessingBudgetConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.enabled {
            return Ok(());
        }

        if self.per_ip_refill_units_per_sec == 0 {
            return Err(ConfigValidationError::new(
                "ProcessingBudgetConfig",
                "per_ip_refill_units_per_sec",
                "must be >= 1 when enabled",
            ));
        }
        if self.per_ip_burst_units == 0 {
            return Err(ConfigValidationError::new(
                "ProcessingBudgetConfig",
                "per_ip_burst_units",
                "must be >= 1 when enabled",
            ));
        }
        if self.global_refill_units_per_sec == 0 {
            return Err(ConfigValidationError::new(
                "ProcessingBudgetConfig",
                "global_refill_units_per_sec",
                "must be >= 1 when enabled",
            ));
        }
        if self.global_burst_units == 0 {
            return Err(ConfigValidationError::new(
                "ProcessingBudgetConfig",
                "global_burst_units",
                "must be >= 1 when enabled",
            ));
        }
        if self.bucket_idle_ttl.is_zero() {
            return Err(ConfigValidationError::new(
                "ProcessingBudgetConfig",
                "bucket_idle_ttl",
                "must be > 0 when enabled",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransportSocketTuning {
    pub recv_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
    pub ipv4_ttl: Option<u32>,
    pub ipv4_tos: Option<u32>,
    pub ipv6_unicast_hops: Option<u32>,
    pub disable_ip_fragmentation: bool,
}

impl TransportSocketTuning {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.recv_buffer_size.is_some_and(|size| size == 0) {
            return Err(ConfigValidationError::new(
                "TransportSocketTuning",
                "recv_buffer_size",
                "must be >= 1 when set",
            ));
        }
        if self.send_buffer_size.is_some_and(|size| size == 0) {
            return Err(ConfigValidationError::new(
                "TransportSocketTuning",
                "send_buffer_size",
                "must be >= 1 when set",
            ));
        }
        if self.ipv4_ttl.is_some_and(|ttl| ttl == 0 || ttl > 255) {
            return Err(ConfigValidationError::new(
                "TransportSocketTuning",
                "ipv4_ttl",
                "must be within [1, 255] when set",
            ));
        }
        if self.ipv4_tos.is_some_and(|tos| tos > 255) {
            return Err(ConfigValidationError::new(
                "TransportSocketTuning",
                "ipv4_tos",
                "must be within [0, 255] when set",
            ));
        }
        if self
            .ipv6_unicast_hops
            .is_some_and(|hops| hops == 0 || hops > 255)
        {
            return Err(ConfigValidationError::new(
                "TransportSocketTuning",
                "ipv6_unicast_hops",
                "must be within [1, 255] when set",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Request2ServerAddrPolicy {
    Disabled,
    #[default]
    PortOnly,
    Exact,
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub bind_addr: SocketAddr,
    pub mtu: usize,
    pub reuse_port: bool,
    pub split_ipv4_ipv6_bind: bool,
    pub ipv6_only: bool,
    pub socket_tuning: TransportSocketTuning,
    pub unconnected_magic: Magic,
    pub server_guid: u64,
    pub advertisement: String,
    pub send_cookie: bool,
    /// Legacy unified handshake timeout fallback for compatibility.
    pub handshake_timeout: Duration,
    /// Stage-1 timeout: OpenConnectionRequest1 -> OpenConnectionRequest2.
    pub handshake_req1_req2_timeout: Duration,
    /// Stage-2 timeout: OpenConnectionReply2 -> connected control completion.
    pub handshake_reply2_connect_timeout: Duration,
    pub ip_recently_connected_window: Duration,
    pub request2_server_addr_policy: Request2ServerAddrPolicy,
    pub cookie_rotation_interval: Duration,
    pub cookie_mismatch_guard: CookieMismatchGuardConfig,
    pub allow_legacy_request2_fallback: bool,
    pub reject_ambiguous_request2: bool,
    pub per_ip_packet_limit: usize,
    pub global_packet_limit: usize,
    pub rate_window: Duration,
    pub block_duration: Duration,
    pub processing_budget: ProcessingBudgetConfig,
    pub max_sessions: usize,
    pub session_idle_timeout: Duration,
    pub session_keepalive_interval: Duration,
    pub unhandled_queue_max_frames: usize,
    pub unhandled_queue_max_bytes: usize,
    pub handshake_heuristics: HandshakeHeuristicsConfig,
    pub session_tunables: SessionTunables,
    pub rate_limit_exceptions: Vec<IpAddr>,
    pub supported_protocols: Vec<u8>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 19132)),
            mtu: MAXIMUM_MTU_SIZE as usize,
            reuse_port: true,
            split_ipv4_ipv6_bind: false,
            ipv6_only: true,
            socket_tuning: TransportSocketTuning::default(),
            unconnected_magic: DEFAULT_UNCONNECTED_MAGIC,
            server_guid: 0xC0DE_CAFE_1234_5678,
            advertisement: "MCBE Rust Engine".to_string(),
            send_cookie: true,
            handshake_timeout: Duration::from_secs(10),
            handshake_req1_req2_timeout: Duration::from_secs(10),
            handshake_reply2_connect_timeout: Duration::from_secs(10),
            ip_recently_connected_window: Duration::ZERO,
            request2_server_addr_policy: Request2ServerAddrPolicy::PortOnly,
            cookie_rotation_interval: Duration::from_secs(120),
            cookie_mismatch_guard: CookieMismatchGuardConfig::default(),
            allow_legacy_request2_fallback: true,
            reject_ambiguous_request2: false,
            per_ip_packet_limit: 120,
            global_packet_limit: 100_000,
            rate_window: Duration::from_millis(10),
            block_duration: Duration::from_secs(10),
            processing_budget: ProcessingBudgetConfig::default(),
            max_sessions: 20_000,
            session_idle_timeout: Duration::from_secs(30),
            session_keepalive_interval: Duration::from_secs(10),
            unhandled_queue_max_frames: 512,
            unhandled_queue_max_bytes: 512 * 1024,
            handshake_heuristics: HandshakeHeuristicsConfig::default(),
            session_tunables: SessionTunables::default(),
            rate_limit_exceptions: Vec::new(),
            supported_protocols: vec![RAKNET_PROTOCOL_VERSION],
        }
    }
}

impl TransportConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.mtu < crate::protocol::constants::MINIMUM_MTU_SIZE as usize
            || self.mtu > MAXIMUM_MTU_SIZE as usize
        {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "mtu",
                format!(
                    "must be within [{}, {}], got {}",
                    crate::protocol::constants::MINIMUM_MTU_SIZE,
                    MAXIMUM_MTU_SIZE,
                    self.mtu
                ),
            ));
        }
        if self.handshake_req1_req2_timeout().is_zero() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "handshake_req1_req2_timeout",
                "must be > 0",
            ));
        }
        if self.handshake_reply2_connect_timeout().is_zero() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "handshake_reply2_connect_timeout",
                "must be > 0",
            ));
        }
        if self.split_ipv4_ipv6_bind && !self.bind_addr.ip().is_unspecified() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "split_ipv4_ipv6_bind",
                "requires bind_addr IP to be unspecified (0.0.0.0 or ::)",
            ));
        }
        if self.split_ipv4_ipv6_bind && !self.ipv6_only {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "ipv6_only",
                "must be true when split_ipv4_ipv6_bind is enabled",
            ));
        }
        if self.rate_window.is_zero() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "rate_window",
                "must be > 0",
            ));
        }
        if self.block_duration.is_zero() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "block_duration",
                "must be > 0",
            ));
        }
        self.processing_budget.validate()?;
        if self.max_sessions == 0 {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "max_sessions",
                "must be >= 1",
            ));
        }
        if self.session_idle_timeout.is_zero() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "session_idle_timeout",
                "must be > 0",
            ));
        }
        if self.session_keepalive_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "session_keepalive_interval",
                "must be > 0",
            ));
        }
        if self.per_ip_packet_limit == 0 {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "per_ip_packet_limit",
                "must be >= 1",
            ));
        }
        if self.global_packet_limit == 0 {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "global_packet_limit",
                "must be >= 1",
            ));
        }
        if self.unhandled_queue_max_frames == 0 {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "unhandled_queue_max_frames",
                "must be >= 1",
            ));
        }
        if self.unhandled_queue_max_bytes < self.mtu {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "unhandled_queue_max_bytes",
                format!(
                    "must be >= mtu ({}), got {}",
                    self.mtu, self.unhandled_queue_max_bytes
                ),
            ));
        }
        if self.supported_protocols.is_empty() {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "supported_protocols",
                "must not be empty",
            ));
        }
        if self.advertisement.len() > MAX_UNCONNECTED_PONG_MOTD_BYTES {
            return Err(ConfigValidationError::new(
                "TransportConfig",
                "advertisement",
                format!(
                    "must be <= {} bytes, got {}",
                    MAX_UNCONNECTED_PONG_MOTD_BYTES,
                    self.advertisement.len()
                ),
            ));
        }
        self.socket_tuning.validate()?;
        self.handshake_heuristics.validate()?;
        self.cookie_mismatch_guard.validate()?;
        self.session_tunables.validate()?;
        Ok(())
    }

    pub fn handshake_req1_req2_timeout(&self) -> Duration {
        if self.handshake_req1_req2_timeout.is_zero() {
            self.handshake_timeout
        } else {
            self.handshake_req1_req2_timeout
        }
    }

    pub fn handshake_reply2_connect_timeout(&self) -> Duration {
        if self.handshake_reply2_connect_timeout.is_zero() {
            self.handshake_timeout
        } else {
            self.handshake_reply2_connect_timeout
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CookieMismatchGuardConfig, HandshakeHeuristicsConfig, ProcessingBudgetConfig,
        Request2ServerAddrPolicy, TransportConfig, TransportSocketTuning,
    };
    use crate::protocol::constants::DEFAULT_UNCONNECTED_MAGIC;
    use crate::protocol::packet::MAX_UNCONNECTED_PONG_MOTD_BYTES;
    use crate::session::tunables::SessionTunables;
    use std::time::Duration;

    #[test]
    fn transport_config_validate_rejects_invalid_mtu() {
        let cfg = TransportConfig {
            mtu: 1,
            ..TransportConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("Mtu below minimum must be rejected");
        assert_eq!(err.config, "TransportConfig");
        assert_eq!(err.field, "mtu");
    }

    #[test]
    fn transport_config_validate_rejects_empty_protocol_list() {
        let cfg = TransportConfig {
            supported_protocols: Vec::new(),
            ..TransportConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("'supported_protocols' must not be empty");
        assert_eq!(err.config, "TransportConfig");
        assert_eq!(err.field, "supported_protocols");
    }

    #[test]
    fn handshake_heuristics_validate_rejects_enabled_zero_threshold() {
        let heuristics = HandshakeHeuristicsConfig {
            enabled: true,
            score_threshold: 0,
            ..HandshakeHeuristicsConfig::default()
        };
        let err = heuristics
            .validate()
            .expect_err("'score_threshold=0' must be rejected when enabled");
        assert_eq!(err.config, "HandshakeHeuristicsConfig");
        assert_eq!(err.field, "score_threshold");
    }

    #[test]
    fn handshake_heuristics_disabled_allows_zero_windows() {
        let heuristics = HandshakeHeuristicsConfig {
            enabled: false,
            event_window: Duration::ZERO,
            block_duration: Duration::ZERO,
            score_threshold: 0,
            ..HandshakeHeuristicsConfig::default()
        };
        heuristics
            .validate()
            .expect("disabled heuristics should allow zero fields");
    }

    #[test]
    fn cookie_mismatch_guard_validate_rejects_zero_threshold_when_enabled() {
        let guard = CookieMismatchGuardConfig {
            enabled: true,
            mismatch_threshold: 0,
            ..CookieMismatchGuardConfig::default()
        };
        let err = guard
            .validate()
            .expect_err("mismatch_threshold=0 must be rejected when enabled");
        assert_eq!(err.config, "CookieMismatchGuardConfig");
        assert_eq!(err.field, "mismatch_threshold");
    }

    #[test]
    fn cookie_mismatch_guard_disabled_allows_zero_values() {
        let guard = CookieMismatchGuardConfig {
            enabled: false,
            event_window: Duration::ZERO,
            mismatch_threshold: 0,
            block_duration: Duration::ZERO,
        };
        guard
            .validate()
            .expect("disabled cookie mismatch guard should allow zero fields");
    }

    #[test]
    fn processing_budget_validate_rejects_zero_fields_when_enabled() {
        let cfg = ProcessingBudgetConfig {
            enabled: true,
            per_ip_refill_units_per_sec: 0,
            ..ProcessingBudgetConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("per_ip_refill_units_per_sec=0 must be rejected");
        assert_eq!(err.config, "ProcessingBudgetConfig");
        assert_eq!(err.field, "per_ip_refill_units_per_sec");
    }

    #[test]
    fn processing_budget_disabled_allows_zero_fields() {
        let cfg = ProcessingBudgetConfig {
            enabled: false,
            per_ip_refill_units_per_sec: 0,
            per_ip_burst_units: 0,
            global_refill_units_per_sec: 0,
            global_burst_units: 0,
            bucket_idle_ttl: Duration::ZERO,
        };
        cfg.validate()
            .expect("disabled processing budget should allow zero fields");
    }

    #[test]
    fn transport_config_validate_rejects_invalid_session_tunables() {
        let cfg = TransportConfig {
            session_tunables: SessionTunables {
                ack_queue_capacity: 0,
                ..SessionTunables::default()
            },
            ..TransportConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("invalid session tunables must be rejected");
        assert_eq!(err.config, "SessionTunables");
        assert_eq!(err.field, "ack_queue_capacity");
    }

    #[test]
    fn transport_config_validate_rejects_oversized_advertisement() {
        let cfg = TransportConfig {
            advertisement: "a".repeat(MAX_UNCONNECTED_PONG_MOTD_BYTES + 1),
            ..TransportConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("oversized advertisement must be rejected");
        assert_eq!(err.config, "TransportConfig");
        assert_eq!(err.field, "advertisement");
    }

    #[test]
    fn transport_config_default_uses_standard_unconnected_magic() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.unconnected_magic, DEFAULT_UNCONNECTED_MAGIC);
    }

    #[test]
    fn transport_config_validate_accepts_custom_unconnected_magic() {
        let cfg = TransportConfig {
            unconnected_magic: [
                0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xF0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                0xDC, 0xFE,
            ],
            ..TransportConfig::default()
        };
        cfg.validate()
            .expect("custom unconnected magic should be allowed");
    }

    #[test]
    fn transport_socket_tuning_validate_rejects_invalid_ranges() {
        let tuning = TransportSocketTuning {
            recv_buffer_size: Some(0),
            ..TransportSocketTuning::default()
        };
        let err = tuning
            .validate()
            .expect_err("recv buffer size=0 must be rejected");
        assert_eq!(err.config, "TransportSocketTuning");
        assert_eq!(err.field, "recv_buffer_size");

        let tuning = TransportSocketTuning {
            ipv4_ttl: Some(0),
            ..TransportSocketTuning::default()
        };
        let err = tuning.validate().expect_err("ttl=0 must be rejected");
        assert_eq!(err.config, "TransportSocketTuning");
        assert_eq!(err.field, "ipv4_ttl");

        let tuning = TransportSocketTuning {
            ipv4_tos: Some(256),
            ..TransportSocketTuning::default()
        };
        let err = tuning.validate().expect_err("tos > 255 must be rejected");
        assert_eq!(err.config, "TransportSocketTuning");
        assert_eq!(err.field, "ipv4_tos");
    }

    #[test]
    fn transport_config_validate_accepts_socket_tuning() {
        let cfg = TransportConfig {
            socket_tuning: TransportSocketTuning {
                recv_buffer_size: Some(512 * 1024),
                send_buffer_size: Some(512 * 1024),
                ipv4_ttl: Some(64),
                ipv4_tos: Some(0x10),
                ipv6_unicast_hops: Some(64),
                disable_ip_fragmentation: false,
            },
            ..TransportConfig::default()
        };
        cfg.validate()
            .expect("valid socket tuning should be accepted");
    }

    #[test]
    fn transport_config_default_disables_ip_recently_connected_window() {
        let cfg = TransportConfig::default();
        assert!(cfg.ip_recently_connected_window.is_zero());
    }

    #[test]
    fn transport_config_default_uses_request2_port_only_policy() {
        let cfg = TransportConfig::default();
        assert_eq!(
            cfg.request2_server_addr_policy,
            Request2ServerAddrPolicy::PortOnly
        );
    }

    #[test]
    fn transport_config_default_uses_single_bind_and_ipv6_only() {
        let cfg = TransportConfig::default();
        assert!(!cfg.split_ipv4_ipv6_bind);
        assert!(cfg.ipv6_only);
    }

    #[test]
    fn transport_config_validate_rejects_split_bind_on_specific_ip() {
        let cfg = TransportConfig {
            bind_addr: "127.0.0.1:19132".parse().expect("valid bind addr"),
            split_ipv4_ipv6_bind: true,
            ..TransportConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("split bind with specific IP must be rejected");
        assert_eq!(err.config, "TransportConfig");
        assert_eq!(err.field, "split_ipv4_ipv6_bind");
    }

    #[test]
    fn transport_config_validate_rejects_split_bind_without_ipv6_only() {
        let cfg = TransportConfig {
            split_ipv4_ipv6_bind: true,
            ipv6_only: false,
            ..TransportConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("split bind requires ipv6_only=true");
        assert_eq!(err.config, "TransportConfig");
        assert_eq!(err.field, "ipv6_only");
    }
}
