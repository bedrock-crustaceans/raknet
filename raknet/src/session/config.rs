use crate::util::constants::{
    AUTOFLUSH, AUTOFLUSH_INTERVAL_MS, CLOSE_TIMEOUT, MAX_ORDERING_CHANNELS, MAX_QUEUED_BYTES,
    RELIABLE_WINDOW,
};
use std::time::Duration;

#[derive(Clone, Debug, facet::Facet)]
pub struct RakSessionConfig {
    pub ordering_channels: i32,
    pub autoflush: bool,
    pub autoflush_interval_ms: Duration,
    pub max_queued_bytes: i32,
    pub max_outbound_bytes: i32,
    pub reliable_window: i32,
    pub close_timeout: Duration,
}

impl Default for RakSessionConfig {
    fn default() -> Self {
        Self {
            ordering_channels: MAX_ORDERING_CHANNELS,
            autoflush: AUTOFLUSH,
            autoflush_interval_ms: Duration::from_millis(AUTOFLUSH_INTERVAL_MS as u64),
            max_queued_bytes: MAX_QUEUED_BYTES,
            max_outbound_bytes: MAX_QUEUED_BYTES,
            reliable_window: RELIABLE_WINDOW,
            close_timeout: CLOSE_TIMEOUT,
        }
    }
}
