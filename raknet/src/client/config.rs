use crate::util::constants;
use rand::random;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct RakClientConfig {
    pub guid: u64,
    pub protocol: u8,
    pub min_mtu_size: u16,
    pub max_mtu_size: u16,
    pub conn_attempt_timeout: Duration,
    pub conn_attempt_interval: Duration,
    pub conn_attempt_max: usize,
}

impl Default for RakClientConfig {
    fn default() -> Self {
        Self {
            min_mtu_size: constants::MIN_MTU_SIZE,
            max_mtu_size: constants::MAX_MTU_SIZE,
            protocol: constants::PROTOCOL,
            guid: random(),
            conn_attempt_timeout: constants::CONNECTION_ATTEMPT_TIMEOUT,
            conn_attempt_interval: constants::CONNECTION_ATTEMPT_INTERVAL,
            conn_attempt_max: constants::CONNECTION_ATTEMPT_MAX,
        }
    }
}
