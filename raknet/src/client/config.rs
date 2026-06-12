use crate::util::constants;
use rand::random;
use std::time::Duration;

pub struct RakClientConfig {
    pub guid: u64,
    pub protocol: u8,
    pub mtu_sizes: Box<[u16]>,
    pub conn_attempt_timeout: Duration,
    pub conn_attempt_interval: Duration,
    pub conn_attempt_max: usize,
}

impl Default for RakClientConfig {
    fn default() -> Self {
        Self {
            mtu_sizes: vec![constants::MIN_MTU_SIZE, 1200, constants::MAX_MTU_SIZE]
                .into_boxed_slice(),
            protocol: constants::PROTOCOL,
            guid: random(),
            conn_attempt_timeout: constants::CONNECTION_ATTEMPT_TIMEOUT,
            conn_attempt_interval: constants::CONNECTION_ATTEMPT_INTERVAL,
            conn_attempt_max: constants::CONNECTION_ATTEMPT_MAX,
        }
    }
}
