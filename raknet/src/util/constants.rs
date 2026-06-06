pub const PROTOCOL: u8 = 11;

pub const UDP_HEADER_SIZE: u16 = 8;
pub const MIN_MTU_SIZE: u16 = 400;
pub const MAX_MTU_SIZE: u16 = 1492;
pub const DGRAM_HEADER_SIZE: u16 = 4;
pub const DGRAM_MTU_OVERHEAD: u16 = 36;

pub const MAX_ORDERING_CHANNELS: i32 = 32;
pub const PACKET_LIMIT: i32 = 120;
pub const TOTAL_PACKET_LIMIT: i32 = 100_000;

pub const SESSION_TIMEOUT_MS: i32 = 10_000;
pub const SESSION_STALE_MS: i32 = 5_000;

pub const CONNECTION_ATTEMPT_TIMEOUT_MS: i32 = 10_000;
pub const CONNECTION_ATTEMPT_INTERVAL_MS: i32 = 1_000;
pub const CONNECTION_ATTEMPT_MAX: i32 = 10;

pub const AUTOFLUSH: bool = true;
pub const AUTOFLUSH_INTERVAL_MS: i32 = 10;

pub const CC_MAX_THRESHOLD: i32 = 2000;
pub const CC_ADDITIONAL_VARIANCE: i32 = 30;
pub const CC_SYN: i32 = 10;

pub const MAX_QUEUED_BYTES: i32 = 67_108_864;

pub const MAGIC: [u8; 16] = [
    0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
];
pub const MTU_SIZES: [u16; 3] = [MIN_MTU_SIZE, 1200, MAX_MTU_SIZE];
