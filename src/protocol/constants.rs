use bitflags::bitflags;

pub type Magic = [u8; 16];

pub const RAKNET_PROTOCOL_VERSION: u8 = 11;

pub const MINIMUM_MTU_SIZE: u16 = 576;
pub const MAXIMUM_MTU_SIZE: u16 = 1400;
pub const MTU_PROBE_ORDER: &[u16] = &[1200, MAXIMUM_MTU_SIZE, MINIMUM_MTU_SIZE];

pub const MAX_ACK_SEQUENCES: u16 = 8192;
pub const MAX_SPLIT_PARTS: u32 = 8192;
pub const SPLIT_REASSEMBLY_TTL_MS: u64 = 30_000;
pub const MAX_INFLIGHT_SPLIT_COMPOUNDS_PER_PEER: usize = 256;

pub const DEFAULT_UNCONNECTED_MAGIC: Magic = [
    0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
];

pub const RAKNET_DATAGRAM_HEADER_SIZE: usize = 4;

pub const FRAME_FLAG_SPLIT: u8 = 0b0001_0000;
pub const FRAME_FLAG_NEEDS_BAS: u8 = 0b0000_0100;

pub const ID_UNCONNECTED_PING: u8 = 0x01;
pub const ID_UNCONNECTED_PING_OPEN_CONNECTIONS: u8 = 0x02;
pub const ID_UNCONNECTED_PONG: u8 = 0x1C;
pub const ID_OPEN_CONNECTION_REQUEST_1: u8 = 0x05;
pub const ID_OPEN_CONNECTION_REPLY_1: u8 = 0x06;
pub const ID_OPEN_CONNECTION_REQUEST_2: u8 = 0x07;
pub const ID_OPEN_CONNECTION_REPLY_2: u8 = 0x08;
pub const ID_CONNECTION_REQUEST_FAILED: u8 = 0x11;
pub const ID_ALREADY_CONNECTED: u8 = 0x12;
pub const ID_NO_FREE_INCOMING_CONNECTIONS: u8 = 0x14;
pub const ID_CONNECTION_BANNED: u8 = 0x17;
pub const ID_INCOMPATIBLE_PROTOCOL_VERSION: u8 = 0x19;
pub const ID_IP_RECENTLY_CONNECTED: u8 = 0x1A;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct DatagramFlags: u8 {
        const VALID            = 0b1000_0000;
        const ACK              = 0b0100_0000;
        const NACK             = 0b0010_0000;
        const PACKET_PAIR      = 0b0001_0000;
        const CONTINUOUS_SEND  = 0b0000_1000;
        const HAS_B_AND_AS     = 0b0000_0100;
    }
}
