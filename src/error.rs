use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid config {config}.{field}: {message}")]
pub struct ConfigValidationError {
    pub config: &'static str,
    pub field: &'static str,
    pub message: String,
}

impl ConfigValidationError {
    pub fn new(config: &'static str, field: &'static str, message: impl Into<String>) -> Self {
        Self {
            config,
            field,
            message: message.into(),
        }
    }
}

pub mod server {
    use std::io;

    use thiserror::Error;

    use super::ConfigValidationError;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ServerError {
        #[error("io error: {message}")]
        Io { message: String },
        #[error("invalid config: {details}")]
        InvalidConfig { details: String },
        #[error("listener is already started")]
        AlreadyStarted,
        #[error("listener is not started")]
        NotStarted,
        #[error("listener command channel closed")]
        CommandChannelClosed,
        #[error("listener accept channel closed")]
        AcceptChannelClosed,
        #[error("listener worker stopped unexpectedly")]
        WorkerStopped,
    }

    impl From<io::Error> for ServerError {
        fn from(value: io::Error) -> Self {
            Self::Io {
                message: value.to_string(),
            }
        }
    }

    impl From<ConfigValidationError> for ServerError {
        fn from(value: ConfigValidationError) -> Self {
            Self::InvalidConfig {
                details: value.to_string(),
            }
        }
    }

    impl From<ServerError> for io::Error {
        fn from(value: ServerError) -> Self {
            let kind = match value {
                ServerError::AlreadyStarted => io::ErrorKind::AlreadyExists,
                ServerError::NotStarted => io::ErrorKind::NotConnected,
                ServerError::CommandChannelClosed
                | ServerError::AcceptChannelClosed
                | ServerError::WorkerStopped => io::ErrorKind::BrokenPipe,
                ServerError::Io { .. } | ServerError::InvalidConfig { .. } => {
                    io::ErrorKind::InvalidInput
                }
            };
            io::Error::new(kind, value.to_string())
        }
    }
}

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("missing reliable index for reliable frame")]
    MissingReliableIndex,
    #[error("missing sequence index for sequenced frame")]
    MissingSequenceIndex,
    #[error("missing ordering index for ordered/sequenced frame")]
    MissingOrderingIndex,
    #[error("missing ordering channel for ordered/sequenced frame")]
    MissingOrderingChannel,
    #[error("missing split metadata for split frame")]
    MissingSplitInfo,
    #[error("frame payload length does not match bit length")]
    FrameBitLengthMismatch,
    #[error("ack/nack record count overflow: {0}")]
    AckRecordOverflow(usize),
    #[error("mtu out of supported range: {0}")]
    InvalidMtu(u16),
    #[error("offline pong motd is too long: {0} bytes")]
    OfflinePongMotdTooLong(usize),
    #[error("invalid datagram flags: 0x{0:02x}")]
    InvalidDatagramFlags(u8),
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("unexpected eof")]
    UnexpectedEof,
    #[error("unknown reliability value: {0}")]
    UnknownReliability(u8),
    #[error("invalid frame bit length: {0}")]
    InvalidFrameBitLength(u16),
    #[error("invalid ack packet")]
    InvalidAckPacket,
    #[error("invalid datagram flags: 0x{0:02x}")]
    InvalidDatagramFlags(u8),
    #[error("invalid offline packet id: 0x{0:02x}")]
    InvalidOfflinePacketId(u8),
    #[error("invalid connected packet id: 0x{0:02x}")]
    InvalidConnectedPacketId(u8),
    #[error("invalid magic for unconnected packet")]
    InvalidMagic,
    #[error("invalid ip address version: {0}")]
    InvalidAddrVersion(u8),
    #[error("invalid open connection request 2 layout")]
    InvalidRequest2Layout,
    #[error("split index out of range")]
    SplitIndexOutOfRange,
    #[error("split count cannot be zero")]
    SplitCountZero,
    #[error("split metadata missing while split flag is set")]
    MissingSplitInfo,
    #[error("split count mismatch")]
    SplitCountMismatch,
    #[error("split packet exceeds maximum part limit")]
    SplitTooLarge,
    #[error("split assembler buffer is full")]
    SplitBufferFull,
    #[error("invalid ack range count: {0}")]
    InvalidAckRangeCount(u16),
}
