use thiserror::Error;

#[derive(Debug, Error)]
pub enum RakCodecError {
    #[error("Unexpected Header: {0:#04X}")]
    UnexpectedHeader(u8),
    #[error("Unexpected Packet ID: expected {0:#04X}, found {1:#04X}")]
    UnexpectedPacketID(u8, u8),
    #[error("Unexpected Magic")]
    UnexpectedMagic,
    #[error("Malformed: {0}")]
    Malformed(&'static str),
    #[error("ACK expands to more than the allowed number of entries")]
    TooManyAckEntries,
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
}
