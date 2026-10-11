use crate::protocol::error::RakCodecError;
use std::time::SystemTimeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RakSessionError {
    #[error("RakCodecError: {0}")]
    RakCodecError(#[from] RakCodecError),
    #[error("SystemTimeError: {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("Closed")]
    Closed,
    #[error("message of {0} bytes exceeds the send limit")]
    MessageSizeExceeded(usize),
}
