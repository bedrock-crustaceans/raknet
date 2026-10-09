use crate::prelude::RakSessionError;
use crate::protocol::error::RakCodecError;
use std::time::SystemTimeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RakClientError {
    #[error("RakCodecError: {0}")]
    RakCodecError(#[from] RakCodecError),
    #[error("RakSessionError: {0}")]
    RakSessionError(#[from] RakSessionError),
    #[error("SystemTimeError: {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("Security Unsupported")]
    SecurityUnsupported,
    #[error("Connection Failed")]
    ConnectionFailed,
    #[error("Connection Attempt Failed")]
    ConnectionAttemptFailed,
    #[error("Incompatible Protocol")]
    IncompatibleProtocol,
    #[error("Already Connected")]
    AlreadyConnected,
    #[error("Recently Connected")]
    RecentlyConnected,
    #[error("No Free Incoming Connections")]
    NoFreeIncomingConnections,
    #[error("Invalid MTU: {0}")]
    InvalidMtu(u16),
    #[error("Closed")]
    Closed,
}
