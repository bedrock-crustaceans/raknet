use crate::protocol::error::RakCodecError;
use crate::session::error::RakSessionError;
use std::time::SystemTimeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RakServerError {
    #[error("Refusing connection, reason: {0}")]
    RefusingConnection(String),
    #[error("Unexpected: {0}")]
    Unexpected(String),
    #[error("RakSessionError: {0}")]
    RakSessionError(#[from] RakSessionError),
    #[error("RakCodecError: {0}")]
    RakCodecError(#[from] RakCodecError),
    #[error("SystemTimeError: {0}")]
    SystemTimeError(#[from] SystemTimeError),
}
