use thiserror::Error;

#[derive(Debug, Error)]
pub enum RakServerError {
    #[error("Closed")]
    Closed,
    #[error(transparent)]
    RakServerError(#[from] raknet::prelude::RakServerError),
    #[error("IO Error: {0}")]
    IOError(#[from] tokio::io::Error),
}
