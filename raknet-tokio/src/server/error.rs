use thiserror::Error;

#[derive(Debug, Error)]
pub enum RakServerError {
    #[error("IO Error: {0}")]
    IOError(#[from] tokio::io::Error)
}