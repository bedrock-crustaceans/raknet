use raknet::prelude::{RakPriority, RakReliability, RakSessionError, RakSessionSnapshot};
use tokio::sync::oneshot::Sender;

pub enum RakSessionMsg {
    Send(
        Box<[u8]>,
        RakReliability,
        RakPriority,
        Sender<Result<(), RakSessionError>>,
    ),
    Close(Sender<Result<(), RakSessionError>>),
    IsClosed(Sender<bool>),
    /// Capture the session's protocol state, leaving the live task running.
    Snapshot(Sender<RakSessionSnapshot>),
}
