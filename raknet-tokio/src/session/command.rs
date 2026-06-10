use raknet::prelude::{RakPriority, RakReliability, RakSessionError};
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
}
