use crate::session::RakSession;
use raknet::prelude::{RakClientError, RakSessionSnapshot};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;

pub enum RakClientMsg {
    Connect(
        SocketAddr,
        oneshot::Sender<Result<RakSession, RakClientError>>,
    ),
    Ping(SocketAddr, oneshot::Sender<(Box<[u8]>, Duration)>),
    Adopt(
        RakSessionSnapshot,
        oneshot::Sender<Result<RakSession, RakClientError>>,
    ),
    Stop,
}
