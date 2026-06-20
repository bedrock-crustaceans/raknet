use crate::session::RakSession;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;

pub enum RakClientMsg {
    Connect(SocketAddr, oneshot::Sender<RakSession>),
    Ping(SocketAddr, oneshot::Sender<(Box<[u8]>, Duration)>),
}
