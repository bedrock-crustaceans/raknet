use crate::session::RakSession;
use std::net::SocketAddr;
use std::time::Duration;

pub enum RakClientOutput {
    SocketDatagram(Box<[u8]>, SocketAddr),
    SessionDatagram(Box<[u8]>),
    SessionConnected(Box<RakSession>),
    Wait(Duration),
}
