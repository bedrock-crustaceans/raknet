use crate::session::RakSession;
use raknet::prelude::RakSession as RakSessionIntl;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::oneshot;

pub enum RakServerMsg {
    SetMessage(Box<[u8]>),
    SetMaxConnections(usize),
    Block(IpAddr, Duration),
    Unblock(IpAddr),
    Stop,
    Adopt(Box<RakSessionIntl>, oneshot::Sender<RakSession>),
}
