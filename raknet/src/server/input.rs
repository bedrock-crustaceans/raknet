use crate::session::RakSessionId;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

pub enum RakServerInput {
    SetMessage(Box<[u8]>),
    SetMaxConnections(usize),
    Datagram(Box<[u8]>, SocketAddr, SystemTime),
    RemoveSession(RakSessionId, SystemTime),
    Update(SystemTime),
    Block(IpAddr, Duration, SystemTime),
    Unblock(IpAddr),
}
