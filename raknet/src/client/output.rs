use std::net::SocketAddr;
use std::time::Duration;

pub enum RakClientOutput {
    Datagram(Box<[u8]>, SocketAddr),
    Wait(Duration),
}
