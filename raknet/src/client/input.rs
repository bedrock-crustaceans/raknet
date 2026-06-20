use std::net::SocketAddr;
use std::time::SystemTime;

pub enum RakClientInput {
    Ping(SocketAddr, SystemTime),
    Connect(SocketAddr, SystemTime),
    Datagram(Box<[u8]>, SocketAddr, SystemTime),
    Update(SystemTime),
}
