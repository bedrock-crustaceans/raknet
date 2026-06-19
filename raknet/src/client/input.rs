use std::net::SocketAddr;
use std::time::SystemTime;

pub enum RakClientInput {
    Datagram(Box<[u8]>, SocketAddr, SystemTime),
    Update(SystemTime),
}
