use std::net::SocketAddr;

pub fn get_overhead(addr: &SocketAddr) -> u16 {
    match addr {
        SocketAddr::V4(_) => 20,
        SocketAddr::V6(_) => 40,
    }
}
