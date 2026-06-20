use std::net::SocketAddr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum RakClientState {
    Unconnected,
    Handshake1(SocketAddr),
    Handshake2(SocketAddr),
    HandshakeCompleted(SocketAddr),
}
