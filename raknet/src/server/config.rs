use crate::util::constants;
use rand::random;

#[derive(Clone, Debug)]
pub struct RakServerConfig {
    pub max_ordering_channels: i32,
    pub guid: u64,
    pub protocols: Box<[u8]>,
    pub max_connections: usize,
    pub message: Box<[u8]>,
    pub min_mtu_size: u16,
    pub max_mtu_size: u16,
    pub packet_limit: i32,
    pub total_packet_limit: i32,
    pub security: bool,
    /// Whether a client must have dialled the port this server is bound to.
    ///
    /// `OpenConnectionRequest2` carries the address the client dialled, and comparing it
    /// against this server's own is a cheap sanity check. It is wrong behind a port
    /// mapping, though: a client reaching a container through a published host port dialled
    /// that port, never the one the socket is bound to inside, so every connection would be
    /// refused. Turn it off when the server sits behind such a mapping.
    pub require_dialled_port: bool,
}

impl Default for RakServerConfig {
    fn default() -> RakServerConfig {
        Self {
            max_ordering_channels: constants::MAX_ORDERING_CHANNELS,
            guid: random(),
            protocols: Box::new([constants::PROTOCOL]),
            max_connections: 10,
            message: Box::new([]),
            min_mtu_size: constants::MIN_MTU_SIZE,
            max_mtu_size: constants::MAX_MTU_SIZE,
            packet_limit: constants::PACKET_LIMIT,
            total_packet_limit: constants::TOTAL_PACKET_LIMIT,
            security: false,
            require_dialled_port: true,
        }
    }
}
