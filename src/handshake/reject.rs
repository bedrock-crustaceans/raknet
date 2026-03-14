use bytes::Buf;

use crate::error::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct ConnectionRequestFailed {
    pub server_guid: u64,
    pub magic: Magic,
}

#[derive(Debug, Clone)]
pub struct AlreadyConnected {
    pub server_guid: u64,
    pub magic: Magic,
}

#[derive(Debug, Clone)]
pub struct NoFreeIncomingConnections {
    pub server_guid: u64,
    pub magic: Magic,
}

#[derive(Debug, Clone)]
pub struct ConnectionBanned {
    pub server_guid: u64,
    pub magic: Magic,
}

#[derive(Debug, Clone)]
pub struct IpRecentlyConnected {
    pub server_guid: u64,
    pub magic: Magic,
}

pub(super) fn decode_reject_packet(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<(Magic, u64), DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;
    Ok((magic, server_guid))
}
