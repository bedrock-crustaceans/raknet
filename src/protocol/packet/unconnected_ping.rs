use bytes::Buf;
use crate::protocol::codec::RaknetCodec;
use crate::DecodeError;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct UnconnectedPing {
    pub ping_time: i64,
    pub client_guid: u64,
    pub magic: Magic,
}

pub(super) fn decode_ping(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<crate::protocol::packet::UnconnectedPing, DecodeError> {
    let ping_time = i64::decode_raknet(src)?;
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let client_guid = u64::decode_raknet(src)?;

    Ok(crate::protocol::packet::UnconnectedPing {
        ping_time,
        client_guid,
        magic,
    })
}