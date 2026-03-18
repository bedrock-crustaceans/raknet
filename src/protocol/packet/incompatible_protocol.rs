use bytes::Buf;

use crate::error::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct IncompatibleProtocolVersion {
    pub protocol_version: u8,
    pub server_guid: u64,
    pub magic: Magic,
}

pub(super) fn decode_incompatible(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<IncompatibleProtocolVersion, DecodeError> {
    let protocol_version = u8::decode_raknet(src)?;
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;

    Ok(IncompatibleProtocolVersion {
        protocol_version,
        server_guid,
        magic,
    })
}
