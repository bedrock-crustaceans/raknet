use bytes::Buf;

use crate::error::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct OpenConnectionRequest1 {
    pub protocol_version: u8,
    pub mtu: u16,
    pub magic: Magic,
}

pub(super) fn decode_request_1(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<crate::protocol::packet::OpenConnectionRequest1, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let protocol_version = u8::decode_raknet(src)?;
    let padding_len = src.remaining();
    let _ = src.copy_to_bytes(padding_len);

    let mtu = (padding_len + 18) as u16;
    Ok(crate::protocol::packet::OpenConnectionRequest1 {
        protocol_version,
        mtu,
        magic,
    })
}