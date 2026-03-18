use bytes::Buf;
use crate::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct OpenConnectionReply1 {
    pub server_guid: u64,
    pub mtu: u16,
    pub cookie: Option<u32>,
    pub magic: Magic,
}

pub(super) fn decode_reply_1(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<OpenConnectionReply1, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;
    let has_cookie = bool::decode_raknet(src)?;
    let cookie = if has_cookie {
        Some(u32::decode_raknet(src)?)
    } else {
        None
    };
    let mtu = u16::decode_raknet(src)?;

    Ok(OpenConnectionReply1 {
        server_guid,
        mtu,
        cookie,
        magic,
    })
}