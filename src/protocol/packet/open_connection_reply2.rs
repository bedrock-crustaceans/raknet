use std::net::SocketAddr;
use bytes::Buf;
use crate::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct OpenConnectionReply2 {
    pub server_guid: u64,
    pub server_addr: SocketAddr,
    pub mtu: u16,
    pub use_encryption: bool,
    pub magic: Magic,
}

pub(super) fn decode_reply_2(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<OpenConnectionReply2, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;
    let server_addr = SocketAddr::decode_raknet(src)?;
    let mtu = u16::decode_raknet(src)?;
    let use_encryption = bool::decode_raknet(src)?;

    Ok(OpenConnectionReply2 {
        server_guid,
        server_addr,
        mtu,
        use_encryption,
        magic,
    })
}