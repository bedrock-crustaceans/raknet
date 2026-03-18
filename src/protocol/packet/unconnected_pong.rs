use bytes::{Buf, Bytes};

use crate::error::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct UnconnectedPong {
    pub ping_time: i64,
    pub server_guid: u64,
    pub magic: Magic,
    pub motd: Bytes,
}

pub(super) fn decode_pong(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<UnconnectedPong, DecodeError> {
    let ping_time = i64::decode_raknet(src)?;
    let server_guid = u64::decode_raknet(src)?;
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let motd_len = u16::decode_raknet(src)? as usize;
    if src.remaining() < motd_len {
        return Err(DecodeError::UnexpectedEof);
    }
    let motd = src.copy_to_bytes(motd_len);

    Ok(UnconnectedPong {
        ping_time,
        server_guid,
        magic,
        motd,
    })
}