use crate::protocol::codec::RakCodec;
use crate::protocol::error::RakCodecError;
use crate::util::packet_id::DISCONNECT;
use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disconnect;

impl RakCodec for Disconnect {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), RakCodecError> {
        writer.write_u8(DISCONNECT)?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, RakCodecError> {
        let id = reader.read_u8()?;
        if id != DISCONNECT {
            return Err(RakCodecError::UnexpectedPacketID(DISCONNECT, id));
        };

        Ok(Self)
    }

    fn size_hint(&self) -> usize {
        size_of::<u8>()
    }
}
