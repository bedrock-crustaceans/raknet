use crate::protocol::codec::RakCodec;
use crate::protocol::error::RakCodecError;
use crate::util::constants::MAGIC;
use crate::util::packet_id::INCOMPATIBLE_PROTOCOL;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompatibleProtocol {
    pub protocol: u8,
    pub guid: u64,
}

impl RakCodec for IncompatibleProtocol {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), RakCodecError> {
        writer.write_u8(INCOMPATIBLE_PROTOCOL)?;
        writer.write_u8(self.protocol)?;
        writer.write_all(&MAGIC)?;
        writer.write_u64::<BigEndian>(self.guid)?;

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, RakCodecError> {
        let id = reader.read_u8()?;
        if id != INCOMPATIBLE_PROTOCOL {
            return Err(RakCodecError::UnexpectedPacketID(INCOMPATIBLE_PROTOCOL, id));
        }

        let protocol = reader.read_u8()?;

        let mut magic = [0u8; MAGIC.len()];
        reader.read_exact(&mut magic)?;

        if magic != MAGIC {
            return Err(RakCodecError::UnexpectedMagic);
        }

        let guid = reader.read_u64::<BigEndian>()?;

        Ok(Self { protocol, guid })
    }

    fn size_hint(&self) -> usize {
        size_of::<u8>() + size_of::<u8>() + MAGIC.len() + size_of::<u64>()
    }
}
