use crate::protocol::error::RakCodecError;
use std::io::{Read, Write};

pub trait RakCodec: Sized {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), RakCodecError>;

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, RakCodecError>;

    fn size_hint(&self) -> usize;
}
