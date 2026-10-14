use crate::protocol::error::RakCodecError;
use std::io::{Read, Write};

pub trait RakCodec: Sized {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), RakCodecError>;

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, RakCodecError>;

    fn size_hint(&self) -> usize;
}

pub trait RakCodecHelper {
    fn serialized(&self) -> Result<Box<[u8]>, RakCodecError>;
}

impl<T: RakCodec> RakCodecHelper for T {
    fn serialized(&self) -> Result<Box<[u8]>, RakCodecError> {
        let mut buf = Vec::with_capacity(T::size_hint(self));
        T::serialize(self, &mut buf)?;
        Ok(buf.into_boxed_slice())
    }
}
