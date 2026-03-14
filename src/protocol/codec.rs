use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

pub trait RaknetCodec: Sized {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError>;
    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError>;
}
