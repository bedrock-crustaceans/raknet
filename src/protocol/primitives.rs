use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;
use super::constants::Magic;

pub struct U24Le(pub u32);

impl RaknetCodec for U24Le {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        let v = self.0 & 0x00FF_FFFF;
        dst.put_u8((v & 0xFF) as u8);
        dst.put_u8(((v >> 8) & 0xFF) as u8);
        dst.put_u8(((v >> 16) & 0xFF) as u8);
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if src.remaining() < 3 {
            return Err(DecodeError::UnexpectedEof);
        }
        let b0 = src.get_u8() as u32;
        let b1 = src.get_u8() as u32;
        let b2 = src.get_u8() as u32;
        Ok(Self(b0 | (b1 << 8) | (b2 << 16)))
    }
}

impl RaknetCodec for bool {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        dst.put_u8(u8::from(*self));
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if !src.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        Ok(src.get_u8() == 1)
    }
}

macro_rules! impl_codec_be_int {
    ($ty:ty, $put:ident, $get:ident, $size:expr) => {
        impl RaknetCodec for $ty {
            fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
                dst.$put(*self as _);
                Ok(())
            }

            fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
                if src.remaining() < $size {
                    return Err(DecodeError::UnexpectedEof);
                }
                Ok(src.$get() as $ty)
            }
        }
    };
}

impl_codec_be_int!(u8, put_u8, get_u8, 1);
impl_codec_be_int!(u16, put_u16, get_u16, 2);
impl_codec_be_int!(u32, put_u32, get_u32, 4);
impl_codec_be_int!(u64, put_u64, get_u64, 8);
impl_codec_be_int!(i16, put_i16, get_i16, 2);
impl_codec_be_int!(i32, put_i32, get_i32, 4);
impl_codec_be_int!(i64, put_i64, get_i64, 8);

impl RaknetCodec for Magic {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        dst.put_slice(self);
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if src.remaining() < 16 {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut magic = [0u8; 16];
        src.copy_to_slice(&mut magic);
        Ok(magic)
    }
}

impl RaknetCodec for SocketAddr {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        match self {
            SocketAddr::V4(addr) => {
                dst.put_u8(4);
                let ip = addr.ip().octets();
                dst.put_u8(!ip[0]);
                dst.put_u8(!ip[1]);
                dst.put_u8(!ip[2]);
                dst.put_u8(!ip[3]);
                dst.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                dst.put_u8(6);
                dst.put_u16_le(23);
                dst.put_u16(addr.port());
                dst.put_u32(addr.flowinfo());
                dst.put_slice(&addr.ip().octets());
                dst.put_u32(addr.scope_id());
            }
        }
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if !src.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }

        let version = src.get_u8();
        match version {
            4 => {
                if src.remaining() < 6 {
                    return Err(DecodeError::UnexpectedEof);
                }
                let ip = [!src.get_u8(), !src.get_u8(), !src.get_u8(), !src.get_u8()];
                let port = src.get_u16();
                Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            6 => {
                if src.remaining() < 28 {
                    return Err(DecodeError::UnexpectedEof);
                }
                let _family = src.get_u16_le();
                let port = src.get_u16();
                let flow_info = src.get_u32();
                let mut ip = [0u8; 16];
                src.copy_to_slice(&mut ip);
                let scope_id = src.get_u32();

                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    flow_info,
                    scope_id,
                )))
            }
            _ => Err(DecodeError::InvalidAddrVersion(version)),
        }
    }
}
