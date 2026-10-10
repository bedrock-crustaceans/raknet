use crate::protocol::codec::RakCodec;
use crate::protocol::error::RakCodecError;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

impl RakCodec for SocketAddr {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), RakCodecError> {
        match self {
            SocketAddr::V4(addr) => {
                writer.write_u8(4)?;
                writer.write_all(&addr.ip().octets().map(|octet| !octet))?;
                writer.write_u16::<BigEndian>(addr.port())?;
            }
            SocketAddr::V6(addr) => {
                writer.write_u8(6)?;
                writer.write_u16::<LittleEndian>(23)?;
                writer.write_u16::<BigEndian>(addr.port())?;
                writer.write_u32::<BigEndian>(addr.flowinfo())?;
                writer.write_all(&addr.ip().octets())?;
                writer.write_u32::<BigEndian>(addr.scope_id())?;
            }
        }

        Ok(())
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, RakCodecError> {
        match reader.read_u8()? {
            4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets)?;
                let ip = Ipv4Addr::from(octets.map(|octet| !octet));
                let port = reader.read_u16::<BigEndian>()?;

                Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            6 => {
                reader.read_u16::<LittleEndian>()?;
                let port = reader.read_u16::<BigEndian>()?;
                let flowinfo = reader.read_u32::<BigEndian>()?;
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets)?;
                let ip = Ipv6Addr::from(octets);
                let scope_id = reader.read_u32::<BigEndian>()?;

                Ok(SocketAddr::V6(SocketAddrV6::new(
                    ip, port, flowinfo, scope_id,
                )))
            }
            _ => Err(RakCodecError::Malformed("socket addr")),
        }
    }

    fn size_hint(&self) -> usize {
        size_of::<u8>()
            + match self {
                SocketAddr::V4(..) => 4 + size_of::<u16>(),
                SocketAddr::V6(..) => {
                    size_of::<u16>() + size_of::<u16>() + size_of::<u32>() + 16 + size_of::<u32>()
                }
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn round_trip(addr: SocketAddr, expected: &[u8]) {
        let mut encoded = Vec::new();
        addr.serialize(&mut encoded).unwrap();
        assert_eq!(encoded, expected, "encoding differs from RakNet");
        assert_eq!(encoded.len(), addr.size_hint());
        assert_eq!(
            SocketAddr::deserialize(&mut Cursor::new(expected)).unwrap(),
            addr
        );
    }

    #[test]
    fn ipv4_octets_are_bit_inverted() {
        round_trip(
            "127.0.0.1:19132".parse().unwrap(),
            &[0x04, 0x80, 0xff, 0xff, 0xfe, 0x4a, 0xbc],
        );
    }

    #[test]
    fn ipv6_family_is_little_endian() {
        let mut expected = vec![0x06, 0x17, 0x00, 0x4a, 0xbc, 0, 0, 0, 0];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&[0, 0, 0, 0]);
        round_trip("[::1]:19132".parse().unwrap(), &expected);
    }
}
