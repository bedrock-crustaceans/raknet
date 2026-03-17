use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::{
    DEFAULT_UNCONNECTED_MAGIC, ID_ALREADY_CONNECTED, ID_CONNECTION_BANNED,
    ID_CONNECTION_REQUEST_FAILED, ID_INCOMPATIBLE_PROTOCOL_VERSION, ID_IP_RECENTLY_CONNECTED,
    ID_NO_FREE_INCOMING_CONNECTIONS, ID_OPEN_CONNECTION_REPLY_1, ID_OPEN_CONNECTION_REPLY_2,
    ID_OPEN_CONNECTION_REQUEST_1, ID_OPEN_CONNECTION_REQUEST_2, ID_UNCONNECTED_PING,
    ID_UNCONNECTED_PING_OPEN_CONNECTIONS, ID_UNCONNECTED_PONG, MAXIMUM_MTU_SIZE, MINIMUM_MTU_SIZE,
    Magic,
};

mod incompatible;
mod offline;
mod open_connection;
mod reject;

pub use incompatible::IncompatibleProtocolVersion;
pub use offline::{UnconnectedPing, UnconnectedPong};
pub use open_connection::{
    OpenConnectionReply1, OpenConnectionReply2, OpenConnectionRequest1, OpenConnectionRequest2,
    Request2ParsePath,
};
pub use reject::{
    AlreadyConnected, ConnectionBanned, ConnectionRequestFailed, IpRecentlyConnected,
    NoFreeIncomingConnections,
};

use incompatible::decode_incompatible;
use offline::{decode_ping, decode_pong};
use open_connection::{decode_reply_1, decode_reply_2, decode_request_1, decode_request_2};
use reject::decode_reject_packet;

pub const MAX_UNCONNECTED_PONG_MOTD_BYTES: usize = i16::MAX as usize;

#[derive(Debug, Clone)]
pub enum OfflinePacket {
    UnconnectedPing(UnconnectedPing),
    UnconnectedPingOpenConnections(UnconnectedPing),
    UnconnectedPong(UnconnectedPong),
    OpenConnectionRequest1(OpenConnectionRequest1),
    OpenConnectionReply1(OpenConnectionReply1),
    OpenConnectionRequest2(OpenConnectionRequest2),
    OpenConnectionReply2(OpenConnectionReply2),
    IncompatibleProtocolVersion(IncompatibleProtocolVersion),
    ConnectionRequestFailed(ConnectionRequestFailed),
    AlreadyConnected(AlreadyConnected),
    NoFreeIncomingConnections(NoFreeIncomingConnections),
    ConnectionBanned(ConnectionBanned),
    IpRecentlyConnected(IpRecentlyConnected),
}

macro_rules! offline_packet_registry {
    ($($id:ident => $variant:ident => $decoder:expr),+ $(,)?) => {
        fn offline_packet_id(packet: &OfflinePacket) -> u8 {
            match packet {
                $(OfflinePacket::$variant(_) => $id,)+
            }
        }

        fn decode_offline_packet_with_registry(
            id: u8,
            src: &mut impl Buf,
            expected_magic: Magic,
        ) -> Result<OfflinePacket, DecodeError> {
            match id {
                $($id => ($decoder)(src, expected_magic),)+
                _ => Err(DecodeError::InvalidOfflinePacketId(id)),
            }
        }
    };
}

offline_packet_registry! {
    ID_UNCONNECTED_PING => UnconnectedPing =>
        |src, expected_magic| decode_ping(src, expected_magic).map(OfflinePacket::UnconnectedPing),
    ID_UNCONNECTED_PING_OPEN_CONNECTIONS => UnconnectedPingOpenConnections =>
        |src, expected_magic| decode_ping(src, expected_magic).map(OfflinePacket::UnconnectedPingOpenConnections),
    ID_UNCONNECTED_PONG => UnconnectedPong =>
        |src, expected_magic| decode_pong(src, expected_magic).map(OfflinePacket::UnconnectedPong),
    ID_OPEN_CONNECTION_REQUEST_1 => OpenConnectionRequest1 =>
        |src, expected_magic| decode_request_1(src, expected_magic).map(OfflinePacket::OpenConnectionRequest1),
    ID_OPEN_CONNECTION_REPLY_1 => OpenConnectionReply1 =>
        |src, expected_magic| decode_reply_1(src, expected_magic).map(OfflinePacket::OpenConnectionReply1),
    ID_OPEN_CONNECTION_REQUEST_2 => OpenConnectionRequest2 =>
        |src, expected_magic| decode_request_2(src, expected_magic).map(OfflinePacket::OpenConnectionRequest2),
    ID_OPEN_CONNECTION_REPLY_2 => OpenConnectionReply2 =>
        |src, expected_magic| decode_reply_2(src, expected_magic).map(OfflinePacket::OpenConnectionReply2),
    ID_INCOMPATIBLE_PROTOCOL_VERSION => IncompatibleProtocolVersion =>
        |src, expected_magic| decode_incompatible(src, expected_magic).map(OfflinePacket::IncompatibleProtocolVersion),
    ID_CONNECTION_REQUEST_FAILED => ConnectionRequestFailed =>
        |src, expected_magic| decode_reject_packet(src, expected_magic).map(|(magic, server_guid)| {
            OfflinePacket::ConnectionRequestFailed(ConnectionRequestFailed {
                server_guid,
                magic,
            })
        }),
    ID_ALREADY_CONNECTED => AlreadyConnected =>
        |src, expected_magic| decode_reject_packet(src, expected_magic).map(|(magic, server_guid)| {
            OfflinePacket::AlreadyConnected(AlreadyConnected { server_guid, magic })
        }),
    ID_NO_FREE_INCOMING_CONNECTIONS => NoFreeIncomingConnections =>
        |src, expected_magic| decode_reject_packet(src, expected_magic).map(|(magic, server_guid)| {
            OfflinePacket::NoFreeIncomingConnections(NoFreeIncomingConnections {
                server_guid,
                magic,
            })
        }),
    ID_CONNECTION_BANNED => ConnectionBanned =>
        |src, expected_magic| decode_reject_packet(src, expected_magic).map(|(magic, server_guid)| {
            OfflinePacket::ConnectionBanned(ConnectionBanned { server_guid, magic })
        }),
    ID_IP_RECENTLY_CONNECTED => IpRecentlyConnected =>
        |src, expected_magic| decode_reject_packet(src, expected_magic).map(|(magic, server_guid)| {
            OfflinePacket::IpRecentlyConnected(IpRecentlyConnected { server_guid, magic })
        }),
}

impl OfflinePacket {
    pub fn id(&self) -> u8 {
        offline_packet_id(self)
    }

    pub fn encode(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        self.id().encode_raknet(dst)?;
        match self {
            OfflinePacket::UnconnectedPing(pkt)
            | OfflinePacket::UnconnectedPingOpenConnections(pkt) => {
                pkt.ping_time.encode_raknet(dst)?;
                pkt.magic.encode_raknet(dst)?;
                pkt.client_guid.encode_raknet(dst)?;
            }
            OfflinePacket::UnconnectedPong(pkt) => {
                pkt.ping_time.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
                pkt.magic.encode_raknet(dst)?;
                validate_unconnected_pong_motd_len(pkt.motd.len())?;
                let motd_len = u16::try_from(pkt.motd.len())
                    .map_err(|_| EncodeError::OfflinePongMotdTooLong(pkt.motd.len()))?;
                motd_len.encode_raknet(dst)?;
                dst.put_slice(&pkt.motd);
            }
            OfflinePacket::OpenConnectionRequest1(pkt) => {
                validate_mtu(pkt.mtu)?;
                pkt.magic.encode_raknet(dst)?;
                pkt.protocol_version.encode_raknet(dst)?;

                // Req1 MTU is inferred from packet length; remaining bytes are zero padding.
                let padding_len = usize::from(pkt.mtu).saturating_sub(18);
                for _ in 0..padding_len {
                    dst.put_u8(0);
                }
            }
            OfflinePacket::OpenConnectionReply1(pkt) => {
                validate_mtu(pkt.mtu)?;
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
                pkt.cookie.is_some().encode_raknet(dst)?;
                if let Some(cookie) = pkt.cookie {
                    cookie.encode_raknet(dst)?;
                }
                pkt.mtu.encode_raknet(dst)?;
            }
            OfflinePacket::OpenConnectionRequest2(pkt) => {
                validate_mtu(pkt.mtu)?;
                pkt.magic.encode_raknet(dst)?;
                if let Some(cookie) = pkt.cookie {
                    cookie.encode_raknet(dst)?;
                    pkt.client_proof.encode_raknet(dst)?;
                }
                pkt.server_addr.encode_raknet(dst)?;
                pkt.mtu.encode_raknet(dst)?;
                pkt.client_guid.encode_raknet(dst)?;
            }
            OfflinePacket::OpenConnectionReply2(pkt) => {
                validate_mtu(pkt.mtu)?;
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
                pkt.server_addr.encode_raknet(dst)?;
                pkt.mtu.encode_raknet(dst)?;
                pkt.use_encryption.encode_raknet(dst)?;
            }
            OfflinePacket::IncompatibleProtocolVersion(pkt) => {
                pkt.protocol_version.encode_raknet(dst)?;
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
            }
            OfflinePacket::ConnectionRequestFailed(pkt) => {
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
            }
            OfflinePacket::AlreadyConnected(pkt) => {
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
            }
            OfflinePacket::NoFreeIncomingConnections(pkt) => {
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
            }
            OfflinePacket::ConnectionBanned(pkt) => {
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
            }
            OfflinePacket::IpRecentlyConnected(pkt) => {
                pkt.magic.encode_raknet(dst)?;
                pkt.server_guid.encode_raknet(dst)?;
            }
        }

        Ok(())
    }

    pub fn decode(src: &mut impl Buf) -> Result<Self, DecodeError> {
        Self::decode_with_magic(src, DEFAULT_UNCONNECTED_MAGIC)
    }

    pub fn decode_with_magic(
        src: &mut impl Buf,
        expected_magic: Magic,
    ) -> Result<Self, DecodeError> {
        let id = u8::decode_raknet(src)?;
        decode_offline_packet_with_registry(id, src, expected_magic)
    }
}

fn validate_magic(magic: Magic, expected_magic: Magic) -> Result<Magic, DecodeError> {
    if magic != expected_magic {
        return Err(DecodeError::InvalidMagic);
    }
    Ok(magic)
}

fn validate_mtu(mtu: u16) -> Result<(), EncodeError> {
    if !(MINIMUM_MTU_SIZE..=MAXIMUM_MTU_SIZE).contains(&mtu) {
        return Err(EncodeError::InvalidMtu(mtu));
    }
    Ok(())
}

pub fn validate_unconnected_pong_motd_len(len: usize) -> Result<(), EncodeError> {
    if len > MAX_UNCONNECTED_PONG_MOTD_BYTES {
        return Err(EncodeError::OfflinePongMotdTooLong(len));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{
        ConnectionBanned, DEFAULT_UNCONNECTED_MAGIC, MAX_UNCONNECTED_PONG_MOTD_BYTES,
        NoFreeIncomingConnections, OfflinePacket, OpenConnectionRequest1, OpenConnectionRequest2,
        Request2ParsePath, UnconnectedPong,
    };
    use crate::error::{DecodeError, EncodeError};

    fn roundtrip(packet: OfflinePacket) -> OfflinePacket {
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).expect("encode must succeed");
        let mut src = &buf[..];
        OfflinePacket::decode(&mut src).expect("decode must succeed")
    }

    #[test]
    fn no_free_incoming_connections_roundtrip() {
        let packet = OfflinePacket::NoFreeIncomingConnections(NoFreeIncomingConnections {
            server_guid: 0xAA11_BB22_CC33_DD44,
            magic: DEFAULT_UNCONNECTED_MAGIC,
        });
        let decoded = roundtrip(packet);
        match decoded {
            OfflinePacket::NoFreeIncomingConnections(p) => {
                assert_eq!(p.server_guid, 0xAA11_BB22_CC33_DD44);
                assert_eq!(p.magic, DEFAULT_UNCONNECTED_MAGIC);
            }
            _ => panic!("unexpected packet variant"),
        }
    }

    #[test]
    fn connection_banned_roundtrip() {
        let packet = OfflinePacket::ConnectionBanned(ConnectionBanned {
            server_guid: 0x1020_3040_5060_7080,
            magic: DEFAULT_UNCONNECTED_MAGIC,
        });
        let decoded = roundtrip(packet);
        match decoded {
            OfflinePacket::ConnectionBanned(p) => {
                assert_eq!(p.server_guid, 0x1020_3040_5060_7080);
                assert_eq!(p.magic, DEFAULT_UNCONNECTED_MAGIC);
            }
            _ => panic!("unexpected packet variant"),
        }
    }

    #[test]
    fn open_connection_request2_without_cookie_prefers_strict_no_cookie_path() {
        let packet = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
            server_addr: "127.0.0.1:19132".parse().expect("valid socket addr"),
            mtu: 1400,
            client_guid: 0x11_22_33_44_55_66_77_88,
            cookie: None,
            client_proof: false,
            parse_path: Request2ParsePath::StrictNoCookie,
            magic: DEFAULT_UNCONNECTED_MAGIC,
        });
        let decoded = roundtrip(packet);
        match decoded {
            OfflinePacket::OpenConnectionRequest2(p) => {
                assert_eq!(p.cookie, None);
                assert_eq!(p.parse_path, Request2ParsePath::StrictNoCookie);
            }
            _ => panic!("unexpected packet variant"),
        }
    }

    #[test]
    fn open_connection_request2_with_cookie_prefers_strict_cookie_path() {
        let packet = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
            server_addr: "127.0.0.1:19132".parse().expect("valid socket addr"),
            mtu: 1400,
            client_guid: 0x88_77_66_55_44_33_22_11,
            cookie: Some(0xAABB_CCDD),
            client_proof: true,
            parse_path: Request2ParsePath::StrictWithCookie,
            magic: DEFAULT_UNCONNECTED_MAGIC,
        });
        let decoded = roundtrip(packet);
        match decoded {
            OfflinePacket::OpenConnectionRequest2(p) => {
                assert_eq!(p.cookie, Some(0xAABB_CCDD));
                assert!(p.client_proof);
                assert_eq!(p.parse_path, Request2ParsePath::StrictWithCookie);
            }
            _ => panic!("unexpected packet variant"),
        }
    }

    #[test]
    fn open_connection_request2_legacy_fallback_accepts_non_boolean_proof_byte() {
        let packet = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
            server_addr: "127.0.0.1:19132".parse().expect("valid socket addr"),
            mtu: 1400,
            client_guid: 0xAB_CD_EF_01_23_45_67_89,
            cookie: Some(0xAABB_CCDD),
            client_proof: true,
            parse_path: Request2ParsePath::StrictWithCookie,
            magic: DEFAULT_UNCONNECTED_MAGIC,
        });
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).expect("encode must succeed");

        let proof_idx = 1 + 16 + 4;
        buf[proof_idx] = 2;

        let mut src = &buf[..];
        let decoded = OfflinePacket::decode(&mut src).expect("decode must succeed");
        match decoded {
            OfflinePacket::OpenConnectionRequest2(p) => {
                assert_eq!(p.parse_path, Request2ParsePath::LegacyHeuristic);
                assert_eq!(p.cookie, Some(0xAABB_CCDD));
                assert!(!p.client_proof);
            }
            _ => panic!("unexpected packet variant"),
        }
    }

    #[test]
    fn unconnected_pong_encode_rejects_oversized_motd() {
        let oversized = vec![b'a'; MAX_UNCONNECTED_PONG_MOTD_BYTES + 1];
        let packet = OfflinePacket::UnconnectedPong(UnconnectedPong {
            ping_time: 1,
            server_guid: 2,
            magic: DEFAULT_UNCONNECTED_MAGIC,
            motd: oversized.into(),
        });
        let mut buf = BytesMut::new();
        let err = packet
            .encode(&mut buf)
            .expect_err("oversized motd must be rejected");
        assert!(matches!(err, EncodeError::OfflinePongMotdTooLong(_)));
    }

    #[test]
    fn decode_with_custom_magic_accepts_matching_packet() {
        let custom_magic = [
            0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xF0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
            0xDC, 0xFE,
        ];
        let packet = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
            protocol_version: 10,
            mtu: 1400,
            magic: custom_magic,
        });
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).expect("encode must succeed");

        let mut src = &buf[..];
        let decoded = OfflinePacket::decode_with_magic(&mut src, custom_magic)
            .expect("decode must accept matching custom magic");
        match decoded {
            OfflinePacket::OpenConnectionRequest1(req1) => {
                assert_eq!(req1.magic, custom_magic);
                assert_eq!(req1.mtu, 1400);
            }
            _ => panic!("unexpected packet variant"),
        }
    }

    #[test]
    fn decode_with_custom_magic_rejects_mismatch() {
        let packet_magic = [
            0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xF0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
            0xDC, 0xFE,
        ];
        let expected_magic = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let packet = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
            protocol_version: 10,
            mtu: 1400,
            magic: packet_magic,
        });
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).expect("encode must succeed");

        let mut src = &buf[..];
        let err = OfflinePacket::decode_with_magic(&mut src, expected_magic)
            .expect_err("decode must reject mismatched magic");
        assert!(matches!(err, DecodeError::InvalidMagic));
    }
}
