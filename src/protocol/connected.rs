use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;

pub const SYSTEM_ADDRESS_COUNT: usize = 10;

pub const ID_CONNECTED_PING: u8 = 0x00;
pub const ID_CONNECTED_PONG: u8 = 0x03;
pub const ID_CONNECTION_REQUEST: u8 = 0x09;
pub const ID_CONNECTION_REQUEST_ACCEPTED: u8 = 0x10;
pub const ID_NEW_INCOMING_CONNECTION: u8 = 0x13;
pub const ID_DISCONNECTION_NOTIFICATION: u8 = 0x15;
pub const ID_DETECT_LOST_CONNECTION: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct ConnectedPing {
    pub ping_time: i64,
}

#[derive(Debug, Clone)]
pub struct ConnectedPong {
    pub ping_time: i64,
    pub pong_time: i64,
}

#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    pub client_guid: u64,
    pub request_time: i64,
    pub use_encryption: bool,
}

#[derive(Debug, Clone)]
pub struct ConnectionRequestAccepted {
    pub client_addr: SocketAddr,
    pub system_index: u16,
    pub internal_addrs: [SocketAddr; SYSTEM_ADDRESS_COUNT],
    pub request_time: i64,
    pub accepted_time: i64,
}

#[derive(Debug, Clone)]
pub struct NewIncomingConnection {
    pub server_addr: SocketAddr,
    pub internal_addrs: [SocketAddr; SYSTEM_ADDRESS_COUNT],
    pub request_time: i64,
    pub accepted_time: i64,
}

#[derive(Debug, Clone)]
pub struct DisconnectionNotification {
    pub reason: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct DetectLostConnection;

#[derive(Debug, Clone)]
pub enum ConnectedControlPacket {
    ConnectedPing(ConnectedPing),
    ConnectedPong(ConnectedPong),
    ConnectionRequest(ConnectionRequest),
    ConnectionRequestAccepted(ConnectionRequestAccepted),
    NewIncomingConnection(NewIncomingConnection),
    DisconnectionNotification(DisconnectionNotification),
    DetectLostConnection(DetectLostConnection),
}

impl ConnectedControlPacket {
    pub fn id(&self) -> u8 {
        match self {
            Self::ConnectedPing(_) => ID_CONNECTED_PING,
            Self::ConnectedPong(_) => ID_CONNECTED_PONG,
            Self::ConnectionRequest(_) => ID_CONNECTION_REQUEST,
            Self::ConnectionRequestAccepted(_) => ID_CONNECTION_REQUEST_ACCEPTED,
            Self::NewIncomingConnection(_) => ID_NEW_INCOMING_CONNECTION,
            Self::DisconnectionNotification(_) => ID_DISCONNECTION_NOTIFICATION,
            Self::DetectLostConnection(_) => ID_DETECT_LOST_CONNECTION,
        }
    }

    pub fn encode(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        self.id().encode_raknet(dst)?;
        match self {
            Self::ConnectedPing(pkt) => pkt.ping_time.encode_raknet(dst)?,
            Self::ConnectedPong(pkt) => {
                pkt.ping_time.encode_raknet(dst)?;
                pkt.pong_time.encode_raknet(dst)?;
            }
            Self::ConnectionRequest(pkt) => {
                pkt.client_guid.encode_raknet(dst)?;
                pkt.request_time.encode_raknet(dst)?;
                pkt.use_encryption.encode_raknet(dst)?;
            }
            Self::ConnectionRequestAccepted(pkt) => {
                pkt.client_addr.encode_raknet(dst)?;
                pkt.system_index.encode_raknet(dst)?;
                for addr in &pkt.internal_addrs {
                    addr.encode_raknet(dst)?;
                }
                pkt.request_time.encode_raknet(dst)?;
                pkt.accepted_time.encode_raknet(dst)?;
            }
            Self::NewIncomingConnection(pkt) => {
                pkt.server_addr.encode_raknet(dst)?;
                for addr in &pkt.internal_addrs {
                    addr.encode_raknet(dst)?;
                }
                pkt.request_time.encode_raknet(dst)?;
                pkt.accepted_time.encode_raknet(dst)?;
            }
            Self::DisconnectionNotification(pkt) => {
                if let Some(reason) = pkt.reason {
                    reason.encode_raknet(dst)?;
                }
            }
            Self::DetectLostConnection(_) => {}
        }
        Ok(())
    }

    pub fn decode(src: &mut impl Buf) -> Result<Self, DecodeError> {
        let id = u8::decode_raknet(src)?;
        match id {
            ID_CONNECTED_PING => Ok(Self::ConnectedPing(ConnectedPing {
                ping_time: i64::decode_raknet(src)?,
            })),
            ID_CONNECTED_PONG => Ok(Self::ConnectedPong(ConnectedPong {
                ping_time: i64::decode_raknet(src)?,
                pong_time: i64::decode_raknet(src)?,
            })),
            ID_CONNECTION_REQUEST => Ok(Self::ConnectionRequest(ConnectionRequest {
                client_guid: u64::decode_raknet(src)?,
                request_time: i64::decode_raknet(src)?,
                use_encryption: bool::decode_raknet(src)?,
            })),
            ID_CONNECTION_REQUEST_ACCEPTED => {
                let client_addr = SocketAddr::decode_raknet(src)?;
                let system_index = u16::decode_raknet(src)?;
                let mut internal_addrs = [default_socket_addr(); SYSTEM_ADDRESS_COUNT];
                for item in &mut internal_addrs {
                    *item = SocketAddr::decode_raknet(src)?;
                }
                let request_time = i64::decode_raknet(src)?;
                let accepted_time = i64::decode_raknet(src)?;

                Ok(Self::ConnectionRequestAccepted(ConnectionRequestAccepted {
                    client_addr,
                    system_index,
                    internal_addrs,
                    request_time,
                    accepted_time,
                }))
            }
            ID_NEW_INCOMING_CONNECTION => {
                let server_addr = SocketAddr::decode_raknet(src)?;
                let mut internal_addrs = [default_socket_addr(); SYSTEM_ADDRESS_COUNT];
                for item in &mut internal_addrs {
                    *item = SocketAddr::decode_raknet(src)?;
                }
                let request_time = i64::decode_raknet(src)?;
                let accepted_time = i64::decode_raknet(src)?;

                Ok(Self::NewIncomingConnection(NewIncomingConnection {
                    server_addr,
                    internal_addrs,
                    request_time,
                    accepted_time,
                }))
            }
            ID_DISCONNECTION_NOTIFICATION => {
                let reason = if src.has_remaining() {
                    Some(u8::decode_raknet(src)?)
                } else {
                    None
                };
                Ok(Self::DisconnectionNotification(DisconnectionNotification {
                    reason,
                }))
            }
            ID_DETECT_LOST_CONNECTION => Ok(Self::DetectLostConnection(DetectLostConnection)),
            _ => Err(DecodeError::InvalidConnectedPacketId(id)),
        }
    }
}

fn default_socket_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}
