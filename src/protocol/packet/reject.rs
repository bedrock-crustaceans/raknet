use crate::DecodeError;
use crate::protocol::constants::{Magic, ID_ALREADY_CONNECTED, ID_CONNECTION_BANNED, ID_CONNECTION_REQUEST_FAILED, ID_IP_RECENTLY_CONNECTED, ID_NO_FREE_INCOMING_CONNECTIONS};
use bytes::Buf;
use crate::protocol::codec::RaknetCodec;

#[derive(Debug, Clone)]
pub struct RejectData {
    pub server_guid: u64,
    pub magic: Magic,
}

#[derive(Clone, Debug)]
pub enum ConnectionRejectReason {
    ConnectionRequestFailed(RejectData),
    AlreadyConnected(RejectData),
    NoFreeIncomingConnections(RejectData),
    ConnectionBanned(RejectData),
    IpRecentlyConnected(RejectData),
}

impl ConnectionRejectReason {
    pub fn from_id(
        id: u8,
        magic: Magic,
        server_guid: u64,
    ) -> Result<Self, DecodeError> {
        let data = RejectData { magic, server_guid };

        Ok(match id {
            ID_CONNECTION_REQUEST_FAILED => Self::ConnectionRequestFailed(data),
            ID_ALREADY_CONNECTED => Self::AlreadyConnected(data),
            ID_NO_FREE_INCOMING_CONNECTIONS => Self::NoFreeIncomingConnections(data),
            ID_CONNECTION_BANNED => Self::ConnectionBanned(data),
            ID_IP_RECENTLY_CONNECTED => Self::IpRecentlyConnected(data),
            _ => return Err(DecodeError::InvalidOfflinePacketId(id)),
        })
    }

    pub fn id(&self) -> u8 {
        match self {
            Self::ConnectionRequestFailed(_) => ID_CONNECTION_REQUEST_FAILED,
            Self::AlreadyConnected(_) => ID_ALREADY_CONNECTED,
            Self::NoFreeIncomingConnections(_) => ID_NO_FREE_INCOMING_CONNECTIONS,
            Self::ConnectionBanned(_) => ID_CONNECTION_BANNED,
            Self::IpRecentlyConnected(_) => ID_IP_RECENTLY_CONNECTED,
        }
    }

    pub fn data(&self) -> &RejectData {
        match self {
            Self::ConnectionRequestFailed(d)
            | Self::AlreadyConnected(d)
            | Self::NoFreeIncomingConnections(d)
            | Self::ConnectionBanned(d)
            | Self::IpRecentlyConnected(d) => d,
        }
    }
}

pub fn decode(
    id: u8,
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<ConnectionRejectReason, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;

    ConnectionRejectReason::from_id(id, magic, server_guid)
}