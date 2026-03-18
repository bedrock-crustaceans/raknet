use std::net::SocketAddr;

use crate::client::RaknetClientEvent;
use crate::proxy::RaknetRelayProxyEvent;
use crate::server::{PeerId, RaknetServerEvent};
use crate::transport::TransportMetricsSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaknetEventSource {
    Server,
    Client,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaknetEventKind {
    Connected,
    Disconnected,
    Packet,
    OfflinePacket,
    Forwarded,
    Dropped,
    ReceiptAcked,
    DecodeError,
    RateLimited,
    SessionLimitReached,
    ProxyDropped,
    WorkerError,
    WorkerStopped,
    Metrics,
}

#[derive(Debug)]
pub enum RaknetEvent {
    Server(RaknetServerEvent),
    Client(RaknetClientEvent),
    Proxy(RaknetRelayProxyEvent),
}

impl RaknetEvent {
    pub fn source(&self) -> RaknetEventSource {
        match self {
            Self::Server(_) => RaknetEventSource::Server,
            Self::Client(_) => RaknetEventSource::Client,
            Self::Proxy(_) => RaknetEventSource::Proxy,
        }
    }

    pub fn kind(&self) -> RaknetEventKind {
        match self {
            Self::Server(event) => match event {
                RaknetServerEvent::PeerConnected { .. } => RaknetEventKind::Connected,
                RaknetServerEvent::PeerDisconnected { .. } => RaknetEventKind::Disconnected,
                RaknetServerEvent::Packet { .. } => RaknetEventKind::Packet,
                RaknetServerEvent::OfflinePacket { .. } => RaknetEventKind::OfflinePacket,
                RaknetServerEvent::ReceiptAcked { .. } => RaknetEventKind::ReceiptAcked,
                RaknetServerEvent::PeerRateLimited { .. } => RaknetEventKind::RateLimited,
                RaknetServerEvent::SessionLimitReached { .. } => {
                    RaknetEventKind::SessionLimitReached
                }
                RaknetServerEvent::ProxyDropped { .. } => RaknetEventKind::ProxyDropped,
                RaknetServerEvent::DecodeError { .. } => RaknetEventKind::DecodeError,
                RaknetServerEvent::WorkerError { .. } => RaknetEventKind::WorkerError,
                RaknetServerEvent::WorkerStopped { .. } => RaknetEventKind::WorkerStopped,
                RaknetServerEvent::Metrics { .. } => RaknetEventKind::Metrics,
            },
            Self::Client(event) => match event {
                RaknetClientEvent::Connected { .. } => RaknetEventKind::Connected,
                RaknetClientEvent::Packet { .. } => RaknetEventKind::Packet,
                RaknetClientEvent::ReceiptAcked { .. } => RaknetEventKind::ReceiptAcked,
                RaknetClientEvent::DecodeError { .. } => RaknetEventKind::DecodeError,
                RaknetClientEvent::Disconnected { .. } => RaknetEventKind::Disconnected,
            },
            Self::Proxy(event) => match event {
                RaknetRelayProxyEvent::SessionStarted { .. } => RaknetEventKind::Connected,
                RaknetRelayProxyEvent::Forwarded { .. } => RaknetEventKind::Forwarded,
                RaknetRelayProxyEvent::Dropped { .. } => RaknetEventKind::Dropped,
                RaknetRelayProxyEvent::DecodeError { .. } => RaknetEventKind::DecodeError,
                RaknetRelayProxyEvent::SessionClosed { .. } => RaknetEventKind::Disconnected,
                RaknetRelayProxyEvent::DownstreamRateLimited { .. } => RaknetEventKind::RateLimited,
                RaknetRelayProxyEvent::DownstreamSessionLimitReached { .. } => {
                    RaknetEventKind::SessionLimitReached
                }
                RaknetRelayProxyEvent::DownstreamProxyDropped { .. } => {
                    RaknetEventKind::ProxyDropped
                }
                RaknetRelayProxyEvent::DownstreamDecodeError { .. } => RaknetEventKind::DecodeError,
                RaknetRelayProxyEvent::DownstreamWorkerError { .. } => RaknetEventKind::WorkerError,
                RaknetRelayProxyEvent::DownstreamWorkerStopped { .. } => {
                    RaknetEventKind::WorkerStopped
                }
            },
        }
    }

    pub fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Server(event) => match event {
                RaknetServerEvent::PeerConnected { peer_id, .. }
                | RaknetServerEvent::PeerDisconnected { peer_id, .. }
                | RaknetServerEvent::Packet { peer_id, .. }
                | RaknetServerEvent::ReceiptAcked { peer_id, .. } => Some(*peer_id),
                RaknetServerEvent::OfflinePacket { .. }
                | RaknetServerEvent::PeerRateLimited { .. }
                | RaknetServerEvent::SessionLimitReached { .. }
                | RaknetServerEvent::ProxyDropped { .. }
                | RaknetServerEvent::DecodeError { .. }
                | RaknetServerEvent::WorkerError { .. }
                | RaknetServerEvent::WorkerStopped { .. }
                | RaknetServerEvent::Metrics { .. } => None,
            },
            Self::Client(_) => None,
            Self::Proxy(event) => match event {
                RaknetRelayProxyEvent::SessionStarted { peer_id, .. }
                | RaknetRelayProxyEvent::Forwarded { peer_id, .. }
                | RaknetRelayProxyEvent::Dropped { peer_id, .. }
                | RaknetRelayProxyEvent::DecodeError { peer_id, .. }
                | RaknetRelayProxyEvent::SessionClosed { peer_id, .. } => Some(*peer_id),
                RaknetRelayProxyEvent::DownstreamRateLimited { .. }
                | RaknetRelayProxyEvent::DownstreamSessionLimitReached { .. }
                | RaknetRelayProxyEvent::DownstreamProxyDropped { .. }
                | RaknetRelayProxyEvent::DownstreamDecodeError { .. }
                | RaknetRelayProxyEvent::DownstreamWorkerError { .. }
                | RaknetRelayProxyEvent::DownstreamWorkerStopped { .. } => None,
            },
        }
    }

    pub fn primary_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Server(event) => match event {
                RaknetServerEvent::PeerConnected { addr, .. }
                | RaknetServerEvent::PeerDisconnected { addr, .. }
                | RaknetServerEvent::Packet { addr, .. }
                | RaknetServerEvent::OfflinePacket { addr, .. }
                | RaknetServerEvent::ReceiptAcked { addr, .. }
                | RaknetServerEvent::PeerRateLimited { addr }
                | RaknetServerEvent::SessionLimitReached { addr }
                | RaknetServerEvent::ProxyDropped { addr }
                | RaknetServerEvent::DecodeError { addr, .. } => Some(*addr),
                RaknetServerEvent::WorkerError { .. }
                | RaknetServerEvent::WorkerStopped { .. }
                | RaknetServerEvent::Metrics { .. } => None,
            },
            Self::Client(event) => match event {
                RaknetClientEvent::Connected { server_addr, .. } => Some(*server_addr),
                RaknetClientEvent::Packet { .. }
                | RaknetClientEvent::ReceiptAcked { .. }
                | RaknetClientEvent::DecodeError { .. }
                | RaknetClientEvent::Disconnected { .. } => None,
            },
            Self::Proxy(event) => match event {
                RaknetRelayProxyEvent::SessionStarted {
                    downstream_addr, ..
                }
                | RaknetRelayProxyEvent::DownstreamRateLimited {
                    addr: downstream_addr,
                }
                | RaknetRelayProxyEvent::DownstreamSessionLimitReached {
                    addr: downstream_addr,
                }
                | RaknetRelayProxyEvent::DownstreamProxyDropped {
                    addr: downstream_addr,
                }
                | RaknetRelayProxyEvent::DownstreamDecodeError {
                    addr: downstream_addr,
                    ..
                } => Some(*downstream_addr),
                RaknetRelayProxyEvent::Forwarded { .. }
                | RaknetRelayProxyEvent::Dropped { .. }
                | RaknetRelayProxyEvent::DecodeError { .. }
                | RaknetRelayProxyEvent::SessionClosed { .. }
                | RaknetRelayProxyEvent::DownstreamWorkerError { .. }
                | RaknetRelayProxyEvent::DownstreamWorkerStopped { .. } => None,
            },
        }
    }

    pub fn payload_len(&self) -> Option<usize> {
        match self {
            Self::Server(event) => match event {
                RaknetServerEvent::Packet { payload, .. } => Some(payload.len()),
                _ => None,
            },
            Self::Client(event) => match event {
                RaknetClientEvent::Packet { payload, .. } => Some(payload.len()),
                _ => None,
            },
            Self::Proxy(event) => match event {
                RaknetRelayProxyEvent::Forwarded { payload_len, .. } => Some(*payload_len),
                _ => None,
            },
        }
    }

    pub fn decode_error(&self) -> Option<&str> {
        match self {
            Self::Server(event) => match event {
                RaknetServerEvent::DecodeError { error, .. } => Some(error.as_str()),
                _ => None,
            },
            Self::Client(event) => match event {
                RaknetClientEvent::DecodeError { error } => Some(error.as_str()),
                _ => None,
            },
            Self::Proxy(event) => match event {
                RaknetRelayProxyEvent::DecodeError { error, .. }
                | RaknetRelayProxyEvent::DownstreamDecodeError { error, .. } => {
                    Some(error.as_str())
                }
                _ => None,
            },
        }
    }

    pub fn metrics_snapshot(&self) -> Option<(usize, &TransportMetricsSnapshot, u64)> {
        match self {
            Self::Server(RaknetServerEvent::Metrics {
                shard_id,
                snapshot,
                dropped_non_critical_events,
            }) => Some((*shard_id, snapshot.as_ref(), *dropped_non_critical_events)),
            _ => None,
        }
    }

    pub fn as_server(&self) -> Option<&RaknetServerEvent> {
        match self {
            Self::Server(event) => Some(event),
            _ => None,
        }
    }

    pub fn as_client(&self) -> Option<&RaknetClientEvent> {
        match self {
            Self::Client(event) => Some(event),
            _ => None,
        }
    }

    pub fn as_proxy(&self) -> Option<&RaknetRelayProxyEvent> {
        match self {
            Self::Proxy(event) => Some(event),
            _ => None,
        }
    }
}

impl From<RaknetServerEvent> for RaknetEvent {
    fn from(value: RaknetServerEvent) -> Self {
        Self::Server(value)
    }
}

impl From<RaknetClientEvent> for RaknetEvent {
    fn from(value: RaknetClientEvent) -> Self {
        Self::Client(value)
    }
}

impl From<RaknetRelayProxyEvent> for RaknetEvent {
    fn from(value: RaknetRelayProxyEvent) -> Self {
        Self::Proxy(value)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{RaknetEvent, RaknetEventKind, RaknetEventSource};
    use crate::client::RaknetClientEvent;
    use crate::protocol::constants::DEFAULT_UNCONNECTED_MAGIC;
    use crate::protocol::packet::{OfflinePacket, UnconnectedPing};
    use crate::protocol::reliability::Reliability;
    use crate::proxy::{
        RaknetRelayProxyEvent, RelayDirection, RelayDropReason, RelaySessionCloseReason,
    };
    use crate::server::{PeerDisconnectReason, PeerId, RaknetServerEvent};
    use crate::transport::TransportMetricsSnapshot;

    #[test]
    fn server_packet_maps_to_common_fields() {
        let peer_id = PeerId::from_u64(7);
        let addr = "127.0.0.1:19132".parse().expect("valid socket addr");
        let event = RaknetEvent::from(RaknetServerEvent::Packet {
            peer_id,
            addr,
            payload: Bytes::from_static(b"abc"),
            reliability: Reliability::ReliableOrdered,
            reliable_index: None,
            sequence_index: None,
            ordering_index: None,
            ordering_channel: Some(0),
        });

        assert_eq!(event.source(), RaknetEventSource::Server);
        assert_eq!(event.kind(), RaknetEventKind::Packet);
        assert_eq!(event.peer_id(), Some(peer_id));
        assert_eq!(event.primary_addr(), Some(addr));
        assert_eq!(event.payload_len(), Some(3));
    }

    #[test]
    fn client_decode_error_is_exposed() {
        let event = RaknetEvent::from(RaknetClientEvent::DecodeError {
            error: "bad packet".to_string(),
        });

        assert_eq!(event.source(), RaknetEventSource::Client);
        assert_eq!(event.kind(), RaknetEventKind::DecodeError);
        assert_eq!(event.decode_error(), Some("bad packet"));
        assert!(event.peer_id().is_none());
        assert!(event.primary_addr().is_none());
    }

    #[test]
    fn proxy_drop_maps_to_common_kind_and_peer() {
        let peer_id = PeerId::from_u64(99);
        let event = RaknetEvent::from(RaknetRelayProxyEvent::Dropped {
            peer_id,
            direction: RelayDirection::DownstreamToUpstream,
            reason: RelayDropReason::NoSession,
        });

        assert_eq!(event.source(), RaknetEventSource::Proxy);
        assert_eq!(event.kind(), RaknetEventKind::Dropped);
        assert_eq!(event.peer_id(), Some(peer_id));
        assert!(event.primary_addr().is_none());
    }

    #[test]
    fn server_metrics_can_be_extracted() {
        let snapshot = TransportMetricsSnapshot {
            session_count: 3,
            ..TransportMetricsSnapshot::default()
        };

        let event = RaknetEvent::from(RaknetServerEvent::Metrics {
            shard_id: 2,
            snapshot: Box::new(snapshot),
            dropped_non_critical_events: 17,
        });

        let (shard_id, extracted_snapshot, dropped) =
            event.metrics_snapshot().expect("metrics must be present");
        assert_eq!(shard_id, 2);
        assert_eq!(dropped, 17);
        assert_eq!(extracted_snapshot.session_count, 3);
    }

    #[test]
    fn disconnected_kind_is_normalized_across_sources() {
        let server_peer_id = PeerId::from_u64(1);
        let server_addr = "127.0.0.1:19132".parse().expect("valid socket addr");
        let server_event = RaknetEvent::from(RaknetServerEvent::PeerDisconnected {
            peer_id: server_peer_id,
            addr: server_addr,
            reason: PeerDisconnectReason::Requested,
        });
        assert_eq!(server_event.kind(), RaknetEventKind::Disconnected);

        let client_event = RaknetEvent::from(RaknetClientEvent::Disconnected {
            reason: crate::client::ClientDisconnectReason::Requested,
        });
        assert_eq!(client_event.kind(), RaknetEventKind::Disconnected);

        let proxy_event = RaknetEvent::from(RaknetRelayProxyEvent::SessionClosed {
            peer_id: server_peer_id,
            reason: RelaySessionCloseReason::ProxyShutdown,
        });
        assert_eq!(proxy_event.kind(), RaknetEventKind::Disconnected);
    }

    #[test]
    fn server_offline_packet_maps_to_common_fields() {
        let addr = "127.0.0.1:19132".parse().expect("valid socket addr");
        let event = RaknetEvent::from(RaknetServerEvent::OfflinePacket {
            addr,
            packet: OfflinePacket::UnconnectedPing(UnconnectedPing {
                ping_time: 123,
                client_guid: 456,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            }),
        });

        assert_eq!(event.source(), RaknetEventSource::Server);
        assert_eq!(event.kind(), RaknetEventKind::OfflinePacket);
        assert_eq!(event.primary_addr(), Some(addr));
        assert!(event.peer_id().is_none());
        assert!(event.payload_len().is_none());
    }
}
