//! `raknet-rust` is an asynchronous RakNet transport library.
//!
//! The crate exposes two API layers:
//! - High-level application API: [`server`], [`client`], [`listener`], [`connection`]
//! - Low-level protocol/session/transport API: [`low_level`]
//!
//! # Quick Start (Server)
//! ```rust,no_run
//! use raknet_rust::server::{RaknetServer, RaknetServerEvent};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> std::io::Result<()> {
//!     let mut server = RaknetServer::bind("0.0.0.0:19132".parse().unwrap()).await?;
//!
//!     while let Some(event) = server.next_event().await {
//!         if let RaknetServerEvent::Packet { peer_id, payload, .. } = event {
//!             server.send(peer_id, payload).await?;
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Quick Start (Client)
//! ```rust,no_run
//! use raknet_rust::client::{RaknetClient, RaknetClientEvent};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> std::io::Result<()> {
//!     let mut client = RaknetClient::connect("127.0.0.1:19132".parse().unwrap()).await?;
//!
//!     while let Some(event) = client.next_event().await {
//!         match event {
//!             RaknetClientEvent::Connected { .. } => {
//!                 client.send(&b"hello"[..]).await?;
//!             }
//!             RaknetClientEvent::Packet { .. } => break,
//!             RaknetClientEvent::Disconnected { .. } => break,
//!             _ => {}
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
pub mod client;
mod concurrency;
pub mod connection;
pub mod error;
pub mod event;
pub mod handshake;
pub mod listener;
mod protocol;
pub mod proxy;
pub mod server;
mod session;
pub mod telemetry;
mod transport;

/// Advanced low-level API surface.
///
/// This namespace exposes protocol/session/transport internals for users that need
/// fine-grained control over wire behavior and runtime tuning.
pub mod low_level {
    /// Wire-level packet/datagram/frame primitives and codecs.
    pub mod protocol {
        pub use crate::protocol::{
            AckNackPayload, ConnectedControlPacket, Datagram, DatagramHeader, DatagramPayload,
            Frame, FrameHeader, RaknetCodec, Reliability, Sequence24, SequenceRange, SplitInfo,
            ack, codec, connected, constants, datagram, frame, frame_header, primitives,
            reliability, sequence24,
        };
    }

    /// Session internals such as queue behavior and reliability tuning.
    pub mod session {
        pub use crate::session::tunables;
        pub use crate::session::{
            QueuePayloadResult, RakPriority, ReceiptProgress, Session, SessionMetricsSnapshot,
            SessionState, TrackedDatagram,
        };
    }

    /// Transport runtime internals, shard runtime config, and routing policies.
    pub mod transport {
        pub use crate::transport::{
            ConnectedFrameDelivery, EventOverflowPolicy, HandshakeHeuristicsConfig,
            IdentityProxyRouter, InboundProxyRoute, OutboundProxyRoute, ProxyRouter,
            QueueDispatchResult, RemoteDisconnectReason, SessionTunables, ShardedRuntimeCommand,
            ShardedRuntimeConfig, ShardedRuntimeEvent, ShardedRuntimeHandle, ShardedSendPayload,
            TransportConfig, TransportEvent, TransportMetricsSnapshot, TransportRateLimitConfig,
            TransportServer,
        };
    }
}

pub use connection::{
    Connection, ConnectionCloseReason, ConnectionId, ConnectionIo, ConnectionMetadata, RecvError,
};
pub use error::{ConfigValidationError, DecodeError, EncodeError};
pub use listener::{Incoming, Listener, ListenerMetadata};
pub use low_level::protocol::{ConnectedControlPacket, Reliability, Sequence24};
pub use low_level::session::RakPriority;
pub use low_level::transport::{
    EventOverflowPolicy, ShardedRuntimeConfig, TransportConfig, TransportMetricsSnapshot,
};
