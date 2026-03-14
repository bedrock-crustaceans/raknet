//! High-level server API.
//!
//! [`RaknetServer`] provides an event-driven surface over the sharded transport
//! runtime. For ergonomic integration, use:
//! - [`ServerFacade`] for closure-based hooks
//! - [`EventFacade`] for handler-trait hooks
//! - [`SessionFacade`] for session-id based hooks

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use bytes::Bytes;
use tracing::{debug, info, warn};

use crate::concurrency::{FastMap, fast_map};
use crate::error::ConfigValidationError;
use crate::handshake::OfflinePacket;
use crate::protocol::reliability::Reliability;
use crate::protocol::sequence24::Sequence24;
use crate::session::RakPriority;
use crate::transport::{
    RemoteDisconnectReason, ShardedRuntimeConfig, ShardedRuntimeEvent, ShardedRuntimeHandle,
    ShardedSendPayload, TransportConfig, TransportEvent, TransportMetricsSnapshot,
    spawn_sharded_runtime,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Stable server-side identifier assigned to a connected peer.
pub struct PeerId(u64);

impl PeerId {
    /// Creates a [`PeerId`] from a raw `u64`.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying raw identifier.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Send policy used when dispatching payloads to a peer.
pub struct SendOptions {
    /// RakNet reliability class for the outgoing frame.
    pub reliability: Reliability,
    /// Ordering channel (used by ordered/sequenced reliabilities).
    pub channel: u8,
    /// Priority used by the session scheduler.
    pub priority: RakPriority,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            reliability: Reliability::ReliableOrdered,
            channel: 0,
            priority: RakPriority::High,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reason reported when a peer session is closed.
pub enum PeerDisconnectReason {
    Requested,
    RemoteDisconnectionNotification { reason_code: Option<u8> },
    RemoteDetectLostConnection,
    WorkerStopped { shard_id: usize },
}

#[derive(Debug)]
/// Event stream produced by [`RaknetServer::next_event`].
pub enum RaknetServerEvent {
    PeerConnected {
        peer_id: PeerId,
        addr: SocketAddr,
        client_guid: u64,
        shard_id: usize,
    },
    PeerDisconnected {
        peer_id: PeerId,
        addr: SocketAddr,
        reason: PeerDisconnectReason,
    },
    Packet {
        peer_id: PeerId,
        addr: SocketAddr,
        payload: Bytes,
        reliability: Reliability,
        reliable_index: Option<Sequence24>,
        sequence_index: Option<Sequence24>,
        ordering_index: Option<Sequence24>,
        ordering_channel: Option<u8>,
    },
    OfflinePacket {
        addr: SocketAddr,
        packet: OfflinePacket,
    },
    ReceiptAcked {
        peer_id: PeerId,
        addr: SocketAddr,
        receipt_id: u64,
    },
    PeerRateLimited {
        addr: SocketAddr,
    },
    SessionLimitReached {
        addr: SocketAddr,
    },
    ProxyDropped {
        addr: SocketAddr,
    },
    DecodeError {
        addr: SocketAddr,
        error: String,
    },
    WorkerError {
        shard_id: usize,
        message: String,
    },
    WorkerStopped {
        shard_id: usize,
    },
    Metrics {
        shard_id: usize,
        snapshot: Box<TransportMetricsSnapshot>,
        dropped_non_critical_events: u64,
    },
}

impl RaknetServerEvent {
    /// Returns metrics payload for [`RaknetServerEvent::Metrics`], otherwise `None`.
    pub fn metrics_snapshot(&self) -> Option<(usize, &TransportMetricsSnapshot, u64)> {
        match self {
            Self::Metrics {
                shard_id,
                snapshot,
                dropped_non_critical_events,
            } => Some((*shard_id, snapshot.as_ref(), *dropped_non_critical_events)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Hook payload for a newly connected peer.
pub struct ConnectEvent {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub client_guid: u64,
    pub shard_id: usize,
}

#[derive(Debug, Clone)]
/// Hook payload for an inbound application packet.
pub struct PacketEvent {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub payload: Bytes,
    pub reliability: Reliability,
    pub reliable_index: Option<Sequence24>,
    pub sequence_index: Option<Sequence24>,
    pub ordering_index: Option<Sequence24>,
    pub ordering_channel: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Hook payload for a disconnected peer.
pub struct DisconnectEvent {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub reason: PeerDisconnectReason,
}

/// Async return type used by server hook callbacks.
pub type ServerHookFuture<'a> = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

type ConnectHandler =
    Box<dyn for<'a> FnMut(&'a mut RaknetServer, ConnectEvent) -> ServerHookFuture<'a> + Send>;
type PacketHandler =
    Box<dyn for<'a> FnMut(&'a mut RaknetServer, PacketEvent) -> ServerHookFuture<'a> + Send>;
type DisconnectHandler =
    Box<dyn for<'a> FnMut(&'a mut RaknetServer, DisconnectEvent) -> ServerHookFuture<'a> + Send>;

/// Closure-based facade over [`RaknetServerEvent`] stream.
///
/// Useful when you want to wire small handlers without defining custom handler traits.
pub struct ServerFacade<'a> {
    server: &'a mut RaknetServer,
    on_connect: Option<ConnectHandler>,
    on_packet: Option<PacketHandler>,
    on_disconnect: Option<DisconnectHandler>,
}

impl<'a> ServerFacade<'a> {
    /// Creates a new facade around a mutable server reference.
    pub fn new(server: &'a mut RaknetServer) -> Self {
        Self {
            server,
            on_connect: None,
            on_packet: None,
            on_disconnect: None,
        }
    }

    /// Registers `on_connect` callback.
    pub fn on_connect<F>(mut self, handler: F) -> Self
    where
        F: for<'b> FnMut(&'b mut RaknetServer, ConnectEvent) -> ServerHookFuture<'b>
            + Send
            + 'static,
    {
        self.on_connect = Some(Box::new(handler));
        self
    }

    /// Registers `on_packet` callback.
    pub fn on_packet<F>(mut self, handler: F) -> Self
    where
        F: for<'b> FnMut(&'b mut RaknetServer, PacketEvent) -> ServerHookFuture<'b>
            + Send
            + 'static,
    {
        self.on_packet = Some(Box::new(handler));
        self
    }

    /// Registers `on_disconnect` callback.
    pub fn on_disconnect<F>(mut self, handler: F) -> Self
    where
        F: for<'b> FnMut(&'b mut RaknetServer, DisconnectEvent) -> ServerHookFuture<'b>
            + Send
            + 'static,
    {
        self.on_disconnect = Some(Box::new(handler));
        self
    }

    /// Polls one server event and dispatches to registered callbacks.
    ///
    /// Returns `Ok(false)` when the server event stream is closed.
    pub async fn next(&mut self) -> io::Result<bool> {
        let Some(event) = self.server.next_event().await else {
            return Ok(false);
        };
        self.dispatch(event).await?;
        Ok(true)
    }

    /// Runs the dispatch loop until stream closure or callback error.
    pub async fn run(&mut self) -> io::Result<()> {
        while self.next().await? {}
        Ok(())
    }

    /// Returns immutable access to wrapped server.
    pub fn server(&self) -> &RaknetServer {
        self.server
    }

    /// Returns mutable access to wrapped server.
    pub fn server_mut(&mut self) -> &mut RaknetServer {
        self.server
    }

    async fn dispatch(&mut self, event: RaknetServerEvent) -> io::Result<()> {
        match event {
            RaknetServerEvent::PeerConnected {
                peer_id,
                addr,
                client_guid,
                shard_id,
            } => {
                if let Some(handler) = self.on_connect.as_mut() {
                    handler(
                        self.server,
                        ConnectEvent {
                            peer_id,
                            addr,
                            client_guid,
                            shard_id,
                        },
                    )
                    .await?;
                }
            }
            RaknetServerEvent::Packet {
                peer_id,
                addr,
                payload,
                reliability,
                reliable_index,
                sequence_index,
                ordering_index,
                ordering_channel,
            } => {
                if let Some(handler) = self.on_packet.as_mut() {
                    handler(
                        self.server,
                        PacketEvent {
                            peer_id,
                            addr,
                            payload,
                            reliability,
                            reliable_index,
                            sequence_index,
                            ordering_index,
                            ordering_channel,
                        },
                    )
                    .await?;
                }
            }
            RaknetServerEvent::PeerDisconnected {
                peer_id,
                addr,
                reason,
            } => {
                if let Some(handler) = self.on_disconnect.as_mut() {
                    handler(
                        self.server,
                        DisconnectEvent {
                            peer_id,
                            addr,
                            reason,
                        },
                    )
                    .await?;
                }
            }
            RaknetServerEvent::OfflinePacket { .. }
            | RaknetServerEvent::ReceiptAcked { .. }
            | RaknetServerEvent::PeerRateLimited { .. }
            | RaknetServerEvent::SessionLimitReached { .. }
            | RaknetServerEvent::ProxyDropped { .. }
            | RaknetServerEvent::DecodeError { .. }
            | RaknetServerEvent::WorkerError { .. }
            | RaknetServerEvent::WorkerStopped { .. }
            | RaknetServerEvent::Metrics { .. } => {}
        }

        Ok(())
    }
}

/// Event-driven callback surface that mirrors RakLibInterface-style hooks.
///
/// This trait is intentionally event-driven and is fed from `RaknetServerEvent`.
/// All methods are optional and default to no-op.
pub trait EventFacadeHandler {
    fn on_connect<'a>(
        &'a mut self,
        _session_id: u64,
        _addr: IpAddr,
        _port: u16,
        _client_guid: u64,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_disconnect<'a>(
        &'a mut self,
        _session_id: u64,
        _reason: PeerDisconnectReason,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_packet<'a>(&'a mut self, _session_id: u64, _payload: Bytes) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_ack<'a>(&'a mut self, _session_id: u64, _receipt_id: u64) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_metrics<'a>(
        &'a mut self,
        _shard_id: usize,
        _snapshot: TransportMetricsSnapshot,
        _dropped_non_critical_events: u64,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

/// Dispatches a single [`RaknetServerEvent`] into an [`EventFacadeHandler`].
pub async fn dispatch_event_facade<H: EventFacadeHandler>(
    handler: &mut H,
    event: RaknetServerEvent,
) -> io::Result<()> {
    match event {
        RaknetServerEvent::PeerConnected {
            peer_id,
            addr,
            client_guid,
            ..
        } => {
            handler
                .on_connect(peer_id.as_u64(), addr.ip(), addr.port(), client_guid)
                .await?;
        }
        RaknetServerEvent::PeerDisconnected {
            peer_id, reason, ..
        } => {
            handler.on_disconnect(peer_id.as_u64(), reason).await?;
        }
        RaknetServerEvent::Packet {
            peer_id, payload, ..
        } => {
            handler.on_packet(peer_id.as_u64(), payload).await?;
        }
        RaknetServerEvent::ReceiptAcked {
            peer_id,
            receipt_id,
            ..
        } => {
            handler.on_ack(peer_id.as_u64(), receipt_id).await?;
        }
        RaknetServerEvent::Metrics {
            shard_id,
            snapshot,
            dropped_non_critical_events,
        } => {
            handler
                .on_metrics(shard_id, *snapshot, dropped_non_critical_events)
                .await?;
        }
        RaknetServerEvent::OfflinePacket { .. }
        | RaknetServerEvent::PeerRateLimited { .. }
        | RaknetServerEvent::SessionLimitReached { .. }
        | RaknetServerEvent::ProxyDropped { .. }
        | RaknetServerEvent::DecodeError { .. }
        | RaknetServerEvent::WorkerError { .. }
        | RaknetServerEvent::WorkerStopped { .. } => {}
    }

    Ok(())
}

/// Trait-based facade runner over server events.
pub struct EventFacade<'a, H: EventFacadeHandler> {
    server: &'a mut RaknetServer,
    handler: &'a mut H,
}

impl<'a, H: EventFacadeHandler> EventFacade<'a, H> {
    /// Creates a new event facade binding a server and handler.
    pub fn new(server: &'a mut RaknetServer, handler: &'a mut H) -> Self {
        Self { server, handler }
    }

    /// Polls one event and dispatches it into handler callbacks.
    ///
    /// Returns `Ok(false)` when the server event stream is closed.
    pub async fn next(&mut self) -> io::Result<bool> {
        let Some(event) = self.server.next_event().await else {
            return Ok(false);
        };
        self.dispatch(event).await?;
        Ok(true)
    }

    /// Runs the facade loop until closure or callback error.
    pub async fn run(&mut self) -> io::Result<()> {
        while self.next().await? {}
        Ok(())
    }

    /// Returns immutable access to wrapped server.
    pub fn server(&self) -> &RaknetServer {
        self.server
    }

    /// Returns mutable access to wrapped server.
    pub fn server_mut(&mut self) -> &mut RaknetServer {
        self.server
    }

    /// Returns immutable access to wrapped handler.
    pub fn handler(&self) -> &H {
        self.handler
    }

    /// Returns mutable access to wrapped handler.
    pub fn handler_mut(&mut self) -> &mut H {
        self.handler
    }

    async fn dispatch(&mut self, event: RaknetServerEvent) -> io::Result<()> {
        dispatch_event_facade(self.handler, event).await
    }
}

pub type SessionId = u32;

#[derive(Debug)]
/// Bidirectional mapping between [`PeerId`] and stable session ids.
pub struct SessionIdAdapter {
    peer_to_session: FastMap<PeerId, SessionId>,
    session_to_peer: FastMap<SessionId, PeerId>,
    next_session_id: SessionId,
}

impl Default for SessionIdAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionIdAdapter {
    /// Creates a new empty adapter.
    pub fn new() -> Self {
        Self {
            peer_to_session: fast_map(),
            session_to_peer: fast_map(),
            next_session_id: 1,
        }
    }

    /// Returns number of currently mapped sessions.
    pub fn len(&self) -> usize {
        self.peer_to_session.len()
    }

    /// Returns `true` if no session is currently mapped.
    pub fn is_empty(&self) -> bool {
        self.peer_to_session.is_empty()
    }

    /// Resolves a [`PeerId`] to session id.
    pub fn session_id_for_peer(&self, peer_id: PeerId) -> Option<SessionId> {
        self.peer_to_session.get(&peer_id).map(|entry| *entry)
    }

    /// Resolves a session id to [`PeerId`].
    pub fn peer_id_for_session(&self, session_id: SessionId) -> Option<PeerId> {
        self.session_to_peer.get(&session_id).map(|entry| *entry)
    }

    /// Resolves an `i32` session id to [`PeerId`].
    pub fn peer_id_for_session_i32(&self, session_id: i32) -> Option<PeerId> {
        let session_id = Self::session_id_from_i32(session_id)?;
        self.peer_id_for_session(session_id)
    }

    /// Registers peer and returns mapped session id.
    ///
    /// If peer is already registered, existing id is returned.
    pub fn register_peer(&mut self, peer_id: PeerId) -> io::Result<SessionId> {
        if let Some(existing) = self.session_id_for_peer(peer_id) {
            return Ok(existing);
        }

        let session_id = self.allocate_session_id()?;
        self.peer_to_session.insert(peer_id, session_id);
        self.session_to_peer.insert(session_id, peer_id);
        Ok(session_id)
    }

    /// Unregisters peer and returns removed session id, if present.
    pub fn unregister_peer(&mut self, peer_id: PeerId) -> Option<SessionId> {
        let (_, session_id) = self.peer_to_session.remove(&peer_id)?;
        self.session_to_peer.remove(&session_id);
        Some(session_id)
    }

    /// Clears all mappings and resets id allocator.
    pub fn clear(&mut self) {
        self.peer_to_session.clear();
        self.session_to_peer.clear();
        self.next_session_id = 1;
    }

    /// Converts internal session id to `i32` when representable.
    pub fn session_id_to_i32(session_id: SessionId) -> Option<i32> {
        i32::try_from(session_id).ok()
    }

    /// Converts `i32` session id into internal type.
    pub fn session_id_from_i32(session_id: i32) -> Option<SessionId> {
        u32::try_from(session_id).ok()
    }

    fn allocate_session_id(&mut self) -> io::Result<SessionId> {
        let mut candidate = if self.next_session_id == 0 {
            1
        } else {
            self.next_session_id
        };

        for _ in 0..u32::MAX {
            if !self.session_to_peer.contains_key(&candidate) {
                self.next_session_id = candidate.wrapping_add(1);
                if self.next_session_id == 0 {
                    self.next_session_id = 1;
                }
                return Ok(candidate);
            }

            candidate = candidate.wrapping_add(1);
            if candidate == 0 {
                candidate = 1;
            }
        }

        Err(io::Error::other("session id space exhausted"))
    }
}

/// Session-id based callback surface.
///
/// Use this when your application prefers integer session ids over [`PeerId`].
pub trait SessionFacadeHandler {
    fn on_connect<'a>(
        &'a mut self,
        _session_id: SessionId,
        _addr: IpAddr,
        _port: u16,
        _client_guid: u64,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_disconnect<'a>(
        &'a mut self,
        _session_id: SessionId,
        _reason: PeerDisconnectReason,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_packet<'a>(
        &'a mut self,
        _session_id: SessionId,
        _payload: Bytes,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_ack<'a>(&'a mut self, _session_id: SessionId, _receipt_id: u64) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn on_metrics<'a>(
        &'a mut self,
        _shard_id: usize,
        _snapshot: TransportMetricsSnapshot,
        _dropped_non_critical_events: u64,
    ) -> ServerHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

/// Dispatches a single event into a [`SessionFacadeHandler`].
pub async fn dispatch_session_facade<H: SessionFacadeHandler>(
    adapter: &mut SessionIdAdapter,
    handler: &mut H,
    event: RaknetServerEvent,
) -> io::Result<()> {
    match event {
        RaknetServerEvent::PeerConnected {
            peer_id,
            addr,
            client_guid,
            ..
        } => {
            let session_id = adapter.register_peer(peer_id)?;
            handler
                .on_connect(session_id, addr.ip(), addr.port(), client_guid)
                .await?;
        }
        RaknetServerEvent::PeerDisconnected {
            peer_id, reason, ..
        } => {
            if let Some(session_id) = adapter.session_id_for_peer(peer_id) {
                handler.on_disconnect(session_id, reason).await?;
                adapter.unregister_peer(peer_id);
            } else {
                debug!(
                    peer_id = peer_id.as_u64(),
                    ?reason,
                    "ignoring disconnect for unknown session id mapping"
                );
            }
        }
        RaknetServerEvent::Packet {
            peer_id, payload, ..
        } => {
            if let Some(session_id) = adapter.session_id_for_peer(peer_id) {
                handler.on_packet(session_id, payload).await?;
            } else {
                debug!(
                    peer_id = peer_id.as_u64(),
                    "dropping packet callback because session id mapping is missing"
                );
            }
        }
        RaknetServerEvent::ReceiptAcked {
            peer_id,
            receipt_id,
            ..
        } => {
            if let Some(session_id) = adapter.session_id_for_peer(peer_id) {
                handler.on_ack(session_id, receipt_id).await?;
            } else {
                debug!(
                    peer_id = peer_id.as_u64(),
                    receipt_id, "dropping ack callback because session id mapping is missing"
                );
            }
        }
        RaknetServerEvent::Metrics {
            shard_id,
            snapshot,
            dropped_non_critical_events,
        } => {
            handler
                .on_metrics(shard_id, *snapshot, dropped_non_critical_events)
                .await?;
        }
        RaknetServerEvent::OfflinePacket { .. }
        | RaknetServerEvent::PeerRateLimited { .. }
        | RaknetServerEvent::SessionLimitReached { .. }
        | RaknetServerEvent::ProxyDropped { .. }
        | RaknetServerEvent::DecodeError { .. }
        | RaknetServerEvent::WorkerError { .. }
        | RaknetServerEvent::WorkerStopped { .. } => {}
    }

    Ok(())
}

/// Session-id based facade over server events.
pub struct SessionFacade<'a, H: SessionFacadeHandler> {
    server: &'a mut RaknetServer,
    handler: &'a mut H,
    adapter: SessionIdAdapter,
}

impl<'a, H: SessionFacadeHandler> SessionFacade<'a, H> {
    /// Creates a new session facade with an empty [`SessionIdAdapter`].
    pub fn new(server: &'a mut RaknetServer, handler: &'a mut H) -> Self {
        Self {
            server,
            handler,
            adapter: SessionIdAdapter::new(),
        }
    }

    /// Creates a session facade with a caller-provided adapter.
    pub fn with_adapter(
        server: &'a mut RaknetServer,
        handler: &'a mut H,
        adapter: SessionIdAdapter,
    ) -> Self {
        Self {
            server,
            handler,
            adapter,
        }
    }

    /// Polls one event and dispatches it to the session handler.
    ///
    /// Returns `Ok(false)` when the server event stream is closed.
    pub async fn next(&mut self) -> io::Result<bool> {
        let Some(event) = self.server.next_event().await else {
            return Ok(false);
        };
        self.dispatch(event).await?;
        Ok(true)
    }

    /// Runs facade loop until stream closure or callback error.
    pub async fn run(&mut self) -> io::Result<()> {
        while self.next().await? {}
        Ok(())
    }

    /// Returns immutable access to wrapped server.
    pub fn server(&self) -> &RaknetServer {
        self.server
    }

    /// Returns mutable access to wrapped server.
    pub fn server_mut(&mut self) -> &mut RaknetServer {
        self.server
    }

    /// Returns immutable access to wrapped handler.
    pub fn handler(&self) -> &H {
        self.handler
    }

    /// Returns mutable access to wrapped handler.
    pub fn handler_mut(&mut self) -> &mut H {
        self.handler
    }

    /// Returns immutable access to the session-id adapter.
    pub fn adapter(&self) -> &SessionIdAdapter {
        &self.adapter
    }

    /// Returns mutable access to the session-id adapter.
    pub fn adapter_mut(&mut self) -> &mut SessionIdAdapter {
        &mut self.adapter
    }

    /// Resolves [`PeerId`] to session id.
    pub fn session_id_for_peer(&self, peer_id: PeerId) -> Option<SessionId> {
        self.adapter.session_id_for_peer(peer_id)
    }

    /// Resolves session id to [`PeerId`].
    pub fn peer_id_for_session(&self, session_id: SessionId) -> Option<PeerId> {
        self.adapter.peer_id_for_session(session_id)
    }

    /// Resolves i32 session id to [`PeerId`].
    pub fn peer_id_for_session_i32(&self, session_id: i32) -> Option<PeerId> {
        self.adapter.peer_id_for_session_i32(session_id)
    }

    /// Sends payload to a session with default send options.
    pub async fn send(
        &mut self,
        session_id: SessionId,
        payload: impl Into<Bytes>,
    ) -> io::Result<()> {
        let peer_id = self.resolve_peer_id(session_id)?;
        self.server.send(peer_id, payload).await
    }

    /// Sends payload to a session with explicit send options.
    pub async fn send_with_options(
        &mut self,
        session_id: SessionId,
        payload: impl Into<Bytes>,
        options: SendOptions,
    ) -> io::Result<()> {
        let peer_id = self.resolve_peer_id(session_id)?;
        self.server
            .send_with_options(peer_id, payload, options)
            .await
    }

    /// Sends payload to a session and tracks a receipt id.
    pub async fn send_with_receipt(
        &mut self,
        session_id: SessionId,
        payload: impl Into<Bytes>,
        receipt_id: u64,
    ) -> io::Result<()> {
        let peer_id = self.resolve_peer_id(session_id)?;
        self.server
            .send_with_receipt(peer_id, payload, receipt_id)
            .await
    }

    /// Disconnects a session.
    pub async fn disconnect(&mut self, session_id: SessionId) -> io::Result<()> {
        let peer_id = self.resolve_peer_id(session_id)?;
        self.server.disconnect(peer_id).await
    }

    async fn dispatch(&mut self, event: RaknetServerEvent) -> io::Result<()> {
        dispatch_session_facade(&mut self.adapter, self.handler, event).await
    }

    fn resolve_peer_id(&self, session_id: SessionId) -> io::Result<PeerId> {
        self.peer_id_for_session(session_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("session id {session_id} is not mapped to any peer"),
            )
        })
    }
}

#[derive(Debug, Clone, Default)]
/// Builder for [`RaknetServer`].
pub struct RaknetServerBuilder {
    transport_config: TransportConfig,
    runtime_config: ShardedRuntimeConfig,
}

impl RaknetServerBuilder {
    /// Replaces transport configuration.
    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.transport_config = config;
        self
    }

    /// Replaces runtime/shard configuration.
    pub fn runtime_config(mut self, config: ShardedRuntimeConfig) -> Self {
        self.runtime_config = config;
        self
    }

    /// Sets bind address in transport configuration.
    pub fn bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.transport_config.bind_addr = bind_addr;
        self
    }

    /// Sets shard count (minimum `1`).
    pub fn shard_count(mut self, shard_count: usize) -> Self {
        self.runtime_config.shard_count = shard_count.max(1);
        self
    }

    /// Returns mutable transport config for in-place adjustments.
    pub fn transport_config_mut(&mut self) -> &mut TransportConfig {
        &mut self.transport_config
    }

    /// Returns mutable runtime config for in-place adjustments.
    pub fn runtime_config_mut(&mut self) -> &mut ShardedRuntimeConfig {
        &mut self.runtime_config
    }

    /// Validates configs and starts the server.
    pub async fn start(self) -> io::Result<RaknetServer> {
        self.transport_config
            .validate()
            .map_err(invalid_config_io_error)?;
        self.runtime_config
            .validate()
            .map_err(invalid_config_io_error)?;
        RaknetServer::start_with_configs(self.transport_config, self.runtime_config).await
    }
}

#[derive(Debug, Clone, Copy)]
struct PeerBinding {
    peer_id: PeerId,
    shard_id: usize,
}

pub struct RaknetServer {
    runtime: ShardedRuntimeHandle,
    peers_by_addr: FastMap<SocketAddr, PeerBinding>,
    addrs_by_peer: FastMap<PeerId, SocketAddr>,
    pending_events: VecDeque<RaknetServerEvent>,
    next_peer_id: u64,
}

impl RaknetServer {
    /// Creates a default builder.
    pub fn builder() -> RaknetServerBuilder {
        RaknetServerBuilder::default()
    }

    /// Starts server with default configs and provided bind address.
    pub async fn bind(bind_addr: SocketAddr) -> io::Result<Self> {
        Self::builder().bind_addr(bind_addr).start().await
    }

    /// Creates closure-based facade over server event stream.
    pub fn facade(&mut self) -> ServerFacade<'_> {
        ServerFacade::new(self)
    }

    /// Creates trait-based event facade over server event stream.
    pub fn event_facade<'a, H: EventFacadeHandler>(
        &'a mut self,
        handler: &'a mut H,
    ) -> EventFacade<'a, H> {
        EventFacade::new(self, handler)
    }

    /// Creates session-id based facade over server event stream.
    pub fn session_facade<'a, H: SessionFacadeHandler>(
        &'a mut self,
        handler: &'a mut H,
    ) -> SessionFacade<'a, H> {
        SessionFacade::new(self, handler)
    }

    /// Starts server from explicit transport and runtime configurations.
    pub async fn start_with_configs(
        transport_config: TransportConfig,
        runtime_config: ShardedRuntimeConfig,
    ) -> io::Result<Self> {
        transport_config
            .validate()
            .map_err(invalid_config_io_error)?;
        runtime_config.validate().map_err(invalid_config_io_error)?;
        let runtime = spawn_sharded_runtime(transport_config, runtime_config).await?;
        Ok(Self {
            runtime,
            peers_by_addr: fast_map(),
            addrs_by_peer: fast_map(),
            pending_events: VecDeque::new(),
            next_peer_id: 1,
        })
    }

    /// Returns peer socket address for a peer id, if present.
    pub fn peer_addr(&self, peer_id: PeerId) -> Option<SocketAddr> {
        self.addrs_by_peer.get(&peer_id).map(|addr| *addr)
    }

    /// Returns shard id owning a peer, if present.
    pub fn peer_shard(&self, peer_id: PeerId) -> Option<usize> {
        let addr = self.addrs_by_peer.get(&peer_id).map(|addr| *addr)?;
        self.peers_by_addr
            .get(&addr)
            .map(|binding| binding.shard_id)
    }

    /// Resolves peer id by remote address, if known.
    pub fn peer_id_for_addr(&self, addr: SocketAddr) -> Option<PeerId> {
        self.peers_by_addr.get(&addr).map(|binding| binding.peer_id)
    }

    /// Sends payload with default send options.
    pub async fn send(&self, peer_id: PeerId, payload: impl Into<Bytes>) -> io::Result<()> {
        self.send_with_options(peer_id, payload, SendOptions::default())
            .await
    }

    /// Sends payload with explicit send options.
    pub async fn send_with_options(
        &self,
        peer_id: PeerId,
        payload: impl Into<Bytes>,
        options: SendOptions,
    ) -> io::Result<()> {
        let (addr, shard_id) = self.resolve_peer_route(peer_id)?;

        self.runtime
            .send_payload_to_shard(
                shard_id,
                ShardedSendPayload {
                    addr,
                    payload: payload.into(),
                    reliability: options.reliability,
                    channel: options.channel,
                    priority: options.priority,
                },
            )
            .await
    }

    /// Sends payload and tracks a receipt id.
    pub async fn send_with_receipt(
        &self,
        peer_id: PeerId,
        payload: impl Into<Bytes>,
        receipt_id: u64,
    ) -> io::Result<()> {
        self.send_with_options_and_receipt(peer_id, payload, SendOptions::default(), receipt_id)
            .await
    }

    /// Sends payload with explicit send options and receipt id.
    pub async fn send_with_options_and_receipt(
        &self,
        peer_id: PeerId,
        payload: impl Into<Bytes>,
        options: SendOptions,
        receipt_id: u64,
    ) -> io::Result<()> {
        let (addr, shard_id) = self.resolve_peer_route(peer_id)?;

        self.runtime
            .send_payload_to_shard_with_receipt(
                shard_id,
                ShardedSendPayload {
                    addr,
                    payload: payload.into(),
                    reliability: options.reliability,
                    channel: options.channel,
                    priority: options.priority,
                },
                receipt_id,
            )
            .await
    }

    /// Requests disconnection and emits a local disconnect event.
    pub async fn disconnect(&mut self, peer_id: PeerId) -> io::Result<()> {
        let (addr, shard_id) = self.resolve_peer_route(peer_id)?;
        info!(
            peer_id = peer_id.as_u64(),
            %addr,
            shard_id,
            "server disconnect requested"
        );

        self.runtime
            .disconnect_peer_from_shard(shard_id, addr)
            .await?;
        self.remove_peer(addr);
        self.pending_events
            .push_back(RaknetServerEvent::PeerDisconnected {
                peer_id,
                addr,
                reason: PeerDisconnectReason::Requested,
            });
        Ok(())
    }

    /// Polls next server event.
    ///
    /// Returns `None` when runtime event channel is closed.
    pub async fn next_event(&mut self) -> Option<RaknetServerEvent> {
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }

        loop {
            let runtime_event = self.runtime.event_rx.recv().await?;
            self.enqueue_runtime_event(runtime_event);
            if let Some(event) = self.pending_events.pop_front() {
                return Some(event);
            }
        }
    }

    /// Gracefully stops all workers and closes sockets.
    pub async fn shutdown(self) -> io::Result<()> {
        self.runtime.shutdown().await
    }

    fn enqueue_runtime_event(&mut self, runtime_event: ShardedRuntimeEvent) {
        match runtime_event {
            ShardedRuntimeEvent::Transport { shard_id, event } => match event {
                TransportEvent::PeerDisconnected { addr, reason } => {
                    if let Some(peer_id) = self.remove_peer(addr) {
                        let reason = match reason {
                            RemoteDisconnectReason::DisconnectionNotification { reason_code } => {
                                PeerDisconnectReason::RemoteDisconnectionNotification {
                                    reason_code,
                                }
                            }
                            RemoteDisconnectReason::DetectLostConnection => {
                                PeerDisconnectReason::RemoteDetectLostConnection
                            }
                        };
                        info!(
                            peer_id = peer_id.as_u64(),
                            %addr,
                            ?reason,
                            "peer disconnected"
                        );
                        self.pending_events
                            .push_back(RaknetServerEvent::PeerDisconnected {
                                peer_id,
                                addr,
                                reason,
                            });
                    } else {
                        debug!(
                            %addr,
                            ?reason,
                            "received peer disconnect for unknown address"
                        );
                    }
                }
                TransportEvent::ConnectedFrames {
                    addr,
                    client_guid,
                    frames,
                    receipts,
                    ..
                } => {
                    let has_frames = !frames.is_empty();
                    let has_receipts = !receipts.acked_receipt_ids.is_empty();

                    if client_guid.is_none() && !has_frames && !has_receipts {
                        debug!(
                            %addr,
                            shard_id,
                            "ignoring pre-connect transport event without frames/receipts"
                        );
                    } else {
                        let (peer_id, is_new) = self.ensure_peer(addr, shard_id);
                        if is_new {
                            let client_guid = client_guid.unwrap_or(peer_id.as_u64());
                            info!(
                                peer_id = peer_id.as_u64(),
                                %addr,
                                client_guid,
                                shard_id,
                                "peer connected"
                            );
                            self.pending_events
                                .push_back(RaknetServerEvent::PeerConnected {
                                    peer_id,
                                    addr,
                                    client_guid,
                                    shard_id,
                                });
                        }

                        for frame in frames {
                            self.pending_events.push_back(RaknetServerEvent::Packet {
                                peer_id,
                                addr,
                                payload: frame.payload,
                                reliability: frame.reliability,
                                reliable_index: frame.reliable_index,
                                sequence_index: frame.sequence_index,
                                ordering_index: frame.ordering_index,
                                ordering_channel: frame.ordering_channel,
                            });
                        }

                        for receipt_id in receipts.acked_receipt_ids {
                            self.pending_events
                                .push_back(RaknetServerEvent::ReceiptAcked {
                                    peer_id,
                                    addr,
                                    receipt_id,
                                });
                        }
                    }
                }
                TransportEvent::RateLimited { addr } => {
                    warn!(%addr, "peer rate-limited");
                    self.pending_events
                        .push_back(RaknetServerEvent::PeerRateLimited { addr });
                }
                TransportEvent::SessionLimitReached { addr } => {
                    warn!(%addr, "session limit reached");
                    self.pending_events
                        .push_back(RaknetServerEvent::SessionLimitReached { addr });
                }
                TransportEvent::ConnectedDatagramDroppedNoSession { .. } => {}
                TransportEvent::ProxyDropped { addr } => {
                    debug!(%addr, "proxy router dropped packet");
                    self.pending_events
                        .push_back(RaknetServerEvent::ProxyDropped { addr });
                }
                TransportEvent::DecodeError { addr, error } => {
                    warn!(%addr, %error, "transport decode error");
                    self.pending_events
                        .push_back(RaknetServerEvent::DecodeError {
                            addr,
                            error: error.to_string(),
                        });
                }
                TransportEvent::OfflinePacket { addr, packet } => {
                    self.pending_events
                        .push_back(RaknetServerEvent::OfflinePacket { addr, packet });
                }
            },
            ShardedRuntimeEvent::Metrics {
                shard_id,
                snapshot,
                dropped_non_critical_events,
            } => {
                if dropped_non_critical_events > 0 {
                    debug!(
                        shard_id,
                        dropped_non_critical_events,
                        "non-critical runtime events were dropped before metrics emit"
                    );
                }
                self.pending_events.push_back(RaknetServerEvent::Metrics {
                    shard_id,
                    snapshot,
                    dropped_non_critical_events,
                });
            }
            ShardedRuntimeEvent::WorkerError { shard_id, message } => {
                warn!(shard_id, %message, "runtime worker error");
                self.pending_events
                    .push_back(RaknetServerEvent::WorkerError { shard_id, message });
            }
            ShardedRuntimeEvent::WorkerStopped { shard_id } => {
                warn!(shard_id, "runtime worker stopped");
                let mut disconnected = Vec::new();
                for peer in self.peers_by_addr.iter() {
                    let addr = *peer.key();
                    let binding = *peer.value();
                    if binding.shard_id == shard_id {
                        disconnected.push((addr, binding.peer_id));
                    }
                }
                for (addr, peer_id) in disconnected {
                    self.remove_peer(addr);
                    info!(
                        peer_id = peer_id.as_u64(),
                        %addr,
                        shard_id,
                        "peer disconnected because worker stopped"
                    );
                    self.pending_events
                        .push_back(RaknetServerEvent::PeerDisconnected {
                            peer_id,
                            addr,
                            reason: PeerDisconnectReason::WorkerStopped { shard_id },
                        });
                }
                self.pending_events
                    .push_back(RaknetServerEvent::WorkerStopped { shard_id });
            }
        }
    }

    fn ensure_peer(&mut self, addr: SocketAddr, shard_id: usize) -> (PeerId, bool) {
        if let Some(mut binding) = self.peers_by_addr.get_mut(&addr) {
            if binding.shard_id != shard_id {
                binding.shard_id = shard_id;
            }
            return (binding.peer_id, false);
        }

        let peer_id = PeerId(self.next_peer_id);
        self.next_peer_id = self.next_peer_id.saturating_add(1);
        self.peers_by_addr
            .insert(addr, PeerBinding { peer_id, shard_id });
        self.addrs_by_peer.insert(peer_id, addr);
        (peer_id, true)
    }

    fn remove_peer(&mut self, addr: SocketAddr) -> Option<PeerId> {
        let (_, binding) = self.peers_by_addr.remove(&addr)?;
        self.addrs_by_peer.remove(&binding.peer_id);
        Some(binding.peer_id)
    }

    fn resolve_peer_route(&self, peer_id: PeerId) -> io::Result<(SocketAddr, usize)> {
        let addr = self
            .addrs_by_peer
            .get(&peer_id)
            .map(|entry| *entry)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer id not found"))?;
        let shard_id = self
            .peers_by_addr
            .get(&addr)
            .map(|binding| binding.shard_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer shard binding missing"))?;
        Ok((addr, shard_id))
    }
}

fn invalid_config_io_error(error: ConfigValidationError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        EventFacadeHandler, PeerDisconnectReason, PeerId, RaknetServer, RaknetServerBuilder,
        RaknetServerEvent, ServerHookFuture, SessionFacadeHandler, SessionId, SessionIdAdapter,
        dispatch_event_facade, dispatch_session_facade,
    };
    use crate::protocol::reliability::Reliability;
    use crate::transport::{ShardedRuntimeConfig, TransportConfig, TransportMetricsSnapshot};
    use bytes::Bytes;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn builder_mutators_keep_values() {
        let builder = RaknetServerBuilder::default().shard_count(4);
        assert_eq!(builder.runtime_config.shard_count, 4);
    }

    #[test]
    fn peer_id_roundtrip() {
        let peer = PeerId::from_u64(42);
        assert_eq!(peer.as_u64(), 42);
    }

    #[test]
    fn builder_type_is_exposed() {
        let _ = RaknetServer::builder();
    }

    #[tokio::test]
    async fn start_with_invalid_runtime_config_fails_fast() {
        let transport = TransportConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            ..TransportConfig::default()
        };
        let runtime = ShardedRuntimeConfig {
            shard_count: 0,
            ..ShardedRuntimeConfig::default()
        };

        match RaknetServer::start_with_configs(transport, runtime).await {
            Ok(_) => panic!("invalid config must fail before runtime start"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }

    #[derive(Default)]
    struct CountingEventHandler {
        connect_calls: usize,
        disconnect_calls: usize,
        packet_calls: usize,
        ack_calls: usize,
        metrics_calls: usize,
        last_connect: Option<(u64, IpAddr, u16, u64)>,
        last_disconnect: Option<(u64, PeerDisconnectReason)>,
        last_packet: Option<(u64, Bytes)>,
        last_ack: Option<(u64, u64)>,
        last_metrics: Option<(usize, TransportMetricsSnapshot, u64)>,
    }

    impl EventFacadeHandler for CountingEventHandler {
        fn on_connect<'a>(
            &'a mut self,
            session_id: u64,
            addr: IpAddr,
            port: u16,
            client_guid: u64,
        ) -> ServerHookFuture<'a> {
            self.connect_calls = self.connect_calls.saturating_add(1);
            self.last_connect = Some((session_id, addr, port, client_guid));
            Box::pin(async { Ok(()) })
        }

        fn on_disconnect<'a>(
            &'a mut self,
            session_id: u64,
            reason: PeerDisconnectReason,
        ) -> ServerHookFuture<'a> {
            self.disconnect_calls = self.disconnect_calls.saturating_add(1);
            self.last_disconnect = Some((session_id, reason));
            Box::pin(async { Ok(()) })
        }

        fn on_packet<'a>(&'a mut self, session_id: u64, payload: Bytes) -> ServerHookFuture<'a> {
            self.packet_calls = self.packet_calls.saturating_add(1);
            self.last_packet = Some((session_id, payload));
            Box::pin(async { Ok(()) })
        }

        fn on_ack<'a>(&'a mut self, session_id: u64, receipt_id: u64) -> ServerHookFuture<'a> {
            self.ack_calls = self.ack_calls.saturating_add(1);
            self.last_ack = Some((session_id, receipt_id));
            Box::pin(async { Ok(()) })
        }

        fn on_metrics<'a>(
            &'a mut self,
            shard_id: usize,
            snapshot: TransportMetricsSnapshot,
            dropped_non_critical_events: u64,
        ) -> ServerHookFuture<'a> {
            self.metrics_calls = self.metrics_calls.saturating_add(1);
            self.last_metrics = Some((shard_id, snapshot, dropped_non_critical_events));
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn dispatch_event_facade_maps_callbacks() -> io::Result<()> {
        let mut handler = CountingEventHandler::default();
        let peer_id = PeerId::from_u64(77);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 19132);
        let payload = Bytes::from_static(b"\x01\x02event");
        let metrics = TransportMetricsSnapshot {
            packets_forwarded_total: 33,
            bytes_forwarded_total: 1200,
            ..TransportMetricsSnapshot::default()
        };

        dispatch_event_facade(
            &mut handler,
            RaknetServerEvent::PeerConnected {
                peer_id,
                addr,
                client_guid: 0xAABB_CCDD_EEFF_0011,
                shard_id: 2,
            },
        )
        .await?;

        dispatch_event_facade(
            &mut handler,
            RaknetServerEvent::Packet {
                peer_id,
                addr,
                payload: payload.clone(),
                reliability: Reliability::ReliableOrdered,
                reliable_index: None,
                sequence_index: None,
                ordering_index: None,
                ordering_channel: None,
            },
        )
        .await?;

        dispatch_event_facade(
            &mut handler,
            RaknetServerEvent::ReceiptAcked {
                peer_id,
                addr,
                receipt_id: 9001,
            },
        )
        .await?;

        dispatch_event_facade(
            &mut handler,
            RaknetServerEvent::Metrics {
                shard_id: 2,
                snapshot: Box::new(metrics),
                dropped_non_critical_events: 5,
            },
        )
        .await?;

        dispatch_event_facade(
            &mut handler,
            RaknetServerEvent::PeerDisconnected {
                peer_id,
                addr,
                reason: PeerDisconnectReason::Requested,
            },
        )
        .await?;

        dispatch_event_facade(
            &mut handler,
            RaknetServerEvent::WorkerStopped { shard_id: 0 },
        )
        .await?;

        assert_eq!(handler.connect_calls, 1);
        assert_eq!(handler.packet_calls, 1);
        assert_eq!(handler.ack_calls, 1);
        assert_eq!(handler.metrics_calls, 1);
        assert_eq!(handler.disconnect_calls, 1);
        assert_eq!(
            handler.last_connect,
            Some((77, addr.ip(), addr.port(), 0xAABB_CCDD_EEFF_0011))
        );
        assert_eq!(handler.last_packet, Some((77, payload)));
        assert_eq!(handler.last_ack, Some((77, 9001)));
        let (metrics_shard, metrics_snapshot, metrics_dropped) = handler
            .last_metrics
            .expect("metrics callback should store last snapshot");
        assert_eq!(metrics_shard, 2);
        assert_eq!(metrics_dropped, 5);
        assert_eq!(metrics_snapshot.packets_forwarded_total, 33);
        assert_eq!(metrics_snapshot.bytes_forwarded_total, 1200);
        assert_eq!(
            handler.last_disconnect,
            Some((77, PeerDisconnectReason::Requested))
        );

        Ok(())
    }

    #[derive(Default)]
    struct CountingSessionHandler {
        connect_calls: usize,
        disconnect_calls: usize,
        packet_calls: usize,
        ack_calls: usize,
        metrics_calls: usize,
        last_connect: Option<(SessionId, IpAddr, u16, u64)>,
        last_disconnect: Option<(SessionId, PeerDisconnectReason)>,
        last_packet: Option<(SessionId, Bytes)>,
        last_ack: Option<(SessionId, u64)>,
        last_metrics: Option<(usize, TransportMetricsSnapshot, u64)>,
    }

    impl SessionFacadeHandler for CountingSessionHandler {
        fn on_connect<'a>(
            &'a mut self,
            session_id: SessionId,
            addr: IpAddr,
            port: u16,
            client_guid: u64,
        ) -> ServerHookFuture<'a> {
            self.connect_calls = self.connect_calls.saturating_add(1);
            self.last_connect = Some((session_id, addr, port, client_guid));
            Box::pin(async { Ok(()) })
        }

        fn on_disconnect<'a>(
            &'a mut self,
            session_id: SessionId,
            reason: PeerDisconnectReason,
        ) -> ServerHookFuture<'a> {
            self.disconnect_calls = self.disconnect_calls.saturating_add(1);
            self.last_disconnect = Some((session_id, reason));
            Box::pin(async { Ok(()) })
        }

        fn on_packet<'a>(
            &'a mut self,
            session_id: SessionId,
            payload: Bytes,
        ) -> ServerHookFuture<'a> {
            self.packet_calls = self.packet_calls.saturating_add(1);
            self.last_packet = Some((session_id, payload));
            Box::pin(async { Ok(()) })
        }

        fn on_ack<'a>(
            &'a mut self,
            session_id: SessionId,
            receipt_id: u64,
        ) -> ServerHookFuture<'a> {
            self.ack_calls = self.ack_calls.saturating_add(1);
            self.last_ack = Some((session_id, receipt_id));
            Box::pin(async { Ok(()) })
        }

        fn on_metrics<'a>(
            &'a mut self,
            shard_id: usize,
            snapshot: TransportMetricsSnapshot,
            dropped_non_critical_events: u64,
        ) -> ServerHookFuture<'a> {
            self.metrics_calls = self.metrics_calls.saturating_add(1);
            self.last_metrics = Some((shard_id, snapshot, dropped_non_critical_events));
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn session_id_adapter_bridges_peer_and_signed_ids() {
        let mut adapter = SessionIdAdapter::new();
        let peer_a = PeerId::from_u64(0x1_0000_0001);
        let peer_b = PeerId::from_u64(0x2_0000_0002);

        let session_a = adapter
            .register_peer(peer_a)
            .expect("first session id allocation should succeed");
        let session_b = adapter
            .register_peer(peer_b)
            .expect("second session id allocation should succeed");

        assert_eq!(session_a, 1);
        assert_eq!(session_b, 2);
        assert_eq!(adapter.session_id_for_peer(peer_a), Some(session_a));
        assert_eq!(adapter.peer_id_for_session(session_b), Some(peer_b));
        assert_eq!(adapter.peer_id_for_session_i32(2), Some(peer_b));
        assert_eq!(adapter.peer_id_for_session_i32(-1), None);
        assert_eq!(SessionIdAdapter::session_id_to_i32(session_a), Some(1));
        assert_eq!(SessionIdAdapter::session_id_from_i32(2), Some(2));
        assert_eq!(SessionIdAdapter::session_id_from_i32(-5), None);

        assert_eq!(adapter.unregister_peer(peer_a), Some(session_a));
        assert_eq!(adapter.session_id_for_peer(peer_a), None);
        assert_eq!(adapter.peer_id_for_session(session_a), None);
    }

    #[tokio::test]
    async fn dispatch_session_facade_maps_callbacks_and_releases_mapping() -> io::Result<()> {
        let mut adapter = SessionIdAdapter::new();
        let mut handler = CountingSessionHandler::default();
        let peer_id = PeerId::from_u64(0xDEAD_BEEF_F00D);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3)), 19133);
        let payload = Bytes::from_static(b"\x10\x20session");
        let metrics = TransportMetricsSnapshot {
            packets_forwarded_total: 5,
            bytes_forwarded_total: 80,
            ..TransportMetricsSnapshot::default()
        };

        dispatch_session_facade(
            &mut adapter,
            &mut handler,
            RaknetServerEvent::PeerConnected {
                peer_id,
                addr,
                client_guid: 0xABCD_EF01_0203_0405,
                shard_id: 0,
            },
        )
        .await?;

        let session_id = adapter
            .session_id_for_peer(peer_id)
            .expect("session id should be registered after connect");
        assert_eq!(session_id, 1);

        dispatch_session_facade(
            &mut adapter,
            &mut handler,
            RaknetServerEvent::Packet {
                peer_id,
                addr,
                payload: payload.clone(),
                reliability: Reliability::ReliableOrdered,
                reliable_index: None,
                sequence_index: None,
                ordering_index: None,
                ordering_channel: None,
            },
        )
        .await?;

        dispatch_session_facade(
            &mut adapter,
            &mut handler,
            RaknetServerEvent::ReceiptAcked {
                peer_id,
                addr,
                receipt_id: 44,
            },
        )
        .await?;

        dispatch_session_facade(
            &mut adapter,
            &mut handler,
            RaknetServerEvent::Metrics {
                shard_id: 0,
                snapshot: Box::new(metrics),
                dropped_non_critical_events: 7,
            },
        )
        .await?;

        dispatch_session_facade(
            &mut adapter,
            &mut handler,
            RaknetServerEvent::PeerDisconnected {
                peer_id,
                addr,
                reason: PeerDisconnectReason::Requested,
            },
        )
        .await?;

        assert_eq!(handler.connect_calls, 1);
        assert_eq!(handler.packet_calls, 1);
        assert_eq!(handler.ack_calls, 1);
        assert_eq!(handler.metrics_calls, 1);
        assert_eq!(handler.disconnect_calls, 1);
        assert_eq!(
            handler.last_connect,
            Some((1, addr.ip(), addr.port(), 0xABCD_EF01_0203_0405))
        );
        assert_eq!(handler.last_packet, Some((1, payload)));
        assert_eq!(handler.last_ack, Some((1, 44)));
        assert_eq!(
            handler.last_disconnect,
            Some((1, PeerDisconnectReason::Requested))
        );
        assert_eq!(adapter.session_id_for_peer(peer_id), None);
        assert_eq!(adapter.peer_id_for_session(1), None);

        let (metrics_shard, metrics_snapshot, metrics_dropped) = handler
            .last_metrics
            .expect("metrics callback should store last snapshot");
        assert_eq!(metrics_shard, 0);
        assert_eq!(metrics_dropped, 7);
        assert_eq!(metrics_snapshot.packets_forwarded_total, 5);
        assert_eq!(metrics_snapshot.bytes_forwarded_total, 80);

        Ok(())
    }
}
