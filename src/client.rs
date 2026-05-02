use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::{self, sleep};
use tracing::{debug, info, warn};

use crate::error::ConfigValidationError;
use crate::protocol::connected::{
    ConnectedControlPacket, ConnectedPing, ConnectedPong, ConnectionRequest,
    ConnectionRequestAccepted, DetectLostConnection, DisconnectionNotification,
    NewIncomingConnection, SYSTEM_ADDRESS_COUNT,
};
use crate::protocol::constants::{
    DEFAULT_UNCONNECTED_MAGIC, MAXIMUM_MTU_SIZE, MINIMUM_MTU_SIZE, MTU_PROBE_ORDER,
    RAKNET_PROTOCOL_VERSION,
};
use crate::protocol::datagram::Datagram;
use crate::protocol::packet::{ConnectionRejectReason, OfflinePacket, OpenConnectionReply1, OpenConnectionReply2, OpenConnectionRequest1, OpenConnectionRequest2, Request2ParsePath};
use crate::protocol::reliability::Reliability;
use crate::protocol::sequence24::Sequence24;
use crate::session::{
    QueuePayloadResult, RakPriority, Session, SessionMetricsSnapshot, SessionState,
};

pub type ClientResult<T> = Result<T, RaknetClientError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientSendOptions {
    /// RakNet reliability class for outgoing payload.
    pub reliability: Reliability,
    /// Ordering channel for ordered/sequenced reliabilities.
    pub channel: u8,
    /// Session scheduling priority.
    pub priority: RakPriority,
}

impl Default for ClientSendOptions {
    fn default() -> Self {
        Self {
            reliability: Reliability::ReliableOrdered,
            channel: 0,
            priority: RakPriority::High,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RaknetClientConfig {
    pub local_addr: Option<SocketAddr>,
    pub guid: u64,
    pub protocol_version: u8,
    pub mtu: u16,
    pub mtu_probe_order: Vec<u16>,
    pub mtu_probe_attempts_per_step: usize,
    pub mtu_probe_wait_per_attempt: Duration,
    pub handshake_timeout: Duration,
    pub outbound_tick_interval: Duration,
    pub session_keepalive_interval: Duration,
    pub session_idle_timeout: Duration,
    pub recv_buffer_capacity: usize,
    pub max_new_datagrams_per_tick: usize,
    pub max_new_bytes_per_tick: usize,
    pub max_resend_datagrams_per_tick: usize,
    pub max_resend_bytes_per_tick: usize,
    pub max_new_datagrams_per_recv: usize,
    pub max_new_bytes_per_recv: usize,
    pub max_resend_datagrams_per_recv: usize,
    pub max_resend_bytes_per_recv: usize,
}

impl Default for RaknetClientConfig {
    fn default() -> Self {
        Self {
            local_addr: None,
            guid: random_guid(),
            protocol_version: RAKNET_PROTOCOL_VERSION,
            mtu: 1200,
            mtu_probe_order: MTU_PROBE_ORDER.to_vec(),
            mtu_probe_attempts_per_step: 2,
            mtu_probe_wait_per_attempt: Duration::from_millis(350),
            handshake_timeout: Duration::from_secs(5),
            outbound_tick_interval: Duration::from_millis(10),
            session_keepalive_interval: Duration::from_secs(10),
            session_idle_timeout: Duration::from_secs(30),
            recv_buffer_capacity: MAXIMUM_MTU_SIZE as usize,
            max_new_datagrams_per_tick: 8,
            max_new_bytes_per_tick: 64 * 1024,
            max_resend_datagrams_per_tick: 8,
            max_resend_bytes_per_tick: 64 * 1024,
            max_new_datagrams_per_recv: 6,
            max_new_bytes_per_recv: 64 * 1024,
            max_resend_datagrams_per_recv: 6,
            max_resend_bytes_per_recv: 64 * 1024,
        }
    }
}

impl RaknetClientConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !(MINIMUM_MTU_SIZE..=MAXIMUM_MTU_SIZE).contains(&self.mtu) {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "mtu",
                format!(
                    "must be within [{MINIMUM_MTU_SIZE}, {MAXIMUM_MTU_SIZE}], got {}",
                    self.mtu
                ),
            ));
        }
        if self.mtu_probe_attempts_per_step == 0 {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "mtu_probe_attempts_per_step",
                "must be >= 1",
            ));
        }
        if self.mtu_probe_wait_per_attempt.is_zero() {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "mtu_probe_wait_per_attempt",
                "must be > 0",
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "handshake_timeout",
                "must be > 0",
            ));
        }
        if self.outbound_tick_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "outbound_tick_interval",
                "must be > 0",
            ));
        }
        if self.session_keepalive_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "session_keepalive_interval",
                "must be > 0",
            ));
        }
        if self.session_idle_timeout.is_zero() {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "session_idle_timeout",
                "must be > 0",
            ));
        }
        if self.recv_buffer_capacity < self.mtu as usize {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "recv_buffer_capacity",
                format!(
                    "must be >= mtu ({}), got {}",
                    self.mtu, self.recv_buffer_capacity
                ),
            ));
        }
        if self.max_new_datagrams_per_tick == 0 {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_new_datagrams_per_tick",
                "must be >= 1",
            ));
        }
        if self.max_new_bytes_per_tick < self.mtu as usize {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_new_bytes_per_tick",
                format!(
                    "must be >= mtu ({}), got {}",
                    self.mtu, self.max_new_bytes_per_tick
                ),
            ));
        }
        if self.max_resend_datagrams_per_tick == 0 {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_resend_datagrams_per_tick",
                "must be >= 1",
            ));
        }
        if self.max_resend_bytes_per_tick < self.mtu as usize {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_resend_bytes_per_tick",
                format!(
                    "must be >= mtu ({}), got {}",
                    self.mtu, self.max_resend_bytes_per_tick
                ),
            ));
        }
        if self.max_new_datagrams_per_recv == 0 {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_new_datagrams_per_recv",
                "must be >= 1",
            ));
        }
        if self.max_new_bytes_per_recv < self.mtu as usize {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_new_bytes_per_recv",
                format!(
                    "must be >= mtu ({}), got {}",
                    self.mtu, self.max_new_bytes_per_recv
                ),
            ));
        }
        if self.max_resend_datagrams_per_recv == 0 {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_resend_datagrams_per_recv",
                "must be >= 1",
            ));
        }
        if self.max_resend_bytes_per_recv < self.mtu as usize {
            return Err(ConfigValidationError::new(
                "RaknetClientConfig",
                "max_resend_bytes_per_recv",
                format!(
                    "must be >= mtu ({}), got {}",
                    self.mtu, self.max_resend_bytes_per_recv
                ),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Last handshake stage reached before timeout.
pub enum HandshakeStage {
    OpenConnectionRequest1,
    OpenConnectionRequest2,
    ConnectionRequestAccepted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Explicit offline handshake rejection reasons.
pub enum OfflineRejectionReason {
    IncompatibleProtocolVersion {
        protocol_version: u8,
        server_guid: u64,
    },
    ConnectionRequestFailed {
        server_guid: u64,
    },
    AlreadyConnected {
        server_guid: u64,
    },
    NoFreeIncomingConnections {
        server_guid: u64,
    },
    ConnectionBanned {
        server_guid: u64,
    },
    IpRecentlyConnected {
        server_guid: u64,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Errors returned by client connect/send/receive operations.
pub enum RaknetClientError {
    #[error("transport io error: {message}")]
    Io { message: String },
    #[error("invalid client config: {details}")]
    InvalidConfig { details: String },
    #[error("handshake timed out at stage {stage:?}")]
    HandshakeTimeout { stage: HandshakeStage },
    #[error("handshake rejected by server: {reason:?}")]
    OfflineRejected { reason: OfflineRejectionReason },
    #[error("handshake protocol violation: {details}")]
    HandshakeProtocolViolation { details: String },
    #[error("client closed: {reason:?}")]
    Closed { reason: ClientDisconnectReason },
    #[error("payload dropped by backpressure")]
    BackpressureDropped,
    #[error("payload deferred by backpressure")]
    BackpressureDeferred,
    #[error("backpressure requested disconnect")]
    BackpressureDisconnect,
}

impl From<io::Error> for RaknetClientError {
    fn from(value: io::Error) -> Self {
        Self::Io {
            message: value.to_string(),
        }
    }
}

impl From<RaknetClientError> for io::Error {
    fn from(value: RaknetClientError) -> Self {
        io::Error::other(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Reason for client-side disconnection.
pub enum ClientDisconnectReason {
    Requested,
    Backpressure,
    IdleTimeout,
    RemoteDisconnectionNotification { reason_code: Option<u8> },
    RemoteDetectLostConnection,
    TransportError { message: String },
}

#[derive(Debug)]
/// Event stream produced by [`RaknetClient::next_event`].
pub enum RaknetClientEvent {
    Connected {
        server_addr: SocketAddr,
        mtu: u16,
    },
    Packet {
        payload: Bytes,
        reliability: Reliability,
        reliable_index: Option<Sequence24>,
        sequence_index: Option<Sequence24>,
        ordering_index: Option<Sequence24>,
        ordering_channel: Option<u8>,
    },
    ReceiptAcked {
        receipt_id: u64,
    },
    DecodeError {
        error: String,
    },
    Disconnected {
        reason: ClientDisconnectReason,
    },
}

#[derive(Debug, Clone)]
/// Retry policy for [`RaknetClient::connect_with_retry`].
pub struct ReconnectPolicy {
    pub max_attempts: usize,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub retry_on_io: bool,
    pub retry_on_handshake_timeout: bool,
    pub fast_fail_on_offline_rejection: bool,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(3),
            retry_on_io: true,
            retry_on_handshake_timeout: true,
            fast_fail_on_offline_rejection: true,
        }
    }
}

impl ReconnectPolicy {
    /// Validates retry policy invariants.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_attempts == 0 {
            return Err(ConfigValidationError::new(
                "ReconnectPolicy",
                "max_attempts",
                "must be >= 1",
            ));
        }
        if self.initial_backoff > self.max_backoff {
            return Err(ConfigValidationError::new(
                "ReconnectPolicy",
                "initial_backoff",
                format!(
                    "must be <= max_backoff ({}ms), got {}ms",
                    self.max_backoff.as_millis(),
                    self.initial_backoff.as_millis()
                ),
            ));
        }
        Ok(())
    }
}

/// Single-session high-level RakNet client.
pub struct RaknetClient {
    socket: UdpSocket,
    server_addr: SocketAddr,
    session: Session,
    config: RaknetClientConfig,
    recv_buffer: Vec<u8>,
    pending_events: VecDeque<RaknetClientEvent>,
    closed: bool,
    close_reason: Option<ClientDisconnectReason>,
    last_inbound_activity: Instant,
}

impl RaknetClient {
    /// Connects with default [`RaknetClientConfig`].
    pub async fn connect(server_addr: SocketAddr) -> ClientResult<Self> {
        Self::connect_with_config(server_addr, RaknetClientConfig::default()).await
    }

    /// Connects with retry policy.
    pub async fn connect_with_retry(
        server_addr: SocketAddr,
        config: RaknetClientConfig,
        policy: ReconnectPolicy,
    ) -> ClientResult<Self> {
        policy
            .validate()
            .map_err(|error| RaknetClientError::InvalidConfig {
                details: error.to_string(),
            })?;

        let mut attempt = 0usize;
        let max_attempts = policy.max_attempts.max(1);
        let mut backoff = policy.initial_backoff;
        let mut last_error: Option<RaknetClientError> = None;

        while attempt < max_attempts {
            attempt = attempt.saturating_add(1);
            match Self::connect_with_config(server_addr, config.clone()).await {
                Ok(client) => return Ok(client),
                Err(error) => {
                    let should_retry =
                        attempt < max_attempts && should_retry_connect(&error, &policy);
                    last_error = Some(error);
                    if !should_retry {
                        break;
                    }

                    if !backoff.is_zero() {
                        sleep(backoff).await;
                    }
                    backoff = next_backoff(backoff, &policy);
                }
            }
        }

        Err(
            last_error.unwrap_or(RaknetClientError::HandshakeProtocolViolation {
                details: "connect_with_retry terminated without a recorded error".to_string(),
            }),
        )
    }

    /// Connects using explicit client configuration.
    pub async fn connect_with_config(
        server_addr: SocketAddr,
        config: RaknetClientConfig,
    ) -> ClientResult<Self> {
        config
            .validate()
            .map_err(|error| RaknetClientError::InvalidConfig {
                details: error.to_string(),
            })?;

        let local_addr = config
            .local_addr
            .unwrap_or_else(|| default_bind_addr_for_server(server_addr));
        info!(%server_addr, %local_addr, "client connecting");
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(RaknetClientError::from)?;

        let now = Instant::now();
        let mut client = Self {
            socket,
            server_addr,
            session: Session::new(config.mtu as usize),
            recv_buffer: vec![0u8; config.recv_buffer_capacity],
            config,
            pending_events: VecDeque::new(),
            closed: false,
            close_reason: None,
            last_inbound_activity: now,
        };

        client.perform_handshake().await?;
        info!(
            %server_addr,
            mtu = client.session.mtu(),
            "client handshake established"
        );
        client
            .pending_events
            .push_back(RaknetClientEvent::Connected {
                server_addr,
                mtu: client.session.mtu() as u16,
            });

        Ok(client)
    }

    /// Returns local socket address used by this client.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns remote server address.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Returns session-level metrics snapshot.
    pub fn metrics_snapshot(&self) -> SessionMetricsSnapshot {
        self.session.metrics_snapshot()
    }

    /// Sends payload with default send options.
    pub async fn send(&mut self, payload: impl Into<Bytes>) -> ClientResult<()> {
        self.send_with_options(payload, ClientSendOptions::default())
            .await
    }

    /// Sends payload with explicit options.
    pub async fn send_with_options(
        &mut self,
        payload: impl Into<Bytes>,
        options: ClientSendOptions,
    ) -> ClientResult<()> {
        self.ensure_open()?;
        self.queue_payload_with_optional_receipt(
            payload.into(),
            options.reliability,
            options.channel,
            options.priority,
            None,
        )?;
        self.flush_outbound_with_limits(
            self.config.max_new_datagrams_per_recv,
            self.config.max_new_bytes_per_recv,
            self.config.max_resend_datagrams_per_recv,
            self.config.max_resend_bytes_per_recv,
        )
        .await
    }

    /// Sends payload and tracks a receipt id.
    pub async fn send_with_receipt(
        &mut self,
        payload: impl Into<Bytes>,
        receipt_id: u64,
        options: ClientSendOptions,
    ) -> ClientResult<()> {
        self.ensure_open()?;
        self.queue_payload_with_optional_receipt(
            payload.into(),
            options.reliability,
            options.channel,
            options.priority,
            Some(receipt_id),
        )?;
        self.flush_outbound_with_limits(
            self.config.max_new_datagrams_per_recv,
            self.config.max_new_bytes_per_recv,
            self.config.max_resend_datagrams_per_recv,
            self.config.max_resend_bytes_per_recv,
        )
        .await
    }

    /// Gracefully disconnects client.
    pub async fn disconnect(&mut self, reason_code: Option<u8>) -> ClientResult<()> {
        if self.closed {
            return Ok(());
        }

        let packet = ConnectedControlPacket::DisconnectionNotification(DisconnectionNotification {
            reason: reason_code,
        });

        let queued = self.queue_connected_control_packet(
            packet,
            Reliability::ReliableOrdered,
            0,
            RakPriority::High,
        );

        if queued.is_ok() {
            let _ = self
                .flush_outbound_with_limits(
                    self.config.max_new_datagrams_per_tick,
                    self.config.max_new_bytes_per_tick,
                    self.config.max_resend_datagrams_per_tick,
                    self.config.max_resend_bytes_per_tick,
                )
                .await;
        }

        self.finish_close(ClientDisconnectReason::Requested);
        queued
    }

    /// Polls next client event.
    ///
    /// Returns `None` once client is fully closed and pending events are drained.
    pub async fn next_event(&mut self) -> Option<RaknetClientEvent> {
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }
        if self.closed {
            return None;
        }

        loop {
            if let Some(event) = self.pending_events.pop_front() {
                return Some(event);
            }
            if self.closed {
                return None;
            }
            if self.check_idle_timeout_and_close() {
                continue;
            }

            match time::timeout(
                self.config.outbound_tick_interval,
                self.socket.recv_from(&mut self.recv_buffer),
            )
            .await
            {
                Ok(Ok((len, addr))) => {
                    if addr != self.server_addr {
                        continue;
                    }
                    self.last_inbound_activity = Instant::now();

                    if let Err(error) = self.process_inbound_packet(len).await {
                        self.finish_close(ClientDisconnectReason::TransportError {
                            message: format!("inbound processing failed: {error}"),
                        });
                    }
                }
                Ok(Err(error)) => {
                    self.finish_close(ClientDisconnectReason::TransportError {
                        message: format!("udp receive failed: {error}"),
                    });
                }
                Err(_) => {
                    if let Err(error) = self
                        .flush_outbound_with_limits(
                            self.config.max_new_datagrams_per_tick,
                            self.config.max_new_bytes_per_tick,
                            self.config.max_resend_datagrams_per_tick,
                            self.config.max_resend_bytes_per_tick,
                        )
                        .await
                    {
                        self.finish_close(ClientDisconnectReason::TransportError {
                            message: format!("outbound tick failed: {error}"),
                        });
                    }
                }
            }
        }
    }

    async fn perform_handshake(&mut self) -> ClientResult<()> {
        debug!(server_addr = %self.server_addr, "starting client handshake");
        if !self.session.transition_to(SessionState::Req1Recv) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed before request1".to_string(),
            });
        }

        let deadline = Instant::now() + self.config.handshake_timeout;
        let reply1 = self.probe_open_connection_reply1(deadline).await?;

        if !self.session.transition_to(SessionState::Reply1Sent) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed after reply1".to_string(),
            });
        }

        self.session
            .set_mtu(reply1.mtu.clamp(MINIMUM_MTU_SIZE, MAXIMUM_MTU_SIZE) as usize);

        if !self.session.transition_to(SessionState::Req2Recv) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed before request2".to_string(),
            });
        }

        let req2 = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
            server_addr: self.server_addr,
            mtu: reply1.mtu,
            client_guid: self.config.guid,
            cookie: reply1.cookie,
            client_proof: false,
            parse_path: if reply1.cookie.is_some() {
                Request2ParsePath::StrictWithCookie
            } else {
                Request2ParsePath::StrictNoCookie
            },
            magic: DEFAULT_UNCONNECTED_MAGIC,
        });
        self.send_offline_packet(&req2).await?;

        let _reply2 = self.wait_for_open_connection_reply2(deadline).await?;
        if !self.session.transition_to(SessionState::Reply2Sent) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed after reply2".to_string(),
            });
        }

        if !self.session.transition_to(SessionState::ConnReqRecv) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed before connection request".to_string(),
            });
        }

        let request_time = unix_timestamp_millis();
        self.queue_connected_control_packet(
            ConnectedControlPacket::ConnectionRequest(ConnectionRequest {
                client_guid: self.config.guid,
                request_time,
                use_encryption: false,
            }),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High,
        )?;
        self.flush_outbound_with_limits(
            self.config.max_new_datagrams_per_recv,
            self.config.max_new_bytes_per_recv,
            self.config.max_resend_datagrams_per_recv,
            self.config.max_resend_bytes_per_recv,
        )
        .await?;

        let accepted = self.wait_for_connection_request_accepted(deadline).await?;

        if !self
            .session
            .transition_to(SessionState::ConnReqAcceptedSent)
        {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed after request accepted".to_string(),
            });
        }

        if !self.session.transition_to(SessionState::NewIncomingRecv) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed before new incoming".to_string(),
            });
        }

        self.queue_connected_control_packet(
            ConnectedControlPacket::NewIncomingConnection(NewIncomingConnection {
                server_addr: self.server_addr,
                internal_addrs: build_internal_addrs(self.server_addr),
                request_time: accepted.request_time,
                accepted_time: accepted.accepted_time,
            }),
            Reliability::ReliableOrdered,
            0,
            RakPriority::High,
        )?;

        self.flush_outbound_with_limits(
            self.config.max_new_datagrams_per_recv,
            self.config.max_new_bytes_per_recv,
            self.config.max_resend_datagrams_per_recv,
            self.config.max_resend_bytes_per_recv,
        )
        .await?;

        if !self.session.transition_to(SessionState::Connected) {
            return Err(RaknetClientError::HandshakeProtocolViolation {
                details: "session transition failed to connected".to_string(),
            });
        }

        debug!(server_addr = %self.server_addr, "client handshake completed");
        self.last_inbound_activity = Instant::now();
        Ok(())
    }

    async fn probe_open_connection_reply1(
        &mut self,
        overall_deadline: Instant,
    ) -> ClientResult<OpenConnectionReply1> {
        let candidates = self.mtu_probe_candidates();
        for mtu in candidates {
            for _ in 0..self.config.mtu_probe_attempts_per_step {
                if Instant::now() >= overall_deadline {
                    warn!(
                        server_addr = %self.server_addr,
                        stage = ?HandshakeStage::OpenConnectionRequest1,
                        "client handshake timed out"
                    );
                    return Err(RaknetClientError::HandshakeTimeout {
                        stage: HandshakeStage::OpenConnectionRequest1,
                    });
                }

                let req1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                    protocol_version: self.config.protocol_version,
                    mtu,
                    magic: DEFAULT_UNCONNECTED_MAGIC,
                });
                self.send_offline_packet(&req1).await?;

                let per_attempt_deadline = std::cmp::min(
                    overall_deadline,
                    Instant::now() + self.config.mtu_probe_wait_per_attempt,
                );

                if let Some(reply) = self
                    .wait_for_open_connection_reply1_in_window(per_attempt_deadline)
                    .await?
                {
                    return Ok(reply);
                }
            }
        }

        warn!(
            server_addr = %self.server_addr,
            stage = ?HandshakeStage::OpenConnectionRequest1,
            "client handshake timed out after mtu probing"
        );
        Err(RaknetClientError::HandshakeTimeout {
            stage: HandshakeStage::OpenConnectionRequest1,
        })
    }

    fn mtu_probe_candidates(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for candidate in self
            .config
            .mtu_probe_order
            .iter()
            .copied()
            .chain([self.config.mtu])
        {
            let mtu = candidate
                .clamp(MINIMUM_MTU_SIZE, MAXIMUM_MTU_SIZE)
                .max(MINIMUM_MTU_SIZE);
            if !out.contains(&mtu) {
                out.push(mtu);
            }
        }

        if out.is_empty() {
            out.push(self.config.mtu);
        }

        out
    }

    async fn wait_for_open_connection_reply1_in_window(
        &mut self,
        deadline: Instant,
    ) -> ClientResult<Option<OpenConnectionReply1>> {
        loop {
            let packet = match self.recv_packet_until(deadline).await? {
                Some(packet) => packet,
                None => return Ok(None),
            };

            let mut src = &packet[..];
            let Ok(offline) = OfflinePacket::decode(&mut src) else {
                continue;
            };

            if let Some(reason) = offline_rejection_reason(&offline) {
                return Err(RaknetClientError::OfflineRejected { reason });
            }

            if let OfflinePacket::OpenConnectionReply1(reply) = offline {
                return Ok(Some(reply));
            }
        }
    }

    async fn wait_for_open_connection_reply2(
        &mut self,
        deadline: Instant,
    ) -> ClientResult<OpenConnectionReply2> {
        loop {
            let packet = match self.recv_packet_until(deadline).await? {
                Some(packet) => packet,
                None => {
                    warn!(
                        server_addr = %self.server_addr,
                        stage = ?HandshakeStage::OpenConnectionRequest2,
                        "client handshake timed out waiting for reply2"
                    );
                    return Err(RaknetClientError::HandshakeTimeout {
                        stage: HandshakeStage::OpenConnectionRequest2,
                    });
                }
            };

            let mut src = &packet[..];
            let Ok(offline) = OfflinePacket::decode(&mut src) else {
                continue;
            };

            if let Some(reason) = offline_rejection_reason(&offline) {
                return Err(RaknetClientError::OfflineRejected { reason });
            }

            if let OfflinePacket::OpenConnectionReply2(reply) = offline {
                return Ok(reply);
            }
        }
    }

    async fn wait_for_connection_request_accepted(
        &mut self,
        deadline: Instant,
    ) -> ClientResult<ConnectionRequestAccepted> {
        loop {
            let packet = match self.recv_packet_until(deadline).await? {
                Some(packet) => packet,
                None => {
                    warn!(
                        server_addr = %self.server_addr,
                        stage = ?HandshakeStage::ConnectionRequestAccepted,
                        "client handshake timed out waiting for request accepted"
                    );
                    return Err(RaknetClientError::HandshakeTimeout {
                        stage: HandshakeStage::ConnectionRequestAccepted,
                    });
                }
            };

            let mut offline_src = &packet[..];
            if let Ok(offline) = OfflinePacket::decode(&mut offline_src) {
                if let Some(reason) = offline_rejection_reason(&offline) {
                    return Err(RaknetClientError::OfflineRejected { reason });
                }
                continue;
            }

            let mut src = &packet[..];
            let datagram = match Datagram::decode(&mut src) {
                Ok(datagram) => datagram,
                Err(_) => continue,
            };

            if let Some(accepted) = self.process_handshake_datagram(datagram).await? {
                return Ok(accepted);
            }
        }
    }

    async fn process_handshake_datagram(
        &mut self,
        datagram: Datagram,
    ) -> ClientResult<Option<ConnectionRequestAccepted>> {
        let now = Instant::now();
        let frames = self
            .session
            .ingest_datagram(datagram, now)
            .map_err(invalid_data_client_error)?;
        let _ = self.session.process_incoming_receipts(now);

        let mut accepted = None;
        for frame in frames {
            let Some(first) = frame.payload.first().copied() else {
                continue;
            };
            if !is_connected_control_id(first) {
                continue;
            }

            let mut control_payload = &frame.payload[..];
            let control =
                ConnectedControlPacket::decode(&mut control_payload).map_err(|error| {
                    RaknetClientError::HandshakeProtocolViolation {
                        details: format!("failed to decode handshake control packet: {error}"),
                    }
                })?;

            match control {
                ConnectedControlPacket::ConnectionRequestAccepted(pkt) => {
                    accepted = Some(pkt);
                }
                ConnectedControlPacket::ConnectedPing(ping) => {
                    self.queue_connected_control_packet(
                        ConnectedControlPacket::ConnectedPong(ConnectedPong {
                            ping_time: ping.ping_time,
                            pong_time: unix_timestamp_millis(),
                        }),
                        Reliability::Unreliable,
                        0,
                        RakPriority::Immediate,
                    )?;
                }
                ConnectedControlPacket::DisconnectionNotification(pkt) => {
                    return Err(RaknetClientError::Closed {
                        reason: ClientDisconnectReason::RemoteDisconnectionNotification {
                            reason_code: pkt.reason,
                        },
                    });
                }
                ConnectedControlPacket::DetectLostConnection(_) => {
                    return Err(RaknetClientError::Closed {
                        reason: ClientDisconnectReason::RemoteDetectLostConnection,
                    });
                }
                ConnectedControlPacket::ConnectedPong(_)
                | ConnectedControlPacket::ConnectionRequest(_)
                | ConnectedControlPacket::NewIncomingConnection(_) => {}
            }
        }

        self.flush_outbound_with_limits(
            self.config.max_new_datagrams_per_recv,
            self.config.max_new_bytes_per_recv,
            self.config.max_resend_datagrams_per_recv,
            self.config.max_resend_bytes_per_recv,
        )
        .await?;

        Ok(accepted)
    }

    async fn recv_packet_until(&mut self, deadline: Instant) -> ClientResult<Option<Vec<u8>>> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let recv = match time::timeout(remaining, self.socket.recv_from(&mut self.recv_buffer))
                .await
            {
                Ok(result) => result,
                Err(_) => return Ok(None),
            }
            .map_err(RaknetClientError::from)?;

            let (len, addr) = recv;
            if addr != self.server_addr {
                continue;
            }

            let mut packet = Vec::with_capacity(len);
            packet.extend_from_slice(&self.recv_buffer[..len]);
            return Ok(Some(packet));
        }
    }

    async fn process_inbound_packet(&mut self, len: usize) -> ClientResult<()> {
        let payload = &self.recv_buffer[..len];
        let Some(first) = payload.first().copied() else {
            return Ok(());
        };

        if is_offline_packet_id(first) {
            self.pending_events
                .push_back(RaknetClientEvent::DecodeError {
                    error: format!("unexpected offline packet id while connected: 0x{first:02x}"),
                });
            return Ok(());
        }

        let mut src = payload;
        let datagram = match Datagram::decode(&mut src) {
            Ok(datagram) => datagram,
            Err(error) => {
                self.pending_events
                    .push_back(RaknetClientEvent::DecodeError {
                        error: error.to_string(),
                    });
                return Ok(());
            }
        };

        self.process_connected_datagram(datagram).await
    }

    async fn process_connected_datagram(&mut self, datagram: Datagram) -> ClientResult<()> {
        let now = Instant::now();
        let frames = match self.session.ingest_datagram(datagram, now) {
            Ok(frames) => frames,
            Err(error) => {
                self.pending_events
                    .push_back(RaknetClientEvent::DecodeError {
                        error: error.to_string(),
                    });
                return Ok(());
            }
        };

        let receipts = self.session.process_incoming_receipts(now);
        for receipt_id in receipts.acked_receipt_ids {
            self.pending_events
                .push_back(RaknetClientEvent::ReceiptAcked { receipt_id });
        }

        for frame in frames {
            let Some(first) = frame.payload.first().copied() else {
                continue;
            };

            if is_connected_control_id(first) {
                let mut control_payload = &frame.payload[..];
                let control = match ConnectedControlPacket::decode(&mut control_payload) {
                    Ok(control) => control,
                    Err(error) => {
                        self.pending_events
                            .push_back(RaknetClientEvent::DecodeError {
                                error: error.to_string(),
                            });
                        continue;
                    }
                };

                self.apply_connected_control(control)?;
                continue;
            }

            self.pending_events.push_back(RaknetClientEvent::Packet {
                payload: frame.payload,
                reliability: frame.header.reliability,
                reliable_index: frame.reliable_index,
                sequence_index: frame.sequence_index,
                ordering_index: frame.ordering_index,
                ordering_channel: frame.ordering_channel,
            });
        }

        // Client facade is poll-driven; make sure control ACK/NACK can flush
        // immediately on this receive path without waiting for a later poll tick.
        self.session.force_control_flush_deadlines(now);

        self.flush_outbound_with_limits(
            self.config.max_new_datagrams_per_recv,
            self.config.max_new_bytes_per_recv,
            self.config.max_resend_datagrams_per_recv,
            self.config.max_resend_bytes_per_recv,
        )
        .await
    }

    fn apply_connected_control(&mut self, control: ConnectedControlPacket) -> ClientResult<()> {
        match control {
            ConnectedControlPacket::ConnectedPing(ping) => {
                self.queue_connected_control_packet(
                    ConnectedControlPacket::ConnectedPong(ConnectedPong {
                        ping_time: ping.ping_time,
                        pong_time: unix_timestamp_millis(),
                    }),
                    Reliability::Unreliable,
                    0,
                    RakPriority::Immediate,
                )?;
            }
            ConnectedControlPacket::DisconnectionNotification(pkt) => {
                self.finish_close(ClientDisconnectReason::RemoteDisconnectionNotification {
                    reason_code: pkt.reason,
                });
            }
            ConnectedControlPacket::DetectLostConnection(DetectLostConnection) => {
                self.finish_close(ClientDisconnectReason::RemoteDetectLostConnection);
            }
            ConnectedControlPacket::ConnectionRequest(_)
            | ConnectedControlPacket::ConnectionRequestAccepted(_)
            | ConnectedControlPacket::NewIncomingConnection(_)
            | ConnectedControlPacket::ConnectedPong(_) => {}
        }

        Ok(())
    }

    fn queue_connected_control_packet(
        &mut self,
        packet: ConnectedControlPacket,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
    ) -> ClientResult<()> {
        let mut out = BytesMut::new();
        packet.encode(&mut out).map_err(invalid_data_client_error)?;
        self.queue_payload_with_optional_receipt(out.freeze(), reliability, channel, priority, None)
    }

    fn queue_payload_with_optional_receipt(
        &mut self,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: Option<u64>,
    ) -> ClientResult<()> {
        let decision = if let Some(receipt_id) = receipt_id {
            self.session.queue_payload_with_receipt(
                payload,
                reliability,
                channel,
                priority,
                Some(receipt_id),
            )
        } else {
            self.session
                .queue_payload(payload, reliability, channel, priority)
        };

        match decision {
            QueuePayloadResult::Enqueued { .. } => Ok(()),
            QueuePayloadResult::Dropped => Err(RaknetClientError::BackpressureDropped),
            QueuePayloadResult::Deferred => Err(RaknetClientError::BackpressureDeferred),
            QueuePayloadResult::DisconnectRequested => {
                self.finish_close(ClientDisconnectReason::Backpressure);
                Err(RaknetClientError::BackpressureDisconnect)
            }
        }
    }

    async fn flush_outbound_with_limits(
        &mut self,
        max_new_datagrams: usize,
        max_new_bytes: usize,
        max_resend_datagrams: usize,
        max_resend_bytes: usize,
    ) -> ClientResult<()> {
        if self.closed {
            return Ok(());
        }

        self.queue_keepalive_ping();

        let now = Instant::now();
        let datagrams = self.session.on_tick(
            now,
            max_new_datagrams,
            max_new_bytes,
            max_resend_datagrams,
            max_resend_bytes,
        );

        for datagram in &datagrams {
            self.send_datagram(datagram).await?;
        }

        if self.session.take_backpressure_disconnect() {
            self.finish_close(ClientDisconnectReason::Backpressure);
            return Err(RaknetClientError::BackpressureDisconnect);
        }

        Ok(())
    }

    fn queue_keepalive_ping(&mut self) {
        let now = Instant::now();
        if !self
            .session
            .should_send_keepalive(now, self.config.session_keepalive_interval)
        {
            return;
        }

        let ping = ConnectedControlPacket::ConnectedPing(ConnectedPing {
            ping_time: unix_timestamp_millis(),
        });

        let decision = {
            let mut out = BytesMut::new();
            if ping.encode(&mut out).is_err() {
                return;
            }
            self.session
                .queue_payload(out.freeze(), Reliability::Unreliable, 0, RakPriority::Low)
        };

        if matches!(decision, QueuePayloadResult::Enqueued { .. }) {
            self.session.mark_keepalive_sent(now);
        }
    }

    fn check_idle_timeout_and_close(&mut self) -> bool {
        if self.closed
            || self.config.session_idle_timeout.is_zero()
            || self.session.state() != SessionState::Connected
        {
            return false;
        }

        let idle = Instant::now().saturating_duration_since(self.last_inbound_activity);
        if idle >= self.config.session_idle_timeout {
            self.finish_close(ClientDisconnectReason::IdleTimeout);
            return true;
        }

        false
    }

    async fn send_offline_packet(&self, packet: &OfflinePacket) -> ClientResult<()> {
        let mut out = BytesMut::new();
        packet.encode(&mut out).map_err(invalid_data_client_error)?;
        let _written = self
            .socket
            .send_to(&out, self.server_addr)
            .await
            .map_err(RaknetClientError::from)?;
        Ok(())
    }

    async fn send_datagram(&self, datagram: &Datagram) -> ClientResult<()> {
        let mut out = BytesMut::with_capacity(datagram.encoded_size());
        datagram
            .encode(&mut out)
            .map_err(invalid_data_client_error)?;
        let _written = self
            .socket
            .send_to(&out, self.server_addr)
            .await
            .map_err(RaknetClientError::from)?;
        Ok(())
    }

    fn ensure_open(&self) -> ClientResult<()> {
        if self.closed {
            return Err(RaknetClientError::Closed {
                reason: self.close_reason.clone().unwrap_or(
                    ClientDisconnectReason::TransportError {
                        message: "closed without explicit reason".to_string(),
                    },
                ),
            });
        }
        Ok(())
    }

    fn finish_close(&mut self, reason: ClientDisconnectReason) {
        if self.closed {
            return;
        }

        if self.session.state() == SessionState::Connected {
            let _ = self.session.transition_to(SessionState::Closing);
        }
        let _ = self.session.transition_to(SessionState::Closed);

        self.close_reason = Some(reason.clone());
        self.closed = true;
        match &reason {
            ClientDisconnectReason::Requested
            | ClientDisconnectReason::RemoteDisconnectionNotification { .. }
            | ClientDisconnectReason::RemoteDetectLostConnection => {
                info!(server_addr = %self.server_addr, ?reason, "client closed")
            }
            ClientDisconnectReason::Backpressure
            | ClientDisconnectReason::IdleTimeout
            | ClientDisconnectReason::TransportError { .. } => {
                warn!(server_addr = %self.server_addr, ?reason, "client closed")
            }
        }
        self.pending_events
            .push_back(RaknetClientEvent::Disconnected { reason });
    }
}

fn should_retry_connect(error: &RaknetClientError, policy: &ReconnectPolicy) -> bool {
    match error {
        RaknetClientError::OfflineRejected { .. } => !policy.fast_fail_on_offline_rejection,
        RaknetClientError::HandshakeTimeout { .. } => policy.retry_on_handshake_timeout,
        RaknetClientError::Io { .. } => policy.retry_on_io,
        RaknetClientError::InvalidConfig { .. } => false,
        RaknetClientError::HandshakeProtocolViolation { .. }
        | RaknetClientError::Closed { .. }
        | RaknetClientError::BackpressureDropped
        | RaknetClientError::BackpressureDeferred
        | RaknetClientError::BackpressureDisconnect => false,
    }
}

fn next_backoff(current: Duration, policy: &ReconnectPolicy) -> Duration {
    if current.is_zero() {
        return Duration::from_millis(1).min(policy.max_backoff);
    }

    let doubled = current.saturating_mul(2);
    if doubled > policy.max_backoff {
        policy.max_backoff
    } else {
        doubled
    }
}

fn invalid_data_client_error<E: std::fmt::Display>(error: E) -> RaknetClientError {
    RaknetClientError::HandshakeProtocolViolation {
        details: error.to_string(),
    }
}

fn offline_rejection_reason(packet: &OfflinePacket) -> Option<OfflineRejectionReason> {
    match packet {
        OfflinePacket::IncompatibleProtocolVersion(pkt) => {
            Some(OfflineRejectionReason::IncompatibleProtocolVersion {
                protocol_version: pkt.protocol_version,
                server_guid: pkt.server_guid,
            })
        }
        OfflinePacket::ConnectionReject(reason) => match reason {
            ConnectionRejectReason::ConnectionRequestFailed(d) => {
                Some(OfflineRejectionReason::ConnectionRequestFailed {
                    server_guid: d.server_guid,
                })
            }
            ConnectionRejectReason::AlreadyConnected(d) => {
                Some(OfflineRejectionReason::AlreadyConnected {
                    server_guid: d.server_guid,
                })
            }
            ConnectionRejectReason::NoFreeIncomingConnections(d) => {
                Some(OfflineRejectionReason::NoFreeIncomingConnections {
                    server_guid: d.server_guid,
                })
            }
            ConnectionRejectReason::ConnectionBanned(d) => {
                Some(OfflineRejectionReason::ConnectionBanned {
                    server_guid: d.server_guid,
                })
            }
            ConnectionRejectReason::IpRecentlyConnected(d) => {
                Some(OfflineRejectionReason::IpRecentlyConnected {
                    server_guid: d.server_guid,
                })
            }
        },
        _ => None,
    }
}

fn is_offline_packet_id(id: u8) -> bool {
    matches!(
        id,
        0x01 | 0x02 | 0x05 | 0x06 | 0x07 | 0x08 | 0x11 | 0x12 | 0x14 | 0x17 | 0x19 | 0x1A | 0x1C
    )
}

fn is_connected_control_id(id: u8) -> bool {
    matches!(id, 0x00 | 0x03 | 0x04 | 0x09 | 0x10 | 0x13 | 0x15)
}

fn default_bind_addr_for_server(server_addr: SocketAddr) -> SocketAddr {
    match server_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            v6.scope_id(),
        )),
    }
}

fn build_internal_addrs(server_addr: SocketAddr) -> [SocketAddr; SYSTEM_ADDRESS_COUNT] {
    let fallback = match server_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            v6.scope_id(),
        )),
    };

    let mut addrs = [fallback; SYSTEM_ADDRESS_COUNT];
    addrs[0] = server_addr;
    addrs
}

fn random_guid() -> u64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_ok() {
        return u64::from_le_bytes(bytes);
    }

    let now = unix_timestamp_millis() as u64;
    now ^ 0xA5A5_5A5A_DEAD_BEEF
}

fn unix_timestamp_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(i64::MAX as u128) as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientSendOptions, OfflineRejectionReason, RaknetClientConfig, RaknetClientError,
        ReconnectPolicy, is_connected_control_id, is_offline_packet_id, next_backoff,
        offline_rejection_reason, should_retry_connect,
    };
    use crate::protocol::packet::{ConnectionRejectReason, OfflinePacket, RejectData};
    use crate::protocol::reliability::Reliability;
    use crate::session::RakPriority;
    use std::time::Duration;

    #[test]
    fn id_guards_cover_known_ranges() {
        assert!(is_offline_packet_id(0x05));
        assert!(is_offline_packet_id(0x1C));
        assert!(!is_offline_packet_id(0xFF));

        assert!(is_connected_control_id(0x10));
        assert!(!is_connected_control_id(0x11));
    }

    #[test]
    fn send_options_default_matches_server_defaults() {
        let options = ClientSendOptions::default();
        assert_eq!(options.reliability, Reliability::ReliableOrdered);
        assert_eq!(options.channel, 0);
        assert_eq!(options.priority, RakPriority::High);
    }

    #[test]
    fn rejection_mapping_extracts_reason() {
        let packet = OfflinePacket::ConnectionReject(
            ConnectionRejectReason::ConnectionBanned(RejectData {
                server_guid: 7,
                magic: crate::protocol::constants::DEFAULT_UNCONNECTED_MAGIC,
            })
        );
        assert_eq!(
            offline_rejection_reason(&packet),
            Some(OfflineRejectionReason::ConnectionBanned { server_guid: 7 })
        );
    }

    #[test]
    fn retry_policy_fast_fail_respects_offline_rejection() {
        let err = RaknetClientError::OfflineRejected {
            reason: OfflineRejectionReason::ConnectionBanned { server_guid: 1 },
        };
        let policy = ReconnectPolicy::default();
        assert!(!should_retry_connect(&err, &policy));

        let mut relaxed = policy;
        relaxed.fast_fail_on_offline_rejection = false;
        assert!(should_retry_connect(&err, &relaxed));
    }

    #[test]
    fn backoff_growth_respects_cap() {
        let policy = ReconnectPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(250),
            ..ReconnectPolicy::default()
        };
        assert_eq!(
            next_backoff(Duration::from_millis(100), &policy),
            Duration::from_millis(200)
        );
        assert_eq!(
            next_backoff(Duration::from_millis(200), &policy),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn mtu_probe_candidates_include_configured_mtu_even_when_order_empty() {
        let cfg = RaknetClientConfig {
            mtu: 1300,
            mtu_probe_order: Vec::new(),
            ..RaknetClientConfig::default()
        };
        assert_eq!(cfg.mtu, 1300);
        cfg.validate().expect("config should be valid");
    }

    #[test]
    fn client_config_validate_rejects_out_of_range_mtu() {
        let cfg = RaknetClientConfig {
            mtu: 10,
            ..RaknetClientConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("invalid MTU must be rejected by validate()");
        assert_eq!(err.config, "RaknetClientConfig");
        assert_eq!(err.field, "mtu");
    }

    #[test]
    fn reconnect_policy_validate_rejects_zero_attempts() {
        let policy = ReconnectPolicy {
            max_attempts: 0,
            ..ReconnectPolicy::default()
        };
        let err = policy
            .validate()
            .expect_err("max_attempts=0 must be rejected");
        assert_eq!(err.config, "ReconnectPolicy");
        assert_eq!(err.field, "max_attempts");
    }
}
