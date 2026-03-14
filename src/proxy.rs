use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::client::{
    ClientDisconnectReason, ClientSendOptions, RaknetClient, RaknetClientConfig, RaknetClientError,
    RaknetClientEvent, ReconnectPolicy,
};
use crate::error::ConfigValidationError;
use crate::protocol::reliability::Reliability;
use crate::server::{PeerDisconnectReason, PeerId, RaknetServer, RaknetServerEvent, SendOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    DownstreamToUpstream,
    UpstreamToDownstream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    Forward(Bytes),
    Drop,
    Disconnect { reason: &'static str },
}

pub trait RelayPolicy: Send + Sync + 'static {
    fn decide(&self, direction: RelayDirection, payload: &Bytes) -> RelayDecision {
        let _ = direction;
        RelayDecision::Forward(payload.clone())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PassthroughRelayPolicy;

impl RelayPolicy for PassthroughRelayPolicy {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayContractConfig {
    pub max_payload_bytes: usize,
    pub allow_empty_payload: bool,
}

impl Default for RelayContractConfig {
    fn default() -> Self {
        Self {
            max_payload_bytes: 2 * 1024 * 1024,
            allow_empty_payload: false,
        }
    }
}

impl RelayContractConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_payload_bytes == 0 {
            return Err(ConfigValidationError::new(
                "RelayContractConfig",
                "max_payload_bytes",
                "must be >= 1",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RelayContractError {
    #[error("empty payload is not allowed by relay contract")]
    EmptyPayload,
    #[error("payload too large for relay contract: {actual} > {max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("relay policy requested disconnect: {reason}")]
    PolicyDisconnect { reason: &'static str },
}

pub struct RelayContract<P = PassthroughRelayPolicy> {
    config: RelayContractConfig,
    policy: P,
}

impl<P> RelayContract<P>
where
    P: RelayPolicy,
{
    pub fn new(config: RelayContractConfig, policy: P) -> Self {
        Self { config, policy }
    }

    pub fn config(&self) -> RelayContractConfig {
        self.config
    }

    pub fn apply(
        &self,
        direction: RelayDirection,
        payload: Bytes,
    ) -> Result<Option<Bytes>, RelayContractError> {
        self.validate_payload(&payload)?;

        match self.policy.decide(direction, &payload) {
            RelayDecision::Forward(bytes) => {
                self.validate_payload(&bytes)?;
                Ok(Some(bytes))
            }
            RelayDecision::Drop => Ok(None),
            RelayDecision::Disconnect { reason } => {
                Err(RelayContractError::PolicyDisconnect { reason })
            }
        }
    }

    fn validate_payload(&self, payload: &Bytes) -> Result<(), RelayContractError> {
        if payload.is_empty() && !self.config.allow_empty_payload {
            return Err(RelayContractError::EmptyPayload);
        }

        if payload.len() > self.config.max_payload_bytes {
            return Err(RelayContractError::PayloadTooLarge {
                actual: payload.len(),
                max: self.config.max_payload_bytes,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamConnectorConfig {
    pub client_config: RaknetClientConfig,
    pub reconnect_policy: ReconnectPolicy,
}

impl UpstreamConnectorConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.client_config.validate()?;
        self.reconnect_policy.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamConnector {
    pub upstream_addr: SocketAddr,
    pub config: UpstreamConnectorConfig,
}

impl UpstreamConnector {
    pub fn new(upstream_addr: SocketAddr, config: UpstreamConnectorConfig) -> Self {
        Self {
            upstream_addr,
            config,
        }
    }

    pub async fn connect(&self) -> Result<RaknetClient, RaknetClientError> {
        RaknetClient::connect_with_retry(
            self.upstream_addr,
            self.config.client_config.clone(),
            self.config.reconnect_policy.clone(),
        )
        .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayOverflowPolicy {
    #[default]
    DropNewest,
    DisconnectSession,
}

#[derive(Debug, Clone, Copy)]
pub struct RelayRuntimeConfig {
    pub per_session_downstream_queue_capacity: usize,
    pub session_event_queue_capacity: usize,
    pub downstream_to_upstream_send: ClientSendOptions,
    pub upstream_to_downstream_send: SendOptions,
    pub downstream_overflow_policy: RelayOverflowPolicy,
    pub budget_overflow_policy: RelayOverflowPolicy,
    pub downstream_max_pending_packets: usize,
    pub downstream_max_pending_bytes: usize,
    pub upstream_max_pending_packets: usize,
    pub upstream_max_pending_bytes: usize,
    pub session_total_max_pending_bytes: usize,
}

impl Default for RelayRuntimeConfig {
    fn default() -> Self {
        Self {
            per_session_downstream_queue_capacity: 256,
            session_event_queue_capacity: 1024,
            downstream_to_upstream_send: ClientSendOptions::default(),
            upstream_to_downstream_send: SendOptions::default(),
            downstream_overflow_policy: RelayOverflowPolicy::DropNewest,
            budget_overflow_policy: RelayOverflowPolicy::DisconnectSession,
            downstream_max_pending_packets: 256,
            downstream_max_pending_bytes: 512 * 1024,
            upstream_max_pending_packets: 512,
            upstream_max_pending_bytes: 1024 * 1024,
            session_total_max_pending_bytes: 1536 * 1024,
        }
    }
}

impl RelayRuntimeConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.per_session_downstream_queue_capacity == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "per_session_downstream_queue_capacity",
                "must be >= 1",
            ));
        }
        if self.session_event_queue_capacity == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "session_event_queue_capacity",
                "must be >= 1",
            ));
        }
        if self.downstream_max_pending_packets == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "downstream_max_pending_packets",
                "must be >= 1",
            ));
        }
        if self.downstream_max_pending_bytes == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "downstream_max_pending_bytes",
                "must be >= 1",
            ));
        }
        if self.upstream_max_pending_packets == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "upstream_max_pending_packets",
                "must be >= 1",
            ));
        }
        if self.upstream_max_pending_bytes == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "upstream_max_pending_bytes",
                "must be >= 1",
            ));
        }
        if self.session_total_max_pending_bytes == 0 {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "session_total_max_pending_bytes",
                "must be >= 1",
            ));
        }
        let min_total = self
            .downstream_max_pending_bytes
            .max(self.upstream_max_pending_bytes);
        if self.session_total_max_pending_bytes < min_total {
            return Err(ConfigValidationError::new(
                "RelayRuntimeConfig",
                "session_total_max_pending_bytes",
                format!(
                    "must be >= max(downstream_max_pending_bytes, upstream_max_pending_bytes) = {min_total}"
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBudgetExceeded {
    pub pending_packets: usize,
    pub pending_bytes: usize,
    pub packet_limit: usize,
    pub byte_limit: usize,
    pub total_pending_bytes: usize,
    pub total_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDropReason {
    NoSession,
    QueueOverflow,
    BudgetExceeded(RelayBudgetExceeded),
    PolicyDrop,
    ContractViolation(RelayContractError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelaySessionCloseReason {
    DownstreamDisconnected {
        reason: PeerDisconnectReason,
    },
    UpstreamDisconnected {
        reason: ClientDisconnectReason,
    },
    UpstreamConnectFailed {
        message: String,
    },
    UpstreamSendFailed {
        message: String,
    },
    DownstreamSendFailed {
        message: String,
    },
    ContractViolation {
        direction: RelayDirection,
        error: RelayContractError,
    },
    PolicyDisconnect {
        direction: RelayDirection,
        reason: &'static str,
    },
    BudgetExceeded {
        direction: RelayDirection,
        details: RelayBudgetExceeded,
    },
    DownstreamQueueOverflow,
    CommandChannelClosed,
    ProxyShutdown,
}

#[derive(Debug)]
pub enum RaknetRelayProxyEvent {
    SessionStarted {
        peer_id: PeerId,
        downstream_addr: SocketAddr,
        upstream_addr: SocketAddr,
    },
    Forwarded {
        peer_id: PeerId,
        direction: RelayDirection,
        payload_len: usize,
    },
    Dropped {
        peer_id: PeerId,
        direction: RelayDirection,
        reason: RelayDropReason,
    },
    DecodeError {
        peer_id: PeerId,
        direction: RelayDirection,
        error: String,
    },
    SessionClosed {
        peer_id: PeerId,
        reason: RelaySessionCloseReason,
    },
    DownstreamRateLimited {
        addr: SocketAddr,
    },
    DownstreamSessionLimitReached {
        addr: SocketAddr,
    },
    DownstreamProxyDropped {
        addr: SocketAddr,
    },
    DownstreamDecodeError {
        addr: SocketAddr,
        error: String,
    },
    DownstreamWorkerError {
        shard_id: usize,
        message: String,
    },
    DownstreamWorkerStopped {
        shard_id: usize,
    },
}

struct RelaySessionHandle {
    command_tx: mpsc::Sender<RelaySessionCommand>,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
    downstream_pending_packets: Arc<AtomicUsize>,
    downstream_pending_bytes: Arc<AtomicUsize>,
    upstream_pending_packets: Arc<AtomicUsize>,
    upstream_pending_bytes: Arc<AtomicUsize>,
}

enum RelayInput {
    Server(Option<RaknetServerEvent>),
    Session(Option<RelaySessionEvent>),
}

enum RelaySessionCommand {
    ForwardDownstreamPayload {
        payload: Bytes,
        send_options: ClientSendOptions,
    },
    Disconnect,
}

enum RelaySessionEvent {
    ForwardToDownstream {
        peer_id: PeerId,
        payload: Bytes,
        send_options: SendOptions,
    },
    Forwarded {
        peer_id: PeerId,
        direction: RelayDirection,
        payload_len: usize,
    },
    Dropped {
        peer_id: PeerId,
        direction: RelayDirection,
        reason: RelayDropReason,
    },
    DecodeError {
        peer_id: PeerId,
        direction: RelayDirection,
        error: String,
    },
    Terminated {
        peer_id: PeerId,
        reason: RelaySessionCloseReason,
    },
}

struct RelaySessionRuntimeContext {
    event_tx: mpsc::Sender<RelaySessionEvent>,
    upstream_to_downstream_send: SendOptions,
    runtime_config: RelayRuntimeConfig,
    stop: Arc<AtomicBool>,
    downstream_pending_packets: Arc<AtomicUsize>,
    downstream_pending_bytes: Arc<AtomicUsize>,
    upstream_pending_packets: Arc<AtomicUsize>,
    upstream_pending_bytes: Arc<AtomicUsize>,
}

pub struct RaknetRelayProxy<P = PassthroughRelayPolicy> {
    server: RaknetServer,
    upstream_connector: UpstreamConnector,
    contract: Arc<RelayContract<P>>,
    runtime_config: RelayRuntimeConfig,
    sessions: HashMap<PeerId, RelaySessionHandle>,
    session_event_tx: mpsc::Sender<RelaySessionEvent>,
    session_event_rx: mpsc::Receiver<RelaySessionEvent>,
    pending_events: VecDeque<RaknetRelayProxyEvent>,
}

impl<P> RaknetRelayProxy<P>
where
    P: RelayPolicy,
{
    pub fn try_new(
        server: RaknetServer,
        upstream_connector: UpstreamConnector,
        contract: RelayContract<P>,
        runtime_config: RelayRuntimeConfig,
    ) -> io::Result<Self> {
        upstream_connector
            .config
            .validate()
            .map_err(invalid_config_io_error)?;
        contract
            .config()
            .validate()
            .map_err(invalid_config_io_error)?;
        runtime_config.validate().map_err(invalid_config_io_error)?;
        Ok(Self::new(
            server,
            upstream_connector,
            contract,
            runtime_config,
        ))
    }

    pub fn new(
        server: RaknetServer,
        upstream_connector: UpstreamConnector,
        contract: RelayContract<P>,
        runtime_config: RelayRuntimeConfig,
    ) -> Self {
        let (session_event_tx, session_event_rx) =
            mpsc::channel(runtime_config.session_event_queue_capacity.max(1));

        Self {
            server,
            upstream_connector,
            contract: Arc::new(contract),
            runtime_config,
            sessions: HashMap::new(),
            session_event_tx,
            session_event_rx,
            pending_events: VecDeque::new(),
        }
    }

    pub async fn bind(
        downstream_bind_addr: SocketAddr,
        upstream_connector: UpstreamConnector,
        contract: RelayContract<P>,
        runtime_config: RelayRuntimeConfig,
    ) -> io::Result<Self> {
        let server = RaknetServer::bind(downstream_bind_addr).await?;
        Self::try_new(server, upstream_connector, contract, runtime_config)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub async fn next_event(&mut self) -> Option<RaknetRelayProxyEvent> {
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }

        loop {
            let input = {
                let server = &mut self.server;
                let session_event_rx = &mut self.session_event_rx;
                tokio::select! {
                    event = server.next_event() => RelayInput::Server(event),
                    event = session_event_rx.recv() => RelayInput::Session(event),
                }
            };

            match input {
                RelayInput::Server(Some(event)) => self.handle_server_event(event).await,
                RelayInput::Session(Some(event)) => self.handle_session_event(event).await,
                RelayInput::Server(None) => return None,
                RelayInput::Session(None) => {
                    if self.sessions.is_empty() {
                        return None;
                    }
                }
            }

            if let Some(event) = self.pending_events.pop_front() {
                return Some(event);
            }
        }
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop_all_sessions().await;
        self.server.shutdown().await
    }

    async fn handle_server_event(&mut self, event: RaknetServerEvent) {
        match event {
            RaknetServerEvent::PeerConnected { peer_id, addr, .. } => {
                if let Some(existing) = self.sessions.remove(&peer_id) {
                    self.finalize_session_handle(existing, true).await;
                }

                match self.upstream_connector.connect().await {
                    Ok(upstream_client) => {
                        let upstream_addr = upstream_client.server_addr();
                        self.spawn_session(peer_id, upstream_client);
                        self.pending_events
                            .push_back(RaknetRelayProxyEvent::SessionStarted {
                                peer_id,
                                downstream_addr: addr,
                                upstream_addr,
                            });
                    }
                    Err(error) => {
                        let reason = RelaySessionCloseReason::UpstreamConnectFailed {
                            message: error.to_string(),
                        };
                        let _ = self.server.disconnect(peer_id).await;
                        self.pending_events
                            .push_back(RaknetRelayProxyEvent::SessionClosed { peer_id, reason });
                    }
                }
            }
            RaknetServerEvent::PeerDisconnected {
                peer_id, reason, ..
            } => {
                let _ = self
                    .close_session(
                        peer_id,
                        RelaySessionCloseReason::DownstreamDisconnected { reason },
                        true,
                        false,
                    )
                    .await;
            }
            RaknetServerEvent::Packet {
                peer_id,
                payload,
                reliability,
                ordering_channel,
                ..
            } => {
                self.forward_downstream_payload(peer_id, payload, reliability, ordering_channel)
                    .await;
            }
            RaknetServerEvent::PeerRateLimited { addr } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DownstreamRateLimited { addr });
            }
            RaknetServerEvent::SessionLimitReached { addr } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DownstreamSessionLimitReached { addr });
            }
            RaknetServerEvent::ProxyDropped { addr } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DownstreamProxyDropped { addr });
            }
            RaknetServerEvent::DecodeError { addr, error } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DownstreamDecodeError { addr, error });
            }
            RaknetServerEvent::WorkerError { shard_id, message } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DownstreamWorkerError { shard_id, message });
            }
            RaknetServerEvent::WorkerStopped { shard_id } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DownstreamWorkerStopped { shard_id });
            }
            RaknetServerEvent::OfflinePacket { .. } => {}
            RaknetServerEvent::ReceiptAcked { .. } => {}
            RaknetServerEvent::Metrics { .. } => {}
        }
    }

    async fn forward_downstream_payload(
        &mut self,
        peer_id: PeerId,
        payload: Bytes,
        reliability: Reliability,
        ordering_channel: Option<u8>,
    ) {
        let Some(session) = self.sessions.get(&peer_id) else {
            self.pending_events
                .push_back(RaknetRelayProxyEvent::Dropped {
                    peer_id,
                    direction: RelayDirection::DownstreamToUpstream,
                    reason: RelayDropReason::NoSession,
                });
            return;
        };

        let payload_len = payload.len();
        let send_options = downstream_to_upstream_send_options(
            self.runtime_config.downstream_to_upstream_send,
            reliability,
            ordering_channel,
        );
        if let Err(details) = try_reserve_budget(
            RelayDirection::DownstreamToUpstream,
            payload_len,
            self.runtime_config,
            &session.downstream_pending_packets,
            &session.downstream_pending_bytes,
            &session.upstream_pending_packets,
            &session.upstream_pending_bytes,
        ) {
            match self.runtime_config.budget_overflow_policy {
                RelayOverflowPolicy::DropNewest => {
                    self.pending_events
                        .push_back(RaknetRelayProxyEvent::Dropped {
                            peer_id,
                            direction: RelayDirection::DownstreamToUpstream,
                            reason: RelayDropReason::BudgetExceeded(details),
                        });
                }
                RelayOverflowPolicy::DisconnectSession => {
                    let _ = self
                        .close_session(
                            peer_id,
                            RelaySessionCloseReason::BudgetExceeded {
                                direction: RelayDirection::DownstreamToUpstream,
                                details,
                            },
                            true,
                            true,
                        )
                        .await;
                }
            }
            return;
        }

        match session
            .command_tx
            .try_send(RelaySessionCommand::ForwardDownstreamPayload {
                payload,
                send_options,
            }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => match self.runtime_config.downstream_overflow_policy {
                RelayOverflowPolicy::DropNewest => {
                    release_reserved_budget(
                        RelayDirection::DownstreamToUpstream,
                        payload_len,
                        &session.downstream_pending_packets,
                        &session.downstream_pending_bytes,
                        &session.upstream_pending_packets,
                        &session.upstream_pending_bytes,
                    );
                    self.pending_events
                        .push_back(RaknetRelayProxyEvent::Dropped {
                            peer_id,
                            direction: RelayDirection::DownstreamToUpstream,
                            reason: RelayDropReason::QueueOverflow,
                        });
                }
                RelayOverflowPolicy::DisconnectSession => {
                    release_reserved_budget(
                        RelayDirection::DownstreamToUpstream,
                        payload_len,
                        &session.downstream_pending_packets,
                        &session.downstream_pending_bytes,
                        &session.upstream_pending_packets,
                        &session.upstream_pending_bytes,
                    );
                    let _ = self
                        .close_session(
                            peer_id,
                            RelaySessionCloseReason::DownstreamQueueOverflow,
                            true,
                            true,
                        )
                        .await;
                }
            },
            Err(TrySendError::Closed(_)) => {
                release_reserved_budget(
                    RelayDirection::DownstreamToUpstream,
                    payload_len,
                    &session.downstream_pending_packets,
                    &session.downstream_pending_bytes,
                    &session.upstream_pending_packets,
                    &session.upstream_pending_bytes,
                );
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::Dropped {
                        peer_id,
                        direction: RelayDirection::DownstreamToUpstream,
                        reason: RelayDropReason::NoSession,
                    });

                let _ = self
                    .close_session(
                        peer_id,
                        RelaySessionCloseReason::CommandChannelClosed,
                        false,
                        true,
                    )
                    .await;
            }
        }
    }

    async fn handle_session_event(&mut self, event: RelaySessionEvent) {
        match event {
            RelaySessionEvent::ForwardToDownstream {
                peer_id,
                payload,
                send_options,
            } => {
                let payload_len = payload.len();
                if let Some(session) = self.sessions.get(&peer_id) {
                    release_reserved_budget(
                        RelayDirection::UpstreamToDownstream,
                        payload_len,
                        &session.downstream_pending_packets,
                        &session.downstream_pending_bytes,
                        &session.upstream_pending_packets,
                        &session.upstream_pending_bytes,
                    );
                }

                match self
                    .server
                    .send_with_options(peer_id, payload, send_options)
                    .await
                {
                    Ok(()) => {
                        self.pending_events
                            .push_back(RaknetRelayProxyEvent::Forwarded {
                                peer_id,
                                direction: RelayDirection::UpstreamToDownstream,
                                payload_len,
                            });
                    }
                    Err(error) => {
                        let _ = self
                            .close_session(
                                peer_id,
                                RelaySessionCloseReason::DownstreamSendFailed {
                                    message: error.to_string(),
                                },
                                true,
                                true,
                            )
                            .await;
                    }
                }
            }
            RelaySessionEvent::Forwarded {
                peer_id,
                direction,
                payload_len,
            } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::Forwarded {
                        peer_id,
                        direction,
                        payload_len,
                    });
            }
            RelaySessionEvent::Dropped {
                peer_id,
                direction,
                reason,
            } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::Dropped {
                        peer_id,
                        direction,
                        reason,
                    });
            }
            RelaySessionEvent::DecodeError {
                peer_id,
                direction,
                error,
            } => {
                self.pending_events
                    .push_back(RaknetRelayProxyEvent::DecodeError {
                        peer_id,
                        direction,
                        error,
                    });
            }
            RelaySessionEvent::Terminated { peer_id, reason } => {
                let disconnect_downstream = should_disconnect_downstream(&reason);
                let _ = self
                    .close_session(peer_id, reason, false, disconnect_downstream)
                    .await;
            }
        }
    }

    fn spawn_session(&mut self, peer_id: PeerId, upstream_client: RaknetClient) {
        let (command_tx, command_rx) = mpsc::channel(
            self.runtime_config
                .per_session_downstream_queue_capacity
                .max(1),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let downstream_pending_packets = Arc::new(AtomicUsize::new(0));
        let downstream_pending_bytes = Arc::new(AtomicUsize::new(0));
        let upstream_pending_packets = Arc::new(AtomicUsize::new(0));
        let upstream_pending_bytes = Arc::new(AtomicUsize::new(0));

        let contract = Arc::clone(&self.contract);
        let session_context = RelaySessionRuntimeContext {
            event_tx: self.session_event_tx.clone(),
            upstream_to_downstream_send: self.runtime_config.upstream_to_downstream_send,
            runtime_config: self.runtime_config,
            stop: Arc::clone(&stop),
            downstream_pending_packets: Arc::clone(&downstream_pending_packets),
            downstream_pending_bytes: Arc::clone(&downstream_pending_bytes),
            upstream_pending_packets: Arc::clone(&upstream_pending_packets),
            upstream_pending_bytes: Arc::clone(&upstream_pending_bytes),
        };

        let join = tokio::spawn(async move {
            run_relay_session(
                peer_id,
                upstream_client,
                contract,
                command_rx,
                session_context,
            )
            .await;
        });

        self.sessions.insert(
            peer_id,
            RelaySessionHandle {
                command_tx,
                stop,
                join,
                downstream_pending_packets,
                downstream_pending_bytes,
                upstream_pending_packets,
                upstream_pending_bytes,
            },
        );
    }

    async fn stop_all_sessions(&mut self) {
        let sessions = self
            .sessions
            .drain()
            .map(|(_, session)| session)
            .collect::<Vec<_>>();

        for session in sessions {
            self.finalize_session_handle(session, true).await;
        }
    }

    async fn finalize_session_handle(&self, session: RelaySessionHandle, request_disconnect: bool) {
        let RelaySessionHandle {
            command_tx,
            stop,
            mut join,
            downstream_pending_packets: _,
            downstream_pending_bytes: _,
            upstream_pending_packets: _,
            upstream_pending_bytes: _,
        } = session;

        if request_disconnect {
            stop.store(true, Ordering::Relaxed);
            let _ = command_tx.try_send(RelaySessionCommand::Disconnect);
        }

        if timeout(Duration::from_millis(200), &mut join)
            .await
            .is_err()
        {
            join.abort();
            let _ = join.await;
        }
    }

    async fn close_session(
        &mut self,
        peer_id: PeerId,
        reason: RelaySessionCloseReason,
        request_upstream_disconnect: bool,
        request_downstream_disconnect: bool,
    ) -> bool {
        let Some(session) = self.sessions.remove(&peer_id) else {
            return false;
        };

        self.finalize_session_handle(session, request_upstream_disconnect)
            .await;
        if request_downstream_disconnect {
            let _ = self.server.disconnect(peer_id).await;
        }
        self.pending_events
            .push_back(RaknetRelayProxyEvent::SessionClosed { peer_id, reason });
        true
    }
}

fn try_reserve_budget(
    direction: RelayDirection,
    payload_len: usize,
    runtime_config: RelayRuntimeConfig,
    downstream_pending_packets: &AtomicUsize,
    downstream_pending_bytes: &AtomicUsize,
    upstream_pending_packets: &AtomicUsize,
    upstream_pending_bytes: &AtomicUsize,
) -> Result<(), RelayBudgetExceeded> {
    let (dir_pending_packets, dir_pending_bytes, packet_limit, byte_limit) = match direction {
        RelayDirection::DownstreamToUpstream => (
            downstream_pending_packets.load(Ordering::Relaxed),
            downstream_pending_bytes.load(Ordering::Relaxed),
            runtime_config.downstream_max_pending_packets.max(1),
            runtime_config.downstream_max_pending_bytes.max(1),
        ),
        RelayDirection::UpstreamToDownstream => (
            upstream_pending_packets.load(Ordering::Relaxed),
            upstream_pending_bytes.load(Ordering::Relaxed),
            runtime_config.upstream_max_pending_packets.max(1),
            runtime_config.upstream_max_pending_bytes.max(1),
        ),
    };

    let total_pending_bytes = downstream_pending_bytes.load(Ordering::Relaxed)
        + upstream_pending_bytes.load(Ordering::Relaxed);
    let total_limit = runtime_config.session_total_max_pending_bytes.max(1);

    if dir_pending_packets.saturating_add(1) > packet_limit
        || dir_pending_bytes.saturating_add(payload_len) > byte_limit
        || total_pending_bytes.saturating_add(payload_len) > total_limit
    {
        return Err(RelayBudgetExceeded {
            pending_packets: dir_pending_packets,
            pending_bytes: dir_pending_bytes,
            packet_limit,
            byte_limit,
            total_pending_bytes,
            total_limit,
        });
    }

    match direction {
        RelayDirection::DownstreamToUpstream => {
            downstream_pending_packets.fetch_add(1, Ordering::Relaxed);
            downstream_pending_bytes.fetch_add(payload_len, Ordering::Relaxed);
        }
        RelayDirection::UpstreamToDownstream => {
            upstream_pending_packets.fetch_add(1, Ordering::Relaxed);
            upstream_pending_bytes.fetch_add(payload_len, Ordering::Relaxed);
        }
    }

    Ok(())
}

fn release_reserved_budget(
    direction: RelayDirection,
    payload_len: usize,
    downstream_pending_packets: &AtomicUsize,
    downstream_pending_bytes: &AtomicUsize,
    upstream_pending_packets: &AtomicUsize,
    upstream_pending_bytes: &AtomicUsize,
) {
    match direction {
        RelayDirection::DownstreamToUpstream => {
            atomic_saturating_sub(downstream_pending_packets, 1);
            atomic_saturating_sub(downstream_pending_bytes, payload_len);
        }
        RelayDirection::UpstreamToDownstream => {
            atomic_saturating_sub(upstream_pending_packets, 1);
            atomic_saturating_sub(upstream_pending_bytes, payload_len);
        }
    }
}

fn atomic_saturating_sub(counter: &AtomicUsize, value: usize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(value))
    });
}

fn should_disconnect_downstream(reason: &RelaySessionCloseReason) -> bool {
    matches!(
        reason,
        RelaySessionCloseReason::UpstreamDisconnected { .. }
            | RelaySessionCloseReason::UpstreamSendFailed { .. }
            | RelaySessionCloseReason::ContractViolation { .. }
            | RelaySessionCloseReason::PolicyDisconnect { .. }
            | RelaySessionCloseReason::BudgetExceeded { .. }
            | RelaySessionCloseReason::CommandChannelClosed
    )
}

#[inline]
fn apply_channel_hint(default_channel: u8, ordering_channel: Option<u8>) -> u8 {
    ordering_channel.unwrap_or(default_channel)
}

#[inline]
fn downstream_to_upstream_send_options(
    defaults: ClientSendOptions,
    reliability: Reliability,
    ordering_channel: Option<u8>,
) -> ClientSendOptions {
    ClientSendOptions {
        reliability,
        channel: apply_channel_hint(defaults.channel, ordering_channel),
        priority: defaults.priority,
    }
}

#[inline]
fn upstream_to_downstream_send_options(
    defaults: SendOptions,
    reliability: Reliability,
    ordering_channel: Option<u8>,
) -> SendOptions {
    SendOptions {
        reliability,
        channel: apply_channel_hint(defaults.channel, ordering_channel),
        priority: defaults.priority,
    }
}

fn invalid_config_io_error(error: ConfigValidationError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

async fn emit_session_event(
    tx: &mpsc::Sender<RelaySessionEvent>,
    event: RelaySessionEvent,
) -> bool {
    tx.send(event).await.is_ok()
}

async fn run_relay_session<P>(
    peer_id: PeerId,
    mut upstream: RaknetClient,
    contract: Arc<RelayContract<P>>,
    mut command_rx: mpsc::Receiver<RelaySessionCommand>,
    context: RelaySessionRuntimeContext,
) where
    P: RelayPolicy,
{
    let RelaySessionRuntimeContext {
        event_tx,
        upstream_to_downstream_send,
        runtime_config,
        stop,
        downstream_pending_packets,
        downstream_pending_bytes,
        upstream_pending_packets,
        upstream_pending_bytes,
    } = context;

    loop {
        if stop.load(Ordering::Relaxed) {
            let _ = upstream.disconnect(None).await;
            emit_session_event(
                &event_tx,
                RelaySessionEvent::Terminated {
                    peer_id,
                    reason: RelaySessionCloseReason::ProxyShutdown,
                },
            )
            .await;
            break;
        }

        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(RelaySessionCommand::ForwardDownstreamPayload {
                        payload,
                        send_options,
                    }) => {
                        release_reserved_budget(
                            RelayDirection::DownstreamToUpstream,
                            payload.len(),
                            &downstream_pending_packets,
                            &downstream_pending_bytes,
                            &upstream_pending_packets,
                            &upstream_pending_bytes,
                        );

                        match contract.apply(RelayDirection::DownstreamToUpstream, payload) {
                            Ok(Some(forward_payload)) => {
                                let payload_len = forward_payload.len();
                                match upstream.send_with_options(forward_payload, send_options).await {
                                    Ok(()) => {
                                        emit_session_event(
                                            &event_tx,
                                            RelaySessionEvent::Forwarded {
                                                peer_id,
                                                direction: RelayDirection::DownstreamToUpstream,
                                                payload_len,
                                            },
                                        ).await;
                                    }
                                    Err(error) => {
                                        emit_session_event(
                                            &event_tx,
                                            RelaySessionEvent::Terminated {
                                                peer_id,
                                                reason: RelaySessionCloseReason::UpstreamSendFailed {
                                                    message: error.to_string(),
                                                },
                                            },
                                        ).await;
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Dropped {
                                        peer_id,
                                        direction: RelayDirection::DownstreamToUpstream,
                                        reason: RelayDropReason::PolicyDrop,
                                    },
                                ).await;
                            }
                            Err(RelayContractError::PolicyDisconnect { reason }) => {
                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Terminated {
                                        peer_id,
                                        reason: RelaySessionCloseReason::PolicyDisconnect {
                                            direction: RelayDirection::DownstreamToUpstream,
                                            reason,
                                        },
                                    },
                                ).await;
                                break;
                            }
                            Err(error) => {
                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Dropped {
                                        peer_id,
                                        direction: RelayDirection::DownstreamToUpstream,
                                        reason: RelayDropReason::ContractViolation(error.clone()),
                                    },
                                ).await;

                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Terminated {
                                        peer_id,
                                        reason: RelaySessionCloseReason::ContractViolation {
                                            direction: RelayDirection::DownstreamToUpstream,
                                            error,
                                        },
                                    },
                                ).await;
                                break;
                            }
                        }
                    }
                    Some(RelaySessionCommand::Disconnect) => {
                        let _ = upstream.disconnect(None).await;
                        emit_session_event(
                            &event_tx,
                            RelaySessionEvent::Terminated {
                                peer_id,
                                reason: RelaySessionCloseReason::ProxyShutdown,
                            },
                        ).await;
                        break;
                    }
                    None => {
                        emit_session_event(
                            &event_tx,
                            RelaySessionEvent::Terminated {
                                peer_id,
                                reason: RelaySessionCloseReason::CommandChannelClosed,
                            },
                        ).await;
                        break;
                    }
                }
            }
            upstream_event = upstream.next_event() => {
                match upstream_event {
                    Some(RaknetClientEvent::Packet {
                        payload,
                        reliability,
                        ordering_channel,
                        ..
                    }) => {
                        match contract.apply(RelayDirection::UpstreamToDownstream, payload) {
                            Ok(Some(forward_payload)) => {
                                let payload_len = forward_payload.len();
                                let send_options = upstream_to_downstream_send_options(
                                    upstream_to_downstream_send,
                                    reliability,
                                    ordering_channel,
                                );
                                match try_reserve_budget(
                                    RelayDirection::UpstreamToDownstream,
                                    payload_len,
                                    runtime_config,
                                    &downstream_pending_packets,
                                    &downstream_pending_bytes,
                                    &upstream_pending_packets,
                                    &upstream_pending_bytes,
                                ) {
                                    Ok(()) => {
                                        if !emit_session_event(
                                            &event_tx,
                                            RelaySessionEvent::ForwardToDownstream {
                                                peer_id,
                                                payload: forward_payload,
                                                send_options,
                                            },
                                        )
                                        .await
                                        {
                                            release_reserved_budget(
                                                RelayDirection::UpstreamToDownstream,
                                                payload_len,
                                                &downstream_pending_packets,
                                                &downstream_pending_bytes,
                                                &upstream_pending_packets,
                                                &upstream_pending_bytes,
                                            );
                                            emit_session_event(
                                                &event_tx,
                                                RelaySessionEvent::Terminated {
                                                    peer_id,
                                                    reason: RelaySessionCloseReason::CommandChannelClosed,
                                                },
                                            )
                                            .await;
                                            break;
                                        }
                                    }
                                    Err(details) => match runtime_config.budget_overflow_policy {
                                        RelayOverflowPolicy::DropNewest => {
                                            emit_session_event(
                                                &event_tx,
                                                RelaySessionEvent::Dropped {
                                                    peer_id,
                                                    direction: RelayDirection::UpstreamToDownstream,
                                                    reason: RelayDropReason::BudgetExceeded(details),
                                                },
                                            )
                                            .await;
                                        }
                                        RelayOverflowPolicy::DisconnectSession => {
                                            emit_session_event(
                                                &event_tx,
                                                RelaySessionEvent::Terminated {
                                                    peer_id,
                                                    reason: RelaySessionCloseReason::BudgetExceeded {
                                                        direction: RelayDirection::UpstreamToDownstream,
                                                        details,
                                                    },
                                                },
                                            )
                                            .await;
                                            break;
                                        }
                                    },
                                }
                            }
                            Ok(None) => {
                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Dropped {
                                        peer_id,
                                        direction: RelayDirection::UpstreamToDownstream,
                                        reason: RelayDropReason::PolicyDrop,
                                    },
                                ).await;
                            }
                            Err(RelayContractError::PolicyDisconnect { reason }) => {
                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Terminated {
                                        peer_id,
                                        reason: RelaySessionCloseReason::PolicyDisconnect {
                                            direction: RelayDirection::UpstreamToDownstream,
                                            reason,
                                        },
                                    },
                                ).await;
                                break;
                            }
                            Err(error) => {
                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Dropped {
                                        peer_id,
                                        direction: RelayDirection::UpstreamToDownstream,
                                        reason: RelayDropReason::ContractViolation(error.clone()),
                                    },
                                ).await;

                                emit_session_event(
                                    &event_tx,
                                    RelaySessionEvent::Terminated {
                                        peer_id,
                                        reason: RelaySessionCloseReason::ContractViolation {
                                            direction: RelayDirection::UpstreamToDownstream,
                                            error,
                                        },
                                    },
                                ).await;
                                break;
                            }
                        }
                    }
                    Some(RaknetClientEvent::Disconnected { reason }) => {
                        emit_session_event(
                            &event_tx,
                            RelaySessionEvent::Terminated {
                                peer_id,
                                reason: RelaySessionCloseReason::UpstreamDisconnected { reason },
                            },
                        ).await;
                        break;
                    }
                    Some(RaknetClientEvent::DecodeError { error }) => {
                        emit_session_event(
                            &event_tx,
                            RelaySessionEvent::DecodeError {
                                peer_id,
                                direction: RelayDirection::UpstreamToDownstream,
                                error,
                            },
                        ).await;
                    }
                    Some(RaknetClientEvent::Connected { .. })
                    | Some(RaknetClientEvent::ReceiptAcked { .. }) => {}
                    None => {
                        emit_session_event(
                            &event_tx,
                            RelaySessionEvent::Terminated {
                                peer_id,
                                reason: RelaySessionCloseReason::UpstreamDisconnected {
                                    reason: ClientDisconnectReason::TransportError {
                                        message: "upstream event stream ended".to_string(),
                                    },
                                },
                            },
                        ).await;
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::client::ClientSendOptions;
    use crate::protocol::reliability::Reliability;
    use crate::server::SendOptions;
    use crate::session::RakPriority;

    use super::{
        PassthroughRelayPolicy, RelayContract, RelayContractConfig, RelayContractError,
        RelayDecision, RelayDirection, RelayPolicy, RelayRuntimeConfig,
    };

    #[test]
    fn contract_rejects_empty_when_disabled() {
        let contract = RelayContract::new(
            RelayContractConfig {
                max_payload_bytes: 64,
                allow_empty_payload: false,
            },
            PassthroughRelayPolicy,
        );

        let err = contract
            .apply(RelayDirection::DownstreamToUpstream, Bytes::new())
            .expect_err("empty payload must be rejected");
        assert_eq!(err, RelayContractError::EmptyPayload);
    }

    #[test]
    fn contract_rejects_oversized_payload() {
        let contract = RelayContract::new(
            RelayContractConfig {
                max_payload_bytes: 2,
                allow_empty_payload: true,
            },
            PassthroughRelayPolicy,
        );

        let err = contract
            .apply(
                RelayDirection::DownstreamToUpstream,
                Bytes::from_static(b"abc"),
            )
            .expect_err("oversized payload must be rejected");

        assert_eq!(
            err,
            RelayContractError::PayloadTooLarge { actual: 3, max: 2 }
        );
    }

    struct DropPolicy;

    impl RelayPolicy for DropPolicy {
        fn decide(&self, _direction: RelayDirection, _payload: &Bytes) -> RelayDecision {
            RelayDecision::Drop
        }
    }

    struct DisconnectPolicy;

    impl RelayPolicy for DisconnectPolicy {
        fn decide(&self, _direction: RelayDirection, _payload: &Bytes) -> RelayDecision {
            RelayDecision::Disconnect {
                reason: "policy_disconnect",
            }
        }
    }

    #[test]
    fn policy_can_drop_payload() {
        let contract = RelayContract::new(RelayContractConfig::default(), DropPolicy);
        let result = contract
            .apply(
                RelayDirection::UpstreamToDownstream,
                Bytes::from_static(b"ok"),
            )
            .expect("drop should not error");

        assert!(result.is_none());
    }

    #[test]
    fn policy_disconnect_is_reported() {
        let contract = RelayContract::new(RelayContractConfig::default(), DisconnectPolicy);
        let err = contract
            .apply(
                RelayDirection::UpstreamToDownstream,
                Bytes::from_static(b"ok"),
            )
            .expect_err("disconnect policy must error");

        assert_eq!(
            err,
            RelayContractError::PolicyDisconnect {
                reason: "policy_disconnect"
            }
        );
    }

    #[test]
    fn runtime_config_defaults_are_non_zero() {
        let cfg = RelayRuntimeConfig::default();
        assert!(cfg.per_session_downstream_queue_capacity > 0);
        assert!(cfg.session_event_queue_capacity > 0);
        cfg.validate()
            .expect("default relay runtime config must be valid");
    }

    #[test]
    fn contract_config_validate_rejects_zero_payload_limit() {
        let cfg = RelayContractConfig {
            max_payload_bytes: 0,
            allow_empty_payload: true,
        };
        let err = cfg
            .validate()
            .expect_err("max_payload_bytes=0 must be rejected");
        assert_eq!(err.config, "RelayContractConfig");
        assert_eq!(err.field, "max_payload_bytes");
    }

    #[test]
    fn runtime_config_validate_rejects_total_budget_below_directional_max() {
        let cfg = RelayRuntimeConfig {
            downstream_max_pending_bytes: 512,
            upstream_max_pending_bytes: 1024,
            session_total_max_pending_bytes: 900,
            ..RelayRuntimeConfig::default()
        };
        let err = cfg.validate().expect_err("invalid total budget must fail");
        assert_eq!(err.config, "RelayRuntimeConfig");
        assert_eq!(err.field, "session_total_max_pending_bytes");
    }

    #[test]
    fn downstream_send_options_preserve_reliability_and_channel_hint() {
        let defaults = ClientSendOptions {
            reliability: Reliability::ReliableOrdered,
            channel: 0,
            priority: RakPriority::Immediate,
        };
        let options =
            super::downstream_to_upstream_send_options(defaults, Reliability::Reliable, Some(9));
        assert_eq!(options.reliability, Reliability::Reliable);
        assert_eq!(options.channel, 9);
        assert_eq!(options.priority, RakPriority::Immediate);
    }

    #[test]
    fn upstream_send_options_fall_back_to_default_channel_when_missing_hint() {
        let defaults = SendOptions {
            reliability: Reliability::ReliableOrdered,
            channel: 3,
            priority: RakPriority::High,
        };
        let options =
            super::upstream_to_downstream_send_options(defaults, Reliability::Unreliable, None);
        assert_eq!(options.reliability, Reliability::Unreliable);
        assert_eq!(options.channel, 3);
        assert_eq!(options.priority, RakPriority::High);
    }
}
