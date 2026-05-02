use hmac::KeyInit;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{mem, os::fd::AsRawFd};

use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::DecodeError;
use crate::protocol::connected::{
    ConnectedControlPacket, ConnectedPing, ConnectedPong, ConnectionRequestAccepted,
    SYSTEM_ADDRESS_COUNT,
};
use crate::protocol::constants::{MAXIMUM_MTU_SIZE, MINIMUM_MTU_SIZE, RAKNET_PROTOCOL_VERSION};
use crate::protocol::datagram::{Datagram, DatagramPayload};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{ConnectionRejectReason, RejectData, IncompatibleProtocolVersion, OfflinePacket, OpenConnectionReply1, OpenConnectionReply2, Request2ParsePath, UnconnectedPong};
use crate::protocol::reliability::Reliability;
use crate::protocol::sequence24::Sequence24;
use crate::session::{
    QueuePayloadResult, RakPriority, ReceiptProgress, Session, SessionMetricsSnapshot, SessionState,
};

use super::config::{
    ProcessingBudgetConfig, Request2ServerAddrPolicy, TransportConfig, TransportSocketTuning,
};
use super::proxy::{InboundProxyRoute, OutboundProxyRoute, ProxyRouter};
use super::rate_limiter::{
    BlockReason, ProcessingBudgetDecision, ProcessingBudgetMetricsSnapshot, RateLimitDecision,
    RateLimiter, RateLimiterConfigSnapshot, RateLimiterMetricsSnapshot,
};
use super::session_pipeline::{
    PipelineFrameAction, SessionPipeline, SessionPipelineMetricsSnapshot,
};

const RECV_PATH_MAX_NEW_DATAGRAMS: usize = 6;
const RECV_PATH_MAX_RESEND_DATAGRAMS: usize = 6;
const COOKIE_KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;
type SecretCookieKey = Zeroizing<[u8; COOKIE_KEY_LEN]>;

#[derive(Debug)]
pub struct ConnectedFrameDelivery {
    pub payload: Bytes,
    pub reliability: Reliability,
    pub reliable_index: Option<Sequence24>,
    pub sequence_index: Option<Sequence24>,
    pub ordering_index: Option<Sequence24>,
    pub ordering_channel: Option<u8>,
}

impl ConnectedFrameDelivery {
    fn from_frame(frame: Frame) -> Self {
        Self {
            payload: frame.payload,
            reliability: frame.header.reliability,
            reliable_index: frame.reliable_index,
            sequence_index: frame.sequence_index,
            ordering_index: frame.ordering_index,
            ordering_channel: frame.ordering_channel,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDisconnectReason {
    DisconnectionNotification { reason_code: Option<u8> },
    DetectLostConnection,
}

#[derive(Debug)]
pub enum TransportEvent {
    RateLimited {
        addr: SocketAddr,
    },
    ProxyDropped {
        addr: SocketAddr,
    },
    SessionLimitReached {
        addr: SocketAddr,
    },
    OfflinePacket {
        addr: SocketAddr,
        packet: OfflinePacket,
    },
    ConnectedFrames {
        addr: SocketAddr,
        client_guid: Option<u64>,
        frames: Vec<ConnectedFrameDelivery>,
        frame_count: usize,
        receipts: ReceiptProgress,
    },
    ConnectedDatagramDroppedNoSession {
        addr: SocketAddr,
    },
    PeerDisconnected {
        addr: SocketAddr,
        reason: RemoteDisconnectReason,
    },
    DecodeError {
        addr: SocketAddr,
        error: DecodeError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDispatchResult {
    MissingSession,
    Enqueued { reliable_bytes: usize },
    Dropped,
    Deferred,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportRateLimitConfig {
    pub per_ip_packet_limit: usize,
    pub global_packet_limit: usize,
    pub rate_window: Duration,
    pub block_duration: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportProcessingBudgetConfig {
    pub enabled: bool,
    pub per_ip_refill_units_per_sec: u32,
    pub per_ip_burst_units: u32,
    pub global_refill_units_per_sec: u32,
    pub global_burst_units: u32,
    pub bucket_idle_ttl: Duration,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TransportMetricsSnapshot {
    pub session_count: usize,
    pub sessions_started_total: u64,
    pub sessions_closed_total: u64,
    pub packets_forwarded_total: u64,
    pub bytes_forwarded_total: u64,
    pub pending_outgoing_frames: usize,
    pub pending_outgoing_bytes: usize,
    pub pending_unhandled_frames: usize,
    pub pending_unhandled_bytes: usize,
    pub ingress_datagrams: u64,
    pub ingress_frames: u64,
    pub duplicate_reliable_drops: u64,
    pub ordered_stale_drops: u64,
    pub ordered_buffer_full_drops: u64,
    pub sequenced_stale_drops: u64,
    pub sequenced_missing_index_drops: u64,
    pub reliable_sent_datagrams: u64,
    pub resent_datagrams: u64,
    pub ack_out_total: u64,
    pub nack_out_total: u64,
    pub acked_datagrams: u64,
    pub nacked_datagrams: u64,
    pub split_ttl_drops: u64,
    pub outgoing_queue_drops: u64,
    pub outgoing_queue_defers: u64,
    pub outgoing_queue_disconnects: u64,
    pub backpressure_delays: u64,
    pub backpressure_drops: u64,
    pub backpressure_disconnects: u64,
    pub local_requested_disconnects: u64,
    pub remote_disconnect_notifications: u64,
    pub remote_detect_lost_disconnects: u64,
    pub illegal_state_transitions: u64,
    pub timed_out_sessions: u64,
    pub keepalive_pings_sent: u64,
    pub unhandled_frames_queued: u64,
    pub unhandled_frames_flushed: u64,
    pub unhandled_frames_dropped: u64,
    pub rate_global_limit_hits: u64,
    pub rate_ip_block_hits: u64,
    pub rate_ip_block_hits_rate_exceeded: u64,
    pub rate_ip_block_hits_manual: u64,
    pub rate_ip_block_hits_handshake_heuristic: u64,
    pub rate_ip_block_hits_cookie_mismatch_guard: u64,
    pub rate_addresses_blocked: u64,
    pub rate_addresses_blocked_rate_exceeded: u64,
    pub rate_addresses_blocked_manual: u64,
    pub rate_addresses_blocked_handshake_heuristic: u64,
    pub rate_addresses_blocked_cookie_mismatch_guard: u64,
    pub rate_addresses_unblocked: u64,
    pub rate_blocked_addresses: usize,
    pub rate_exception_addresses: usize,
    pub processing_budget_drops_total: u64,
    pub processing_budget_drops_ip_exhausted_total: u64,
    pub processing_budget_drops_global_exhausted_total: u64,
    pub processing_budget_consumed_units_total: u64,
    pub processing_budget_active_ip_buckets: usize,
    pub cookie_rotations: u64,
    pub cookie_mismatch_drops: u64,
    pub cookie_mismatch_blocks: u64,
    pub handshake_stage_cancel_drops: u64,
    pub handshake_req1_req2_timeouts: u64,
    pub handshake_reply2_connect_timeouts: u64,
    pub handshake_missing_req1_drops: u64,
    pub handshake_auto_blocks: u64,
    pub handshake_already_connected_rejects: u64,
    pub handshake_ip_recently_connected_rejects: u64,
    pub request2_server_addr_mismatch_drops: u64,
    pub request2_legacy_parse_hits: u64,
    pub request2_legacy_drops: u64,
    pub request2_ambiguous_parse_hits: u64,
    pub request2_ambiguous_drops: u64,
    pub proxy_inbound_reroutes: u64,
    pub proxy_inbound_drops: u64,
    pub proxy_outbound_reroutes: u64,
    pub proxy_outbound_drops: u64,
    pub avg_srtt_ms: f64,
    pub avg_rttvar_ms: f64,
    pub avg_resend_rto_ms: f64,
    pub avg_congestion_window_packets: f64,
    pub resend_ratio: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingHandshakeStage {
    AwaitingRequest2,
    AwaitingConnectionRequest,
}

#[derive(Debug, Clone, Copy)]
struct PendingHandshake {
    mtu: u16,
    cookie: Option<u32>,
    client_guid: Option<u64>,
    stage: PendingHandshakeStage,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct HandshakeHeuristicState {
    window_started_at: Instant,
    score: u32,
}

#[derive(Debug, Clone, Copy)]
struct CookieMismatchGuardState {
    window_started_at: Instant,
    mismatches: u32,
}

#[derive(Debug, Clone, Copy)]
enum HandshakeViolation {
    Req1Req2Timeout,
    Reply2ConnectTimeout,
    MissingPendingReq1,
    CookieMismatch,
    ParseAnomalyDrop,
}

impl HandshakeViolation {
    fn score(self, config: &TransportConfig) -> u32 {
        let h = config.handshake_heuristics;
        match self {
            Self::Req1Req2Timeout => h.req1_req2_timeout_score,
            Self::Reply2ConnectTimeout => h.reply2_connect_timeout_score,
            Self::MissingPendingReq1 => h.missing_req1_score,
            Self::CookieMismatch => h.cookie_mismatch_score,
            Self::ParseAnomalyDrop => h.parse_anomaly_score,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlAction {
    None,
    CloseSession {
        remote_reason: Option<RemoteDisconnectReason>,
        illegal_state: bool,
    },
}

pub struct TransportServer {
    socket: UdpSocket,
    recv_buffer: Vec<u8>,
    config: TransportConfig,
    advertisement_bytes: Bytes,
    rate_limiter: RateLimiter,
    proxy_router: Option<Arc<dyn ProxyRouter>>,
    cookie_key_current: SecretCookieKey,
    cookie_key_previous: Option<SecretCookieKey>,
    next_cookie_rotation: Instant,
    sessions: HashMap<SocketAddr, Session>,
    session_pipelines: HashMap<SocketAddr, SessionPipeline>,
    pending_handshakes: HashMap<SocketAddr, PendingHandshake>,
    sessions_started_total: u64,
    sessions_closed_total: u64,
    packets_forwarded_total: u64,
    bytes_forwarded_total: u64,
    illegal_state_transitions: u64,
    timed_out_sessions: u64,
    local_requested_disconnects: u64,
    remote_disconnect_notifications: u64,
    remote_detect_lost_disconnects: u64,
    keepalive_pings_sent: u64,
    cookie_rotations: u64,
    cookie_mismatch_drops: u64,
    cookie_mismatch_blocks: u64,
    handshake_stage_cancel_drops: u64,
    handshake_req1_req2_timeouts: u64,
    handshake_reply2_connect_timeouts: u64,
    handshake_missing_req1_drops: u64,
    handshake_auto_blocks: u64,
    handshake_already_connected_rejects: u64,
    handshake_ip_recently_connected_rejects: u64,
    request2_server_addr_mismatch_drops: u64,
    handshake_heuristics: HashMap<IpAddr, HandshakeHeuristicState>,
    cookie_mismatch_guard_states: HashMap<IpAddr, CookieMismatchGuardState>,
    ip_recently_connected_until: HashMap<IpAddr, Instant>,
    request2_legacy_parse_hits: u64,
    request2_legacy_drops: u64,
    request2_ambiguous_parse_hits: u64,
    request2_ambiguous_drops: u64,
    proxy_inbound_reroutes: u64,
    proxy_inbound_drops: u64,
    proxy_outbound_reroutes: u64,
    proxy_outbound_drops: u64,
}

impl TransportServer {
    pub const fn supports_reuse_port_sharded_bind() -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))
    }

    pub async fn bind(config: TransportConfig) -> io::Result<Self> {
        config.validate().map_err(invalid_config_io_error)?;
        if config.split_ipv4_ipv6_bind {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "split_ipv4_ipv6_bind requires bind_shards(); use shard_count >= 1",
            ));
        }
        let socket = Self::bind_socket(
            config.bind_addr,
            config.reuse_port,
            config.ipv6_only,
            config.socket_tuning,
        )
        .await?;
        Self::with_socket(config, socket)
    }

    pub async fn bind_shards(config: TransportConfig, shard_count: usize) -> io::Result<Vec<Self>> {
        config.validate().map_err(invalid_config_io_error)?;
        let bind_plan = Self::build_shard_bind_plan(&config, shard_count.max(1));
        if !config.reuse_port && Self::has_duplicate_bind_targets(&bind_plan) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate shard bind targets require transport_config.reuse_port = true",
            ));
        }

        if Self::has_duplicate_bind_targets(&bind_plan) && !Self::supports_reuse_port_sharded_bind()
        {
            return Self::bind_shards_with_shared_socket(config, bind_plan).await;
        }

        let mut workers = Vec::with_capacity(bind_plan.len());
        for bind_addr in bind_plan {
            let mut worker_config = config.clone();
            worker_config.bind_addr = bind_addr;
            let socket = Self::bind_socket(
                bind_addr,
                worker_config.reuse_port,
                worker_config.ipv6_only,
                worker_config.socket_tuning,
            )
            .await?;
            workers.push(Self::with_socket(worker_config, socket)?);
        }
        Ok(workers)
    }

    fn build_shard_bind_plan(config: &TransportConfig, shard_count: usize) -> Vec<SocketAddr> {
        let targets = Self::bind_targets(config);
        let effective_count = if config.split_ipv4_ipv6_bind {
            shard_count.max(targets.len())
        } else {
            shard_count
        };
        let mut plan = Vec::with_capacity(effective_count);
        for idx in 0..effective_count {
            plan.push(targets[idx % targets.len()]);
        }
        plan
    }

    fn bind_targets(config: &TransportConfig) -> Vec<SocketAddr> {
        if !config.split_ipv4_ipv6_bind {
            return vec![config.bind_addr];
        }

        let port = config.bind_addr.port();
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
        match config.bind_addr {
            SocketAddr::V4(_) => vec![v4, v6],
            SocketAddr::V6(_) => vec![v6, v4],
        }
    }

    fn has_duplicate_bind_targets(bind_plan: &[SocketAddr]) -> bool {
        let mut unique = HashSet::with_capacity(bind_plan.len());
        for addr in bind_plan {
            if !unique.insert(*addr) {
                return true;
            }
        }
        false
    }

    async fn bind_shards_with_shared_socket(
        config: TransportConfig,
        bind_plan: Vec<SocketAddr>,
    ) -> io::Result<Vec<Self>> {
        let mut base_sockets: HashMap<SocketAddr, std::net::UdpSocket> = HashMap::with_capacity(2);
        let mut workers = Vec::with_capacity(bind_plan.len());
        for bind_addr in bind_plan {
            let socket = if let Some(base_socket) = base_sockets.get(&bind_addr) {
                let clone = base_socket.try_clone()?;
                clone.set_nonblocking(true)?;
                UdpSocket::from_std(clone)?
            } else {
                let base_socket =
                    Self::bind_socket(bind_addr, false, config.ipv6_only, config.socket_tuning)
                        .await?;
                let base_std = base_socket.into_std()?;
                base_std.set_nonblocking(true)?;
                let worker_std = base_std.try_clone()?;
                worker_std.set_nonblocking(true)?;
                base_sockets.insert(bind_addr, base_std);
                UdpSocket::from_std(worker_std)?
            };

            let mut worker_config = config.clone();
            worker_config.bind_addr = bind_addr;
            workers.push(Self::with_socket(worker_config, socket)?);
        }

        Ok(workers)
    }

    fn with_socket(config: TransportConfig, socket: UdpSocket) -> io::Result<Self> {
        let mut rate_limiter = RateLimiter::new(
            config.per_ip_packet_limit,
            config.global_packet_limit,
            config.rate_window,
            config.block_duration,
        );
        rate_limiter.set_processing_budget_config(config.processing_budget);
        for ip in &config.rate_limit_exceptions {
            rate_limiter.add_exception(*ip);
        }
        let now = Instant::now();
        let cookie_key_current = SecretCookieKey::new(random_cookie_key());
        let next_cookie_rotation = now + config.cookie_rotation_interval;
        let advertisement_bytes = Bytes::copy_from_slice(config.advertisement.as_bytes());

        Ok(Self {
            socket,
            recv_buffer: vec![0u8; config.mtu.max(MAXIMUM_MTU_SIZE as usize).max(2048)],
            config,
            advertisement_bytes,
            rate_limiter,
            proxy_router: None,
            cookie_key_current,
            cookie_key_previous: None,
            next_cookie_rotation,
            sessions: HashMap::new(),
            session_pipelines: HashMap::new(),
            pending_handshakes: HashMap::new(),
            sessions_started_total: 0,
            sessions_closed_total: 0,
            packets_forwarded_total: 0,
            bytes_forwarded_total: 0,
            illegal_state_transitions: 0,
            timed_out_sessions: 0,
            local_requested_disconnects: 0,
            remote_disconnect_notifications: 0,
            remote_detect_lost_disconnects: 0,
            keepalive_pings_sent: 0,
            cookie_rotations: 0,
            cookie_mismatch_drops: 0,
            cookie_mismatch_blocks: 0,
            handshake_stage_cancel_drops: 0,
            handshake_req1_req2_timeouts: 0,
            handshake_reply2_connect_timeouts: 0,
            handshake_missing_req1_drops: 0,
            handshake_auto_blocks: 0,
            handshake_already_connected_rejects: 0,
            handshake_ip_recently_connected_rejects: 0,
            request2_server_addr_mismatch_drops: 0,
            handshake_heuristics: HashMap::new(),
            cookie_mismatch_guard_states: HashMap::new(),
            ip_recently_connected_until: HashMap::new(),
            request2_legacy_parse_hits: 0,
            request2_legacy_drops: 0,
            request2_ambiguous_parse_hits: 0,
            request2_ambiguous_drops: 0,
            proxy_inbound_reroutes: 0,
            proxy_inbound_drops: 0,
            proxy_outbound_reroutes: 0,
            proxy_outbound_drops: 0,
        })
    }

    async fn bind_socket(
        addr: SocketAddr,
        reuse_port: bool,
        ipv6_only: bool,
        socket_tuning: TransportSocketTuning,
    ) -> io::Result<UdpSocket> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        if reuse_port {
            socket.set_reuse_port(true)?;
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        let _ = reuse_port;

        if addr.is_ipv6() {
            socket.set_only_v6(ipv6_only)?;
        }
        Self::apply_socket_tuning(&socket, addr, socket_tuning)?;
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket)
    }

    fn apply_socket_tuning(
        socket: &Socket,
        addr: SocketAddr,
        tuning: TransportSocketTuning,
    ) -> io::Result<()> {
        if let Some(size) = tuning.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = tuning.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }

        match addr {
            SocketAddr::V4(_) => {
                if let Some(ttl) = tuning.ipv4_ttl {
                    socket.set_ttl_v4(ttl)?;
                }
                #[cfg(not(any(
                    target_os = "fuchsia",
                    target_os = "redox",
                    target_os = "solaris",
                    target_os = "illumos",
                    target_os = "haiku",
                )))]
                if let Some(tos) = tuning.ipv4_tos {
                    socket.set_tos_v4(tos)?;
                }

                if tuning.disable_ip_fragmentation {
                    set_df_path_mtu_discovery_v4(socket)?;
                }
            }
            SocketAddr::V6(_) => {
                if let Some(hops) = tuning.ipv6_unicast_hops {
                    socket.set_unicast_hops_v6(hops)?;
                }
                if tuning.disable_ip_fragmentation {
                    set_df_path_mtu_discovery_v6(socket)?;
                }
            }
        }

        Ok(())
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub async fn recv_and_process(&mut self) -> io::Result<TransportEvent> {
        let (len, observed_addr) = self.socket.recv_from(&mut self.recv_buffer).await?;
        let now = Instant::now();
        let local_addr = self.local_addr().unwrap_or(self.config.bind_addr);
        let addr = if let Some(router) = &self.proxy_router {
            match router.route_inbound(observed_addr, local_addr) {
                InboundProxyRoute::Local { session_addr } => {
                    if session_addr != observed_addr {
                        self.proxy_inbound_reroutes = self.proxy_inbound_reroutes.saturating_add(1);
                    }
                    session_addr
                }
                InboundProxyRoute::Drop => {
                    self.proxy_inbound_drops = self.proxy_inbound_drops.saturating_add(1);
                    return Ok(TransportEvent::ProxyDropped {
                        addr: observed_addr,
                    });
                }
            }
        } else {
            observed_addr
        };

        self.prune_pending_handshakes(now);
        self.prune_cookie_mismatch_guard_states(now);
        self.prune_ip_recently_connected(now);
        self.prune_idle_sessions(now, Some(addr));
        self.rate_limiter.tick(now);
        self.rotate_cookie_keys_if_needed(now);

        let slice = &self.recv_buffer[..len];
        let Some(first) = slice.first().copied() else {
            return Ok(TransportEvent::DecodeError {
                addr,
                error: DecodeError::UnexpectedEof,
            });
        };

        let is_offline = is_offline_packet_id(first);
        match self.rate_limiter.check(addr.ip(), now) {
            RateLimitDecision::Allow => {}
            RateLimitDecision::GlobalLimit => {
                return Ok(TransportEvent::RateLimited { addr });
            }
            RateLimitDecision::IpBlocked { newly_blocked, .. } => {
                if is_offline && newly_blocked {
                    self.send_connection_banned(addr).await?;
                }
                return Ok(TransportEvent::RateLimited { addr });
            }
        }

        if is_offline {
            let mut payload = slice;
            let packet =
                match OfflinePacket::decode_with_magic(&mut payload, self.config.unconnected_magic)
                {
                    Ok(packet) => packet,
                    Err(error) => return Ok(TransportEvent::DecodeError { addr, error }),
                };

            if let Some(event) = self.handle_offline_packet(addr, &packet, now).await? {
                return Ok(event);
            }

            return Ok(TransportEvent::OfflinePacket { addr, packet });
        }

        let mut payload = slice;
        let datagram = match Datagram::decode(&mut payload) {
            Ok(d) => d,
            Err(error) => return Ok(TransportEvent::DecodeError { addr, error }),
        };

        if !self.sessions.contains_key(&addr) && !self.pending_handshakes.contains_key(&addr) {
            return Ok(TransportEvent::ConnectedDatagramDroppedNoSession { addr });
        }

        if !self.sessions.contains_key(&addr) && self.sessions.len() >= self.config.max_sessions {
            return Ok(TransportEvent::SessionLimitReached { addr });
        }

        if matches!(&datagram.payload, DatagramPayload::Frames(_))
            && !self.rate_limiter.is_exception(addr.ip())
        {
            let processing_cost = estimate_connected_datagram_processing_cost(len, &datagram);
            let budget_decision =
                self.rate_limiter
                    .consume_processing_budget(addr.ip(), processing_cost, now);
            match budget_decision {
                ProcessingBudgetDecision::Allow => {}
                ProcessingBudgetDecision::IpExhausted
                | ProcessingBudgetDecision::GlobalExhausted => {
                    warn!(
                        %addr,
                        cost_units = processing_cost,
                        decision = ?budget_decision,
                        "dropping connected datagram due to processing budget exhaustion"
                    );
                    return Ok(TransportEvent::RateLimited { addr });
                }
            }
        }

        let server_addr = self.local_addr().unwrap_or(self.config.bind_addr);
        let now_millis = unix_timestamp_millis();
        let unhandled_queue_max_frames = self.config.unhandled_queue_max_frames;
        let unhandled_queue_max_bytes = self.config.unhandled_queue_max_bytes;

        let mut decode_error: Option<DecodeError> = None;
        let mut close_session = false;
        let mut illegal_transition = false;
        let mut remote_disconnect_reason: Option<RemoteDisconnectReason> = None;

        let (mut frames, receipts, datagrams_to_send, became_connected) = {
            let session_tunables = self.config.session_tunables.clone();
            let session = self
                .sessions
                .entry(addr)
                .or_insert_with(|| Session::with_tunables(self.config.mtu, session_tunables));
            let pipeline = self.session_pipelines.entry(addr).or_insert_with(|| {
                SessionPipeline::new(unhandled_queue_max_frames, unhandled_queue_max_bytes)
            });
            session.touch_activity(now);

            let frames = match session.ingest_datagram(datagram, now) {
                Ok(frames) => frames,
                Err(error) => return Ok(TransportEvent::DecodeError { addr, error }),
            };

            let receipts = session.process_incoming_receipts(now);
            let mut app_frames = Vec::new();
            let was_connected = session.state() == SessionState::Connected;

            for frame in frames {
                let Some(id) = frame.payload.first().copied() else {
                    continue;
                };

                if !is_connected_control_id(id) {
                    match pipeline.route_inbound_app_frame(session.state(), frame, &mut app_frames)
                    {
                        PipelineFrameAction::Deliver | PipelineFrameAction::Queued => {}
                        PipelineFrameAction::Overflow => {
                            close_session = true;
                            break;
                        }
                    }
                    continue;
                }

                let mut control_payload = &frame.payload[..];
                let control_packet = match ConnectedControlPacket::decode(&mut control_payload) {
                    Ok(pkt) => pkt,
                    Err(error) => {
                        decode_error = Some(error);
                        break;
                    }
                };

                match Self::apply_connected_control(
                    session,
                    addr,
                    server_addr,
                    now_millis,
                    control_packet,
                ) {
                    Ok(ControlAction::None) => {}
                    Ok(ControlAction::CloseSession {
                        remote_reason,
                        illegal_state,
                    }) => {
                        close_session = true;
                        illegal_transition = illegal_state;
                        if remote_disconnect_reason.is_none() {
                            remote_disconnect_reason = remote_reason;
                        }
                        break;
                    }
                    Err(error) => {
                        decode_error = Some(error);
                        break;
                    }
                }
            }

            if !close_session && decode_error.is_none() {
                let _ = pipeline.flush_if_connected(session.state(), &mut app_frames);
            }

            let immediate_datagrams = if close_session {
                Vec::new()
            } else {
                session.on_tick(
                    now,
                    RECV_PATH_MAX_NEW_DATAGRAMS,
                    self.config.mtu.saturating_mul(RECV_PATH_MAX_NEW_DATAGRAMS),
                    RECV_PATH_MAX_RESEND_DATAGRAMS,
                    self.config
                        .mtu
                        .saturating_mul(RECV_PATH_MAX_RESEND_DATAGRAMS),
                )
            };
            if session.take_backpressure_disconnect() {
                close_session = true;
            }

            let app_frames: Vec<ConnectedFrameDelivery> = app_frames
                .into_iter()
                .map(ConnectedFrameDelivery::from_frame)
                .collect();
            let became_connected = !was_connected && session.state() == SessionState::Connected;

            (app_frames, receipts, immediate_datagrams, became_connected)
        };

        if let Some(error) = decode_error {
            return Ok(TransportEvent::DecodeError { addr, error });
        }

        if illegal_transition {
            self.illegal_state_transitions = self.illegal_state_transitions.saturating_add(1);
        } else {
            for datagram in &datagrams_to_send {
                self.send_datagram(addr, datagram).await?;
            }
        }

        if close_session {
            frames.clear();
            if let Some(reason) = remote_disconnect_reason {
                self.record_remote_disconnect(reason);
            }
            self.close_session(addr);
            if let Some(reason) = remote_disconnect_reason {
                return Ok(TransportEvent::PeerDisconnected { addr, reason });
            }
        }

        if became_connected {
            self.sessions_started_total = self.sessions_started_total.saturating_add(1);
        }

        let client_guid = if became_connected {
            self.pending_handshakes
                .get(&addr)
                .and_then(|pending| pending.client_guid)
        } else {
            None
        };

        if self
            .sessions
            .get(&addr)
            .is_some_and(|session| session.state() == SessionState::Connected)
        {
            self.pending_handshakes.remove(&addr);
        }

        let frame_count = frames.len();
        let forwarded_bytes = frames
            .iter()
            .map(|frame| frame.payload.len() as u64)
            .sum::<u64>();
        self.packets_forwarded_total = self
            .packets_forwarded_total
            .saturating_add(frame_count as u64);
        self.bytes_forwarded_total = self.bytes_forwarded_total.saturating_add(forwarded_bytes);
        Ok(TransportEvent::ConnectedFrames {
            addr,
            client_guid,
            frames,
            frame_count,
            receipts,
        })
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    pub fn set_proxy_router(&mut self, router: Arc<dyn ProxyRouter>) {
        self.proxy_router = Some(router);
    }

    pub fn clear_proxy_router(&mut self) {
        self.proxy_router = None;
    }

    pub fn add_rate_limit_exception(&mut self, ip: IpAddr) {
        self.rate_limiter.add_exception(ip);
    }

    pub fn remove_rate_limit_exception(&mut self, ip: IpAddr) {
        self.rate_limiter.remove_exception(ip);
    }

    pub fn rate_limit_config(&self) -> TransportRateLimitConfig {
        let cfg: RateLimiterConfigSnapshot = self.rate_limiter.config_snapshot();
        TransportRateLimitConfig {
            per_ip_packet_limit: cfg.per_ip_limit,
            global_packet_limit: cfg.global_limit,
            rate_window: cfg.window,
            block_duration: cfg.block_duration,
        }
    }

    pub fn processing_budget_config(&self) -> TransportProcessingBudgetConfig {
        let cfg = self.rate_limiter.processing_budget_config();
        TransportProcessingBudgetConfig {
            enabled: cfg.enabled,
            per_ip_refill_units_per_sec: cfg.per_ip_refill_units_per_sec,
            per_ip_burst_units: cfg.per_ip_burst_units,
            global_refill_units_per_sec: cfg.global_refill_units_per_sec,
            global_burst_units: cfg.global_burst_units,
            bucket_idle_ttl: cfg.bucket_idle_ttl,
        }
    }

    pub fn set_processing_budget_config(&mut self, config: TransportProcessingBudgetConfig) {
        let raw = ProcessingBudgetConfig {
            enabled: config.enabled,
            per_ip_refill_units_per_sec: config.per_ip_refill_units_per_sec,
            per_ip_burst_units: config.per_ip_burst_units,
            global_refill_units_per_sec: config.global_refill_units_per_sec,
            global_burst_units: config.global_burst_units,
            bucket_idle_ttl: config.bucket_idle_ttl,
        };
        self.rate_limiter.set_processing_budget_config(raw);
        self.config.processing_budget = self.rate_limiter.processing_budget_config();
    }

    pub fn set_rate_limit_config(&mut self, config: TransportRateLimitConfig) {
        self.rate_limiter.update_limits(
            config.per_ip_packet_limit,
            config.global_packet_limit,
            config.rate_window,
            config.block_duration,
        );
        let effective = self.rate_limit_config();
        self.config.per_ip_packet_limit = effective.per_ip_packet_limit;
        self.config.global_packet_limit = effective.global_packet_limit;
        self.config.rate_window = effective.rate_window;
        self.config.block_duration = effective.block_duration;
    }

    pub fn set_per_ip_packet_limit(&mut self, limit: usize) {
        self.rate_limiter.set_per_ip_limit(limit);
        self.config.per_ip_packet_limit = self.rate_limit_config().per_ip_packet_limit;
    }

    pub fn set_global_packet_limit(&mut self, limit: usize) {
        self.rate_limiter.set_global_limit(limit);
        self.config.global_packet_limit = self.rate_limit_config().global_packet_limit;
    }

    pub fn set_rate_window(&mut self, window: Duration) {
        self.rate_limiter.set_window(window);
        self.config.rate_window = self.rate_limit_config().rate_window;
    }

    pub fn set_block_duration(&mut self, block_duration: Duration) {
        self.rate_limiter.set_block_duration(block_duration);
        self.config.block_duration = self.rate_limit_config().block_duration;
    }

    pub fn block_address(&mut self, ip: IpAddr) -> bool {
        self.rate_limiter.block_address(ip)
    }

    pub fn block_address_for(&mut self, ip: IpAddr, duration: Duration) -> bool {
        self.rate_limiter
            .block_address_for(ip, Instant::now(), duration)
    }

    pub fn unblock_address(&mut self, ip: IpAddr) -> bool {
        self.rate_limiter.unblock_address(ip)
    }

    pub fn disconnect_peer(&mut self, addr: SocketAddr) -> bool {
        let exists =
            self.sessions.contains_key(&addr) || self.pending_handshakes.contains_key(&addr);
        if exists {
            self.local_requested_disconnects = self.local_requested_disconnects.saturating_add(1);
            self.close_session(addr);
        }
        exists
    }

    pub fn metrics_snapshot(&self) -> TransportMetricsSnapshot {
        let mut total = TransportMetricsSnapshot {
            session_count: self.sessions.len(),
            sessions_started_total: self.sessions_started_total,
            sessions_closed_total: self.sessions_closed_total,
            packets_forwarded_total: self.packets_forwarded_total,
            bytes_forwarded_total: self.bytes_forwarded_total,
            illegal_state_transitions: self.illegal_state_transitions,
            timed_out_sessions: self.timed_out_sessions,
            local_requested_disconnects: self.local_requested_disconnects,
            remote_disconnect_notifications: self.remote_disconnect_notifications,
            remote_detect_lost_disconnects: self.remote_detect_lost_disconnects,
            keepalive_pings_sent: self.keepalive_pings_sent,
            cookie_rotations: self.cookie_rotations,
            cookie_mismatch_drops: self.cookie_mismatch_drops,
            cookie_mismatch_blocks: self.cookie_mismatch_blocks,
            handshake_stage_cancel_drops: self.handshake_stage_cancel_drops,
            handshake_req1_req2_timeouts: self.handshake_req1_req2_timeouts,
            handshake_reply2_connect_timeouts: self.handshake_reply2_connect_timeouts,
            handshake_missing_req1_drops: self.handshake_missing_req1_drops,
            handshake_auto_blocks: self.handshake_auto_blocks,
            handshake_already_connected_rejects: self.handshake_already_connected_rejects,
            handshake_ip_recently_connected_rejects: self.handshake_ip_recently_connected_rejects,
            request2_server_addr_mismatch_drops: self.request2_server_addr_mismatch_drops,
            request2_legacy_parse_hits: self.request2_legacy_parse_hits,
            request2_legacy_drops: self.request2_legacy_drops,
            request2_ambiguous_parse_hits: self.request2_ambiguous_parse_hits,
            request2_ambiguous_drops: self.request2_ambiguous_drops,
            proxy_inbound_reroutes: self.proxy_inbound_reroutes,
            proxy_inbound_drops: self.proxy_inbound_drops,
            proxy_outbound_reroutes: self.proxy_outbound_reroutes,
            proxy_outbound_drops: self.proxy_outbound_drops,
            ..TransportMetricsSnapshot::default()
        };
        let mut srtt_sum = 0.0;
        let mut rttvar_sum = 0.0;
        let mut resend_rto_sum = 0.0;
        let mut cwnd_sum = 0.0;

        for session in self.sessions.values() {
            let s: SessionMetricsSnapshot = session.metrics_snapshot();
            total.pending_outgoing_frames += s.pending_outgoing_frames;
            total.pending_outgoing_bytes += s.pending_outgoing_bytes;
            total.ingress_datagrams = total.ingress_datagrams.saturating_add(s.ingress_datagrams);
            total.ingress_frames = total.ingress_frames.saturating_add(s.ingress_frames);
            total.duplicate_reliable_drops = total
                .duplicate_reliable_drops
                .saturating_add(s.duplicate_reliable_drops);
            total.ordered_stale_drops = total
                .ordered_stale_drops
                .saturating_add(s.ordered_stale_drops);
            total.ordered_buffer_full_drops = total
                .ordered_buffer_full_drops
                .saturating_add(s.ordered_buffer_full_drops);
            total.sequenced_stale_drops = total
                .sequenced_stale_drops
                .saturating_add(s.sequenced_stale_drops);
            total.sequenced_missing_index_drops = total
                .sequenced_missing_index_drops
                .saturating_add(s.sequenced_missing_index_drops);
            total.reliable_sent_datagrams = total
                .reliable_sent_datagrams
                .saturating_add(s.reliable_sent_datagrams);
            total.resent_datagrams = total.resent_datagrams.saturating_add(s.resent_datagrams);
            total.ack_out_total = total.ack_out_total.saturating_add(s.ack_out_datagrams);
            total.nack_out_total = total.nack_out_total.saturating_add(s.nack_out_datagrams);
            total.acked_datagrams = total.acked_datagrams.saturating_add(s.acked_datagrams);
            total.nacked_datagrams = total.nacked_datagrams.saturating_add(s.nacked_datagrams);
            total.split_ttl_drops = total.split_ttl_drops.saturating_add(s.split_ttl_drops);
            total.outgoing_queue_drops = total
                .outgoing_queue_drops
                .saturating_add(s.outgoing_queue_drops);
            total.outgoing_queue_defers = total
                .outgoing_queue_defers
                .saturating_add(s.outgoing_queue_defers);
            total.outgoing_queue_disconnects = total
                .outgoing_queue_disconnects
                .saturating_add(s.outgoing_queue_disconnects);
            total.backpressure_delays = total
                .backpressure_delays
                .saturating_add(s.backpressure_delays);
            total.backpressure_drops = total
                .backpressure_drops
                .saturating_add(s.backpressure_drops);
            total.backpressure_disconnects = total
                .backpressure_disconnects
                .saturating_add(s.backpressure_disconnects);

            srtt_sum += s.srtt_ms;
            rttvar_sum += s.rttvar_ms;
            resend_rto_sum += s.resend_rto_ms;
            cwnd_sum += s.congestion_window_packets;
        }

        for pipeline in self.session_pipelines.values() {
            let p: SessionPipelineMetricsSnapshot = pipeline.metrics_snapshot();
            total.pending_unhandled_frames += p.pending_unhandled_frames;
            total.pending_unhandled_bytes += p.pending_unhandled_bytes;
            total.unhandled_frames_queued = total
                .unhandled_frames_queued
                .saturating_add(p.unhandled_frames_queued);
            total.unhandled_frames_flushed = total
                .unhandled_frames_flushed
                .saturating_add(p.unhandled_frames_flushed);
            total.unhandled_frames_dropped = total
                .unhandled_frames_dropped
                .saturating_add(p.unhandled_frames_dropped);
        }

        let r: RateLimiterMetricsSnapshot = self.rate_limiter.metrics_snapshot();
        let p: ProcessingBudgetMetricsSnapshot =
            self.rate_limiter.processing_budget_metrics_snapshot();
        total.rate_global_limit_hits = r.global_limit_hits;
        total.rate_ip_block_hits = r.ip_block_hits;
        total.rate_ip_block_hits_rate_exceeded = r.ip_block_hits_rate_exceeded;
        total.rate_ip_block_hits_manual = r.ip_block_hits_manual;
        total.rate_ip_block_hits_handshake_heuristic = r.ip_block_hits_handshake_heuristic;
        total.rate_ip_block_hits_cookie_mismatch_guard = r.ip_block_hits_cookie_mismatch_guard;
        total.rate_addresses_blocked = r.addresses_blocked;
        total.rate_addresses_blocked_rate_exceeded = r.addresses_blocked_rate_exceeded;
        total.rate_addresses_blocked_manual = r.addresses_blocked_manual;
        total.rate_addresses_blocked_handshake_heuristic = r.addresses_blocked_handshake_heuristic;
        total.rate_addresses_blocked_cookie_mismatch_guard =
            r.addresses_blocked_cookie_mismatch_guard;
        total.rate_addresses_unblocked = r.addresses_unblocked;
        total.rate_blocked_addresses = r.blocked_addresses;
        total.rate_exception_addresses = r.exception_addresses;
        total.processing_budget_drops_total = p.drops_total;
        total.processing_budget_drops_ip_exhausted_total = p.drops_ip_exhausted;
        total.processing_budget_drops_global_exhausted_total = p.drops_global_exhausted;
        total.processing_budget_consumed_units_total = p.consumed_units_total;
        total.processing_budget_active_ip_buckets = p.active_ip_buckets;

        if total.session_count > 0 {
            let denom = total.session_count as f64;
            total.avg_srtt_ms = srtt_sum / denom;
            total.avg_rttvar_ms = rttvar_sum / denom;
            total.avg_resend_rto_ms = resend_rto_sum / denom;
            total.avg_congestion_window_packets = cwnd_sum / denom;
        }

        total.resend_ratio = if total.reliable_sent_datagrams == 0 {
            0.0
        } else {
            total.resent_datagrams as f64 / total.reliable_sent_datagrams as f64
        };

        total
    }

    pub async fn flush_resends(
        &mut self,
        max_per_session: usize,
        max_bytes_per_session: usize,
    ) -> io::Result<usize> {
        self.tick_outbound(0, 0, max_per_session, max_bytes_per_session)
            .await
    }

    pub fn queue_payload(
        &mut self,
        addr: SocketAddr,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
    ) -> QueueDispatchResult {
        self.queue_payload_with_optional_receipt(
            addr,
            payload,
            reliability,
            channel,
            priority,
            None,
        )
    }

    pub fn queue_payload_with_receipt(
        &mut self,
        addr: SocketAddr,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: u64,
    ) -> QueueDispatchResult {
        self.queue_payload_with_optional_receipt(
            addr,
            payload,
            reliability,
            channel,
            priority,
            Some(receipt_id),
        )
    }

    fn queue_payload_with_optional_receipt(
        &mut self,
        addr: SocketAddr,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: Option<u64>,
    ) -> QueueDispatchResult {
        let Some(session) = self.sessions.get_mut(&addr) else {
            return QueueDispatchResult::MissingSession;
        };
        let decision =
            session.queue_payload_with_receipt(payload, reliability, channel, priority, receipt_id);
        let disconnect = matches!(decision, QueuePayloadResult::DisconnectRequested)
            || session.take_backpressure_disconnect();
        if disconnect {
            self.close_session(addr);
            return QueueDispatchResult::Disconnected;
        }

        match decision {
            QueuePayloadResult::Enqueued { reliable_bytes } => {
                QueueDispatchResult::Enqueued { reliable_bytes }
            }
            QueuePayloadResult::Dropped => QueueDispatchResult::Dropped,
            QueuePayloadResult::Deferred => QueueDispatchResult::Deferred,
            QueuePayloadResult::DisconnectRequested => QueueDispatchResult::Disconnected,
        }
    }

    pub async fn tick_outbound(
        &mut self,
        max_new_datagrams_per_session: usize,
        max_new_bytes_per_session: usize,
        max_resend_datagrams_per_session: usize,
        max_resend_bytes_per_session: usize,
    ) -> io::Result<usize> {
        let now = Instant::now();
        self.prune_pending_handshakes(now);
        self.prune_cookie_mismatch_guard_states(now);
        self.prune_ip_recently_connected(now);
        self.prune_idle_sessions(now, None);
        self.queue_keepalive_pings(now);
        self.rate_limiter.tick(now);
        self.rotate_cookie_keys_if_needed(now);

        let mut pending = Vec::new();

        for (addr, session) in &mut self.sessions {
            let datagrams = session.on_tick(
                now,
                max_new_datagrams_per_session,
                max_new_bytes_per_session,
                max_resend_datagrams_per_session,
                max_resend_bytes_per_session,
            );
            for d in datagrams {
                pending.push((*addr, d));
            }
        }

        for (addr, datagram) in &pending {
            self.send_datagram(*addr, datagram).await?;
        }

        Ok(pending.len())
    }

    pub async fn send_datagram(&mut self, addr: SocketAddr, datagram: &Datagram) -> io::Result<()> {
        let Some(target_addr) = self.route_outbound_target(addr) else {
            return Ok(());
        };
        let mut out = BytesMut::with_capacity(datagram.encoded_size());
        datagram.encode(&mut out).map_err(invalid_data_io_error)?;
        let _written = self.socket.send_to(&out, target_addr).await?;
        Ok(())
    }

    async fn send_offline_packet(
        &mut self,
        addr: SocketAddr,
        packet: &OfflinePacket,
    ) -> io::Result<()> {
        let Some(target_addr) = self.route_outbound_target(addr) else {
            return Ok(());
        };
        let mut out = BytesMut::new();
        packet.encode(&mut out).map_err(invalid_data_io_error)?;
        let _written = self.socket.send_to(&out, target_addr).await?;
        Ok(())
    }

    async fn send_no_free_incoming_connections(&mut self, addr: SocketAddr) -> io::Result<()> {
        let packet = OfflinePacket::ConnectionReject(
            ConnectionRejectReason::NoFreeIncomingConnections(RejectData {
                server_guid: self.config.server_guid,
                magic: self.config.unconnected_magic,
            })
        );
        self.send_offline_packet(addr, &packet).await
    }

    async fn send_connection_banned(&mut self, addr: SocketAddr) -> io::Result<()> {
        let packet = OfflinePacket::ConnectionReject(
            ConnectionRejectReason::ConnectionBanned(RejectData {
                server_guid: self.config.server_guid,
                magic: self.config.unconnected_magic,
            })
        );
        self.send_offline_packet(addr, &packet).await
    }

    async fn send_already_connected(&mut self, addr: SocketAddr) -> io::Result<()> {
        let packet = OfflinePacket::ConnectionReject(
            ConnectionRejectReason::AlreadyConnected(RejectData {
                server_guid: self.config.server_guid,
                magic: self.config.unconnected_magic,
            })
        );
        self.send_offline_packet(addr, &packet).await
    }

    async fn send_ip_recently_connected(&mut self, addr: SocketAddr) -> io::Result<()> {
        let packet = OfflinePacket::ConnectionReject(
            ConnectionRejectReason::IpRecentlyConnected(RejectData {
                server_guid: self.config.server_guid,
                magic: self.config.unconnected_magic,
            })
        );
        self.send_offline_packet(addr, &packet).await
    }

    fn route_outbound_target(&mut self, addr: SocketAddr) -> Option<SocketAddr> {
        let Some(router) = self.proxy_router.as_ref() else {
            return Some(addr);
        };

        let local_addr = self.local_addr().unwrap_or(self.config.bind_addr);
        match router.route_outbound(addr, local_addr) {
            OutboundProxyRoute::Send { target_addr } => {
                if target_addr != addr {
                    self.proxy_outbound_reroutes = self.proxy_outbound_reroutes.saturating_add(1);
                }
                Some(target_addr)
            }
            OutboundProxyRoute::Drop => {
                self.proxy_outbound_drops = self.proxy_outbound_drops.saturating_add(1);
                None
            }
        }
    }

    async fn handle_offline_packet(
        &mut self,
        addr: SocketAddr,
        packet: &OfflinePacket,
        now: Instant,
    ) -> io::Result<Option<TransportEvent>> {
        match packet {
            OfflinePacket::UnconnectedPing(ping)
            | OfflinePacket::UnconnectedPingOpenConnections(ping) => {
                let pong = OfflinePacket::UnconnectedPong(UnconnectedPong {
                    ping_time: ping.ping_time,
                    server_guid: self.config.server_guid,
                    magic: self.config.unconnected_magic,
                    motd: self.advertisement_bytes.clone(),
                });
                self.send_offline_packet(addr, &pong).await?;
            }
            OfflinePacket::OpenConnectionRequest1(req1) => {
                if !supports_protocol(&self.config.supported_protocols, req1.protocol_version) {
                    warn!(
                        %addr,
                        protocol_version = req1.protocol_version,
                        "rejecting request1: incompatible protocol version"
                    );
                    let incompatible =
                        OfflinePacket::IncompatibleProtocolVersion(IncompatibleProtocolVersion {
                            protocol_version: primary_protocol_version(
                                &self.config.supported_protocols,
                            ),
                            server_guid: self.config.server_guid,
                            magic: self.config.unconnected_magic,
                        });
                    self.send_offline_packet(addr, &incompatible).await?;
                    return Ok(None);
                }

                if self.has_ip_recently_connected(addr, now) {
                    self.handshake_ip_recently_connected_rejects = self
                        .handshake_ip_recently_connected_rejects
                        .saturating_add(1);
                    warn!(%addr, "rejecting request1: ip recently connected");
                    self.send_ip_recently_connected(addr).await?;
                    return Ok(None);
                }

                if self.has_active_session_for_offline_reject(addr) {
                    self.handshake_already_connected_rejects =
                        self.handshake_already_connected_rejects.saturating_add(1);
                    warn!(%addr, "rejecting request1: already connected");
                    self.send_already_connected(addr).await?;
                    return Ok(None);
                }

                if self.pending_handshakes.get(&addr).is_some_and(|pending| {
                    pending.stage == PendingHandshakeStage::AwaitingConnectionRequest
                }) {
                    self.handshake_already_connected_rejects =
                        self.handshake_already_connected_rejects.saturating_add(1);
                    warn!(%addr, "rejecting request1: handshake already in progress");
                    self.send_already_connected(addr).await?;
                    return Ok(None);
                }

                if self.would_exceed_session_limit(addr) {
                    warn!(%addr, "rejecting request1: session limit reached");
                    self.send_no_free_incoming_connections(addr).await?;
                    return Ok(Some(TransportEvent::SessionLimitReached { addr }));
                }

                let mtu = self.negotiate_mtu(req1.mtu);
                let previous_cookie = self.pending_handshakes.get(&addr).and_then(|pending| {
                    if pending.stage == PendingHandshakeStage::AwaitingRequest2 {
                        pending.cookie
                    } else {
                        None
                    }
                });
                let cookie = if self.config.send_cookie {
                    previous_cookie.or_else(|| Some(self.generate_cookie(addr)))
                } else {
                    None
                };

                self.pending_handshakes.insert(
                    addr,
                    PendingHandshake {
                        mtu,
                        cookie,
                        client_guid: None,
                        stage: PendingHandshakeStage::AwaitingRequest2,
                        expires_at: now + self.config.handshake_req1_req2_timeout(),
                    },
                );

                self.sessions.remove(&addr);
                self.session_pipelines.remove(&addr);
                self.sessions.insert(
                    addr,
                    Session::with_tunables(mtu as usize, self.config.session_tunables.clone()),
                );
                let mut valid_transition = true;
                if let Some(session) = self.sessions.get_mut(&addr) {
                    valid_transition = Self::apply_session_transitions(
                        session,
                        &[SessionState::Req1Recv, SessionState::Reply1Sent],
                    );
                }
                if !valid_transition {
                    self.record_illegal_state_transition(addr);
                    return Ok(None);
                }

                let reply = OfflinePacket::OpenConnectionReply1(OpenConnectionReply1 {
                    server_guid: self.config.server_guid,
                    mtu,
                    cookie,
                    magic: self.config.unconnected_magic,
                });
                self.send_offline_packet(addr, &reply).await?;
            }
            OfflinePacket::OpenConnectionRequest2(req2) => {
                if self.has_ip_recently_connected(addr, now) {
                    self.handshake_ip_recently_connected_rejects = self
                        .handshake_ip_recently_connected_rejects
                        .saturating_add(1);
                    warn!(%addr, "rejecting request2: ip recently connected");
                    self.send_ip_recently_connected(addr).await?;
                    return Ok(None);
                }

                if self.has_active_session_for_offline_reject(addr) {
                    self.handshake_already_connected_rejects =
                        self.handshake_already_connected_rejects.saturating_add(1);
                    warn!(%addr, "rejecting request2: already connected");
                    self.send_already_connected(addr).await?;
                    return Ok(None);
                }

                match req2.parse_path {
                    Request2ParsePath::LegacyHeuristic => {
                        self.request2_legacy_parse_hits =
                            self.request2_legacy_parse_hits.saturating_add(1);
                        if !self.config.allow_legacy_request2_fallback {
                            self.request2_legacy_drops =
                                self.request2_legacy_drops.saturating_add(1);
                            self.handshake_stage_cancel_drops =
                                self.handshake_stage_cancel_drops.saturating_add(1);
                            warn!(%addr, "dropping request2: legacy parse path disallowed");
                            let newly_blocked = self.record_handshake_violation(
                                addr,
                                HandshakeViolation::ParseAnomalyDrop,
                                now,
                            );
                            if newly_blocked {
                                self.send_connection_banned(addr).await?;
                            }
                            return Ok(None);
                        }
                    }
                    Request2ParsePath::AmbiguousPreferredNoCookie
                    | Request2ParsePath::AmbiguousPreferredWithCookie => {
                        self.request2_ambiguous_parse_hits =
                            self.request2_ambiguous_parse_hits.saturating_add(1);
                        if self.config.reject_ambiguous_request2 {
                            self.request2_ambiguous_drops =
                                self.request2_ambiguous_drops.saturating_add(1);
                            self.handshake_stage_cancel_drops =
                                self.handshake_stage_cancel_drops.saturating_add(1);
                            warn!(%addr, "dropping request2: ambiguous parse path rejected");
                            let newly_blocked = self.record_handshake_violation(
                                addr,
                                HandshakeViolation::ParseAnomalyDrop,
                                now,
                            );
                            if newly_blocked {
                                self.send_connection_banned(addr).await?;
                            }
                            return Ok(None);
                        }
                    }
                    Request2ParsePath::StrictNoCookie | Request2ParsePath::StrictWithCookie => {}
                }

                let local_server_addr = self.local_addr().unwrap_or(self.config.bind_addr);
                if !self.is_request2_server_addr_allowed(req2.server_addr, local_server_addr) {
                    self.request2_server_addr_mismatch_drops =
                        self.request2_server_addr_mismatch_drops.saturating_add(1);
                    self.handshake_stage_cancel_drops =
                        self.handshake_stage_cancel_drops.saturating_add(1);
                    warn!(
                        %addr,
                        request_server_addr = %req2.server_addr,
                        local_server_addr = %local_server_addr,
                        "dropping request2: server_addr mismatch"
                    );
                    return Ok(None);
                }

                let Some(pending) = self.pending_handshakes.get(&addr).copied() else {
                    self.handshake_missing_req1_drops =
                        self.handshake_missing_req1_drops.saturating_add(1);
                    self.handshake_stage_cancel_drops =
                        self.handshake_stage_cancel_drops.saturating_add(1);
                    warn!(%addr, "dropping request2: missing pending request1");
                    let newly_blocked = self.record_handshake_violation(
                        addr,
                        HandshakeViolation::MissingPendingReq1,
                        now,
                    );
                    if newly_blocked {
                        self.send_connection_banned(addr).await?;
                    }
                    return Ok(None);
                };

                if pending.expires_at <= now {
                    match pending.stage {
                        PendingHandshakeStage::AwaitingRequest2 => {
                            self.handshake_req1_req2_timeouts =
                                self.handshake_req1_req2_timeouts.saturating_add(1);
                        }
                        PendingHandshakeStage::AwaitingConnectionRequest => {
                            self.handshake_reply2_connect_timeouts =
                                self.handshake_reply2_connect_timeouts.saturating_add(1);
                        }
                    }
                    self.handshake_stage_cancel_drops =
                        self.handshake_stage_cancel_drops.saturating_add(1);
                    warn!(
                        %addr,
                        stage = ?pending.stage,
                        "dropping request2: pending handshake timed out"
                    );
                    let violation = match pending.stage {
                        PendingHandshakeStage::AwaitingRequest2 => {
                            HandshakeViolation::Req1Req2Timeout
                        }
                        PendingHandshakeStage::AwaitingConnectionRequest => {
                            HandshakeViolation::Reply2ConnectTimeout
                        }
                    };
                    let newly_blocked = self.record_handshake_violation(addr, violation, now);
                    self.close_session(addr);
                    if newly_blocked {
                        self.send_connection_banned(addr).await?;
                    }
                    return Ok(None);
                }

                if self.config.send_cookie
                    && (pending.cookie.is_none() || !self.verify_cookie(addr, req2.cookie))
                {
                    self.cookie_mismatch_drops = self.cookie_mismatch_drops.saturating_add(1);
                    self.handshake_stage_cancel_drops =
                        self.handshake_stage_cancel_drops.saturating_add(1);
                    warn!(%addr, "dropping request2: cookie verification failed");
                    let blocked_by_guard = self.record_cookie_mismatch(addr.ip(), now);
                    let blocked_by_heuristics = self.record_handshake_violation(
                        addr,
                        HandshakeViolation::CookieMismatch,
                        now,
                    );
                    if blocked_by_guard || blocked_by_heuristics {
                        self.send_connection_banned(addr).await?;
                    }
                    return Ok(None);
                }
                self.clear_cookie_mismatch_state(addr.ip());

                if pending.stage == PendingHandshakeStage::AwaitingConnectionRequest {
                    let retry_mtu = self.negotiate_mtu(req2.mtu.min(pending.mtu));
                    let Some(session) = self.sessions.get_mut(&addr) else {
                        self.record_illegal_state_transition(addr);
                        return Ok(None);
                    };
                    if !is_post_reply2_handshake_state(session.state()) {
                        self.record_illegal_state_transition(addr);
                        return Ok(None);
                    }
                    session.set_mtu(retry_mtu as usize);
                    session.touch_activity(now);

                    let reply = OfflinePacket::OpenConnectionReply2(OpenConnectionReply2 {
                        server_guid: self.config.server_guid,
                        server_addr: local_server_addr,
                        mtu: retry_mtu,
                        use_encryption: false,
                        magic: self.config.unconnected_magic,
                    });
                    self.send_offline_packet(addr, &reply).await?;
                    return Ok(None);
                }

                if self.would_exceed_session_limit(addr) {
                    warn!(%addr, "rejecting request2: session limit reached");
                    self.send_no_free_incoming_connections(addr).await?;
                    return Ok(Some(TransportEvent::SessionLimitReached { addr }));
                }

                let mtu = self.negotiate_mtu(req2.mtu.min(pending.mtu));
                let Some(session) = self.sessions.get_mut(&addr) else {
                    self.record_illegal_state_transition(addr);
                    return Ok(None);
                };
                session.set_mtu(mtu as usize);
                session.touch_activity(now);
                if !Self::apply_session_transitions(
                    session,
                    &[SessionState::Req2Recv, SessionState::Reply2Sent],
                ) {
                    self.record_illegal_state_transition(addr);
                    return Ok(None);
                }
                self.pending_handshakes.insert(
                    addr,
                    PendingHandshake {
                        mtu,
                        cookie: pending.cookie,
                        client_guid: Some(req2.client_guid),
                        stage: PendingHandshakeStage::AwaitingConnectionRequest,
                        expires_at: now + self.config.handshake_reply2_connect_timeout(),
                    },
                );
                let reply = OfflinePacket::OpenConnectionReply2(OpenConnectionReply2 {
                    server_guid: self.config.server_guid,
                    server_addr: local_server_addr,
                    mtu,
                    use_encryption: false,
                    magic: self.config.unconnected_magic,
                });
                self.send_offline_packet(addr, &reply).await?;
            }
            _ => {}
        }

        Ok(None)
    }

    fn apply_connected_control(
        session: &mut Session,
        addr: SocketAddr,
        server_addr: SocketAddr,
        now_millis: i64,
        packet: ConnectedControlPacket,
    ) -> Result<ControlAction, DecodeError> {
        match packet {
            ConnectedControlPacket::ConnectedPing(ping) => {
                if session.state() != SessionState::Connected {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: true,
                    });
                }
                let pong = ConnectedControlPacket::ConnectedPong(ConnectedPong {
                    ping_time: ping.ping_time,
                    pong_time: now_millis,
                });
                let queued = Self::queue_connected_control_packet(
                    session,
                    pong,
                    Reliability::Unreliable,
                    0,
                    RakPriority::Immediate,
                )?;
                if matches!(queued, QueuePayloadResult::DisconnectRequested)
                    || session.take_backpressure_disconnect()
                {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: false,
                    });
                }
            }
            ConnectedControlPacket::ConnectionRequest(request) => {
                if !Self::apply_session_transitions(session, &[SessionState::ConnReqRecv]) {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: true,
                    });
                }

                let accepted =
                    ConnectedControlPacket::ConnectionRequestAccepted(ConnectionRequestAccepted {
                        client_addr: addr,
                        system_index: 0,
                        internal_addrs: build_internal_addrs(server_addr),
                        request_time: request.request_time,
                        accepted_time: now_millis,
                    });

                let queued = Self::queue_connected_control_packet(
                    session,
                    accepted,
                    Reliability::ReliableOrdered,
                    0,
                    RakPriority::High,
                )?;
                if !matches!(queued, QueuePayloadResult::Enqueued { .. }) {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: false,
                    });
                }
                if session.take_backpressure_disconnect() {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: false,
                    });
                }

                if !Self::apply_session_transitions(session, &[SessionState::ConnReqAcceptedSent]) {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: true,
                    });
                }
            }
            ConnectedControlPacket::NewIncomingConnection(_) => {
                if !Self::apply_session_transitions(
                    session,
                    &[SessionState::NewIncomingRecv, SessionState::Connected],
                ) {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: true,
                    });
                }
            }
            ConnectedControlPacket::DisconnectionNotification(pkt) => {
                if !Self::apply_session_transitions(
                    session,
                    &[SessionState::Closing, SessionState::Closed],
                ) {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: true,
                    });
                }
                return Ok(ControlAction::CloseSession {
                    remote_reason: Some(RemoteDisconnectReason::DisconnectionNotification {
                        reason_code: pkt.reason,
                    }),
                    illegal_state: false,
                });
            }
            ConnectedControlPacket::DetectLostConnection(_) => {
                if !Self::apply_session_transitions(
                    session,
                    &[SessionState::Closing, SessionState::Closed],
                ) {
                    return Ok(ControlAction::CloseSession {
                        remote_reason: None,
                        illegal_state: true,
                    });
                }
                return Ok(ControlAction::CloseSession {
                    remote_reason: Some(RemoteDisconnectReason::DetectLostConnection),
                    illegal_state: false,
                });
            }
            ConnectedControlPacket::ConnectedPong(_)
            | ConnectedControlPacket::ConnectionRequestAccepted(_) => {}
        }

        Ok(ControlAction::None)
    }

    fn apply_session_transitions(session: &mut Session, transitions: &[SessionState]) -> bool {
        for &next in transitions {
            if !session.transition_to(next) {
                return false;
            }
        }
        true
    }

    fn queue_connected_control_packet(
        session: &mut Session,
        packet: ConnectedControlPacket,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
    ) -> Result<QueuePayloadResult, DecodeError> {
        let mut bytes = BytesMut::new();
        packet
            .encode(&mut bytes)
            .map_err(|_| DecodeError::UnexpectedEof)?;
        let payload = bytes.freeze();
        Ok(session.queue_payload(payload, reliability, channel, priority))
    }

    fn prune_pending_handshakes(&mut self, now: Instant) {
        let mut expired = Vec::new();
        for (addr, pending) in &self.pending_handshakes {
            if pending.expires_at <= now {
                expired.push((*addr, *pending));
            }
        }

        for (addr, pending) in expired {
            let violation = match pending.stage {
                PendingHandshakeStage::AwaitingRequest2 => {
                    self.handshake_req1_req2_timeouts =
                        self.handshake_req1_req2_timeouts.saturating_add(1);
                    HandshakeViolation::Req1Req2Timeout
                }
                PendingHandshakeStage::AwaitingConnectionRequest => {
                    self.handshake_reply2_connect_timeouts =
                        self.handshake_reply2_connect_timeouts.saturating_add(1);
                    HandshakeViolation::Reply2ConnectTimeout
                }
            };
            warn!(
                %addr,
                stage = ?pending.stage,
                "pending handshake expired and session is being closed"
            );
            self.handshake_stage_cancel_drops = self.handshake_stage_cancel_drops.saturating_add(1);
            let _ = self.record_handshake_violation(addr, violation, now);
            self.close_session(addr);
        }

        self.prune_handshake_heuristic_states(now);
    }

    fn clear_cookie_mismatch_state(&mut self, ip: IpAddr) {
        self.cookie_mismatch_guard_states.remove(&ip);
    }

    fn record_cookie_mismatch(&mut self, ip: IpAddr, now: Instant) -> bool {
        let guard = self.config.cookie_mismatch_guard;
        if !guard.enabled
            || guard.event_window.is_zero()
            || guard.block_duration.is_zero()
            || guard.mismatch_threshold == 0
        {
            return false;
        }

        let state =
            self.cookie_mismatch_guard_states
                .entry(ip)
                .or_insert(CookieMismatchGuardState {
                    window_started_at: now,
                    mismatches: 0,
                });

        if now.saturating_duration_since(state.window_started_at) > guard.event_window {
            state.window_started_at = now;
            state.mismatches = 0;
        }

        state.mismatches = state.mismatches.saturating_add(1);
        if state.mismatches < guard.mismatch_threshold {
            return false;
        }

        state.window_started_at = now;
        state.mismatches = 0;

        let newly_blocked = self.rate_limiter.block_address_for_with_reason(
            ip,
            now,
            guard.block_duration,
            BlockReason::CookieMismatchGuard,
        );
        if newly_blocked {
            self.cookie_mismatch_blocks = self.cookie_mismatch_blocks.saturating_add(1);
            warn!(
                %ip,
                mismatches_required = guard.mismatch_threshold,
                block_secs = guard.block_duration.as_secs(),
                "cookie mismatch guard blocked address"
            );
        }
        newly_blocked
    }

    fn prune_cookie_mismatch_guard_states(&mut self, now: Instant) {
        let guard = self.config.cookie_mismatch_guard;
        if !guard.enabled || guard.event_window.is_zero() {
            self.cookie_mismatch_guard_states.clear();
            return;
        }

        self.cookie_mismatch_guard_states.retain(|_, state| {
            now.saturating_duration_since(state.window_started_at) <= guard.event_window
        });
    }

    fn record_handshake_violation(
        &mut self,
        addr: SocketAddr,
        violation: HandshakeViolation,
        now: Instant,
    ) -> bool {
        let h = self.config.handshake_heuristics;
        if !h.enabled
            || h.score_threshold == 0
            || h.event_window.is_zero()
            || h.block_duration.is_zero()
        {
            return false;
        }

        let points = violation.score(&self.config);
        if points == 0 {
            return false;
        }
        debug!(%addr, ?violation, points, "recorded handshake violation");

        let mut should_block = false;
        {
            let entry =
                self.handshake_heuristics
                    .entry(addr.ip())
                    .or_insert(HandshakeHeuristicState {
                        window_started_at: now,
                        score: 0,
                    });

            if now.saturating_duration_since(entry.window_started_at) > h.event_window {
                entry.window_started_at = now;
                entry.score = 0;
            }

            entry.score = entry.score.saturating_add(points);
            if entry.score >= h.score_threshold {
                entry.window_started_at = now;
                entry.score = 0;
                should_block = true;
            }
        }

        if !should_block {
            return false;
        }

        let newly_blocked = self.rate_limiter.block_address_for_with_reason(
            addr.ip(),
            now,
            h.block_duration,
            BlockReason::HandshakeHeuristic,
        );
        if newly_blocked {
            self.handshake_auto_blocks = self.handshake_auto_blocks.saturating_add(1);
            warn!(
                %addr,
                ?violation,
                block_secs = h.block_duration.as_secs(),
                "handshake heuristic blocked address"
            );
        }
        newly_blocked
    }

    fn prune_handshake_heuristic_states(&mut self, now: Instant) {
        let h = self.config.handshake_heuristics;
        if !h.enabled || h.event_window.is_zero() {
            self.handshake_heuristics.clear();
            return;
        }

        self.handshake_heuristics.retain(|_, state| {
            now.saturating_duration_since(state.window_started_at) <= h.event_window
        });
    }

    fn close_session(&mut self, addr: SocketAddr) {
        self.pending_handshakes.remove(&addr);
        if let Some(session) = self.sessions.remove(&addr) {
            let state = session.state();
            if should_count_closed_session(state) {
                self.sessions_closed_total = self.sessions_closed_total.saturating_add(1);
            }
            if should_mark_ip_recently_connected(state) {
                self.mark_ip_recently_connected(addr, Instant::now());
            }
        }
        self.session_pipelines.remove(&addr);
    }

    fn has_active_session_for_offline_reject(&self, addr: SocketAddr) -> bool {
        let Some(session) = self.sessions.get(&addr) else {
            return false;
        };
        if self.pending_handshakes.contains_key(&addr) {
            return false;
        }
        matches!(
            session.state(),
            SessionState::Req2Recv
                | SessionState::Reply2Sent
                | SessionState::ConnReqRecv
                | SessionState::ConnReqAcceptedSent
                | SessionState::NewIncomingRecv
                | SessionState::Connected
                | SessionState::Closing
                | SessionState::Closed
        )
    }

    fn is_request2_server_addr_allowed(
        &self,
        request_server_addr: SocketAddr,
        local_server_addr: SocketAddr,
    ) -> bool {
        match self.config.request2_server_addr_policy {
            Request2ServerAddrPolicy::Disabled => true,
            Request2ServerAddrPolicy::PortOnly => {
                request_server_addr.port() == local_server_addr.port()
            }
            Request2ServerAddrPolicy::Exact => {
                if local_server_addr.ip().is_unspecified() {
                    request_server_addr.port() == local_server_addr.port()
                } else {
                    request_server_addr == local_server_addr
                }
            }
        }
    }

    fn has_ip_recently_connected(&mut self, addr: SocketAddr, now: Instant) -> bool {
        self.prune_ip_recently_connected(now);
        self.ip_recently_connected_until
            .get(&addr.ip())
            .is_some_and(|until| *until > now)
    }

    fn mark_ip_recently_connected(&mut self, addr: SocketAddr, now: Instant) {
        let window = self.config.ip_recently_connected_window;
        if window.is_zero() {
            return;
        }
        self.ip_recently_connected_until
            .insert(addr.ip(), now + window);
    }

    fn prune_ip_recently_connected(&mut self, now: Instant) {
        if self.config.ip_recently_connected_window.is_zero() {
            self.ip_recently_connected_until.clear();
            return;
        }
        self.ip_recently_connected_until
            .retain(|_, until| *until > now);
    }

    fn record_remote_disconnect(&mut self, reason: RemoteDisconnectReason) {
        match reason {
            RemoteDisconnectReason::DisconnectionNotification { .. } => {
                self.remote_disconnect_notifications =
                    self.remote_disconnect_notifications.saturating_add(1);
            }
            RemoteDisconnectReason::DetectLostConnection => {
                self.remote_detect_lost_disconnects =
                    self.remote_detect_lost_disconnects.saturating_add(1);
            }
        }
    }

    fn prune_idle_sessions(&mut self, now: Instant, protected_addr: Option<SocketAddr>) {
        let timeout = self.config.session_idle_timeout;
        if timeout.is_zero() {
            return;
        }

        let mut stale = Vec::new();
        for (addr, session) in &self.sessions {
            if Some(*addr) == protected_addr {
                continue;
            }
            if session.state() != SessionState::Connected {
                continue;
            }
            if session.idle_for(now) >= timeout {
                stale.push(*addr);
            }
        }

        for addr in stale {
            self.timed_out_sessions = self.timed_out_sessions.saturating_add(1);
            self.close_session(addr);
        }
    }

    fn queue_keepalive_pings(&mut self, now: Instant) {
        let interval = self.config.session_keepalive_interval;
        if interval.is_zero() {
            return;
        }

        let mut close_addrs = Vec::new();
        for (addr, session) in &mut self.sessions {
            if !session.should_send_keepalive(now, interval) {
                continue;
            }

            let ping = ConnectedControlPacket::ConnectedPing(ConnectedPing {
                ping_time: unix_timestamp_millis(),
            });

            if matches!(
                Self::queue_connected_control_packet(
                    session,
                    ping,
                    Reliability::Unreliable,
                    0,
                    RakPriority::Low,
                ),
                Ok(QueuePayloadResult::Enqueued { .. })
            ) {
                session.mark_keepalive_sent(now);
                self.keepalive_pings_sent = self.keepalive_pings_sent.saturating_add(1);
            }

            if session.take_backpressure_disconnect() {
                close_addrs.push(*addr);
            }
        }

        for addr in close_addrs {
            self.close_session(addr);
        }
    }

    fn record_illegal_state_transition(&mut self, addr: SocketAddr) {
        self.illegal_state_transitions = self.illegal_state_transitions.saturating_add(1);
        self.close_session(addr);
    }

    fn would_exceed_session_limit(&self, addr: SocketAddr) -> bool {
        !self.sessions.contains_key(&addr) && self.sessions.len() >= self.config.max_sessions
    }

    fn negotiate_mtu(&self, requested: u16) -> u16 {
        let server_cap =
            self.config
                .mtu
                .clamp(MINIMUM_MTU_SIZE as usize, MAXIMUM_MTU_SIZE as usize) as u16;
        requested.clamp(MINIMUM_MTU_SIZE, server_cap)
    }

    fn rotate_cookie_keys_if_needed(&mut self, now: Instant) {
        if !self.config.send_cookie || self.config.cookie_rotation_interval.is_zero() {
            return;
        }
        if now < self.next_cookie_rotation {
            return;
        }

        let next_key = SecretCookieKey::new(random_cookie_key());
        let previous_key = std::mem::replace(&mut self.cookie_key_current, next_key);
        self.cookie_key_previous = Some(previous_key);
        self.next_cookie_rotation = now + self.config.cookie_rotation_interval;
        self.cookie_rotations = self.cookie_rotations.saturating_add(1);
    }

    fn generate_cookie(&self, addr: SocketAddr) -> u32 {
        self.compute_cookie_for_key(addr, self.cookie_key_current.as_ref())
    }

    fn verify_cookie(&self, addr: SocketAddr, cookie: Option<u32>) -> bool {
        let Some(cookie) = cookie else {
            return false;
        };

        if self.compute_cookie_for_key(addr, self.cookie_key_current.as_ref()) == cookie {
            return true;
        }

        if let Some(previous_key) = self.cookie_key_previous.as_ref()
            && self.compute_cookie_for_key(addr, previous_key.as_ref()) == cookie
        {
            return true;
        }

        false
    }

    fn compute_cookie_for_key(&self, addr: SocketAddr, key: &[u8]) -> u32 {
        let mut mac = Hmac::new_from_slice(key).expect("HMAC supports arbitrary key lengths");
        update_mac_with_socket_addr(&mut mac, addr);
        update_mac_with_socket_addr(&mut mac, self.config.bind_addr);
        mac.update(&self.config.server_guid.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]])
    }
}

fn invalid_data_io_error<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn supports_protocol(supported: &[u8], incoming: u8) -> bool {
    if supported.is_empty() {
        return incoming == RAKNET_PROTOCOL_VERSION;
    }
    supported.contains(&incoming)
}

fn primary_protocol_version(supported: &[u8]) -> u8 {
    supported
        .iter()
        .copied()
        .max()
        .unwrap_or(RAKNET_PROTOCOL_VERSION)
}

fn random_cookie_key() -> [u8; COOKIE_KEY_LEN] {
    let mut key = [0u8; COOKIE_KEY_LEN];
    if getrandom::fill(&mut key).is_ok() {
        return key;
    }

    let fallback = unix_timestamp_millis() as u64;
    for (idx, chunk) in key.chunks_exact_mut(8).enumerate() {
        let seed = fallback
            .wrapping_mul((idx as u64).saturating_add(1))
            .rotate_left((idx as u32).saturating_mul(11));
        chunk.copy_from_slice(&seed.to_le_bytes());
    }
    key
}

fn invalid_config_io_error(error: crate::error::ConfigValidationError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_df_path_mtu_discovery_v4(socket: &Socket) -> io::Result<()> {
    let mode: libc::c_int = libc::IP_PMTUDISC_DO;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &mode as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_df_path_mtu_discovery_v4(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "disable_ip_fragmentation is unsupported for IPv4 on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_df_path_mtu_discovery_v6(socket: &Socket) -> io::Result<()> {
    let mode: libc::c_int = libc::IPV6_PMTUDISC_DO;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            &mode as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_df_path_mtu_discovery_v6(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "disable_ip_fragmentation is unsupported for IPv6 on this platform",
    ))
}

fn update_mac_with_socket_addr(mac: &mut HmacSha256, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            mac.update(&[4]);
            mac.update(&v4.ip().octets());
            mac.update(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            mac.update(&[6]);
            mac.update(&v6.ip().octets());
            mac.update(&v6.port().to_le_bytes());
            mac.update(&v6.flowinfo().to_le_bytes());
            mac.update(&v6.scope_id().to_le_bytes());
        }
    }
}

fn unix_timestamp_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(i64::MAX as u128) as i64,
        Err(_) => 0,
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

fn estimate_connected_datagram_processing_cost(raw_len: usize, datagram: &Datagram) -> usize {
    match &datagram.payload {
        DatagramPayload::Ack(payload) | DatagramPayload::Nack(payload) => {
            payload.ranges.len().saturating_mul(8).max(1)
        }
        DatagramPayload::Frames(frames) => {
            let mut cost = raw_len.max(1);
            cost = cost.saturating_add(frames.len().saturating_mul(48));

            for frame in frames {
                let payload_len = frame.payload.len();
                cost = cost.saturating_add(payload_len);

                if frame.header.reliability.is_reliable() {
                    cost = cost.saturating_add(32);
                }
                if frame.header.reliability.is_ordered() || frame.header.reliability.is_sequenced()
                {
                    cost = cost.saturating_add(24);
                }
                if frame.header.is_split {
                    let split_parts = frame
                        .split
                        .as_ref()
                        .map(|s| s.part_count as usize)
                        .unwrap_or(1);
                    cost = cost.saturating_add(512);
                    cost = cost.saturating_add(payload_len.saturating_mul(2));
                    cost = cost.saturating_add(split_parts.min(2_048));
                }
            }

            cost.max(1)
        }
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

fn is_post_reply2_handshake_state(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Reply2Sent
            | SessionState::ConnReqRecv
            | SessionState::ConnReqAcceptedSent
            | SessionState::NewIncomingRecv
    )
}

fn should_mark_ip_recently_connected(state: SessionState) -> bool {
    state == SessionState::Connected
        || state == SessionState::Closing
        || state == SessionState::Closed
        || is_post_reply2_handshake_state(state)
}

fn should_count_closed_session(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Connected | SessionState::Closing | SessionState::Closed
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::time::{Duration, Instant};

    use bytes::{Bytes, BytesMut};
    use tokio::runtime::Builder;

    use super::{
        ConnectedFrameDelivery, ControlAction, HandshakeViolation, PendingHandshake,
        PendingHandshakeStage, RemoteDisconnectReason, TransportEvent,
        TransportProcessingBudgetConfig, TransportRateLimitConfig, TransportServer,
        build_internal_addrs, is_connected_control_id, is_offline_packet_id,
        primary_protocol_version, supports_protocol,
    };
    use crate::error::DecodeError;
    use crate::protocol::connected::{
        ConnectedControlPacket, ConnectedPing, ConnectionRequest, DetectLostConnection,
        DisconnectionNotification,
    };
    use crate::protocol::constants::{
        DEFAULT_UNCONNECTED_MAGIC, DatagramFlags, RAKNET_PROTOCOL_VERSION,
    };
    use crate::protocol::datagram::{Datagram, DatagramHeader, DatagramPayload};
    use crate::protocol::frame::Frame;
    use crate::protocol::frame_header::FrameHeader;
    use crate::protocol::packet::{
        OfflinePacket, OpenConnectionRequest1, OpenConnectionRequest2, Request2ParsePath,
    };
    use crate::protocol::reliability::Reliability;
    use crate::protocol::sequence24::Sequence24;
    use crate::session::tunables::SessionTunables;
    use crate::session::{QueuePayloadResult, RakPriority, Session, SessionState};
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    use crate::transport::config::TransportSocketTuning;
    use crate::transport::config::{
        CookieMismatchGuardConfig, HandshakeHeuristicsConfig, ProcessingBudgetConfig,
        Request2ServerAddrPolicy, TransportConfig,
    };

    fn build_test_server(mut config: TransportConfig) -> TransportServer {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");

        rt.block_on(async move {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            TransportServer::with_socket(config, socket).expect("server should build")
        })
    }

    #[test]
    fn connected_frame_delivery_preserves_payload_and_metadata() {
        let payload = Bytes::from_static(b"\xfepayload");
        let frame = Frame {
            header: FrameHeader {
                reliability: Reliability::ReliableOrdered,
                is_split: false,
                needs_bas: false,
            },
            bit_length: (payload.len() as u16) << 3,
            reliable_index: Some(Sequence24::new(3)),
            sequence_index: None,
            ordering_index: Some(Sequence24::new(8)),
            ordering_channel: Some(2),
            split: None,
            payload: payload.clone(),
        };

        let delivered = ConnectedFrameDelivery::from_frame(frame);
        assert_eq!(delivered.payload, payload);
        assert_eq!(delivered.reliability, Reliability::ReliableOrdered);
        assert_eq!(delivered.reliable_index, Some(Sequence24::new(3)));
        assert_eq!(delivered.ordering_index, Some(Sequence24::new(8)));
        assert_eq!(delivered.ordering_channel, Some(2));
        assert!(delivered.sequence_index.is_none());
    }

    #[test]
    fn apply_session_transitions_accepts_valid_path() {
        let mut session = Session::new(1492);
        let ok = TransportServer::apply_session_transitions(
            &mut session,
            &[
                SessionState::Req1Recv,
                SessionState::Reply1Sent,
                SessionState::Req2Recv,
                SessionState::Reply2Sent,
                SessionState::ConnReqRecv,
                SessionState::ConnReqAcceptedSent,
                SessionState::NewIncomingRecv,
                SessionState::Connected,
            ],
        );
        assert!(ok);
        assert_eq!(session.state(), SessionState::Connected);
    }

    #[test]
    fn apply_session_transitions_rejects_invalid_jump() {
        let mut session = Session::new(1492);
        let ok =
            TransportServer::apply_session_transitions(&mut session, &[SessionState::ConnReqRecv]);
        assert!(!ok);
        assert_eq!(session.state(), SessionState::Offline);
    }

    #[test]
    fn connected_ping_before_connected_state_is_rejected() {
        let mut session = Session::new(1492);
        let result = TransportServer::apply_connected_control(
            &mut session,
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            123,
            ConnectedControlPacket::ConnectedPing(ConnectedPing { ping_time: 11 }),
        );

        assert!(matches!(
            result,
            Ok(ControlAction::CloseSession {
                remote_reason: None,
                illegal_state: true,
            })
        ));
        assert_eq!(session.state(), SessionState::Offline);
    }

    #[test]
    fn disconnection_notification_exposes_remote_reason_code() {
        let mut session = Session::new(1492);
        assert!(TransportServer::apply_session_transitions(
            &mut session,
            &[
                SessionState::Req1Recv,
                SessionState::Reply1Sent,
                SessionState::Req2Recv,
                SessionState::Reply2Sent,
                SessionState::ConnReqRecv,
                SessionState::ConnReqAcceptedSent,
                SessionState::NewIncomingRecv,
                SessionState::Connected,
            ],
        ));

        let result = TransportServer::apply_connected_control(
            &mut session,
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            123,
            ConnectedControlPacket::DisconnectionNotification(DisconnectionNotification {
                reason: Some(7),
            }),
        );

        assert!(matches!(
            result,
            Ok(ControlAction::CloseSession {
                remote_reason: Some(RemoteDisconnectReason::DisconnectionNotification {
                    reason_code: Some(7)
                }),
                illegal_state: false,
            })
        ));
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn detect_lost_connection_is_reported_as_remote_disconnect() {
        let mut session = Session::new(1492);
        assert!(TransportServer::apply_session_transitions(
            &mut session,
            &[
                SessionState::Req1Recv,
                SessionState::Reply1Sent,
                SessionState::Req2Recv,
                SessionState::Reply2Sent,
                SessionState::ConnReqRecv,
                SessionState::ConnReqAcceptedSent,
                SessionState::NewIncomingRecv,
                SessionState::Connected,
            ],
        ));

        let result = TransportServer::apply_connected_control(
            &mut session,
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            123,
            ConnectedControlPacket::DetectLostConnection(DetectLostConnection),
        );

        assert!(matches!(
            result,
            Ok(ControlAction::CloseSession {
                remote_reason: Some(RemoteDisconnectReason::DetectLostConnection),
                illegal_state: false,
            })
        ));
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn connection_request_after_reply2_is_accepted() {
        let mut session = Session::new(1492);
        assert!(TransportServer::apply_session_transitions(
            &mut session,
            &[
                SessionState::Req1Recv,
                SessionState::Reply1Sent,
                SessionState::Req2Recv,
                SessionState::Reply2Sent,
            ],
        ));

        let result = TransportServer::apply_connected_control(
            &mut session,
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            "127.0.0.1:19132"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            123,
            ConnectedControlPacket::ConnectionRequest(ConnectionRequest {
                client_guid: 42,
                request_time: 77,
                use_encryption: false,
            }),
        );

        assert!(matches!(result, Ok(ControlAction::None)));
        assert_eq!(session.state(), SessionState::ConnReqAcceptedSent);
    }

    #[test]
    fn protocol_support_accepts_configured_versions() {
        let versions = [10, 11, 12];
        assert!(supports_protocol(&versions, 10));
        assert!(supports_protocol(&versions, 12));
        assert!(!supports_protocol(&versions, 9));
        assert!(supports_protocol(&[], RAKNET_PROTOCOL_VERSION));
        assert!(!supports_protocol(
            &[],
            RAKNET_PROTOCOL_VERSION.saturating_sub(1)
        ));
    }

    #[test]
    fn primary_protocol_version_uses_highest_configured_version() {
        let versions = [11, 13, 12];
        assert_eq!(primary_protocol_version(&versions), 13);
        assert_eq!(primary_protocol_version(&[]), RAKNET_PROTOCOL_VERSION);
    }

    #[test]
    fn cookie_rotation_keeps_previous_key_valid_temporarily() {
        let config = TransportConfig {
            send_cookie: true,
            cookie_rotation_interval: Duration::from_secs(1),
            ..TransportConfig::default()
        };
        let mut server = build_test_server(config);
        let addr = "127.0.0.1:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");

        let mut original_key = [0u8; super::COOKIE_KEY_LEN];
        original_key.copy_from_slice(server.cookie_key_current.as_ref());
        let old_cookie = server.generate_cookie(addr);
        server.rotate_cookie_keys_if_needed(Instant::now() + Duration::from_secs(2));

        assert_eq!(server.cookie_rotations, 1);
        let previous_key = server.cookie_key_previous.as_ref().map(|key| {
            let mut value = [0u8; super::COOKIE_KEY_LEN];
            value.copy_from_slice(key.as_ref());
            value
        });
        assert_eq!(
            previous_key,
            Some(original_key),
            "rotating cookies must retain previous key for grace period"
        );
        assert!(server.verify_cookie(addr, Some(old_cookie)));
    }

    #[test]
    fn cookie_is_bound_to_socket_address() {
        let config = TransportConfig {
            send_cookie: true,
            ..TransportConfig::default()
        };
        let server = build_test_server(config);
        let addr_a = "127.0.0.1:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let addr_b = "127.0.0.2:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");

        let cookie = server.generate_cookie(addr_a);
        assert!(server.verify_cookie(addr_a, Some(cookie)));
        assert!(!server.verify_cookie(addr_b, Some(cookie)));
    }

    #[test]
    fn cookie_mismatch_guard_blocks_after_threshold() {
        let config = TransportConfig {
            cookie_mismatch_guard: CookieMismatchGuardConfig {
                enabled: true,
                event_window: Duration::from_secs(30),
                mismatch_threshold: 2,
                block_duration: Duration::from_secs(10),
            },
            ..TransportConfig::default()
        };
        let mut server = build_test_server(config);
        let ip: IpAddr = "203.0.113.9".parse().expect("valid ip");
        let now = Instant::now();

        assert!(!server.record_cookie_mismatch(ip, now));
        assert!(server.record_cookie_mismatch(ip, now + Duration::from_millis(1)));

        let metrics = server.metrics_snapshot();
        assert_eq!(metrics.cookie_mismatch_blocks, 1);
        assert_eq!(metrics.rate_blocked_addresses, 1);
    }

    #[test]
    fn request2_cookie_mismatch_updates_metrics_and_uses_guard_blocking() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig {
                send_cookie: true,
                handshake_heuristics: HandshakeHeuristicsConfig {
                    enabled: false,
                    ..HandshakeHeuristicsConfig::default()
                },
                cookie_mismatch_guard: CookieMismatchGuardConfig {
                    enabled: true,
                    event_window: Duration::from_secs(30),
                    mismatch_threshold: 1,
                    block_duration: Duration::from_secs(10),
                },
                ..TransportConfig::default()
            };
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20320"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });
            server
                .handle_offline_packet(addr, &request1, Instant::now())
                .await
                .expect("request1 handling should succeed");

            let wrong_cookie = server.generate_cookie(addr).wrapping_add(1);
            let request2 = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
                server_addr: server.local_addr().expect("local addr should be available"),
                mtu: 1200,
                client_guid: 0xABCD_ABCD_ABCD_ABCD,
                cookie: Some(wrong_cookie),
                client_proof: true,
                parse_path: Request2ParsePath::StrictWithCookie,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });
            let result = server
                .handle_offline_packet(addr, &request2, Instant::now())
                .await
                .expect("request2 handling should succeed");
            assert!(result.is_none());

            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.cookie_mismatch_drops, 1);
            assert_eq!(metrics.cookie_mismatch_blocks, 1);
            assert_eq!(metrics.rate_blocked_addresses, 1);
            assert_eq!(metrics.rate_addresses_blocked_cookie_mismatch_guard, 1);
        });
    }

    #[test]
    fn pending_handshake_timeout_updates_metrics_and_closes_session() {
        let mut server = build_test_server(TransportConfig::default());
        let addr = "127.0.0.1:20001"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let now = Instant::now();

        let mut session = Session::new(1492);
        assert!(TransportServer::apply_session_transitions(
            &mut session,
            &[SessionState::Req1Recv, SessionState::Reply1Sent]
        ));
        server.sessions.insert(addr, session);
        server.pending_handshakes.insert(
            addr,
            PendingHandshake {
                mtu: 1492,
                cookie: None,
                client_guid: None,
                stage: PendingHandshakeStage::AwaitingRequest2,
                expires_at: now - Duration::from_millis(1),
            },
        );

        server.prune_pending_handshakes(now);

        assert!(!server.sessions.contains_key(&addr));
        assert!(!server.pending_handshakes.contains_key(&addr));

        let metrics = server.metrics_snapshot();
        assert_eq!(metrics.handshake_req1_req2_timeouts, 1);
        assert_eq!(metrics.handshake_stage_cancel_drops, 1);
    }

    #[test]
    fn reply2_connect_timeout_updates_metrics_and_closes_session() {
        let config = TransportConfig {
            handshake_reply2_connect_timeout: Duration::from_secs(1),
            ..TransportConfig::default()
        };
        let mut server = build_test_server(config);
        let addr = "127.0.0.1:20002"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let now = Instant::now();

        let mut session = Session::new(1492);
        assert!(TransportServer::apply_session_transitions(
            &mut session,
            &[
                SessionState::Req1Recv,
                SessionState::Reply1Sent,
                SessionState::Req2Recv,
                SessionState::Reply2Sent,
            ]
        ));
        session.touch_activity(now - Duration::from_secs(2));
        server.sessions.insert(addr, session);
        server.pending_handshakes.insert(
            addr,
            PendingHandshake {
                mtu: 1492,
                cookie: None,
                client_guid: None,
                stage: PendingHandshakeStage::AwaitingConnectionRequest,
                expires_at: now - Duration::from_millis(1),
            },
        );

        server.prune_pending_handshakes(now);

        assert!(!server.sessions.contains_key(&addr));
        let metrics = server.metrics_snapshot();
        assert_eq!(metrics.handshake_reply2_connect_timeouts, 1);
        assert_eq!(metrics.handshake_stage_cancel_drops, 1);
    }

    #[test]
    fn handshake_heuristic_blocks_after_threshold() {
        let config = TransportConfig {
            handshake_heuristics: HandshakeHeuristicsConfig {
                enabled: true,
                event_window: Duration::from_secs(30),
                block_duration: Duration::from_secs(10),
                score_threshold: 3,
                req1_req2_timeout_score: 1,
                reply2_connect_timeout_score: 1,
                missing_req1_score: 1,
                cookie_mismatch_score: 2,
                parse_anomaly_score: 1,
            },
            ..TransportConfig::default()
        };
        let mut server = build_test_server(config);
        let addr = "127.0.0.1:20003"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let now = Instant::now();

        let blocked_1 =
            server.record_handshake_violation(addr, HandshakeViolation::CookieMismatch, now);
        let blocked_2 = server.record_handshake_violation(
            addr,
            HandshakeViolation::CookieMismatch,
            now + Duration::from_millis(1),
        );

        assert!(!blocked_1);
        assert!(blocked_2);

        let metrics = server.metrics_snapshot();
        assert_eq!(metrics.handshake_auto_blocks, 1);
        assert_eq!(metrics.rate_blocked_addresses, 1);
        assert_eq!(metrics.rate_addresses_blocked_handshake_heuristic, 1);
    }

    #[test]
    fn packet_id_classification_and_internal_addresses_are_consistent() {
        assert!(is_offline_packet_id(0x05));
        assert!(!is_offline_packet_id(0x03));
        assert!(is_connected_control_id(0x03));
        assert!(!is_connected_control_id(0x05));

        let server_addr = "10.1.2.3:19132"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let internal = build_internal_addrs(server_addr);
        assert_eq!(internal[0], server_addr);
        for addr in internal.iter().skip(1) {
            assert!(addr.ip().is_unspecified());
            assert_eq!(addr.port(), 0);
        }
    }

    #[test]
    fn open_connection_request1_creates_session_with_transport_tunables() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig {
                session_tunables: SessionTunables {
                    outgoing_queue_max_frames: 1,
                    outgoing_queue_max_bytes: 128,
                    outgoing_queue_soft_ratio: 0.95,
                    ..SessionTunables::default()
                },
                ..TransportConfig::default()
            };
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20123"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });

            let event = server
                .handle_offline_packet(addr, &request1, Instant::now())
                .await
                .expect("offline request1 handling should succeed");
            assert!(
                event.is_none(),
                "request1 should not emit a transport event in healthy path"
            );

            let session = server
                .sessions
                .get_mut(&addr)
                .expect("request1 must create a pending session");
            let first = session.queue_payload(
                Bytes::from_static(b"\xFEfirst"),
                Reliability::Unreliable,
                0,
                RakPriority::Normal,
            );
            let second = session.queue_payload(
                Bytes::from_static(b"\xFEsecond"),
                Reliability::Unreliable,
                0,
                RakPriority::Normal,
            );

            assert!(
                matches!(first, QueuePayloadResult::Enqueued { .. }),
                "first packet should fit in queue"
            );
            assert_eq!(
                second,
                QueuePayloadResult::Dropped,
                "second packet should be dropped because configured queue max frames=1"
            );
        });
    }

    #[test]
    fn process_next_event_uses_configured_unconnected_magic() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");

        rt.block_on(async {
            let custom_magic = [
                0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xF0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                0xDC, 0xFE,
            ];
            let mut config = TransportConfig {
                unconnected_magic: custom_magic,
                ..TransportConfig::default()
            };

            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let server_addr = config.bind_addr;
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");

            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client bind should succeed");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: custom_magic,
            });
            let mut buf = BytesMut::new();
            request1.encode(&mut buf).expect("encode must succeed");
            client
                .send_to(&buf, server_addr)
                .await
                .expect("send should succeed");

            let event = tokio::time::timeout(Duration::from_secs(1), server.recv_and_process())
                .await
                .expect("server should receive packet in time")
                .expect("processing should succeed");
            assert!(
                matches!(event, TransportEvent::OfflinePacket { .. }),
                "matching custom magic should parse as offline packet event"
            );
        });
    }

    #[test]
    fn process_next_event_rejects_mismatched_unconnected_magic() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");

        rt.block_on(async {
            let custom_magic = [
                0x13, 0x57, 0x9B, 0xDF, 0x24, 0x68, 0xAC, 0xF0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                0xDC, 0xFE,
            ];
            let mut config = TransportConfig {
                unconnected_magic: custom_magic,
                ..TransportConfig::default()
            };

            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let server_addr = config.bind_addr;
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");

            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client bind should succeed");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });
            let mut buf = BytesMut::new();
            request1.encode(&mut buf).expect("encode must succeed");
            client
                .send_to(&buf, server_addr)
                .await
                .expect("send should succeed");

            let event = tokio::time::timeout(Duration::from_secs(1), server.recv_and_process())
                .await
                .expect("server should receive packet in time")
                .expect("processing should succeed");
            assert!(
                matches!(
                    event,
                    TransportEvent::DecodeError {
                        error: DecodeError::InvalidMagic,
                        ..
                    }
                ),
                "mismatched magic should be rejected as invalid magic"
            );
        });
    }

    #[test]
    fn rate_limit_config_updates_sync_with_transport_config() {
        let mut server = build_test_server(TransportConfig::default());
        server.set_rate_limit_config(TransportRateLimitConfig {
            per_ip_packet_limit: 0,
            global_packet_limit: 0,
            rate_window: Duration::ZERO,
            block_duration: Duration::ZERO,
        });

        let effective = server.rate_limit_config();
        assert_eq!(effective.per_ip_packet_limit, 1);
        assert_eq!(effective.global_packet_limit, 1);
        assert_eq!(effective.rate_window, Duration::from_millis(1));
        assert_eq!(effective.block_duration, Duration::from_millis(1));
        assert_eq!(server.config().per_ip_packet_limit, 1);
        assert_eq!(server.config().global_packet_limit, 1);
        assert_eq!(server.config().rate_window, Duration::from_millis(1));
        assert_eq!(server.config().block_duration, Duration::from_millis(1));
    }

    #[test]
    fn permanent_block_api_tracks_metrics_and_requires_manual_unblock() {
        let mut server = build_test_server(TransportConfig::default());
        let ip: IpAddr = "198.51.100.9".parse().expect("valid ip");

        assert!(server.block_address(ip));
        assert!(!server.block_address(ip));
        let metrics_after_block = server.metrics_snapshot();
        assert_eq!(metrics_after_block.rate_blocked_addresses, 1);
        assert_eq!(metrics_after_block.rate_addresses_blocked_manual, 1);

        assert!(server.unblock_address(ip));
        assert_eq!(server.metrics_snapshot().rate_blocked_addresses, 0);
    }

    #[test]
    fn local_and_remote_disconnect_metrics_are_tracked_separately() {
        let mut server = build_test_server(TransportConfig::default());
        let addr = "127.0.0.1:20100"
            .parse::<SocketAddr>()
            .expect("valid socket addr");
        let mut session = Session::new(1492);
        assert!(TransportServer::apply_session_transitions(
            &mut session,
            &[
                SessionState::Req1Recv,
                SessionState::Reply1Sent,
                SessionState::Req2Recv,
                SessionState::Reply2Sent,
                SessionState::ConnReqRecv,
                SessionState::ConnReqAcceptedSent,
                SessionState::NewIncomingRecv,
                SessionState::Connected,
            ],
        ));
        server.sessions.insert(addr, session);

        assert!(server.disconnect_peer(addr));
        server.record_remote_disconnect(RemoteDisconnectReason::DisconnectionNotification {
            reason_code: Some(3),
        });
        server.record_remote_disconnect(RemoteDisconnectReason::DetectLostConnection);

        let metrics = server.metrics_snapshot();
        assert_eq!(metrics.local_requested_disconnects, 1);
        assert_eq!(metrics.remote_disconnect_notifications, 1);
        assert_eq!(metrics.remote_detect_lost_disconnects, 1);
        assert_eq!(metrics.sessions_closed_total, 1);
    }

    #[test]
    fn processing_budget_config_updates_sync_with_transport_config() {
        let mut server = build_test_server(TransportConfig::default());
        server.set_processing_budget_config(TransportProcessingBudgetConfig {
            enabled: true,
            per_ip_refill_units_per_sec: 0,
            per_ip_burst_units: 0,
            global_refill_units_per_sec: 0,
            global_burst_units: 0,
            bucket_idle_ttl: Duration::ZERO,
        });

        let effective = server.processing_budget_config();
        assert!(effective.enabled);
        assert_eq!(effective.per_ip_refill_units_per_sec, 1);
        assert_eq!(effective.per_ip_burst_units, 1);
        assert_eq!(effective.global_refill_units_per_sec, 1);
        assert_eq!(effective.global_burst_units, 1);
        assert_eq!(effective.bucket_idle_ttl, Duration::from_millis(1));
        assert_eq!(
            server
                .config()
                .processing_budget
                .per_ip_refill_units_per_sec,
            1
        );
        assert_eq!(server.config().processing_budget.per_ip_burst_units, 1);
        assert_eq!(
            server
                .config()
                .processing_budget
                .global_refill_units_per_sec,
            1
        );
        assert_eq!(server.config().processing_budget.global_burst_units, 1);
        assert_eq!(
            server.config().processing_budget.bucket_idle_ttl,
            Duration::from_millis(1)
        );
    }

    #[test]
    fn processing_budget_exhaustion_drops_datagram_without_forcing_disconnect() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig {
                per_ip_packet_limit: 10_000,
                global_packet_limit: 10_000,
                processing_budget: ProcessingBudgetConfig {
                    enabled: true,
                    per_ip_refill_units_per_sec: 1,
                    per_ip_burst_units: 1,
                    global_refill_units_per_sec: 10_000,
                    global_burst_units: 10_000,
                    bucket_idle_ttl: Duration::from_secs(5),
                },
                ..TransportConfig::default()
            };

            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let server_addr = config.bind_addr;
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");

            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client bind should succeed");
            let client_addr = client.local_addr().expect("client local addr");

            let mut session = Session::new(1492);
            assert!(TransportServer::apply_session_transitions(
                &mut session,
                &[
                    SessionState::Req1Recv,
                    SessionState::Reply1Sent,
                    SessionState::Req2Recv,
                    SessionState::Reply2Sent,
                    SessionState::ConnReqRecv,
                    SessionState::ConnReqAcceptedSent,
                    SessionState::NewIncomingRecv,
                    SessionState::Connected,
                ],
            ));
            server.sessions.insert(client_addr, session);

            let make_datagram = |seq: u32| Datagram {
                header: DatagramHeader {
                    flags: DatagramFlags::VALID,
                    sequence: Sequence24::new(seq),
                },
                payload: DatagramPayload::Frames(vec![Frame {
                    header: FrameHeader::new(Reliability::Unreliable, false, false),
                    bit_length: (8u16) << 3,
                    reliable_index: None,
                    sequence_index: None,
                    ordering_index: None,
                    ordering_channel: None,
                    split: None,
                    payload: Bytes::from_static(b"payload!"),
                }]),
            };

            let mut first = BytesMut::new();
            make_datagram(1)
                .encode(&mut first)
                .expect("datagram encode should succeed");
            client
                .send_to(&first, server_addr)
                .await
                .expect("send first datagram should succeed");
            let first_event =
                tokio::time::timeout(Duration::from_secs(1), server.recv_and_process())
                    .await
                    .expect("first recv should complete")
                    .expect("first recv should succeed");
            assert!(
                matches!(first_event, TransportEvent::ConnectedFrames { .. }),
                "first datagram should pass before budget is depleted"
            );

            let mut second = BytesMut::new();
            make_datagram(2)
                .encode(&mut second)
                .expect("datagram encode should succeed");
            client
                .send_to(&second, server_addr)
                .await
                .expect("send second datagram should succeed");
            let second_event =
                tokio::time::timeout(Duration::from_secs(1), server.recv_and_process())
                    .await
                    .expect("second recv should complete")
                    .expect("second recv should succeed");
            assert!(
                matches!(second_event, TransportEvent::RateLimited { addr } if addr == client_addr),
                "second datagram should be dropped by processing budget"
            );

            assert!(
                server.sessions.contains_key(&client_addr),
                "budget drop must not force disconnect"
            );
            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.processing_budget_drops_total, 1);
            assert_eq!(metrics.processing_budget_drops_ip_exhausted_total, 1);
        });
    }

    #[test]
    fn open_connection_request2_rejects_already_connected_session() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig::default();
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20310"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let mut session = Session::new(1492);
            assert!(TransportServer::apply_session_transitions(
                &mut session,
                &[
                    SessionState::Req1Recv,
                    SessionState::Reply1Sent,
                    SessionState::Req2Recv,
                    SessionState::Reply2Sent,
                    SessionState::ConnReqRecv,
                    SessionState::ConnReqAcceptedSent,
                    SessionState::NewIncomingRecv,
                    SessionState::Connected,
                ]
            ));
            server.sessions.insert(addr, session);

            let request2 = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
                server_addr: server.local_addr().expect("local addr should be available"),
                mtu: 1200,
                client_guid: 0xAABB_CCDD_EEFF_0011,
                cookie: None,
                client_proof: false,
                parse_path: Request2ParsePath::StrictNoCookie,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });

            let event = server
                .handle_offline_packet(addr, &request2, Instant::now())
                .await
                .expect("request2 handling should succeed");
            assert!(event.is_none(), "reject path must not emit transport event");

            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.handshake_already_connected_rejects, 1);
            assert_eq!(metrics.handshake_missing_req1_drops, 0);
        });
    }

    #[test]
    fn open_connection_request1_rejects_ip_recently_connected() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig {
                ip_recently_connected_window: Duration::from_secs(3),
                ..TransportConfig::default()
            };
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20311"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let mut session = Session::new(1492);
            assert!(TransportServer::apply_session_transitions(
                &mut session,
                &[
                    SessionState::Req1Recv,
                    SessionState::Reply1Sent,
                    SessionState::Req2Recv,
                    SessionState::Reply2Sent,
                    SessionState::ConnReqRecv,
                    SessionState::ConnReqAcceptedSent,
                    SessionState::NewIncomingRecv,
                    SessionState::Connected,
                ]
            ));
            server.sessions.insert(addr, session);
            server.close_session(addr);

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });

            let event = server
                .handle_offline_packet(addr, &request1, Instant::now())
                .await
                .expect("request1 handling should succeed");
            assert!(event.is_none(), "reject path must not emit transport event");
            assert!(
                !server.pending_handshakes.contains_key(&addr),
                "rejected address must not create pending handshake"
            );
            assert!(
                !server.sessions.contains_key(&addr),
                "rejected address must not create session"
            );

            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.handshake_ip_recently_connected_rejects, 1);
        });
    }

    #[test]
    fn open_connection_request2_drops_when_server_addr_policy_rejects_port() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig {
                request2_server_addr_policy: Request2ServerAddrPolicy::PortOnly,
                ..TransportConfig::default()
            };
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20312"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });
            let event = server
                .handle_offline_packet(addr, &request1, Instant::now())
                .await
                .expect("request1 handling should succeed");
            assert!(event.is_none());
            assert!(
                server.pending_handshakes.contains_key(&addr),
                "request1 should create pending handshake"
            );

            let local_addr = server.local_addr().expect("local addr should be available");
            let wrong_port = local_addr.port().saturating_add(1);
            let request2 = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
                server_addr: SocketAddr::from(([203, 0, 113, 10], wrong_port)),
                mtu: 1200,
                client_guid: 0x0123_4567_89AB_CDEF,
                cookie: None,
                client_proof: false,
                parse_path: Request2ParsePath::StrictNoCookie,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });

            let event = server
                .handle_offline_packet(addr, &request2, Instant::now())
                .await
                .expect("request2 handling should succeed");
            assert!(event.is_none(), "policy mismatch should be silent drop");
            assert!(
                server.pending_handshakes.contains_key(&addr),
                "policy mismatch must keep pending handshake for retry"
            );

            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.request2_server_addr_mismatch_drops, 1);
            assert_eq!(metrics.handshake_stage_cancel_drops, 1);
            assert_eq!(metrics.handshake_missing_req1_drops, 0);
        });
    }

    #[test]
    fn open_connection_request2_accepts_mismatch_when_policy_disabled() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig {
                request2_server_addr_policy: Request2ServerAddrPolicy::Disabled,
                ..TransportConfig::default()
            };
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20313"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });
            server
                .handle_offline_packet(addr, &request1, Instant::now())
                .await
                .expect("request1 handling should succeed");

            let local_addr = server.local_addr().expect("local addr should be available");
            let wrong_port = local_addr.port().saturating_add(1);
            let cookie = server.generate_cookie(addr);
            let request2 = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
                server_addr: SocketAddr::from(([203, 0, 113, 10], wrong_port)),
                mtu: 1200,
                client_guid: 0x1020_3040_5060_7080,
                cookie: Some(cookie),
                client_proof: true,
                parse_path: Request2ParsePath::StrictWithCookie,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });

            let event = server
                .handle_offline_packet(addr, &request2, Instant::now())
                .await
                .expect("request2 handling should succeed");
            assert!(event.is_none(), "successful request2 should not emit event");

            assert!(
                server.pending_handshakes.contains_key(&addr),
                "accepted request2 must keep pending handshake until connected"
            );
            let session = server
                .sessions
                .get(&addr)
                .expect("accepted request2 must keep session");
            assert_eq!(session.state(), SessionState::Reply2Sent);

            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.request2_server_addr_mismatch_drops, 0);
        });
    }

    #[test]
    fn open_connection_request2_retry_resends_reply2_without_missing_req1_penalty() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        rt.block_on(async {
            let mut config = TransportConfig::default();
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind should succeed");
            config.bind_addr = socket.local_addr().expect("local addr should be available");
            let mut server =
                TransportServer::with_socket(config, socket).expect("server should build");
            let addr = "127.0.0.1:20314"
                .parse::<SocketAddr>()
                .expect("valid socket addr");

            let request1 = OfflinePacket::OpenConnectionRequest1(OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: 1200,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });
            server
                .handle_offline_packet(addr, &request1, Instant::now())
                .await
                .expect("request1 handling should succeed");

            let cookie = server.generate_cookie(addr);
            let request2 = OfflinePacket::OpenConnectionRequest2(OpenConnectionRequest2 {
                server_addr: server.local_addr().expect("local addr should be available"),
                mtu: 1200,
                client_guid: 0x1111_2222_3333_4444,
                cookie: Some(cookie),
                client_proof: true,
                parse_path: Request2ParsePath::StrictWithCookie,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            });

            let first = server
                .handle_offline_packet(addr, &request2, Instant::now())
                .await
                .expect("first request2 should succeed");
            assert!(first.is_none());

            let second = server
                .handle_offline_packet(addr, &request2, Instant::now() + Duration::from_millis(10))
                .await
                .expect("retry request2 should succeed");
            assert!(second.is_none());

            let pending = server
                .pending_handshakes
                .get(&addr)
                .copied()
                .expect("pending handshake should remain until connected");
            assert_eq!(
                pending.stage,
                PendingHandshakeStage::AwaitingConnectionRequest
            );

            let session = server
                .sessions
                .get(&addr)
                .expect("session should exist during post-reply2 handshake stage");
            assert_eq!(session.state(), SessionState::Reply2Sent);

            let metrics = server.metrics_snapshot();
            assert_eq!(metrics.handshake_missing_req1_drops, 0);
            assert_eq!(metrics.handshake_stage_cancel_drops, 0);
        });
    }

    #[test]
    fn bind_shards_requires_reuse_port_when_count_is_greater_than_one() {
        let config = TransportConfig {
            reuse_port: false,
            ..TransportConfig::default()
        };
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        match rt.block_on(TransportServer::bind_shards(config, 2)) {
            Ok(_) => panic!("should reject shard_count > 1 without reuse_port"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
        }
    }

    #[test]
    fn bind_shard_plan_enables_both_families_for_split_mode() {
        let config = TransportConfig {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 19132)),
            split_ipv4_ipv6_bind: true,
            ..TransportConfig::default()
        };
        let plan = TransportServer::build_shard_bind_plan(&config, 1);
        let expected_v4 = SocketAddr::from(([0, 0, 0, 0], 19132));
        let expected_v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 19132, 0, 0));
        assert_eq!(plan.len(), 2);
        assert!(plan.contains(&expected_v4));
        assert!(plan.contains(&expected_v6));
    }

    #[test]
    fn bind_shard_plan_round_robins_families_when_split_mode_exceeds_two_workers() {
        let config = TransportConfig {
            bind_addr: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 19132)),
            split_ipv4_ipv6_bind: true,
            ..TransportConfig::default()
        };
        let plan = TransportServer::build_shard_bind_plan(&config, 3);
        let expected_v4 = SocketAddr::from(([0, 0, 0, 0], 19132));
        let expected_v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 19132, 0, 0));
        assert_eq!(plan, vec![expected_v4, expected_v6, expected_v4]);
        assert!(TransportServer::has_duplicate_bind_targets(&plan));
    }

    #[test]
    fn bind_shards_split_mode_rejects_duplicate_workers_without_reuse_port() {
        let config = TransportConfig {
            reuse_port: false,
            split_ipv4_ipv6_bind: true,
            ..TransportConfig::default()
        };
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        match rt.block_on(TransportServer::bind_shards(config, 3)) {
            Ok(_) => panic!("should reject duplicate split bind targets without reuse_port"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
        }
    }

    #[test]
    fn bind_rejects_split_mode_in_single_socket_path() {
        let config = TransportConfig {
            split_ipv4_ipv6_bind: true,
            ..TransportConfig::default()
        };
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        match rt.block_on(TransportServer::bind(config)) {
            Ok(_) => panic!("single-socket bind must reject split mode"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput),
        }
    }

    #[test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn bind_accepts_socket_tuning_profile() {
        let config = TransportConfig {
            socket_tuning: TransportSocketTuning {
                recv_buffer_size: Some(512 * 1024),
                send_buffer_size: Some(512 * 1024),
                ipv4_ttl: Some(64),
                ipv4_tos: Some(0x10),
                ipv6_unicast_hops: None,
                disable_ip_fragmentation: false,
            },
            ..TransportConfig::default()
        };
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        let server = rt
            .block_on(TransportServer::bind(config))
            .expect("bind with valid socket tuning should succeed");
        let _addr = server.local_addr().expect("server must have local addr");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn bind_accepts_disable_ip_fragmentation_on_linux_like_targets() {
        let config = TransportConfig {
            socket_tuning: TransportSocketTuning {
                disable_ip_fragmentation: true,
                ..TransportSocketTuning::default()
            },
            ..TransportConfig::default()
        };
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        let server = rt
            .block_on(TransportServer::bind(config))
            .expect("disable_ip_fragmentation should be supported");
        let _addr = server.local_addr().expect("server must have local addr");
    }

    #[test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn platform_reports_sharded_reuse_port_support() {
        assert!(TransportServer::supports_reuse_port_sharded_bind());
    }

    #[test]
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    fn bind_shards_uses_shared_socket_fallback_on_unsupported_platform() {
        assert!(!TransportServer::supports_reuse_port_sharded_bind());
        let config = TransportConfig {
            reuse_port: true,
            ..TransportConfig::default()
        };
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime must build");
        let workers = rt
            .block_on(TransportServer::bind_shards(config, 2))
            .expect("fallback bind should succeed");
        assert_eq!(workers.len(), 2);
        let first_addr = workers[0].local_addr().expect("worker local addr");
        for worker in workers.iter().skip(1) {
            let addr = worker.local_addr().expect("worker local addr");
            assert_eq!(addr, first_addr);
        }
    }
}
