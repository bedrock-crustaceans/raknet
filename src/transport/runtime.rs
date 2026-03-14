use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::error::ConfigValidationError;
use crate::protocol::reliability::Reliability;
use crate::session::RakPriority;

use super::config::TransportConfig;
use super::server::{TransportEvent, TransportMetricsSnapshot, TransportServer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOverflowPolicy {
    BlockProducer,
    ShedNonCritical,
}

#[derive(Debug, Clone)]
pub struct ShardedRuntimeConfig {
    pub shard_count: usize,
    pub outbound_tick_interval: Duration,
    pub metrics_emit_interval: Duration,
    pub event_queue_capacity: usize,
    pub command_queue_capacity: usize,
    pub event_overflow_policy: EventOverflowPolicy,
    pub max_new_datagrams_per_session: usize,
    pub max_new_bytes_per_session: usize,
    pub max_resend_datagrams_per_session: usize,
    pub max_resend_bytes_per_session: usize,
}

impl Default for ShardedRuntimeConfig {
    fn default() -> Self {
        Self {
            shard_count: std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1)
                .max(1),
            outbound_tick_interval: Duration::from_millis(10),
            metrics_emit_interval: Duration::from_millis(1000),
            event_queue_capacity: 4096,
            command_queue_capacity: 4096,
            event_overflow_policy: EventOverflowPolicy::ShedNonCritical,
            max_new_datagrams_per_session: 8,
            max_new_bytes_per_session: 64 * 1024,
            max_resend_datagrams_per_session: 8,
            max_resend_bytes_per_session: 64 * 1024,
        }
    }
}

impl ShardedRuntimeConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.shard_count == 0 {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "shard_count",
                "must be >= 1",
            ));
        }
        if self.outbound_tick_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "outbound_tick_interval",
                "must be > 0",
            ));
        }
        if self.metrics_emit_interval.is_zero() {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "metrics_emit_interval",
                "must be > 0",
            ));
        }
        if self.event_queue_capacity == 0 {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "event_queue_capacity",
                "must be >= 1",
            ));
        }
        if self.command_queue_capacity == 0 {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "command_queue_capacity",
                "must be >= 1",
            ));
        }
        if self.max_new_datagrams_per_session == 0 {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "max_new_datagrams_per_session",
                "must be >= 1",
            ));
        }
        if self.max_new_bytes_per_session < crate::protocol::constants::MINIMUM_MTU_SIZE as usize {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "max_new_bytes_per_session",
                format!(
                    "must be >= {}, got {}",
                    crate::protocol::constants::MINIMUM_MTU_SIZE,
                    self.max_new_bytes_per_session
                ),
            ));
        }
        if self.max_resend_datagrams_per_session == 0 {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "max_resend_datagrams_per_session",
                "must be >= 1",
            ));
        }
        if self.max_resend_bytes_per_session < crate::protocol::constants::MINIMUM_MTU_SIZE as usize
        {
            return Err(ConfigValidationError::new(
                "ShardedRuntimeConfig",
                "max_resend_bytes_per_session",
                format!(
                    "must be >= {}, got {}",
                    crate::protocol::constants::MINIMUM_MTU_SIZE,
                    self.max_resend_bytes_per_session
                ),
            ));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ShardedRuntimeEvent {
    Transport {
        shard_id: usize,
        event: TransportEvent,
    },
    Metrics {
        shard_id: usize,
        snapshot: Box<TransportMetricsSnapshot>,
        dropped_non_critical_events: u64,
    },
    WorkerError {
        shard_id: usize,
        message: String,
    },
    WorkerStopped {
        shard_id: usize,
    },
}

#[derive(Debug, Clone)]
pub enum ShardedRuntimeCommand {
    SendPayload {
        addr: SocketAddr,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
        receipt_id: Option<u64>,
    },
    DisconnectPeer {
        addr: SocketAddr,
    },
}

#[derive(Debug, Clone)]
pub struct ShardedSendPayload {
    pub addr: SocketAddr,
    pub payload: Bytes,
    pub reliability: Reliability,
    pub channel: u8,
    pub priority: RakPriority,
}

pub struct ShardedRuntimeHandle {
    pub event_rx: mpsc::Receiver<ShardedRuntimeEvent>,
    shutdown_tx: broadcast::Sender<()>,
    command_txs: Vec<mpsc::Sender<ShardedRuntimeCommand>>,
    handles: Vec<JoinHandle<io::Result<()>>>,
}

impl ShardedRuntimeHandle {
    pub fn shard_count(&self) -> usize {
        self.command_txs.len()
    }

    pub async fn send_payload_to_shard(
        &self,
        shard_id: usize,
        payload: ShardedSendPayload,
    ) -> io::Result<()> {
        self.send_command_to_shard(
            shard_id,
            ShardedRuntimeCommand::SendPayload {
                addr: payload.addr,
                payload: payload.payload,
                reliability: payload.reliability,
                channel: payload.channel,
                priority: payload.priority,
                receipt_id: None,
            },
        )
        .await
    }

    pub async fn send_payload_to_shard_with_receipt(
        &self,
        shard_id: usize,
        payload: ShardedSendPayload,
        receipt_id: u64,
    ) -> io::Result<()> {
        self.send_command_to_shard(
            shard_id,
            ShardedRuntimeCommand::SendPayload {
                addr: payload.addr,
                payload: payload.payload,
                reliability: payload.reliability,
                channel: payload.channel,
                priority: payload.priority,
                receipt_id: Some(receipt_id),
            },
        )
        .await
    }

    pub async fn send_payload_any_shard(
        &self,
        addr: SocketAddr,
        payload: Bytes,
        reliability: Reliability,
        channel: u8,
        priority: RakPriority,
    ) -> io::Result<()> {
        for tx in &self.command_txs {
            tx.send(ShardedRuntimeCommand::SendPayload {
                addr,
                payload: payload.clone(),
                reliability,
                channel,
                priority,
                receipt_id: None,
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "runtime command channel closed")
            })?;
        }
        Ok(())
    }

    pub async fn disconnect_peer_from_shard(
        &self,
        shard_id: usize,
        addr: SocketAddr,
    ) -> io::Result<()> {
        self.send_command_to_shard(shard_id, ShardedRuntimeCommand::DisconnectPeer { addr })
            .await
    }

    pub async fn disconnect_peer_any_shard(&self, addr: SocketAddr) -> io::Result<()> {
        for tx in &self.command_txs {
            tx.send(ShardedRuntimeCommand::DisconnectPeer { addr })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "runtime command channel closed")
                })?;
        }
        Ok(())
    }

    async fn send_command_to_shard(
        &self,
        shard_id: usize,
        command: ShardedRuntimeCommand,
    ) -> io::Result<()> {
        let tx = self.command_txs.get(shard_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid shard_id {shard_id}"),
            )
        })?;

        tx.send(command).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "runtime command channel closed")
        })
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        self.request_shutdown();

        while let Some(handle) = self.handles.pop() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(join_err) => {
                    return Err(io::Error::other(format!("worker join error: {join_err}")));
                }
            }
        }

        Ok(())
    }
}

pub async fn spawn_sharded_runtime(
    transport_config: TransportConfig,
    runtime_config: ShardedRuntimeConfig,
) -> io::Result<ShardedRuntimeHandle> {
    transport_config
        .validate()
        .map_err(invalid_config_io_error)?;
    runtime_config.validate().map_err(invalid_config_io_error)?;

    let shard_count = runtime_config.shard_count.max(1);
    let workers = TransportServer::bind_shards(transport_config, shard_count).await?;

    let (event_tx, event_rx) = mpsc::channel(runtime_config.event_queue_capacity.max(1));
    let (shutdown_tx, _) = broadcast::channel(1);

    let mut handles = Vec::with_capacity(workers.len());
    let mut command_txs = Vec::with_capacity(workers.len());
    for (shard_id, server) in workers.into_iter().enumerate() {
        let tx = event_tx.clone();
        let cfg = runtime_config.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        let (command_tx, command_rx) = mpsc::channel(runtime_config.command_queue_capacity.max(1));
        command_txs.push(command_tx);

        handles.push(tokio::spawn(async move {
            run_worker_loop(shard_id, server, cfg, tx, command_rx, shutdown_rx).await
        }));
    }

    Ok(ShardedRuntimeHandle {
        event_rx,
        shutdown_tx,
        command_txs,
        handles,
    })
}

async fn run_worker_loop(
    shard_id: usize,
    mut server: TransportServer,
    cfg: ShardedRuntimeConfig,
    event_tx: mpsc::Sender<ShardedRuntimeEvent>,
    mut command_rx: mpsc::Receiver<ShardedRuntimeCommand>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> io::Result<()> {
    let mut outbound_tick = time::interval(cfg.outbound_tick_interval);
    outbound_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut metrics_tick = time::interval(cfg.metrics_emit_interval);
    metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut dropped_non_critical_events = 0u64;
    let initial_dropped_snapshot = dropped_non_critical_events;
    send_non_critical_event(
        &event_tx,
        cfg.event_overflow_policy,
        &mut dropped_non_critical_events,
        ShardedRuntimeEvent::Metrics {
            shard_id,
            snapshot: Box::new(server.metrics_snapshot()),
            dropped_non_critical_events: initial_dropped_snapshot,
        },
    )
    .await?;

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                send_critical_event(&event_tx, ShardedRuntimeEvent::WorkerStopped { shard_id }).await?;
                return Ok(());
            }

            command = command_rx.recv() => {
                if let Some(command) = command {
                    apply_command(&mut server, command);
                }
            }

            _ = outbound_tick.tick() => {
                if let Err(e) = server.tick_outbound(
                    cfg.max_new_datagrams_per_session,
                    cfg.max_new_bytes_per_session,
                    cfg.max_resend_datagrams_per_session,
                    cfg.max_resend_bytes_per_session,
                ).await {
                    let _ = send_critical_event(&event_tx, ShardedRuntimeEvent::WorkerError {
                        shard_id,
                        message: format!("outbound tick failed: {e}"),
                    }).await;
                    return Err(e);
                }
            }

            _ = metrics_tick.tick() => {
                let dropped_snapshot = dropped_non_critical_events;
                send_non_critical_event(
                    &event_tx,
                    cfg.event_overflow_policy,
                    &mut dropped_non_critical_events,
                    ShardedRuntimeEvent::Metrics {
                        shard_id,
                        snapshot: Box::new(server.metrics_snapshot()),
                        dropped_non_critical_events: dropped_snapshot,
                    },
                ).await?;
            }

            recv_result = server.recv_and_process() => {
                match recv_result {
                    Ok(event) => {
                        send_non_critical_event(
                            &event_tx,
                            cfg.event_overflow_policy,
                            &mut dropped_non_critical_events,
                            ShardedRuntimeEvent::Transport {
                                shard_id,
                                event,
                            },
                        ).await?;
                    }
                    Err(e) => {
                        if is_recoverable_udp_recv_error(&e) {
                            continue;
                        }
                        let _ = send_critical_event(&event_tx, ShardedRuntimeEvent::WorkerError {
                            shard_id,
                            message: format!("recv loop failed: {e}"),
                        }).await;
                        return Err(e);
                    }
                }
            }
        }
    }
}

fn is_recoverable_udp_recv_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

fn apply_command(server: &mut TransportServer, command: ShardedRuntimeCommand) {
    match command {
        ShardedRuntimeCommand::SendPayload {
            addr,
            payload,
            reliability,
            channel,
            priority,
            receipt_id,
        } => {
            let _ = if let Some(receipt_id) = receipt_id {
                server.queue_payload_with_receipt(
                    addr,
                    payload,
                    reliability,
                    channel,
                    priority,
                    receipt_id,
                )
            } else {
                server.queue_payload(addr, payload, reliability, channel, priority)
            };
        }
        ShardedRuntimeCommand::DisconnectPeer { addr } => {
            let _ = server.disconnect_peer(addr);
        }
    }
}

async fn send_non_critical_event(
    event_tx: &mpsc::Sender<ShardedRuntimeEvent>,
    overflow_policy: EventOverflowPolicy,
    dropped_non_critical_events: &mut u64,
    event: ShardedRuntimeEvent,
) -> io::Result<()> {
    match overflow_policy {
        EventOverflowPolicy::BlockProducer => event_tx
            .send(event)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "runtime event channel closed")),
        EventOverflowPolicy::ShedNonCritical => match event_tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                *dropped_non_critical_events = dropped_non_critical_events.saturating_add(1);
                Ok(())
            }
            Err(TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "runtime event channel closed",
            )),
        },
    }
}

async fn send_critical_event(
    event_tx: &mpsc::Sender<ShardedRuntimeEvent>,
    event: ShardedRuntimeEvent,
) -> io::Result<()> {
    event_tx
        .send(event)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "runtime event channel closed"))
}

fn invalid_config_io_error(error: ConfigValidationError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        EventOverflowPolicy, ShardedRuntimeConfig, ShardedRuntimeEvent, send_non_critical_event,
    };
    use crate::transport::server::TransportMetricsSnapshot;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn metrics_event(shard_id: usize) -> ShardedRuntimeEvent {
        ShardedRuntimeEvent::Metrics {
            shard_id,
            snapshot: Box::new(TransportMetricsSnapshot::default()),
            dropped_non_critical_events: 0,
        }
    }

    #[tokio::test]
    async fn shed_policy_drops_non_critical_when_channel_is_full() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(metrics_event(1))
            .await
            .expect("initial send should succeed");

        let mut dropped = 0u64;
        send_non_critical_event(
            &tx,
            EventOverflowPolicy::ShedNonCritical,
            &mut dropped,
            metrics_event(2),
        )
        .await
        .expect("shed policy should not fail on full queue");

        assert_eq!(dropped, 1);
        let first = rx.recv().await.expect("first event should be present");
        assert!(matches!(
            first,
            ShardedRuntimeEvent::Metrics { shard_id: 1, .. }
        ));
        assert!(rx.try_recv().is_err(), "second event should be shed");
    }

    #[tokio::test]
    async fn block_policy_enqueues_event_normally() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut dropped = 0u64;
        send_non_critical_event(
            &tx,
            EventOverflowPolicy::BlockProducer,
            &mut dropped,
            metrics_event(5),
        )
        .await
        .expect("block policy send should succeed");

        assert_eq!(dropped, 0);
        let event = rx.recv().await.expect("event should be available");
        assert!(matches!(
            event,
            ShardedRuntimeEvent::Metrics { shard_id: 5, .. }
        ));
    }

    #[test]
    fn runtime_config_validate_rejects_zero_shards() {
        let cfg = ShardedRuntimeConfig {
            shard_count: 0,
            ..ShardedRuntimeConfig::default()
        };
        let err = cfg.validate().expect_err("shard_count=0 must be rejected");
        assert_eq!(err.config, "ShardedRuntimeConfig");
        assert_eq!(err.field, "shard_count");
    }

    #[test]
    fn runtime_config_validate_rejects_zero_tick_interval() {
        let cfg = ShardedRuntimeConfig {
            outbound_tick_interval: Duration::ZERO,
            ..ShardedRuntimeConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("outbound_tick_interval=0 must be rejected");
        assert_eq!(err.config, "ShardedRuntimeConfig");
        assert_eq!(err.field, "outbound_tick_interval");
    }
}
