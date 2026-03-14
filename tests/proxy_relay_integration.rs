use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use raknet_rust::client::{ClientSendOptions, RaknetClient, RaknetClientError, RaknetClientEvent};
use raknet_rust::low_level::protocol::reliability::Reliability;
use raknet_rust::low_level::session::RakPriority;
use raknet_rust::low_level::transport::EventOverflowPolicy;
use raknet_rust::proxy::{
    PassthroughRelayPolicy, RaknetRelayProxy, RaknetRelayProxyEvent, RelayContract,
    RelayContractConfig, RelayDecision, RelayDirection, RelayDropReason, RelayOverflowPolicy,
    RelayPolicy, RelayRuntimeConfig, RelaySessionCloseReason, UpstreamConnector,
    UpstreamConnectorConfig,
};
use raknet_rust::server::{PeerId, RaknetServer, RaknetServerEvent, SendOptions};
use tokio::time::timeout;

fn allocate_loopback_bind_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("ephemeral loopback bind must succeed");
    socket
        .local_addr()
        .expect("ephemeral local addr must be available")
}

async fn start_server(bind_addr: SocketAddr) -> io::Result<RaknetServer> {
    let mut builder = RaknetServer::builder().bind_addr(bind_addr).shard_count(1);

    {
        let transport = builder.transport_config_mut();
        transport.per_ip_packet_limit = 100_000;
        transport.global_packet_limit = 1_000_000;
    }

    {
        let runtime = builder.runtime_config_mut();
        runtime.event_queue_capacity = 4096;
        runtime.metrics_emit_interval = Duration::from_secs(3600);
        runtime.outbound_tick_interval = Duration::from_millis(5);
        runtime.event_overflow_policy = EventOverflowPolicy::ShedNonCritical;
    }

    builder.start().await
}

async fn wait_for_client_connected(client: &mut RaknetClient) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("timed out waiting for client event")
            .expect("client event stream unexpectedly ended");

        if matches!(event, RaknetClientEvent::Connected { .. }) {
            return;
        }
    }

    panic!("timed out waiting for client connected event");
}

async fn wait_for_proxy_session_started<P>(
    proxy: &mut RaknetRelayProxy<P>,
) -> (PeerId, SocketAddr, SocketAddr)
where
    P: RelayPolicy,
{
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        let event = timeout(Duration::from_secs(1), proxy.next_event())
            .await
            .expect("timed out waiting for proxy session started event")
            .expect("proxy event stream unexpectedly ended");

        if let RaknetRelayProxyEvent::SessionStarted {
            peer_id,
            downstream_addr,
            upstream_addr,
        } = event
        {
            return (peer_id, downstream_addr, upstream_addr);
        }
    }

    panic!("timed out waiting for proxy SessionStarted event");
}

async fn collect_session_closed_reasons<P>(
    proxy: &mut RaknetRelayProxy<P>,
    peer_id: PeerId,
    budget: Duration,
) -> Vec<RelaySessionCloseReason>
where
    P: RelayPolicy,
{
    let deadline = Instant::now() + budget;
    let mut reasons = Vec::new();
    while Instant::now() < deadline {
        if let Ok(Some(RaknetRelayProxyEvent::SessionClosed {
            peer_id: closed_peer_id,
            reason,
        })) = timeout(Duration::from_millis(30), proxy.next_event()).await
            && closed_peer_id == peer_id
        {
            reasons.push(reason);
        }
    }

    reasons
}

async fn wait_for_upstream_packet<P>(
    proxy: &mut RaknetRelayProxy<P>,
    upstream: &mut RaknetServer,
) -> (u64, Bytes)
where
    P: RelayPolicy,
{
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if let Ok(Some(_proxy_event)) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
        }

        if let Ok(Some(server_event)) =
            timeout(Duration::from_millis(20), upstream.next_event()).await
        {
            match server_event {
                RaknetServerEvent::Packet {
                    peer_id, payload, ..
                } => return (peer_id.as_u64(), payload),
                RaknetServerEvent::Metrics { .. } => {}
                _ => {}
            }
        }
    }

    panic!("timed out waiting for upstream packet");
}

async fn wait_for_upstream_packet_with_metadata<P>(
    proxy: &mut RaknetRelayProxy<P>,
    upstream: &mut RaknetServer,
) -> (u64, Bytes, Reliability, Option<u8>)
where
    P: RelayPolicy,
{
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if let Ok(Some(_proxy_event)) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
        }

        if let Ok(Some(server_event)) =
            timeout(Duration::from_millis(20), upstream.next_event()).await
        {
            match server_event {
                RaknetServerEvent::Packet {
                    peer_id,
                    payload,
                    reliability,
                    ordering_channel,
                    ..
                } => return (peer_id.as_u64(), payload, reliability, ordering_channel),
                RaknetServerEvent::Metrics { .. } => {}
                _ => {}
            }
        }
    }

    panic!("timed out waiting for upstream packet");
}

async fn wait_for_client_payload_through_proxy<P>(
    proxy: &mut RaknetRelayProxy<P>,
    client: &mut RaknetClient,
) -> Bytes
where
    P: RelayPolicy,
{
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if let Ok(Some(_proxy_event)) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
        }

        if let Ok(Some(client_event)) =
            timeout(Duration::from_millis(20), client.next_event()).await
        {
            match client_event {
                RaknetClientEvent::Packet { payload, .. } => return payload,
                RaknetClientEvent::Disconnected { reason } => {
                    panic!("client disconnected unexpectedly while waiting for payload: {reason:?}")
                }
                RaknetClientEvent::Connected { .. }
                | RaknetClientEvent::ReceiptAcked { .. }
                | RaknetClientEvent::DecodeError { .. } => {}
            }
        }
    }

    panic!("timed out waiting for client payload through proxy");
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_forwards_bidirectionally_between_downstream_and_upstream() -> io::Result<()> {
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let mut upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), PassthroughRelayPolicy);
    let mut proxy = RaknetRelayProxy::new(
        downstream,
        connector,
        contract,
        RelayRuntimeConfig::default(),
    );

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let _ = wait_for_proxy_session_started(&mut proxy).await;

    let down_payload = Bytes::from_static(b"\xFEproxy-d2u");
    client.send(down_payload.clone()).await?;

    let (upstream_peer_id_raw, got_upstream_payload) =
        wait_for_upstream_packet(&mut proxy, &mut upstream).await;
    assert_eq!(got_upstream_payload, down_payload);

    let upstream_peer_id = raknet_rust::server::PeerId::from_u64(upstream_peer_id_raw);
    let up_payload = Bytes::from_static(b"\xFEproxy-u2d");
    upstream.send(upstream_peer_id, up_payload.clone()).await?;

    let got_client_payload = wait_for_client_payload_through_proxy(&mut proxy, &mut client).await;
    assert_eq!(got_client_payload, up_payload);

    client.disconnect(None).await?;
    proxy.shutdown().await?;
    upstream.shutdown().await
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_preserves_packet_reliability_and_channel_across_both_directions() -> io::Result<()> {
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let mut upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), PassthroughRelayPolicy);
    let mut proxy = RaknetRelayProxy::new(
        downstream,
        connector,
        contract,
        RelayRuntimeConfig::default(),
    );

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let _ = wait_for_proxy_session_started(&mut proxy).await;

    let down_payload = Bytes::from_static(b"\xFEproxy-meta-d2u");
    let down_options = ClientSendOptions {
        reliability: Reliability::ReliableOrdered,
        channel: 5,
        priority: RakPriority::High,
    };
    client
        .send_with_options(down_payload.clone(), down_options)
        .await?;

    let (upstream_peer_id_raw, got_upstream_payload, got_reliability, got_channel) =
        wait_for_upstream_packet_with_metadata(&mut proxy, &mut upstream).await;
    assert_eq!(got_upstream_payload, down_payload);
    assert_eq!(got_reliability, down_options.reliability);
    assert_eq!(got_channel, Some(down_options.channel));

    let upstream_peer_id = PeerId::from_u64(upstream_peer_id_raw);
    let up_payload = Bytes::from_static(b"\xFEproxy-meta-u2d");
    let up_options = SendOptions {
        reliability: Reliability::ReliableOrdered,
        channel: 7,
        priority: RakPriority::High,
    };
    upstream
        .send_with_options(upstream_peer_id, up_payload.clone(), up_options)
        .await?;

    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if let Ok(Some(_proxy_event)) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
        }

        if let Ok(Some(client_event)) =
            timeout(Duration::from_millis(20), client.next_event()).await
        {
            match client_event {
                RaknetClientEvent::Packet {
                    payload,
                    reliability,
                    ordering_channel,
                    ..
                } => {
                    assert_eq!(payload, up_payload);
                    assert_eq!(reliability, up_options.reliability);
                    assert_eq!(ordering_channel, Some(up_options.channel));
                    client.disconnect(None).await?;
                    proxy.shutdown().await?;
                    return upstream.shutdown().await;
                }
                RaknetClientEvent::Disconnected { reason } => {
                    panic!(
                        "client disconnected unexpectedly while waiting for metadata packet: {reason:?}"
                    )
                }
                RaknetClientEvent::Connected { .. }
                | RaknetClientEvent::ReceiptAcked { .. }
                | RaknetClientEvent::DecodeError { .. } => {}
            }
        }
    }

    panic!("timed out waiting for client metadata packet")
}

#[derive(Debug, Clone, Copy)]
struct DropDownstreamPolicy;

impl RelayPolicy for DropDownstreamPolicy {
    fn decide(&self, direction: RelayDirection, payload: &Bytes) -> RelayDecision {
        if matches!(direction, RelayDirection::DownstreamToUpstream) {
            RelayDecision::Drop
        } else {
            RelayDecision::Forward(payload.clone())
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_policy_can_drop_downstream_payloads_before_upstream() -> io::Result<()> {
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let mut upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), DropDownstreamPolicy);
    let mut proxy = RaknetRelayProxy::new(
        downstream,
        connector,
        contract,
        RelayRuntimeConfig::default(),
    );

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let _ = wait_for_proxy_session_started(&mut proxy).await;

    client.send(Bytes::from_static(b"\xFEdropped")).await?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_upstream_packet = false;
    let mut saw_drop_event = false;

    while Instant::now() < deadline {
        if let Ok(Some(RaknetRelayProxyEvent::Dropped {
            direction: RelayDirection::DownstreamToUpstream,
            ..
        })) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
            saw_drop_event = true;
        }

        if let Ok(Some(server_event)) =
            timeout(Duration::from_millis(20), upstream.next_event()).await
        {
            match server_event {
                RaknetServerEvent::Packet { .. } => {
                    saw_upstream_packet = true;
                    break;
                }
                RaknetServerEvent::Metrics { .. } => {}
                _ => {}
            }
        }
    }

    assert!(
        !saw_upstream_packet,
        "upstream must not receive dropped payload"
    );
    assert!(
        saw_drop_event,
        "proxy should emit dropped event for policy drop"
    );

    client.disconnect(None).await?;
    proxy.shutdown().await?;
    upstream.shutdown().await
}

#[derive(Debug, Clone, Copy)]
struct DisconnectDownstreamPolicy;

impl RelayPolicy for DisconnectDownstreamPolicy {
    fn decide(&self, direction: RelayDirection, payload: &Bytes) -> RelayDecision {
        if matches!(direction, RelayDirection::DownstreamToUpstream) {
            RelayDecision::Disconnect {
                reason: "blocked_by_policy",
            }
        } else {
            RelayDecision::Forward(payload.clone())
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_policy_disconnect_closes_downstream_session() -> io::Result<()> {
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), DisconnectDownstreamPolicy);
    let mut proxy = RaknetRelayProxy::new(
        downstream,
        connector,
        contract,
        RelayRuntimeConfig::default(),
    );

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let (session_peer_id, _, _) = wait_for_proxy_session_started(&mut proxy).await;

    let send_result = client.send(Bytes::from_static(b"\xFEdisconnect-me")).await;
    if let Err(err) = send_result
        && !matches!(err, RaknetClientError::Closed { .. })
    {
        let is_windows_forced_close = match &err {
            RaknetClientError::Io { message } => {
                let lower = message.to_ascii_lowercase();
                lower.contains("forcibly closed")
                    || lower.contains("connection reset")
                    || lower.contains("10054")
            }
            _ => false,
        };
        if !is_windows_forced_close {
            return Err(io::Error::other(err.to_string()));
        }
    }

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut saw_policy_disconnect = false;
    let mut saw_client_disconnect = false;

    while Instant::now() < deadline {
        if let Ok(Some(RaknetRelayProxyEvent::SessionClosed {
            reason:
                RelaySessionCloseReason::PolicyDisconnect {
                    direction: RelayDirection::DownstreamToUpstream,
                    reason: "blocked_by_policy",
                },
            ..
        })) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
            saw_policy_disconnect = true;
        }

        if let Ok(Some(RaknetClientEvent::Disconnected { .. })) =
            timeout(Duration::from_millis(20), client.next_event()).await
        {
            saw_client_disconnect = true;
            break;
        }
    }

    assert!(
        saw_policy_disconnect,
        "proxy should close session with policy disconnect reason"
    );
    assert_eq!(
        proxy.session_count(),
        0,
        "proxy session must be torn down after policy disconnect"
    );

    if !saw_client_disconnect {
        let _ = client.disconnect(None).await;
    }

    let close_reasons =
        collect_session_closed_reasons(&mut proxy, session_peer_id, Duration::from_millis(300))
            .await;
    assert!(
        close_reasons.is_empty(),
        "session should not emit duplicate close after initial policy close"
    );

    proxy.shutdown().await?;
    upstream.shutdown().await
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_simultaneous_upstream_and_downstream_disconnect_emits_single_close() -> io::Result<()>
{
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let mut upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), PassthroughRelayPolicy);
    let mut proxy = RaknetRelayProxy::new(
        downstream,
        connector,
        contract,
        RelayRuntimeConfig::default(),
    );

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let (session_peer_id, _, _) = wait_for_proxy_session_started(&mut proxy).await;

    client.send(Bytes::from_static(b"\xFErace-init")).await?;
    let (upstream_peer_raw, _) = wait_for_upstream_packet(&mut proxy, &mut upstream).await;
    let upstream_peer_id = PeerId::from_u64(upstream_peer_raw);

    let (client_disconnect_result, upstream_disconnect_result) = tokio::join!(
        client.disconnect(None),
        upstream.disconnect(upstream_peer_id)
    );
    let _ = client_disconnect_result;
    let _ = upstream_disconnect_result;

    let close_reasons =
        collect_session_closed_reasons(&mut proxy, session_peer_id, Duration::from_secs(2)).await;
    assert_eq!(
        close_reasons.len(),
        1,
        "disconnect race must emit exactly one SessionClosed for the same session"
    );
    assert_eq!(
        proxy.session_count(),
        0,
        "proxy must not leak session after disconnect race"
    );

    proxy.shutdown().await?;
    upstream.shutdown().await
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_shutdown_terminates_active_session_without_hanging() -> io::Result<()> {
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), PassthroughRelayPolicy);
    let proxy = RaknetRelayProxy::new(
        downstream,
        connector,
        contract,
        RelayRuntimeConfig::default(),
    );

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;

    let mut proxy = proxy;
    let _ = wait_for_proxy_session_started(&mut proxy).await;
    assert_eq!(
        proxy.session_count(),
        1,
        "proxy should hold one active session"
    );

    timeout(Duration::from_secs(2), proxy.shutdown())
        .await
        .expect("proxy shutdown timed out")?;
    let _ = client.disconnect(None).await;
    upstream.shutdown().await
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_budget_overflow_drop_newest_drops_packet_without_closing_session() -> io::Result<()>
{
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let mut upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), PassthroughRelayPolicy);
    let runtime = RelayRuntimeConfig {
        budget_overflow_policy: RelayOverflowPolicy::DropNewest,
        downstream_max_pending_packets: 1,
        downstream_max_pending_bytes: 1,
        session_total_max_pending_bytes: 1,
        ..RelayRuntimeConfig::default()
    };
    let mut proxy = RaknetRelayProxy::new(downstream, connector, contract, runtime);

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let _ = wait_for_proxy_session_started(&mut proxy).await;

    client.send(Bytes::from_static(b"\xFEbudget")).await?;

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_budget_drop = false;
    let mut saw_upstream_packet = false;
    while Instant::now() < deadline {
        if let Ok(Some(RaknetRelayProxyEvent::Dropped {
            direction: RelayDirection::DownstreamToUpstream,
            reason: RelayDropReason::BudgetExceeded(_),
            ..
        })) = timeout(Duration::from_millis(20), proxy.next_event()).await
        {
            saw_budget_drop = true;
        }

        if let Ok(Some(RaknetServerEvent::Packet { .. })) =
            timeout(Duration::from_millis(20), upstream.next_event()).await
        {
            saw_upstream_packet = true;
            break;
        }
    }

    assert!(saw_budget_drop, "expected budget-based drop event");
    assert!(
        !saw_upstream_packet,
        "budget dropped packet must not reach upstream"
    );
    assert_eq!(
        proxy.session_count(),
        1,
        "drop policy should keep session alive"
    );

    let _ = client.disconnect(None).await;
    proxy.shutdown().await?;
    upstream.shutdown().await
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_budget_overflow_disconnect_closes_session() -> io::Result<()> {
    let upstream_addr = allocate_loopback_bind_addr();
    let downstream_addr = allocate_loopback_bind_addr();

    let upstream = start_server(upstream_addr).await?;
    let downstream = start_server(downstream_addr).await?;

    let connector = UpstreamConnector::new(upstream_addr, UpstreamConnectorConfig::default());
    let contract = RelayContract::new(RelayContractConfig::default(), PassthroughRelayPolicy);
    let runtime = RelayRuntimeConfig {
        budget_overflow_policy: RelayOverflowPolicy::DisconnectSession,
        downstream_max_pending_packets: 1,
        downstream_max_pending_bytes: 1,
        session_total_max_pending_bytes: 1,
        ..RelayRuntimeConfig::default()
    };
    let mut proxy = RaknetRelayProxy::new(downstream, connector, contract, runtime);

    let mut client = RaknetClient::connect(downstream_addr).await?;
    wait_for_client_connected(&mut client).await;
    let (session_peer_id, _, _) = wait_for_proxy_session_started(&mut proxy).await;

    client.send(Bytes::from_static(b"\xFEbudget")).await?;

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_budget_close = false;
    while Instant::now() < deadline {
        if let Ok(Some(RaknetRelayProxyEvent::SessionClosed {
            peer_id,
            reason:
                RelaySessionCloseReason::BudgetExceeded {
                    direction: RelayDirection::DownstreamToUpstream,
                    ..
                },
        })) = timeout(Duration::from_millis(20), proxy.next_event()).await
            && peer_id == session_peer_id
        {
            saw_budget_close = true;
            break;
        }
    }

    assert!(saw_budget_close, "expected budget-based session close");
    assert_eq!(
        proxy.session_count(),
        0,
        "disconnect budget policy must close session"
    );

    let _ = client.disconnect(None).await;
    proxy.shutdown().await?;
    upstream.shutdown().await
}
