use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use raknet_rs::client::{
    ClientDisconnectReason, ClientSendOptions, OfflineRejectionReason, RaknetClient,
    RaknetClientConfig, RaknetClientError, RaknetClientEvent, ReconnectPolicy,
};
use raknet_rs::low_level::protocol::connected::{
    ConnectedControlPacket, DisconnectionNotification,
};
use raknet_rs::low_level::transport::EventOverflowPolicy;
use raknet_rs::server::{PeerId, RaknetServer, RaknetServerEvent};
use tokio::time::timeout;

fn allocate_loopback_bind_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("Ephemeral loopback bind must succeed");
    socket
        .local_addr()
        .expect("Ephemeral local addr must be available")
}

fn encode_control(packet: ConnectedControlPacket) -> Bytes {
    let mut out = BytesMut::new();
    packet
        .encode(&mut out)
        .expect("Control packet encoding should succeed");
    out.freeze()
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
        runtime.event_queue_capacity = 2048;
        runtime.metrics_emit_interval = Duration::from_secs(3600);
        runtime.outbound_tick_interval = Duration::from_millis(5);
        runtime.event_overflow_policy = EventOverflowPolicy::ShedNonCritical;
    }

    builder.start().await
}

async fn start_server_with_protocols(
    bind_addr: SocketAddr,
    supported_protocols: Vec<u8>,
) -> io::Result<RaknetServer> {
    let mut builder = RaknetServer::builder().bind_addr(bind_addr).shard_count(1);
    {
        let transport = builder.transport_config_mut();
        transport.per_ip_packet_limit = 100_000;
        transport.global_packet_limit = 1_000_000;
        transport.supported_protocols = supported_protocols;
    }
    {
        let runtime = builder.runtime_config_mut();
        runtime.event_queue_capacity = 2048;
        runtime.metrics_emit_interval = Duration::from_secs(3600);
        runtime.outbound_tick_interval = Duration::from_millis(5);
        runtime.event_overflow_policy = EventOverflowPolicy::ShedNonCritical;
    }
    builder.start().await
}

async fn next_non_metrics_server_event(server: &mut RaknetServer) -> RaknetServerEvent {
    loop {
        let event = timeout(Duration::from_secs(3), server.next_event())
            .await
            .expect("Timed out waiting for server event")
            .expect("Server event stream unexpectedly ended");
        if !matches!(
            event,
            RaknetServerEvent::Metrics { .. } | RaknetServerEvent::OfflinePacket { .. }
        ) {
            return event;
        }
    }
}

async fn wait_for_server_peer_connected(server: &mut RaknetServer) -> (PeerId, SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let RaknetServerEvent::PeerConnected {
            peer_id,
            addr,
            client_guid,
            shard_id,
        } = next_non_metrics_server_event(server).await
        {
            assert_eq!(shard_id, 0, "Single-shard server must report shard 0");
            assert_ne!(client_guid, 0, "'client_guid' must be populated");
            return (peer_id, addr);
        }
    }

    panic!("timed out waiting for PeerConnected");
}

async fn wait_for_client_packet(client: &mut RaknetClient) -> Bytes {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("Timed out waiting for client event")
            .expect("Client event stream unexpectedly ended");

        match event {
            RaknetClientEvent::Packet { payload, .. } => return payload,
            RaknetClientEvent::DecodeError { error } => {
                panic!("Unexpected client decode error: {error}")
            }
            RaknetClientEvent::Disconnected { reason } => {
                panic!("Client disconnected unexpectedly: {reason:?}")
            }
            RaknetClientEvent::Connected { .. } | RaknetClientEvent::ReceiptAcked { .. } => {}
        }
    }

    panic!("Timed out waiting for client packet");
}

#[tokio::test(flavor = "current_thread")]
async fn client_connects_and_exchanges_packets_with_server() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(bind_addr).await?;
    let mut client = RaknetClient::connect(bind_addr).await?;

    match timeout(Duration::from_secs(3), client.next_event())
        .await
        .expect("Timed out waiting for connected event")
        .expect("Client event stream unexpectedly ended")
    {
        RaknetClientEvent::Connected { server_addr, mtu } => {
            assert_eq!(server_addr, bind_addr);
            assert!((576..=1400).contains(&mtu));
        }
        other => panic!("Expected connected event, got {other:?}"),
    }

    let payload = Bytes::from_static(b"\xFEclient->server");
    client.send(payload.clone()).await?;

    let (peer_id, peer_addr) = wait_for_server_peer_connected(&mut server).await;

    let packet_event = next_non_metrics_server_event(&mut server).await;
    match packet_event {
        RaknetServerEvent::Packet {
            peer_id: got_peer_id,
            addr,
            payload: got_payload,
            ..
        } => {
            assert_eq!(got_peer_id, peer_id);
            assert_eq!(addr, peer_addr);
            assert_eq!(got_payload, payload);
        }
        other => panic!("Expected packet event after connect, got {other:?}"),
    }

    let echo = Bytes::from_static(b"\xFEserver->client");
    server.send(peer_id, echo.clone()).await?;

    let client_payload = wait_for_client_packet(&mut client).await;
    assert_eq!(client_payload, echo);

    client.disconnect(None).await?;
    server.shutdown().await
}

#[tokio::test(flavor = "current_thread")]
async fn client_surfaces_remote_disconnection_notification() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(bind_addr).await?;
    let mut client = RaknetClient::connect(bind_addr).await?;

    let _ = timeout(Duration::from_secs(3), client.next_event())
        .await
        .expect("Timed out waiting for connected event")
        .expect("Client event stream unexpectedly ended");

    client.send(Bytes::from_static(b"\xFEhello")).await?;
    let (peer_id, _) = wait_for_server_peer_connected(&mut server).await;

    let disconnect_payload = encode_control(ConnectedControlPacket::DisconnectionNotification(
        DisconnectionNotification { reason: Some(7) },
    ));
    server.send(peer_id, disconnect_payload).await?;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("Timed out waiting for client disconnect event")
            .expect("Client event stream unexpectedly ended");

        match event {
            RaknetClientEvent::Disconnected { reason } => {
                assert_eq!(
                    reason,
                    ClientDisconnectReason::RemoteDisconnectionNotification {
                        reason_code: Some(7)
                    }
                );
                server.shutdown().await?;
                return Ok(());
            }
            RaknetClientEvent::Connected { .. }
            | RaknetClientEvent::Packet { .. }
            | RaknetClientEvent::ReceiptAcked { .. }
            | RaknetClientEvent::DecodeError { .. } => {}
        }
    }

    panic!("Timed out waiting for remote disconnect event");
}

#[tokio::test(flavor = "current_thread")]
async fn client_send_with_receipt_emits_receipt_acked_event() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(bind_addr).await?;
    let mut client = RaknetClient::connect(bind_addr).await?;

    let _ = timeout(Duration::from_secs(3), client.next_event())
        .await
        .expect("Timed out waiting for connected event")
        .expect("Client event stream unexpectedly ended");

    let receipt_id = 0xAA55_AA55_AA55_AA55;
    client
        .send_with_receipt(
            Bytes::from_static(b"\xFEsend-with-receipt"),
            receipt_id,
            ClientSendOptions::default(),
        )
        .await?;

    let _ = wait_for_server_peer_connected(&mut server).await;
    let _ = next_non_metrics_server_event(&mut server).await;

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("Timed out waiting for receipt ack event")
            .expect("Client event stream unexpectedly ended");

        match event {
            RaknetClientEvent::ReceiptAcked {
                receipt_id: acked_id,
            } => {
                assert_eq!(acked_id, receipt_id);
                client.disconnect(None).await?;
                server.shutdown().await?;
                return Ok(());
            }
            RaknetClientEvent::Disconnected { reason } => {
                panic!("Unexpected disconnect before receipt ack: {reason:?}");
            }
            RaknetClientEvent::Connected { .. }
            | RaknetClientEvent::Packet { .. }
            | RaknetClientEvent::DecodeError { .. } => {}
        }
    }

    panic!("Timed out waiting for receipt ack event");
}

#[tokio::test(flavor = "current_thread")]
async fn server_send_with_receipt_emits_receipt_acked_event() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(bind_addr).await?;
    let mut client = RaknetClient::connect(bind_addr).await?;

    let _ = timeout(Duration::from_secs(3), client.next_event())
        .await
        .expect("Timed out waiting for connected event")
        .expect("Client event stream unexpectedly ended");

    let (peer_id, peer_addr) = wait_for_server_peer_connected(&mut server).await;

    let payload = Bytes::from_static(b"\xFEserver-send-with-receipt");
    let receipt_id = 0x55AA_55AA_55AA_55AA;
    server
        .send_with_receipt(peer_id, payload.clone(), receipt_id)
        .await?;

    let client_payload = wait_for_client_packet(&mut client).await;
    assert_eq!(client_payload, payload);

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = timeout(
            remaining.min(Duration::from_millis(400)),
            server.next_event(),
        )
        .await;
        let Ok(Some(event)) = event else {
            continue;
        };

        match event {
            RaknetServerEvent::Metrics { .. }
            | RaknetServerEvent::Packet { .. }
            | RaknetServerEvent::OfflinePacket { .. } => {}
            RaknetServerEvent::ReceiptAcked {
                peer_id: got_peer_id,
                addr,
                receipt_id: acked_id,
            } => {
                assert_eq!(got_peer_id, peer_id);
                assert_eq!(addr, peer_addr);
                assert_eq!(acked_id, receipt_id);
                client.disconnect(None).await?;
                server.shutdown().await?;
                return Ok(());
            }
            RaknetServerEvent::PeerDisconnected { reason, .. } => {
                panic!("Unexpected server-side disconnect before receipt ack: {reason:?}");
            }
            RaknetServerEvent::PeerConnected { .. }
            | RaknetServerEvent::PeerRateLimited { .. }
            | RaknetServerEvent::SessionLimitReached { .. }
            | RaknetServerEvent::ProxyDropped { .. }
            | RaknetServerEvent::DecodeError { .. }
            | RaknetServerEvent::WorkerError { .. }
            | RaknetServerEvent::WorkerStopped { .. } => {}
        }
    }

    panic!("Timed out waiting for server-side receipt ack event");
}

#[tokio::test(flavor = "current_thread")]
async fn client_idle_timeout_closes_connection_without_inbound_activity() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let server = start_server(bind_addr).await?;

    let cfg = RaknetClientConfig {
        session_idle_timeout: Duration::from_millis(120),
        session_keepalive_interval: Duration::from_secs(3600),
        outbound_tick_interval: Duration::from_millis(10),
        ..RaknetClientConfig::default()
    };

    let mut client = RaknetClient::connect_with_config(bind_addr, cfg).await?;
    let _ = timeout(Duration::from_secs(3), client.next_event())
        .await
        .expect("Timed out waiting for connected event")
        .expect("Client event stream unexpectedly ended");

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("Timed out waiting for idle timeout event")
            .expect("Client event stream unexpectedly ended");

        if let RaknetClientEvent::Disconnected { reason } = event {
            assert_eq!(reason, ClientDisconnectReason::IdleTimeout);
            server.shutdown().await?;
            return Ok(());
        }
    }

    panic!("Timed out waiting for idle timeout disconnect");
}

#[tokio::test(flavor = "current_thread")]
async fn connect_maps_incompatible_protocol_to_explicit_error() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let server = start_server_with_protocols(bind_addr, vec![10]).await?;

    let result = RaknetClient::connect(bind_addr).await;
    let error = match result {
        Ok(_) => panic!("Connect should fail with incompatible protocol"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RaknetClientError::OfflineRejected {
            reason: OfflineRejectionReason::IncompatibleProtocolVersion {
                protocol_version: 10,
                ..
            }
        }
    ));

    server.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connect_with_retry_fast_fails_on_offline_rejection() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let server = start_server_with_protocols(bind_addr, vec![10]).await?;

    let policy = ReconnectPolicy {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(40),
        fast_fail_on_offline_rejection: true,
        ..ReconnectPolicy::default()
    };

    let start = Instant::now();
    let result =
        RaknetClient::connect_with_retry(bind_addr, RaknetClientConfig::default(), policy).await;
    let elapsed = start.elapsed();

    let error = match result {
        Ok(_) => panic!("Connect_with_retry should fail with incompatible protocol"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RaknetClientError::OfflineRejected {
            reason: OfflineRejectionReason::IncompatibleProtocolVersion { .. }
        }
    ));
    assert!(
        elapsed < Duration::from_secs(1),
        "Fast-fail should not spend retry backoff budget"
    );

    server.shutdown().await?;
    Ok(())
}
