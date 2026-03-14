use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use raknet_rust::handshake::{
    OfflinePacket, OpenConnectionRequest1, OpenConnectionRequest2, Request2ParsePath,
    UnconnectedPing,
};
use raknet_rust::low_level::protocol::connected::{
    ConnectedControlPacket, ConnectionRequest, NewIncomingConnection, SYSTEM_ADDRESS_COUNT,
};
use raknet_rust::low_level::protocol::constants::{
    DEFAULT_UNCONNECTED_MAGIC, DatagramFlags, RAKNET_PROTOCOL_VERSION,
};
use raknet_rust::low_level::protocol::datagram::{Datagram, DatagramHeader, DatagramPayload};
use raknet_rust::low_level::protocol::frame::Frame;
use raknet_rust::low_level::protocol::frame_header::FrameHeader;
use raknet_rust::low_level::protocol::reliability::Reliability;
use raknet_rust::low_level::protocol::sequence24::Sequence24;
use raknet_rust::low_level::transport::EventOverflowPolicy;
use raknet_rust::server::{PeerId, RaknetServer, RaknetServerEvent};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep, timeout};

fn allocate_loopback_bind_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("ephemeral loopback bind must succeed");
    socket
        .local_addr()
        .expect("ephemeral local addr must be available")
}

fn invalid_data_io_error<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn next_sequence(counter: &mut u32) -> Sequence24 {
    let seq = Sequence24::new(*counter);
    *counter = counter.wrapping_add(1);
    seq
}

fn is_connected_control_id(id: u8) -> bool {
    matches!(id, 0x00 | 0x03 | 0x04 | 0x09 | 0x10 | 0x13 | 0x15)
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

struct TestRaknetClient {
    socket: UdpSocket,
    server_addr: SocketAddr,
    guid: u64,
    mtu: u16,
    datagram_sequence: u32,
    reliable_index: u32,
    ordering_index: u32,
}

impl TestRaknetClient {
    async fn connect(server_addr: SocketAddr, guid: u64) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let mut client = Self {
            socket,
            server_addr,
            guid,
            mtu: 1200,
            datagram_sequence: 0,
            reliable_index: 0,
            ordering_index: 0,
        };
        client.perform_handshake().await?;
        Ok(client)
    }

    fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("client local addr should be available")
    }

    async fn perform_handshake(&mut self) -> io::Result<()> {
        self.send_offline(OfflinePacket::OpenConnectionRequest1(
            OpenConnectionRequest1 {
                protocol_version: RAKNET_PROTOCOL_VERSION,
                mtu: self.mtu,
                magic: DEFAULT_UNCONNECTED_MAGIC,
            },
        ))
        .await?;

        let reply1 = match self.recv_offline(Duration::from_secs(2)).await? {
            OfflinePacket::OpenConnectionReply1(reply) => reply,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected OpenConnectionReply1, got {other:?}"),
                ));
            }
        };

        self.send_offline(OfflinePacket::OpenConnectionRequest2(
            OpenConnectionRequest2 {
                server_addr: self.server_addr,
                mtu: reply1.mtu,
                client_guid: self.guid,
                cookie: reply1.cookie,
                client_proof: false,
                parse_path: if reply1.cookie.is_some() {
                    Request2ParsePath::StrictWithCookie
                } else {
                    Request2ParsePath::StrictNoCookie
                },
                magic: DEFAULT_UNCONNECTED_MAGIC,
            },
        ))
        .await?;

        match self.recv_offline(Duration::from_secs(2)).await? {
            OfflinePacket::OpenConnectionReply2(_) => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected OpenConnectionReply2, got {other:?}"),
                ));
            }
        }

        self.send_control(ConnectedControlPacket::ConnectionRequest(
            ConnectionRequest {
                client_guid: self.guid,
                request_time: 1,
                use_encryption: false,
            },
        ))
        .await?;

        self.wait_for_connection_request_accepted(Duration::from_secs(2))
            .await?;

        self.send_control(ConnectedControlPacket::NewIncomingConnection(
            NewIncomingConnection {
                server_addr: self.server_addr,
                internal_addrs: build_internal_addrs(self.server_addr),
                request_time: 2,
                accepted_time: 3,
            },
        ))
        .await?;

        Ok(())
    }

    async fn send_offline(&self, packet: OfflinePacket) -> io::Result<()> {
        let mut out = BytesMut::new();
        packet.encode(&mut out).map_err(invalid_data_io_error)?;
        let _written = self.socket.send_to(&out, self.server_addr).await?;
        Ok(())
    }

    async fn recv_offline(&self, timeout_budget: Duration) -> io::Result<OfflinePacket> {
        let deadline = Instant::now() + timeout_budget;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for offline packet",
                ));
            }

            let packet = self.recv_packet(remaining).await?;
            let mut src = &packet[..];
            if let Ok(decoded) = OfflinePacket::decode(&mut src) {
                return Ok(decoded);
            }
        }
    }

    async fn recv_packet(&self, timeout_budget: Duration) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let recv = timeout(timeout_budget, self.socket.recv_from(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "udp receive timed out"))?;
        let (len, _) = recv?;
        buf.truncate(len);
        Ok(buf)
    }

    async fn wait_for_connection_request_accepted(
        &self,
        timeout_budget: Duration,
    ) -> io::Result<()> {
        let deadline = Instant::now() + timeout_budget;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for ConnectionRequestAccepted",
                ));
            }

            let packet = self.recv_packet(remaining).await?;
            let mut src = &packet[..];
            let Ok(datagram) = Datagram::decode(&mut src) else {
                continue;
            };

            let DatagramPayload::Frames(frames) = datagram.payload else {
                continue;
            };

            for frame in frames {
                let Some(first) = frame.payload.first().copied() else {
                    continue;
                };
                if !is_connected_control_id(first) {
                    continue;
                }

                let mut control_src = &frame.payload[..];
                let Ok(control) = ConnectedControlPacket::decode(&mut control_src) else {
                    continue;
                };
                if matches!(
                    control,
                    ConnectedControlPacket::ConnectionRequestAccepted(_)
                ) {
                    return Ok(());
                }
            }
        }
    }

    async fn send_control(&mut self, packet: ConnectedControlPacket) -> io::Result<()> {
        let mut payload = BytesMut::new();
        packet.encode(&mut payload).map_err(invalid_data_io_error)?;
        self.send_reliable_ordered_frames(vec![payload.freeze()])
            .await
    }

    async fn send_app_payload(&mut self, payload: Bytes) -> io::Result<()> {
        self.send_reliable_ordered_frames(vec![payload]).await
    }

    async fn send_app_payload_batch(&mut self, payloads: Vec<Bytes>) -> io::Result<()> {
        self.send_reliable_ordered_frames(payloads).await
    }

    async fn send_reliable_ordered_frames(&mut self, payloads: Vec<Bytes>) -> io::Result<()> {
        let mut frames = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let reliable_index = next_sequence(&mut self.reliable_index);
            let ordering_index = next_sequence(&mut self.ordering_index);
            frames.push(Frame {
                header: FrameHeader::new(Reliability::ReliableOrdered, false, false),
                bit_length: (payload.len() as u16) << 3,
                reliable_index: Some(reliable_index),
                sequence_index: None,
                ordering_index: Some(ordering_index),
                ordering_channel: Some(0),
                split: None,
                payload,
            });
        }

        let datagram = Datagram {
            header: DatagramHeader {
                flags: DatagramFlags::VALID,
                sequence: next_sequence(&mut self.datagram_sequence),
            },
            payload: DatagramPayload::Frames(frames),
        };

        let mut out = BytesMut::new();
        datagram.encode(&mut out).map_err(invalid_data_io_error)?;
        let _written = self.socket.send_to(&out, self.server_addr).await?;
        Ok(())
    }

    async fn recv_next_app_payload(&self, timeout_budget: Duration) -> io::Result<Bytes> {
        let deadline = Instant::now() + timeout_budget;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for app payload",
                ));
            }

            let packet = self.recv_packet(remaining).await?;
            let mut src = &packet[..];
            let Ok(datagram) = Datagram::decode(&mut src) else {
                continue;
            };

            let DatagramPayload::Frames(frames) = datagram.payload else {
                continue;
            };

            for frame in frames {
                let Some(first) = frame.payload.first().copied() else {
                    continue;
                };
                if !is_connected_control_id(first) {
                    return Ok(frame.payload);
                }
            }
        }
    }
}

async fn start_server(
    bind_addr: SocketAddr,
    shard_count: usize,
    event_queue_capacity: usize,
    metrics_interval: Duration,
    overflow_policy: EventOverflowPolicy,
) -> io::Result<RaknetServer> {
    let mut builder = RaknetServer::builder()
        .bind_addr(bind_addr)
        .shard_count(shard_count);

    {
        let transport = builder.transport_config_mut();
        transport.per_ip_packet_limit = 100_000;
        transport.global_packet_limit = 1_000_000;
    }

    {
        let runtime = builder.runtime_config_mut();
        runtime.event_queue_capacity = event_queue_capacity.max(1);
        runtime.metrics_emit_interval = metrics_interval;
        runtime.outbound_tick_interval = Duration::from_millis(5);
        runtime.event_overflow_policy = overflow_policy;
    }

    builder.start().await
}

async fn next_non_metrics_event(server: &mut RaknetServer) -> RaknetServerEvent {
    loop {
        let event = timeout(Duration::from_secs(3), server.next_event())
            .await
            .expect("timed out waiting for server event")
            .expect("server event stream unexpectedly ended");
        if !matches!(
            event,
            RaknetServerEvent::Metrics { .. } | RaknetServerEvent::OfflinePacket { .. }
        ) {
            return event;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn server_surfaces_unconnected_ping_as_offline_event() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(
        bind_addr,
        1,
        1024,
        Duration::from_secs(3600),
        EventOverflowPolicy::ShedNonCritical,
    )
    .await?;

    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let client_addr = socket.local_addr()?;

    let ping = OfflinePacket::UnconnectedPing(UnconnectedPing {
        ping_time: 0x1122_3344_5566_7788,
        client_guid: 0xAABB_CCDD_EEFF_0011,
        magic: DEFAULT_UNCONNECTED_MAGIC,
    });
    let mut out = BytesMut::new();
    ping.encode(&mut out).map_err(invalid_data_io_error)?;
    let _written = socket.send_to(&out, bind_addr).await?;

    let mut pong_buf = vec![0u8; 2048];
    let (pong_len, pong_from) = timeout(Duration::from_secs(2), socket.recv_from(&mut pong_buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for pong"))??;
    assert_eq!(pong_from, bind_addr);
    let mut pong_src = &pong_buf[..pong_len];
    let pong = OfflinePacket::decode(&mut pong_src).map_err(invalid_data_io_error)?;
    assert!(
        matches!(pong, OfflinePacket::UnconnectedPong(_)),
        "server should still emit unconnected pong"
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = timeout(
            remaining.min(Duration::from_millis(300)),
            server.next_event(),
        )
        .await;
        let Ok(Some(event)) = event else {
            continue;
        };

        match event {
            RaknetServerEvent::Metrics { .. } => {}
            RaknetServerEvent::OfflinePacket { addr, packet } => {
                assert_eq!(addr, client_addr);
                match packet {
                    OfflinePacket::UnconnectedPing(observed) => {
                        assert_eq!(observed.ping_time, 0x1122_3344_5566_7788);
                        assert_eq!(observed.client_guid, 0xAABB_CCDD_EEFF_0011);
                        assert_eq!(observed.magic, DEFAULT_UNCONNECTED_MAGIC);
                        server.shutdown().await?;
                        return Ok(());
                    }
                    other => {
                        panic!("expected UnconnectedPing offline event, got {other:?}");
                    }
                }
            }
            _ => {}
        }
    }

    panic!("timed out waiting for offline packet event");
}

#[tokio::test(flavor = "current_thread")]
async fn peer_connected_precedes_packet_events_and_is_not_re_emitted() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(
        bind_addr,
        1,
        1024,
        Duration::from_secs(3600),
        EventOverflowPolicy::ShedNonCritical,
    )
    .await?;

    let mut client = TestRaknetClient::connect(bind_addr, 0xA11CE001).await?;

    let first = Bytes::from_static(b"\xfefirst");
    let second = Bytes::from_static(b"\xfesecond");
    client
        .send_app_payload_batch(vec![first.clone(), second.clone()])
        .await?;

    let connected = next_non_metrics_event(&mut server).await;
    let (peer_id, peer_addr) = match connected {
        RaknetServerEvent::PeerConnected {
            peer_id,
            addr,
            client_guid,
            shard_id,
        } => {
            assert_eq!(shard_id, 0);
            assert_eq!(client_guid, 0xA11CE001);
            (peer_id, addr)
        }
        other => panic!("expected PeerConnected as first event, got {other:?}"),
    };
    assert_eq!(peer_addr, client.local_addr());

    let packet1 = next_non_metrics_event(&mut server).await;
    match packet1 {
        RaknetServerEvent::Packet {
            peer_id: got_peer_id,
            addr,
            payload,
            ..
        } => {
            assert_eq!(got_peer_id, peer_id);
            assert_eq!(addr, peer_addr);
            assert_eq!(payload, first);
        }
        other => panic!("expected first packet event, got {other:?}"),
    }

    let packet2 = next_non_metrics_event(&mut server).await;
    match packet2 {
        RaknetServerEvent::Packet {
            peer_id: got_peer_id,
            addr,
            payload,
            ..
        } => {
            assert_eq!(got_peer_id, peer_id);
            assert_eq!(addr, peer_addr);
            assert_eq!(payload, second);
        }
        other => panic!("expected second packet event, got {other:?}"),
    }

    assert_eq!(server.peer_id_for_addr(peer_addr), Some(peer_id));
    assert_eq!(server.peer_addr(peer_id), Some(peer_addr));

    let third = Bytes::from_static(b"\xfethird");
    client.send_app_payload(third.clone()).await?;
    let next = next_non_metrics_event(&mut server).await;
    match next {
        RaknetServerEvent::Packet {
            peer_id: got_peer_id,
            addr,
            payload,
            ..
        } => {
            assert_eq!(got_peer_id, peer_id);
            assert_eq!(addr, peer_addr);
            assert_eq!(payload, third);
        }
        RaknetServerEvent::PeerConnected { .. } => {
            panic!("peer connected must be idempotent for an existing addr");
        }
        other => panic!("expected packet event for existing peer, got {other:?}"),
    }

    server.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn multi_shard_server_tracks_peers_and_supports_send_path() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(
        bind_addr,
        2,
        2048,
        Duration::from_secs(3600),
        EventOverflowPolicy::ShedNonCritical,
    )
    .await?;

    let mut client_a = TestRaknetClient::connect(bind_addr, 0xBEEF1001).await?;
    let mut client_b = TestRaknetClient::connect(bind_addr, 0xBEEF1002).await?;

    client_a
        .send_app_payload(Bytes::from_static(b"\xfeclient-a"))
        .await?;
    client_b
        .send_app_payload(Bytes::from_static(b"\xfeclient-b"))
        .await?;

    let mut peers_by_addr: HashMap<SocketAddr, PeerId> = HashMap::new();
    let mut packet_count = 0usize;
    for _ in 0..24 {
        match next_non_metrics_event(&mut server).await {
            RaknetServerEvent::PeerConnected { peer_id, addr, .. } => {
                peers_by_addr.insert(addr, peer_id);
            }
            RaknetServerEvent::Packet { .. } => {
                packet_count = packet_count.saturating_add(1);
            }
            _ => {}
        }

        if peers_by_addr.len() == 2 && packet_count >= 2 {
            break;
        }
    }

    assert_eq!(peers_by_addr.len(), 2, "expected two connected peers");
    assert!(packet_count >= 2, "expected at least two packet events");

    for (addr, peer_id) in &peers_by_addr {
        let shard = server
            .peer_shard(*peer_id)
            .expect("peer shard should exist for connected peer");
        assert!(shard < 2, "peer shard index must be within shard_count");
        assert_eq!(server.peer_addr(*peer_id), Some(*addr));
    }

    let peer_a = peers_by_addr
        .get(&client_a.local_addr())
        .copied()
        .expect("client A peer id must be registered");
    let peer_b = peers_by_addr
        .get(&client_b.local_addr())
        .copied()
        .expect("client B peer id must be registered");

    let echo_a = Bytes::from_static(b"\xfeecho-a");
    let echo_b = Bytes::from_static(b"\xfeecho-b");
    server.send(peer_a, echo_a.clone()).await?;
    server.send(peer_b, echo_b.clone()).await?;

    let recv_a = client_a
        .recv_next_app_payload(Duration::from_secs(2))
        .await?;
    let recv_b = client_b
        .recv_next_app_payload(Duration::from_secs(2))
        .await?;
    assert_eq!(recv_a, echo_a);
    assert_eq!(recv_b, echo_b);

    server.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn shed_policy_surfaces_dropped_non_critical_event_metrics() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = start_server(
        bind_addr,
        1,
        1,
        Duration::from_millis(25),
        EventOverflowPolicy::ShedNonCritical,
    )
    .await?;

    let mut client = TestRaknetClient::connect(bind_addr, 0xDD050001).await?;

    for i in 0..300u16 {
        let payload = Bytes::from(vec![0xFE, (i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8]);
        client.send_app_payload(payload).await?;
    }

    sleep(Duration::from_millis(120)).await;

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut observed_drop_count: Option<u64> = None;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = timeout(
            remaining.min(Duration::from_millis(300)),
            server.next_event(),
        )
        .await;
        let Ok(Some(event)) = event else {
            continue;
        };

        if let RaknetServerEvent::Metrics {
            dropped_non_critical_events,
            ..
        } = event
            && dropped_non_critical_events > 0
        {
            observed_drop_count = Some(dropped_non_critical_events);
            break;
        }
    }

    assert!(
        observed_drop_count.is_some(),
        "expected dropped_non_critical_events > 0 under shed policy overload"
    );

    server.shutdown().await?;
    Ok(())
}
