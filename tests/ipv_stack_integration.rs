use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use raknet_rs::client::{RaknetClient, RaknetClientEvent};
use raknet_rs::low_level::transport::{ShardedRuntimeConfig, TransportConfig};
use raknet_rs::server::{PeerId, RaknetServer, RaknetServerEvent};
use tokio::time::timeout;

fn allocate_ipv4_loopback_bind_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("ephemeral IPv4 loopback bind must succeed");
    socket
        .local_addr()
        .expect("ephemeral IPv4 loopback local addr must be available")
}

fn allocate_ipv6_loopback_bind_addr() -> io::Result<SocketAddr> {
    let socket = std::net::UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        0,
        0,
        0,
    )))?;
    socket.local_addr()
}

fn ipv6_loopback_available() -> bool {
    allocate_ipv6_loopback_bind_addr().is_ok()
}

async fn wait_for_client_connected(client: &mut RaknetClient) -> io::Result<()> {
    loop {
        let event = timeout(Duration::from_secs(5), client.next_event())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for client event",
                )
            })?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "client event stream ended")
            })?;

        match event {
            RaknetClientEvent::Connected { .. } => return Ok(()),
            RaknetClientEvent::Disconnected { reason } => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("client disconnected before connect completed: {reason:?}"),
                ));
            }
            RaknetClientEvent::Packet { .. }
            | RaknetClientEvent::ReceiptAcked { .. }
            | RaknetClientEvent::DecodeError { .. } => {}
        }
    }
}

async fn wait_for_server_peer_connected(
    server: &mut RaknetServer,
) -> io::Result<(PeerId, SocketAddr)> {
    loop {
        let event = timeout(Duration::from_secs(5), server.next_event())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for server event",
                )
            })?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "server event stream ended")
            })?;

        match event {
            RaknetServerEvent::PeerConnected { peer_id, addr, .. } => return Ok((peer_id, addr)),
            RaknetServerEvent::WorkerError { message, .. } => {
                return Err(io::Error::other(format!(
                    "worker error while waiting for peer connect: {message}"
                )));
            }
            RaknetServerEvent::PeerDisconnected { .. }
            | RaknetServerEvent::Packet { .. }
            | RaknetServerEvent::OfflinePacket { .. }
            | RaknetServerEvent::ReceiptAcked { .. }
            | RaknetServerEvent::PeerRateLimited { .. }
            | RaknetServerEvent::SessionLimitReached { .. }
            | RaknetServerEvent::ProxyDropped { .. }
            | RaknetServerEvent::DecodeError { .. }
            | RaknetServerEvent::WorkerStopped { .. }
            | RaknetServerEvent::Metrics { .. } => {}
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ipv4_only_bind_accepts_ipv4_client() -> io::Result<()> {
    let bind_addr = allocate_ipv4_loopback_bind_addr();
    let transport_config = TransportConfig {
        bind_addr,
        ..TransportConfig::default()
    };
    let runtime_config = ShardedRuntimeConfig {
        shard_count: 1,
        ..ShardedRuntimeConfig::default()
    };

    let mut server = RaknetServer::start_with_configs(transport_config, runtime_config).await?;
    let mut client = RaknetClient::connect(bind_addr).await?;

    wait_for_client_connected(&mut client).await?;
    let _peer = wait_for_server_peer_connected(&mut server).await?;

    let _ = client.disconnect(None).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ipv6_only_bind_accepts_ipv6_client() -> io::Result<()> {
    if !ipv6_loopback_available() {
        eprintln!("ipv6 loopback unavailable; skipping ipv6-only integration test");
        return Ok(());
    }

    let bind_addr = allocate_ipv6_loopback_bind_addr()?;
    let transport_config = TransportConfig {
        bind_addr,
        ipv6_only: true,
        ..TransportConfig::default()
    };
    let runtime_config = ShardedRuntimeConfig {
        shard_count: 1,
        ..ShardedRuntimeConfig::default()
    };

    let mut server = RaknetServer::start_with_configs(transport_config, runtime_config).await?;
    let mut client = RaknetClient::connect(bind_addr).await?;

    wait_for_client_connected(&mut client).await?;
    let (_peer, peer_addr) = wait_for_server_peer_connected(&mut server).await?;
    assert!(
        peer_addr.is_ipv6(),
        "ipv6-only bind should accept ipv6 client addr, got {peer_addr}"
    );

    let _ = client.disconnect(None).await;
    server.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn split_dual_stack_bind_accepts_ipv4_and_ipv6_clients() -> io::Result<()> {
    if !ipv6_loopback_available() {
        eprintln!("ipv6 loopback unavailable; skipping split dual-stack integration test");
        return Ok(());
    }

    let port = allocate_ipv4_loopback_bind_addr().port();
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let transport_config = TransportConfig {
        bind_addr,
        split_ipv4_ipv6_bind: true,
        ipv6_only: true,
        ..TransportConfig::default()
    };
    let runtime_config = ShardedRuntimeConfig {
        shard_count: 2,
        ..ShardedRuntimeConfig::default()
    };

    let mut server = RaknetServer::start_with_configs(transport_config, runtime_config).await?;

    let mut client_v4 =
        RaknetClient::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
    wait_for_client_connected(&mut client_v4).await?;
    let (_peer_v4, addr_v4) = wait_for_server_peer_connected(&mut server).await?;

    let mut client_v6 = RaknetClient::connect(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        port,
        0,
        0,
    )))
    .await?;
    wait_for_client_connected(&mut client_v6).await?;
    let (_peer_v6, addr_v6) = wait_for_server_peer_connected(&mut server).await?;

    assert!(
        addr_v4 != addr_v6,
        "split dual-stack should surface distinct remote addresses"
    );
    assert!(
        addr_v4.is_ipv4() || addr_v6.is_ipv4(),
        "split dual-stack should accept an IPv4 client; addresses=({addr_v4}, {addr_v6})"
    );
    assert!(
        addr_v4.is_ipv6() || addr_v6.is_ipv6(),
        "split dual-stack should accept an IPv6 client; addresses=({addr_v4}, {addr_v6})"
    );

    let _ = client_v4.disconnect(None).await;
    let _ = client_v6.disconnect(None).await;
    server.shutdown().await?;
    Ok(())
}
