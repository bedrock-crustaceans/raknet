use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use raknet::client::{RaknetClient, RaknetClientEvent};
use raknet::connection::{Connection, ConnectionCloseReason, RecvError};
use raknet::listener::Listener;
use tokio::time::timeout;

fn allocate_loopback_bind_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("Ephemeral loopback bind must succeed");
    socket
        .local_addr()
        .expect("Ephemeral local addr must be available")
}

async fn wait_for_client_connected(client: &mut RaknetClient) {
    loop {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("Timed out waiting for client event")
            .expect("Client event stream unexpectedly ended");

        match event {
            RaknetClientEvent::Connected { .. } => return,
            RaknetClientEvent::Packet { .. }
            | RaknetClientEvent::ReceiptAcked { .. }
            | RaknetClientEvent::DecodeError { .. }
            | RaknetClientEvent::Disconnected { .. } => {}
        }
    }
}

async fn wait_for_client_packet(client: &mut RaknetClient) -> Bytes {
    loop {
        let event = timeout(Duration::from_secs(3), client.next_event())
            .await
            .expect("Timed out waiting for client packet")
            .expect("Client event stream unexpectedly ended");

        match event {
            RaknetClientEvent::Packet { payload, .. } => return payload,
            RaknetClientEvent::Disconnected { reason } => {
                panic!("Client disconnected before packet arrived: {reason:?}")
            }
            RaknetClientEvent::Connected { .. }
            | RaknetClientEvent::ReceiptAcked { .. }
            | RaknetClientEvent::DecodeError { .. } => {}
        }
    }
}

async fn wait_for_connection_payload(connection: &mut Connection) -> Vec<u8> {
    timeout(Duration::from_secs(3), connection.recv())
        .await
        .expect("Timed out waiting for accepted connection payload")
        .expect("Connection recv failed unexpectedly")
}

#[tokio::test(flavor = "current_thread")]
async fn listener_accepts_and_exchanges_payloads() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut listener = Listener::bind(bind_addr)
        .await
        .expect("Listener bind should succeed");

    listener.set_pong_data("Compat Listener");
    listener
        .start()
        .await
        .expect("Listener start should succeed");

    let mut client = RaknetClient::connect(bind_addr).await?;
    wait_for_client_connected(&mut client).await;

    let mut connection = timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("Timed out waiting for accepted connection")
        .expect("Listener accept failed");
    let connection_meta = connection.metadata();
    let client_local = client.local_addr()?;
    assert_ne!(connection_meta.id().as_u64(), 0);
    assert_eq!(connection_meta.remote_addr().port(), client_local.port());
    assert!(
        connection_meta.remote_addr().ip().is_loopback(),
        "Accepted remote addr should resolve to loopback, got {}",
        connection_meta.remote_addr()
    );

    let c2s = Bytes::from_static(b"\xferaknet-compat-c2s");
    client.send(c2s.clone()).await?;

    let recv = wait_for_connection_payload(&mut connection).await;
    assert_eq!(recv.as_slice(), c2s.as_ref());

    let s2c = Bytes::from_static(b"\xferaknet-compat-s2c");
    connection
        .send(s2c.as_ref())
        .await
        .expect("Connection send should succeed");

    let client_payload = wait_for_client_packet(&mut client).await;
    assert_eq!(client_payload, s2c);

    connection.close().await;
    let _ = client.disconnect(None).await;

    listener.stop().await.expect("Listener stop should succeed");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn listener_incoming_yields_connections() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut listener = Listener::bind(bind_addr)
        .await
        .expect("Listener bind should succeed");
    listener
        .start()
        .await
        .expect("Listener start should succeed");

    let mut client = RaknetClient::connect(bind_addr).await?;
    wait_for_client_connected(&mut client).await;

    let connection_meta = {
        let mut incoming = listener
            .incoming()
            .expect("Incoming stream should be available after start");
        let connection = timeout(Duration::from_secs(3), incoming.next())
            .await
            .expect("Timed out waiting for incoming connection")
            .expect("Incoming stream closed unexpectedly");
        connection.metadata()
    };

    let client_local = client.local_addr()?;
    assert_ne!(connection_meta.id().as_u64(), 0);
    assert_eq!(connection_meta.remote_addr().port(), client_local.port());
    assert!(
        connection_meta.remote_addr().ip().is_loopback(),
        "incoming remote addr should resolve to loopback, got {}",
        connection_meta.remote_addr()
    );

    let _ = client.disconnect(None).await;
    listener.stop().await.expect("listener stop should succeed");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn listener_stop_closes_accepted_connection() {
    let bind_addr = allocate_loopback_bind_addr();
    let mut listener = Listener::bind(bind_addr)
        .await
        .expect("listener bind should succeed");
    listener
        .start()
        .await
        .expect("listener start should succeed");

    let mut client = RaknetClient::connect(bind_addr)
        .await
        .expect("client connect should work");
    wait_for_client_connected(&mut client).await;

    let mut connection = timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("timed out waiting for accepted connection")
        .expect("listener accept failed");

    listener.stop().await.expect("listener stop should succeed");

    let recv_result = timeout(Duration::from_secs(3), connection.recv())
        .await
        .expect("timed out waiting for closed recv")
        .expect_err("recv must fail after listener stop");

    assert!(
        matches!(
            recv_result,
            RecvError::ConnectionClosed {
                reason: ConnectionCloseReason::ListenerStopped
            } | RecvError::ChannelClosed
        ),
        "unexpected recv error after stop: {recv_result:?}"
    );
}
