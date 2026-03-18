use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use raknet_rs::client::{RaknetClient, RaknetClientEvent};
use raknet_rs::listener::Listener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

#[tokio::test(flavor = "current_thread")]
async fn accepted_connection_supports_async_read_and_write() -> io::Result<()> {
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

    let connection = timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("Timed out waiting for accepted connection")
        .expect("Listener accept failed");
    let mut connection_io = connection.into_io();

    client.send(Bytes::from_static(b"abc")).await?;
    client.send(Bytes::from_static(b"defg")).await?;

    let mut recv = [0u8; 7];
    timeout(Duration::from_secs(3), connection_io.read_exact(&mut recv))
        .await
        .expect("Timed out waiting for AsyncRead payload")?;
    assert_eq!(&recv, b"abcdefg");

    timeout(
        Duration::from_secs(3),
        connection_io.write_all(Bytes::from_static(b"reply-io").as_ref()),
    )
    .await
    .expect("Timed out waiting for AsyncWrite payload")?;
    timeout(Duration::from_secs(3), connection_io.flush())
        .await
        .expect("Timed out waiting for AsyncWrite flush")?;

    let client_payload = wait_for_client_packet(&mut client).await;
    assert_eq!(client_payload, Bytes::from_static(b"reply-io"));

    timeout(Duration::from_secs(3), connection_io.shutdown())
        .await
        .expect("Timed out waiting for AsyncWrite shutdown")?;

    let _ = client.disconnect(None).await;
    listener.stop().await.expect("Listener stop should succeed");

    Ok(())
}
