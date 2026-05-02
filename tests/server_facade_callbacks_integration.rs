use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use raknet::client::{RaknetClient, RaknetClientEvent};
use raknet::server::{RaknetServer, ServerFacade};
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

async fn pump_facade_until(
    facade: &mut ServerFacade<'_>,
    timeout_budget: Duration,
    mut condition: impl FnMut() -> bool,
) -> io::Result<()> {
    timeout(timeout_budget, async {
        while !condition() {
            let progressed = facade.next().await?;
            if !progressed {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Server event stream closed",
                ));
            }
        }

        Ok(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Timed out waiting for facade condition",
        )
    })?
}

#[tokio::test(flavor = "current_thread")]
async fn facade_handlers_drive_connect_packet_disconnect_flow() -> io::Result<()> {
    let bind_addr = allocate_loopback_bind_addr();
    let mut server = RaknetServer::bind(bind_addr).await?;

    let connect_count = Arc::new(AtomicUsize::new(0));
    let packet_count = Arc::new(AtomicUsize::new(0));
    let disconnect_count = Arc::new(AtomicUsize::new(0));

    let mut facade = server
        .facade()
        .on_connect({
            let connect_count = Arc::clone(&connect_count);
            move |_server, event| {
                let connect_count = Arc::clone(&connect_count);
                Box::pin(async move {
                    assert_ne!(event.peer_id.as_u64(), 0);
                    assert!(event.addr.ip().is_loopback());
                    connect_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
        })
        .on_packet({
            let packet_count = Arc::clone(&packet_count);
            move |server, event| {
                let packet_count = Arc::clone(&packet_count);
                Box::pin(async move {
                    packet_count.fetch_add(1, Ordering::SeqCst);
                    server.send(event.peer_id, event.payload).await?;
                    Ok(())
                })
            }
        })
        .on_disconnect({
            let disconnect_count = Arc::clone(&disconnect_count);
            move |_server, _event| {
                let disconnect_count = Arc::clone(&disconnect_count);
                Box::pin(async move {
                    disconnect_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
        });

    let mut client = RaknetClient::connect(bind_addr).await?;
    wait_for_client_connected(&mut client).await;

    pump_facade_until(&mut facade, Duration::from_secs(3), || {
        connect_count.load(Ordering::SeqCst) >= 1
    })
    .await?;

    let payload = Bytes::from_static(b"\xfe-facade-echo");
    client.send(payload.clone()).await?;

    pump_facade_until(&mut facade, Duration::from_secs(3), || {
        packet_count.load(Ordering::SeqCst) >= 1
    })
    .await?;

    let echoed = wait_for_client_packet(&mut client).await;
    assert_eq!(echoed, payload);

    let _ = client.disconnect(None).await;

    pump_facade_until(&mut facade, Duration::from_secs(3), || {
        disconnect_count.load(Ordering::SeqCst) >= 1
    })
    .await?;

    drop(facade);
    server.shutdown().await
}
