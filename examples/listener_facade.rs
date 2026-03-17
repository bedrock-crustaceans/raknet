use std::io;
use std::net::SocketAddr;
use std::str::FromStr;

use raknet_rs::client::{RaknetClient, RaknetClientEvent};
use raknet_rs::connection::{Connection, RecvError};
use raknet_rs::listener::Listener;

fn parse_args() -> io::Result<(SocketAddr, Option<SocketAddr>)> {
    let mut listen = SocketAddr::from(([0, 0, 0, 0], 19132));
    let mut upstream = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => {
                let value = it.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--listen expects <ip:port>")
                })?;
                listen = SocketAddr::from_str(&value).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid --listen value '{value}': {error}"),
                    )
                })?;
            }
            "--upstream" => {
                let value = it.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--upstream expects <ip:port>")
                })?;
                upstream = Some(SocketAddr::from_str(&value).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid --upstream value '{value}': {error}"),
                    )
                })?);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: cargo run --example listener_facade -- [--listen IP:PORT] [--upstream IP:PORT]"
                );
                println!("  - no upstream: echo mode");
                println!("  - with upstream: simple relay mode");
                std::process::exit(0);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {other}"),
                ));
            }
        }
    }

    Ok((listen, upstream))
}

async fn wait_client_connected(client: &mut RaknetClient) -> io::Result<()> {
    loop {
        match client.next_event().await {
            Some(RaknetClientEvent::Connected { .. }) => return Ok(()),
            Some(RaknetClientEvent::Disconnected { reason }) => {
                return Err(io::Error::other(format!(
                    "upstream disconnected before connected state: {reason:?}"
                )));
            }
            Some(RaknetClientEvent::Packet { .. })
            | Some(RaknetClientEvent::ReceiptAcked { .. })
            | Some(RaknetClientEvent::DecodeError { .. }) => {}
            None => return Err(io::Error::other("upstream event stream ended unexpectedly")),
        }
    }
}

async fn run_echo(mut connection: Connection) -> io::Result<()> {
    loop {
        match connection.recv_bytes().await {
            Ok(payload) => {
                connection
                    .send_bytes(payload)
                    .await
                    .map_err(|error| io::Error::other(format!("echo send failed: {error}")))?;
            }
            Err(RecvError::ConnectionClosed { .. }) | Err(RecvError::ChannelClosed) => {
                break;
            }
            Err(RecvError::DecodeError { message }) => {
                eprintln!("[listener_facade] downstream decode error: {message}");
            }
        }
    }
    Ok(())
}

async fn run_proxy(mut connection: Connection, upstream_addr: SocketAddr) -> io::Result<()> {
    let mut upstream = RaknetClient::connect(upstream_addr).await?;
    wait_client_connected(&mut upstream).await?;

    loop {
        tokio::select! {
            downstream = connection.recv_bytes() => {
                match downstream {
                    Ok(payload) => {
                        upstream.send(payload).await?;
                    }
                    Err(RecvError::ConnectionClosed { .. }) | Err(RecvError::ChannelClosed) => {
                        let _ = upstream.disconnect(None).await;
                        break;
                    }
                    Err(RecvError::DecodeError { message }) => {
                        eprintln!("[listener_facade] downstream decode error: {message}");
                    }
                }
            }
            upstream_event = upstream.next_event() => {
                match upstream_event {
                    Some(RaknetClientEvent::Packet { payload, .. }) => {
                        connection.send_bytes(payload).await.map_err(|error| {
                            io::Error::other(format!("downstream send failed: {error}"))
                        })?;
                    }
                    Some(RaknetClientEvent::Disconnected { reason }) => {
                        eprintln!("[listener_facade] upstream disconnected: {reason:?}");
                        connection.close().await;
                        break;
                    }
                    Some(RaknetClientEvent::DecodeError { error }) => {
                        eprintln!("[listener_facade] upstream decode error: {error}");
                    }
                    Some(RaknetClientEvent::Connected { .. }) | Some(RaknetClientEvent::ReceiptAcked { .. }) => {}
                    None => {
                        connection.close().await;
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let (listen_addr, upstream) = parse_args()?;
    let mut listener = Listener::bind(listen_addr).await?;
    listener.start().await?;

    let metadata = listener.metadata();
    println!(
        "listener start: listen={}, shard_count={}, mode={}",
        metadata.bind_addr(),
        metadata.shard_count(),
        if upstream.is_some() { "proxy" } else { "echo" }
    );

    loop {
        let connection = listener.accept().await?;
        let conn_meta = connection.metadata();
        println!(
            "accepted: id={} remote={}",
            conn_meta.id().as_u64(),
            conn_meta.remote_addr()
        );

        if let Some(upstream_addr) = upstream {
            tokio::spawn(async move {
                if let Err(error) = run_proxy(connection, upstream_addr).await {
                    eprintln!("[listener_facade] proxy session failed: {error}");
                }
            });
        } else {
            tokio::spawn(async move {
                if let Err(error) = run_echo(connection).await {
                    eprintln!("[listener_facade] echo session failed: {error}");
                }
            });
        }
    }
}
