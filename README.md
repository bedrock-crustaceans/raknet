# raknet-rs

[![Rust](https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen)](#)
[![Platform](https://img.shields.io/badge/Platform-%20RakNet-2ea44f)](#)

`raknet-rs` is a RakNet transport library written in Rust.

It is built for modern async server/client networking and is especially useful for
Minecraft Bedrock Edition projects (servers, proxies, and tooling), while still remaining
usable as a general RakNet library.

## Getting Started

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
raknet = { git = "https://github.com/bedrock-crustaceans/raknet-rs.git" }
```

## API Surface

- Stable application API lives under `client`, `server`, `listener`, `connection` and root re-exports.
- Advanced low-level API is namespaced under `raknet_rs::low_level::{protocol, session, transport}`.

### Usage

Basic server:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use raknet_rs::server::{RaknetServer, RaknetServerEvent};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 19132);
    let mut server = RaknetServer::bind(bind).await?;

    while let Some(event) = server.next_event().await {
        if let RaknetServerEvent::Packet { peer_id, payload, .. } = event {
            server.send(peer_id, payload).await?;
        }
    }

    Ok(())
}
```

Basic client:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use raknet_rs::client::{RaknetClient, RaknetClientEvent};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19132);
    let mut client = RaknetClient::connect(addr).await?;

    while let Some(event) = client.next_event().await {
        match event {
            RaknetClientEvent::Connected { .. } => client.send(b"\xfehello").await?,
            RaknetClientEvent::Packet { .. } => break,
            RaknetClientEvent::Disconnected { .. } => break,
            _ => {}
        }
    }

    Ok(())
}
```

Callback facade (`on_connect / on_packet / on_disconnect`):

```rust
use std::pin::Pin;
use std::future::Future;
use raknet_rs::server::RaknetServer;

fn hook_ok<'a>() -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
    Box::pin(async { Ok(()) })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let mut server = RaknetServer::bind("0.0.0.0:19132".parse().unwrap()).await?;
    let mut facade = server
        .facade()
        .on_connect(|_server, _event| hook_ok())
        .on_packet(|server, event| Box::pin(async move {
            server.send(event.peer_id, event.payload).await?;
            Ok(())
        }))
        .on_disconnect(|_server, _event| hook_ok());

    facade.run().await
}
```

Listener incoming helper:

```rust
use std::net::SocketAddr;
use raknet_rs::Listener;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let bind: SocketAddr = "0.0.0.0:19132".parse().unwrap();
    let mut listener = Listener::bind(bind).await?;
    listener.start().await?;

    let mut incoming = listener.incoming()?;
    while let Some(conn) = incoming.next().await {
        let meta = conn.metadata();
        println!("accepted peer={} addr={}", meta.id().as_u64(), meta.remote_addr());
    }

    Ok(())
}
```

## Observability

- The runtime emits `tracing` events (connect, disconnect, decode error, handshake reject/timeout).
- To collect logs in your application, configure a subscriber (for example, `tracing-subscriber`).
- For Prometheus format export, use `telemetry::TelemetryExporter`:
  - `exporter.ingest_server_event(&event)`
  - `let body = exporter.render_prometheus()`

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
