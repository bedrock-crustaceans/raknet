<br />
<div align="center">

# RakNet

A RakNet transport library written in Rust.

[![rust][rust_badge_url]][rust_url]
[![transport][transport_badge_url]][transport_url]
[![license][license_badge_url]][license_url]

</div>

Built for modern async server/client networking and is especially useful for
Minecraft Bedrock Edition projects (servers, proxies, and tooling), while still remaining
usable as a general RakNet library.

## Getting Started

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
raknet = { git = "https://github.com/bedrock-crustaceans/raknet.git" }
```

## API Surface

- Stable application API lives under `client`, `server`, `listener`, `connection` and root re-exports.
- Advanced low-level API is namespaced under `raknet::low_level::{protocol, session, transport}`.

### Usage

Basic server:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use raknet::server::{RaknetServer, RaknetServerEvent};

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
use raknet::client::{RaknetClient, RaknetClientEvent};

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
use raknet::server::RaknetServer;

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
use raknet::Listener;

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

<!-- BADGES -->
[transport_badge_url]: https://img.shields.io/badge/transport-raknet-black?style=flat-square
[transport_url]: https://github.com/facebookarchive/RakNet

[rust_badge_url]: https://img.shields.io/badge/rust-2024-%23D34516?style=flat-square&logo=rust&logoColor=%23D34516&labelColor=white
[rust_url]: https://rust-lang.org/

[license_badge_url]: https://img.shields.io/github/license/bedrock-crustaceans/raknet?style=flat-square
[license_url]: LICENSE
<!-- BADGES -->
