pub mod msg;
pub mod state;

use crate::client::msg::RakClientMsg;
use crate::client::state::RakClientState;
use crate::prelude::{RakServerError, RakSession};
use raknet::prelude::{
    RakClient as RakClientIntl, RakClientConfig, RakClientError, RakClientInput, RakClientOutput,
    RakSession as RakSessionIntl, RakSessionId, RakSessionInput, RakSessionSnapshot, Sans,
    constants,
};
use std::collections::HashMap;
use std::mem::take;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tracing::debug;

struct ClientSockets {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

impl ClientSockets {
    async fn bind(port: u16) -> std::io::Result<Self> {
        let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?;
        let v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)).await.ok();

        Ok(Self { v4, v6 })
    }

    async fn recv(
        &self,
        buf4: &mut [u8],
        buf6: &mut [u8],
    ) -> std::io::Result<(Box<[u8]>, SocketAddr)> {
        tokio::select! {
            received = self.v4.recv_from(buf4) => {
                received.map(|(len, addr)| (buf4[..len].into(), addr))
            }
            received = async {
                match &self.v6 {
                    Some(socket) => socket.recv_from(buf6).await,
                    None => std::future::pending().await,
                }
            } => received.map(|(len, addr)| (buf6[..len].into(), addr)),
        }
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        match &self.v6 {
            Some(socket) if addr.is_ipv6() => socket.send_to(buf, addr).await,
            _ => self.v4.send_to(buf, addr).await,
        }
    }
}

const PING_TIMEOUT: Duration = Duration::from_secs(5);

struct PendingPing {
    sent_ms: u64,
    sent: SystemTime,
    sender: oneshot::Sender<(Box<[u8]>, Duration)>,
}

fn millis_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn fail_pending_connect(
    client: &RakClientIntl,
    connect: &mut Option<oneshot::Sender<Result<RakSession, RakClientError>>>,
    result: Result<(), RakClientError>,
) {
    let Err(e) = result else {
        return;
    };

    debug!("client failed to handle input: {e}");

    if !client.is_connecting()
        && let Some(sender) = connect.take()
    {
        let _ = sender.send(Err(e));
    }
}

pub struct RakClient {
    state: RakClientState,
}

impl RakClient {
    pub fn new<T>(conf: T) -> Self
    where
        T: FnOnce(&mut RakClientConfig),
    {
        let mut config = RakClientConfig::default();
        conf(&mut config);

        Self {
            state: RakClientState::Initialized { config },
        }
    }

    pub async fn start(&mut self) -> Result<(), RakServerError> {
        let RakClientState::Initialized { config } = &self.state else {
            return Ok(());
        };

        let (msg_tx, msg_rx) = unbounded_channel();

        let sockets = ClientSockets::bind(config.local_port).await?;

        let handle = tokio::spawn({
            let config = config.clone();
            let sockets = sockets;
            let mut msg_rx = msg_rx;

            async move {
                let mut session_tx: Option<UnboundedSender<RakSessionInput>> = None;
                let mut pings: HashMap<SocketAddr, Vec<PendingPing>> = HashMap::new();
                let mut connect: Option<oneshot::Sender<Result<RakSession, RakClientError>>> = None;

                let mut buf4 = vec![0u8; config.max_mtu_size as usize];
                let mut buf6 = vec![0u8; config.max_mtu_size as usize];
                let mut client = RakClientIntl::new(config);

                let (dgram_tx, mut dgram_rx) = unbounded_channel::<(Box<[u8]>, SocketAddr)>();
                let (disconnect_tx, mut disconnect_rx) = unbounded_channel::<RakSessionId>();

                let timer = sleep(Duration::ZERO);
                tokio::pin!(timer);

                let mut stop_deadline: Option<Instant> = None;

                loop {
                    tokio::select! {
                        Ok((datagram, addr)) = sockets.recv(&mut buf4, &mut buf6) => {
                            let now = SystemTime::now();

                            let result = client.handle(RakClientInput::Datagram(datagram, addr, now));
                            fail_pending_connect(&client, &mut connect, result);
                        }
                        Some((buf, addr)) = dgram_rx.recv() => {
                            let _ = sockets.send_to(buf.as_ref(), addr).await;
                        }
                        Some(_) = disconnect_rx.recv() => {
                            session_tx = None;
                            let _ = client.handle(RakClientInput::Disconnect);
                        }
                        Some(msg) = msg_rx.recv() => {
                            let now = SystemTime::now();
                            match msg {
                                RakClientMsg::Ping(addr, sender) => {
                                    let _ = client.handle(RakClientInput::Ping(addr, now));

                                    let sent_ms = millis_since_epoch(now);
                                    let queue = pings.entry(addr).or_default();
                                    queue.retain(|ping| !ping.sender.is_closed());
                                    queue.push(PendingPing { sent_ms, sent: now, sender });
                                }
                                RakClientMsg::Connect(addr, sender) => {
                                    match client.handle(RakClientInput::Connect(addr, now)) {
                                        Ok(()) => connect = Some(sender),
                                        Err(e) => {
                                            let _ = sender.send(Err(e));
                                        }
                                    }
                                }
                                RakClientMsg::Adopt(snapshot, reply) => {
                                    match RakSessionIntl::restore(*snapshot) {
                                        Ok(session) => match client.adopt(session) {
                                            Ok(()) => connect = Some(reply),
                                            Err(e) => {
                                                let _ = reply.send(Err(e));
                                            }
                                        },
                                        Err(e) => debug!("cannot adopt a session: {e}"),
                                    }
                                }
                                RakClientMsg::Stop => {
                                    if let Some(session) = &session_tx {
                                        let _ = session.send(RakSessionInput::Disconnect(now));
                                    }

                                    stop_deadline = Some(
                                        Instant::now() + constants::CLOSE_TIMEOUT + Duration::from_secs(1),
                                    );
                                }
                            }
                        }
                        _ = &mut timer => {
                            let result = client.handle(RakClientInput::Update(SystemTime::now()));
                            fail_pending_connect(&client, &mut connect, result);
                        }
                        _ = async {
                            match stop_deadline {
                                Some(deadline) => sleep_until(deadline).await,
                                None => std::future::pending().await,
                            }
                        } => {}
                    }

                    while let Some(msg) = client.poll() {
                        match msg {
                            RakClientOutput::SocketDatagram(buf, addr) => {
                                let _ = sockets.send_to(&buf, addr).await;
                            }
                            RakClientOutput::SessionDatagram(buf) => {
                                if let Some(session) = &session_tx {
                                    let now = SystemTime::now();

                                    let _ = session.send(RakSessionInput::Datagram(buf, now));
                                } else {
                                    debug!("no session found");
                                }
                            }
                            RakClientOutput::SessionConnected(session) => {
                                debug!("session connected");

                                let (session, tx) = RakSession::spawn(
                                    *session,
                                    dgram_tx.clone(),
                                    disconnect_tx.clone(),
                                );

                                if stop_deadline.is_some() {
                                    let _ = tx.send(RakSessionInput::Disconnect(SystemTime::now()));
                                    session_tx = Some(tx);
                                    continue;
                                }

                                session_tx = Some(tx);

                                if let Some(sender) = take(&mut connect) {
                                    let _ = sender.send(Ok(session));
                                }
                            }
                            RakClientOutput::Wait(duration) => {
                                timer.as_mut().reset(Instant::now() + duration);
                            }
                            RakClientOutput::Pong(addr, msg, time) => {
                                if let Some(queue) = pings.get_mut(&addr) {
                                    queue.retain(|ping| !ping.sender.is_closed());

                                    let echoed_ms = millis_since_epoch(time);
                                    if let Some(index) =
                                        queue.iter().position(|ping| ping.sent_ms == echoed_ms)
                                    {
                                        let ping = queue.remove(index);
                                        let latency = SystemTime::now()
                                            .duration_since(ping.sent)
                                            .unwrap_or_default();
                                        let _ = ping.sender.send((msg, latency));
                                    }
                                }
                            }
                        }
                    }

                    if let Some(deadline) = stop_deadline
                        && (session_tx.is_none() || Instant::now() >= deadline)
                    {
                        break;
                    }
                }

                while let Ok((buf, addr)) = dgram_rx.try_recv() {
                    let _ = sockets.send_to(buf.as_ref(), addr).await;
                }
            }
        });

        self.state = RakClientState::Running { handle, msg_tx };
        Ok(())
    }

    pub async fn stop(&mut self) {
        if !matches!(self.state, RakClientState::Running { .. }) {
            return;
        }

        let RakClientState::Running { handle, msg_tx } =
            std::mem::replace(&mut self.state, RakClientState::Shutdown)
        else {
            unreachable!()
        };

        let _ = msg_tx.send(RakClientMsg::Stop);
        let _ = handle.await;
    }

    pub async fn ping(&self, addr: SocketAddr) -> Result<(Box<[u8]>, Duration), RakClientError> {
        let RakClientState::Running { msg_tx, .. } = &self.state else {
            return Err(RakClientError::Closed);
        };

        let (tx, rx) = oneshot::channel();

        let _ = msg_tx.send(RakClientMsg::Ping(addr, tx));
        timeout(PING_TIMEOUT, rx)
            .await
            .map_err(|_| RakClientError::Timeout)?
            .map_err(|_| RakClientError::Closed)
    }

    /// Resumes a session captured with [`RakSession::snapshot`] on another client.
    ///
    /// Fails with [`RakClientError::AlreadyConnected`] if this client already has a
    /// session or is connecting. The peer is not contacted, so the caller is responsible
    /// for pointing it at this client's socket.
    pub async fn adopt(&self, snapshot: RakSessionSnapshot) -> Result<RakSession, RakClientError> {
        let RakClientState::Running { msg_tx, .. } = &self.state else {
            return Err(RakClientError::Closed);
        };

        let (tx, rx) = oneshot::channel();

        msg_tx
            .send(RakClientMsg::Adopt(Box::new(snapshot), tx))
            .map_err(|_| RakClientError::Closed)?;

        rx.await.map_err(|_| RakClientError::Closed)?
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<RakSession, RakClientError> {
        let RakClientState::Running { msg_tx, .. } = &self.state else {
            return Err(RakClientError::Closed);
        };

        let (tx, rx) = oneshot::channel();

        let _ = msg_tx.send(RakClientMsg::Connect(addr, tx));
        rx.await.map_err(|_| RakClientError::Closed)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fake_server(reply_after: Option<Duration>) -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Some(delay) = reply_after else {
                    continue;
                };
                if len < 9 {
                    continue;
                }

                let mut pong = vec![0x1C];
                pong.extend_from_slice(&buf[1..9]);
                pong.extend_from_slice(&[0u8; 8]);
                pong.extend_from_slice(&constants::MAGIC);
                pong.extend_from_slice(&2u16.to_be_bytes());
                pong.extend_from_slice(b"hi");

                sleep(delay).await;
                let _ = socket.send_to(&pong, from).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn ping_latency_is_the_round_trip_time() {
        let server = fake_server(Some(Duration::from_millis(50))).await;
        let mut client = RakClient::new(|_| {});
        client.start().await.unwrap();

        let (message, latency) = client.ping(server).await.unwrap();

        assert_eq!(message.as_ref(), b"hi");
        assert!(
            latency >= Duration::from_millis(40) && latency < Duration::from_millis(500),
            "latency was {latency:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ping_to_a_silent_server_times_out() {
        let server = fake_server(None).await;
        let mut client = RakClient::new(|_| {});
        client.start().await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(60), client.ping(server))
            .await
            .expect("ping never gave up");

        assert!(
            matches!(result, Err(RakClientError::Timeout)),
            "got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn ping() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_test_writer()
            .compact()
            .try_init();

        let mut client = RakClient::new(|_| {});

        let _ = client.start().await;

        loop {
            let pong = client
                .ping("127.0.0.1:19132".parse().unwrap())
                .await
                .unwrap();
            debug!(
                "ponged in {}ms with message: {:?}",
                pong.1.as_millis(),
                String::from_utf8_lossy(&pong.0)
            );
        }
    }

    #[tokio::test]
    async fn connect_over_ipv6_sends_open_connection_request_1() {
        let Ok(listener) = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await else {
            return;
        };
        let addr = listener.local_addr().unwrap();

        let mut client = RakClient::new(|_| {});
        client.start().await.unwrap();

        let connect = client.connect(addr);
        tokio::pin!(connect);
        let mut buf = [0u8; 2048];

        tokio::select! {
            _ = &mut connect => panic!("connect resolved without a server"),
            received = timeout(Duration::from_secs(2), listener.recv_from(&mut buf)) => {
                let (len, _) = received
                    .expect("no datagram reached the IPv6 listener")
                    .unwrap();
                assert!(len > 0);
                assert_eq!(buf[0], 0x05);
            }
        }
    }
}
