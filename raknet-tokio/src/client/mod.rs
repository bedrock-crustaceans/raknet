pub mod msg;
pub mod state;

use crate::client::msg::RakClientMsg;
use crate::client::state::RakClientState;
use crate::prelude::{RakServerError, RakSession};
use raknet::prelude::{
    RakClient as RakClientIntl, RakClientConfig, RakClientError, RakClientInput, RakClientOutput,
    RakSessionInput, Sans,
};
use std::collections::{HashMap, VecDeque};
use std::mem::take;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep};
use tracing::debug;

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

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;

        let handle = tokio::spawn({
            let config = config.clone();
            let socket = socket;
            let mut msg_rx = msg_rx;

            async move {
                let mut session_tx: Option<UnboundedSender<RakSessionInput>> = None;
                let mut pings: HashMap<
                    SocketAddr,
                    VecDeque<(oneshot::Sender<(Box<[u8]>, Duration)>, SystemTime)>,
                > = HashMap::new();
                let mut connect: Option<oneshot::Sender<RakSession>> = None;

                let mut buf = vec![0u8; config.max_mtu_size as usize];
                let mut client = RakClientIntl::new(config);

                let (dgram_tx, mut dgram_rx) = unbounded_channel::<(Box<[u8]>, SocketAddr)>();

                let timer = sleep(Duration::ZERO);
                tokio::pin!(timer);

                loop {
                    tokio::select! {
                        Ok((len, addr)) = socket.recv_from(&mut buf) => {
                            let now = SystemTime::now();

                            match client.handle(RakClientInput::Datagram(buf[..len].into(), addr, now)) {
                                Ok(_) => {},
                                Err(e) => debug!("server failed to handle inbound datagram: {e}")
                            }
                        }
                        Some((buf, addr)) = dgram_rx.recv() => {
                            let _ = socket.send_to(buf.as_ref(), addr).await;
                        }
                        Some(msg) = msg_rx.recv() => {
                            let now = SystemTime::now();
                            match msg {
                                RakClientMsg::Ping(addr, sender) => {
                                    let _ = client.handle(RakClientInput::Ping(addr, now));

                                    pings.entry(addr).or_default().push_back((sender, now));
                                }
                                RakClientMsg::Connect(addr, sender) => {
                                    let _ = client.handle(RakClientInput::Connect(addr, now));

                                    connect = Some(sender);
                                }
                            }
                        }
                        _ = &mut timer => {
                            let _ = client.handle(RakClientInput::Update(SystemTime::now()));
                        }
                    }

                    while let Some(msg) = client.poll() {
                        match msg {
                            RakClientOutput::SocketDatagram(buf, addr) => {
                                let _ = socket.send_to(&buf, addr).await;
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

                                let (session, tx) = RakSession::spawn(*session, dgram_tx.clone());

                                session_tx = Some(tx);

                                if let Some(sender) = take(&mut connect) {
                                    let _ = sender.send(session);
                                }
                            }
                            RakClientOutput::Wait(duration) => {
                                timer.as_mut().reset(Instant::now() + duration);
                            }
                            RakClientOutput::Pong(addr, msg, time) => {
                                if let Some(queue) = pings.get_mut(&addr) {
                                    if let Some((sender, ping_time)) = queue.pop_front() {
                                        let _ = sender.send((
                                            msg,
                                            ping_time
                                                .duration_since(time)
                                                .unwrap_or(Duration::from_secs(0)),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        self.state = RakClientState::Running { handle, msg_tx };
        Ok(())
    }

    pub async fn ping(&self, addr: SocketAddr) -> Result<(Box<[u8]>, Duration), RakClientError> {
        let RakClientState::Running { msg_tx, .. } = &self.state else {
            return Err(RakClientError::Closed);
        };

        let (tx, rx) = oneshot::channel();

        let _ = msg_tx.send(RakClientMsg::Ping(addr, tx));
        rx.await.map_err(|_| RakClientError::Closed)
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<RakSession, RakClientError> {
        let RakClientState::Running { msg_tx, .. } = &self.state else {
            return Err(RakClientError::Closed);
        };

        let (tx, rx) = oneshot::channel();

        let _ = msg_tx.send(RakClientMsg::Connect(addr, tx));
        rx.await.map_err(|_| RakClientError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
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
}
