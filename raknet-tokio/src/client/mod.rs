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
use std::collections::{HashMap, VecDeque};
use std::mem::take;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep, sleep_until};
use tracing::debug;

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

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, config.local_port)).await?;

        let handle = tokio::spawn({
            let config = config.clone();
            let socket = socket;
            let mut msg_rx = msg_rx;

            async move {
                let mut session_tx: Option<UnboundedSender<RakSessionInput>> = None;
                let mut pings: HashMap<SocketAddr, VecDeque<_>> = HashMap::new();
                let mut connect: Option<oneshot::Sender<Result<RakSession, RakClientError>>> = None;

                let mut buf = vec![0u8; config.max_mtu_size as usize];
                let mut client = RakClientIntl::new(config);

                let (dgram_tx, mut dgram_rx) = unbounded_channel::<(Box<[u8]>, SocketAddr)>();
                let (disconnect_tx, mut disconnect_rx) = unbounded_channel::<RakSessionId>();

                let timer = sleep(Duration::ZERO);
                tokio::pin!(timer);

                let mut stop_deadline: Option<Instant> = None;

                loop {
                    tokio::select! {
                        Ok((len, addr)) = socket.recv_from(&mut buf) => {
                            let now = SystemTime::now();

                            let result = client.handle(RakClientInput::Datagram(buf[..len].into(), addr, now));
                            fail_pending_connect(&client, &mut connect, result);
                        }
                        Some((buf, addr)) = dgram_rx.recv() => {
                            let _ = socket.send_to(buf.as_ref(), addr).await;
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

                                    pings.entry(addr).or_default().push_back((sender, now));
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
                                if let Some(queue) = pings.get_mut(&addr)
                                    && let Some((sender, ping_time)) = queue.pop_front()
                                {
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

                    if let Some(deadline) = stop_deadline
                        && (session_tx.is_none() || Instant::now() >= deadline)
                    {
                        break;
                    }
                }

                while let Ok((buf, addr)) = dgram_rx.try_recv() {
                    let _ = socket.send_to(buf.as_ref(), addr).await;
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
        rx.await.map_err(|_| RakClientError::Closed)
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
}
