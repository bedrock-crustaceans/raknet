pub mod error;
pub mod msg;
mod state;

use crate::server::error::RakServerError;
use crate::server::msg::RakServerMsg;
use crate::server::state::RakServerState;
use crate::session::RakSession;
use raknet::prelude::{
    RakServer as RakServerIntl, RakServerConfig, RakServerInput, RakServerOutput,
    RakSession as RakSessionIntl, RakSessionId, RakSessionInput, RakSessionSnapshot, Sans,
};
use state::{Initialized, Running};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::time::interval;
use tracing::debug;

pub struct RakServer {
    state: RakServerState,
}

impl RakServer {
    pub fn new<T>(addr: SocketAddr, conf: T) -> Self
    where
        T: FnOnce(&mut RakServerConfig),
    {
        let mut config = RakServerConfig::default();
        conf(&mut config);

        RakServer {
            state: RakServerState::Initialized(Initialized { addr, config }),
        }
    }

    pub fn set_message<T>(&mut self, val: T)
    where
        T: Into<Box<[u8]>>,
    {
        let buf = val.into();
        match &mut self.state {
            RakServerState::Initialized(Initialized { config, .. }) => {
                config.message = buf;
            }
            RakServerState::Running(Running { msg_tx, .. }) => {
                let _ = msg_tx.send(RakServerMsg::SetMessage(buf));
            }
            _ => {}
        }
    }

    pub fn set_max_connections(&mut self, val: usize) {
        match &mut self.state {
            RakServerState::Initialized(Initialized { config, .. }) => {
                config.max_connections = val;
            }
            RakServerState::Running(Running { msg_tx, .. }) => {
                let _ = msg_tx.send(RakServerMsg::SetMaxConnections(val));
            }
            _ => {}
        }
    }

    pub async fn start(&mut self) -> Result<(), RakServerError> {
        let RakServerState::Initialized(Initialized { config, addr }) = &self.state else {
            return Ok(());
        };

        let (session_tx, session_rx) = unbounded_channel();
        let (msg_tx, msg_rx) = unbounded_channel();

        let socket = UdpSocket::bind(addr).await?;

        let handle = tokio::spawn({
            let config = config.clone();
            let addr = *addr;
            let socket = socket;
            let mut msg_rx = msg_rx;

            async move {
                let mut sessions: HashMap<RakSessionId, UnboundedSender<RakSessionInput>> =
                    HashMap::new();

                let mut buf = vec![0u8; config.max_mtu_size as usize].into_boxed_slice();
                let mut server = RakServerIntl::new(config, addr);

                let (dgram_tx, mut dgram_rx) = unbounded_channel::<(Box<[u8]>, SocketAddr)>();
                let (disconnect_tx, mut disconnect_rx) = unbounded_channel::<RakSessionId>();

                let mut update_interval = interval(Duration::from_secs(1));

                loop {
                    tokio::select! {
                        _ = update_interval.tick() => {
                            let now = SystemTime::now();

                            let _ = server.handle(RakServerInput::Update(now));
                        }
                        Ok((len, addr)) = socket.recv_from(&mut buf) => {
                            let now = SystemTime::now();

                            match server.handle(RakServerInput::Datagram(buf[..len].into(), addr, now)) {
                                Ok(_) => {},
                                Err(e) => debug!("server failed to handle inbound datagram: {e}")
                            }
                        }
                        Some((buf, addr)) = dgram_rx.recv() => {
                            let _ = socket.send_to(buf.as_ref(), addr).await;
                        }
                        Some(id) = disconnect_rx.recv() => {
                            let now = SystemTime::now();

                            let _ = server.handle(RakServerInput::RemoveSession(id, now));
                            sessions.remove(&id);
                        }
                        Some(msg) = msg_rx.recv() => {
                            match msg {
                                RakServerMsg::SetMessage(msg) => {
                                    let _ = server.handle(RakServerInput::SetMessage(msg));
                                },
                                RakServerMsg::SetMaxConnections(n) => {
                                    let _ = server.handle(RakServerInput::SetMaxConnections(n));
                                }
                                RakServerMsg::Adopt(session, reply) => {
                                    server.adopt(session);

                                    if let Some(RakServerOutput::SessionConnected(session)) = server.poll() {
                                        let id = session.id;

                                        let (session, tx) = RakSession::spawn(
                                            *session,
                                            dgram_tx.clone(),
                                            disconnect_tx.clone(),
                                        );

                                        sessions.insert(id, tx);
                                        let _ = reply.send(session);
                                    }
                                }
                                RakServerMsg::Stop => {
                                    let now = SystemTime::now();

                                    for session in sessions.values() {
                                        let _ = session.send(RakSessionInput::Disconnect(now));
                                    }

                                    break;
                                }
                            }
                        }
                    }

                    while let Some(msg) = server.poll() {
                        match msg {
                            RakServerOutput::SocketDatagram(buf, addr) => {
                                let _ = socket.send_to(&buf, addr).await;
                            }
                            RakServerOutput::SessionDatagram(buf, id) => {
                                if let Some(session) = sessions.get_mut(&id) {
                                    let now = SystemTime::now();

                                    let _ = session.send(RakSessionInput::Datagram(buf, now));
                                } else {
                                    debug!("no session found with id {id:?}");
                                }
                            }
                            RakServerOutput::SessionConnected(session) => {
                                let id = session.id;

                                debug!("session {:?} connected", id);

                                let (session, tx) = RakSession::spawn(
                                    *session,
                                    dgram_tx.clone(),
                                    disconnect_tx.clone(),
                                );

                                sessions.insert(id, tx);

                                let _ = session_tx.send(session);
                            }
                        }
                    }
                }
            }
        });

        self.state = RakServerState::Running(Running {
            handle,
            session_rx,
            msg_tx,
        });
        Ok(())
    }

    pub async fn stop(&mut self) {
        if !matches!(self.state, RakServerState::Running(_)) {
            return;
        }

        let RakServerState::Running(Running { handle, msg_tx, .. }) =
            std::mem::replace(&mut self.state, RakServerState::Shutdown)
        else {
            unreachable!()
        };

        let _ = msg_tx.send(RakServerMsg::Stop);
        let _ = handle.await;
    }

    /// Resumes a session captured with [`crate::session::RakSession::snapshot`] on
    /// another server, returning its handle here.
    pub async fn adopt(
        &mut self,
        snapshot: RakSessionSnapshot,
    ) -> Result<RakSession, RakServerError> {
        let RakServerState::Running(Running { msg_tx, .. }) = &self.state else {
            return Err(RakServerError::Closed);
        };

        let session = RakSessionIntl::restore(snapshot)?;
        let (tx, rx) = tokio::sync::oneshot::channel();

        msg_tx
            .send(RakServerMsg::Adopt(session, tx))
            .map_err(|_| RakServerError::Closed)?;

        rx.await.map_err(|_| RakServerError::Closed)
    }

    pub async fn accept(&mut self) -> Result<RakSession, RakServerError> {
        let RakServerState::Running(Running { session_rx, .. }) = &mut self.state else {
            return Err(RakServerError::Closed);
        };

        session_rx.recv().await.ok_or(RakServerError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn rak_server() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_test_writer()
            .compact()
            .try_init();

        let mut server = RakServer::new("127.0.0.1:19132".parse().unwrap(), |config| {
            config.guid = 123456789;
            config.message = Box::new(*b"MCPE;Chorus;0;1.0.0;0;-1;123456789;Chorus;Survival");
        });

        let _ = server.start().await;

        let mut sessions = Vec::new();

        loop {
            tokio::select! {
                Ok(session) = server.accept() => {
                    sessions.push(session);
                    debug!("received session")
                }
            }
        }
    }
}
