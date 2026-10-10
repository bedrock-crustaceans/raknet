pub mod command;

use crate::session::command::RakSessionMsg;
use raknet::prelude::{RakSession as RakSessionIntl, *};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep};

pub struct RakSession {
    pub(crate) msg_tx: UnboundedSender<RakSessionMsg>,
    pub(crate) buf_rx: UnboundedReceiver<Box<[u8]>>,
    pub(crate) addr: SocketAddr,
    pub(crate) max_message_len: usize,
}

impl RakSession {
    pub(crate) fn spawn(
        session: RakSessionIntl,
        datagram_tx: UnboundedSender<(Box<[u8]>, SocketAddr)>,
        disconnect_tx: UnboundedSender<RakSessionId>,
    ) -> (Self, UnboundedSender<RakSessionInput>) {
        let (msg_tx, msg_rx) = unbounded_channel();
        let (buf_tx, buf_rx) = unbounded_channel();
        let (tx, rx) = unbounded_channel();

        let addr = session.addr;
        let id = session.id;
        let max_message_len = session.max_message_len();

        tokio::spawn(async move {
            let mut msg_rx = msg_rx;
            let mut rx = rx;
            let mut session = session;

            let timer = sleep(Duration::ZERO);
            tokio::pin!(timer);

            loop {
                tokio::select! {
                    Some(msg) = msg_rx.recv() => {
                        match msg {
                            RakSessionMsg::Send(buf, reliability, priority, sender) => {
                                let now = SystemTime::now();

                                let res = session.handle(RakSessionInput::Send(buf, reliability, priority, now));
                                let _ = sender.send(res);
                            }
                            RakSessionMsg::Close(sender) => {
                                let now = SystemTime::now();

                                let res = session.handle(RakSessionInput::Disconnect(now));
                                let _ = sender.send(res);
                            }
                            RakSessionMsg::IsClosed(sender) => {
                                let closed = !matches!(session.get_state(), RakSessionState::Connected);
                                let _ = sender.send(closed);
                            },
                            RakSessionMsg::Snapshot(sender) => {
                                let _ = sender.send(session.snapshot());
                            },
                        }
                    }
                    Some(recv) = rx.recv() => {
                        let _ = session.handle(recv);
                    }
                    _ = &mut timer => {
                        let now = SystemTime::now();

                        let _ = session.handle(RakSessionInput::Update(now));
                    }
                }

                while let Some(out) = session.poll() {
                    match out {
                        RakSessionOutput::Wait(when) => timer.as_mut().reset(Instant::now() + when),
                        RakSessionOutput::Datagram(buf, addr) => {
                            let _ = datagram_tx.send((buf, addr));
                        }
                        RakSessionOutput::Packet(buf) => {
                            if buf.is_empty() {
                                continue;
                            }

                            let _ = buf_tx.send(buf);
                        }
                        RakSessionOutput::Disconnected(..) => {
                            let _ = disconnect_tx.send(id);
                            return;
                        }
                    }
                }
            }
        });

        (
            Self {
                msg_tx,
                buf_rx,
                addr,
                max_message_len,
            },
            tx,
        )
    }

    pub async fn recv<T>(&mut self) -> Result<T, RakSessionError>
    where
        Box<[u8]>: Into<T>,
    {
        self.buf_rx
            .recv()
            .await
            .map(Into::into)
            .ok_or(RakSessionError::Closed)
    }

    pub async fn send<T>(
        &self,
        buf: T,
        reliability: RakReliability,
        priority: RakPriority,
    ) -> Result<(), RakSessionError>
    where
        T: Into<Box<[u8]>>,
    {
        let (tx, rx) = oneshot::channel();

        self.msg_tx
            .send(RakSessionMsg::Send(buf.into(), reliability, priority, tx))
            .map_err(|_| RakSessionError::Closed)?;
        rx.await.map_err(|_| RakSessionError::Closed)?
    }

    pub async fn close(&self) -> Result<(), RakSessionError> {
        let (tx, rx) = oneshot::channel();

        self.msg_tx
            .send(RakSessionMsg::Close(tx))
            .map_err(|_| RakSessionError::Closed)?;
        rx.await.map_err(|_| RakSessionError::Closed)?
    }

    pub async fn is_closed(&self) -> bool {
        let (tx, rx) = oneshot::channel();
        let _ = self.msg_tx.send(RakSessionMsg::IsClosed(tx));
        rx.await.unwrap_or(true)
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn max_message_len(&self) -> usize {
        self.max_message_len
    }

    /// Captures this session's protocol state for [`crate::server::RakServer::adopt`].
    ///
    /// The live task keeps running - shutting it down once the target has taken over is
    /// the caller's job, or the two copies diverge.
    pub async fn snapshot(&self) -> Result<RakSessionSnapshot, RakSessionError> {
        let (tx, rx) = oneshot::channel();
        self.msg_tx
            .send(RakSessionMsg::Snapshot(tx))
            .map_err(|_| RakSessionError::Closed)?;
        rx.await.map_err(|_| RakSessionError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn max_message_len_comes_from_the_session_config() {
        let session = RakSessionIntl::new(
            RakSessionId(0),
            "127.0.0.1:19132".parse().unwrap(),
            0,
            1492,
            |conf| conf.max_queued_bytes = 1 << 20,
        );
        let (datagram_tx, _datagram_rx) = unbounded_channel();
        let (disconnect_tx, _disconnect_rx) = unbounded_channel();

        let (session, _input_tx) = RakSession::spawn(session, datagram_tx, disconnect_tx);

        assert_eq!(session.max_message_len(), 1 << 20);
    }
}
