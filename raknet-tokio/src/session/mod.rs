pub mod command;

use crate::session::command::RakSessionMsg;
use raknet::prelude::{RakSession as RakSessionIntl, *};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep};
use tracing::debug;

pub struct RakSession {
    pub(crate) msg_tx: UnboundedSender<RakSessionMsg>,
    pub(crate) buf_rx: UnboundedReceiver<Box<[u8]>>,
    pub(crate) addr: SocketAddr,
}

impl RakSession {
    pub(crate) fn spawn(
        session: RakSessionIntl,
        datagram_tx: UnboundedSender<(Box<[u8]>, SocketAddr)>,
    ) -> (Self, UnboundedSender<RakSessionInput>) {
        let (msg_tx, msg_rx) = unbounded_channel();
        let (buf_tx, buf_rx) = unbounded_channel();
        let (tx, rx) = unbounded_channel();

        let addr = session.addr;

        tokio::spawn(async move {
            let mut msg_rx = msg_rx;
            let mut rx = rx;
            let mut session = session;

            let timeout = sleep(Duration::ZERO);
            tokio::pin!(timeout);

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
                                let closed = matches!(session.get_state(), RakSessionState::Disconnected);
                                let _ = sender.send(closed);
                            },
                        }
                    }
                    Some(recv) = rx.recv() => {
                        let _ = session.handle(recv);
                    }
                    _ = &mut timeout => {
                        let now = SystemTime::now();

                        let _ = session.handle(RakSessionInput::Timeout(now));
                    }
                }

                while let Some(out) = session.poll() {
                    match out {
                        RakSessionOutput::Timeout(when) => {
                            timeout.as_mut().reset(Instant::now() + when)
                        }
                        RakSessionOutput::Datagram(buf, addr) => {
                            let _ = datagram_tx.send((buf, addr));
                        }
                        RakSessionOutput::Packet(buf) => {
                            let Some(&b) = buf.first() else {
                                continue;
                            };
                            debug!("received packet 0x{:02X} from {}", b, session.addr);

                            let _ = buf_tx.send(buf);
                        }
                        RakSessionOutput::Disconnected(..) => return,
                    }
                }
            }
        });

        (
            Self {
                msg_tx,
                buf_rx,
                addr,
            },
            tx,
        )
    }

    pub async fn recv<T>(&mut self) -> Option<T>
    where
        Box<[u8]>: Into<T>,
    {
        self.buf_rx.recv().await.map(Into::into)
    }

    pub async fn send<T>(&self, buf: T, reliability: RakReliability, priority: RakPriority) -> Result<(), RakSessionError>
    where
        T: Into<Box<[u8]>>,
    {
        let (tx, rx) = oneshot::channel();
        
        self.msg_tx.send(RakSessionMsg::Send(buf.into(), reliability, priority, tx)).map_err(|_| RakSessionError::Closed)?;
        rx.await.map_err(|_| RakSessionError::Closed)?
    }

    pub async fn close(&self) -> Result<(), RakSessionError> {
        let (tx, rx) = oneshot::channel();
        
        self.msg_tx.send(RakSessionMsg::Close(tx)).map_err(|_| RakSessionError::Closed)?;
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
}
