pub mod config;
pub mod error;
pub mod input;
pub mod output;
pub mod state;

use crate::client::config::RakClientConfig;
use crate::client::error::RakClientError;
use crate::client::input::RakClientInput;
use crate::client::output::RakClientOutput;
use crate::client::state::RakClientState;
use crate::prelude::{
    RakPriority, RakReliability, RakSession, RakSessionInput, RakSessionOutput, RakSessionState,
};
use crate::protocol::codec::RakCodec;
use crate::protocol::packets::connection_request::ConnectionRequest;
use crate::protocol::packets::connection_request_accepted::ConnectionRequestAccepted;
use crate::protocol::packets::new_incoming_connection::NewIncomingConnection;
use crate::protocol::packets::open_connection_reply_1::OpenConnectionReply1;
use crate::protocol::packets::open_connection_reply_2::OpenConnectionReply2;
use crate::protocol::packets::open_connection_request_1::OpenConnectionRequest1;
use crate::protocol::packets::open_connection_request_2::OpenConnectionRequest2;
use crate::sans::Sans;
use crate::session::RakSessionId;
use crate::util::packet_id;
use std::collections::VecDeque;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

pub struct RakClient {
    addr: SocketAddr,
    config: RakClientConfig,

    state: RakClientState,
    attempts: usize,
    mtu: u16,
    cookie: Option<i32>,
    session: Option<RakSession>,

    last_attempt: SystemTime,

    output: VecDeque<RakClientOutput>,
}

impl Sans for RakClient {
    type Input = RakClientInput;
    type Output = RakClientOutput;
    type Error = RakClientError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            RakClientInput::Datagram(buf, addr, now) => match self.state {
                RakClientState::HandshakeCompleted => {
                    let mut success: Option<bool> = None;
                    match self.session.as_mut() {
                        Some(session) => {
                            session.handle(RakSessionInput::Datagram(buf, now))?;

                            while let Some(msg) = session.poll() {
                                match msg {
                                    RakSessionOutput::Datagram(buf, addr) => self
                                        .output
                                        .push_back(RakClientOutput::SocketDatagram(buf, addr)),
                                    RakSessionOutput::Packet(buf) => {
                                        if let Some(&b) = buf.first() {
                                            let mut cursor = Cursor::new(buf.as_ref());
                                            match b {
                                                packet_id::CONNECTION_REQUEST_ACCEPTED => {
                                                    Self::handle_connection_request_accepted(
                                                        session,
                                                        addr,
                                                        &mut cursor,
                                                        now,
                                                    )?;
                                                    success = Some(true);
                                                }
                                                packet_id::CONNECTION_REQUEST_FAILED => {
                                                    session
                                                        .handle(RakSessionInput::Disconnect(now))?;
                                                    success = Some(false);
                                                }
                                                _ => {
                                                    debug!(
                                                        "unexpected packet {:02X} received from {} during connection phase",
                                                        b, addr
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        None => self.output.push_back(RakClientOutput::SessionDatagram(buf)),
                    }

                    if let Some(succeeded) = success
                        && let Some(session) = self.session.take()
                    {
                        match succeeded {
                            true => self
                                .output
                                .push_back(RakClientOutput::SessionConnected(Box::new(session))),
                            false => {
                                debug!("connection request failed");
                                return Err(RakClientError::ConnectionRequestFailed);
                            }
                        }
                    }
                }
                _ => {
                    if let Some(&b) = buf.first() {
                        let mut cursor = Cursor::new(buf.as_ref());
                        match b {
                            packet_id::OPEN_CONNECTION_REPLY_1 => {
                                self.handle_open_connection_reply_1(&mut cursor)?
                            }
                            packet_id::OPEN_CONNECTION_REPLY_2 => {
                                self.handle_open_connection_reply_2(&mut cursor, now)?
                            }
                            packet_id::INCOMPATIBLE_PROTOCOL => {
                                debug!(
                                    "RakClient connection failed due to incompatible protocol version"
                                );
                                return Err(RakClientError::IncompatibleProtocol);
                            }
                            packet_id::ALREADY_CONNECTED => {
                                debug!(
                                    "RakClient connection failed because this IP is already connected"
                                );
                                return Err(RakClientError::AlreadyConnected);
                            }
                            packet_id::NO_FREE_INCOMING_CONNECTIONS => {
                                debug!(
                                    "RakClient connection failed because the server has no free connections"
                                );
                                return Err(RakClientError::NoFreeIncomingConnections);
                            }
                            packet_id::IP_RECENTLY_CONNECTED => {
                                debug!(
                                    "RakClient connection failed because this IP recently connected"
                                );
                                return Err(RakClientError::RecentlyConnected);
                            }
                            _ => {}
                        }
                    }
                }
            },
            RakClientInput::Update(now) => self.handle_timeout(now)?,
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl RakClient {
    fn handle_timeout(&mut self, now: SystemTime) -> Result<(), RakClientError> {
        if now >= self.last_attempt + self.config.conn_attempt_interval {
            if self.attempts < self.config.conn_attempt_max {
                match self.state {
                    RakClientState::Handshake1 => {
                        self.send_open_connection_request_1()?;
                        self.attempts += 1;
                        self.last_attempt = now;
                    }
                    RakClientState::Handshake2 => self.send_open_connection_request_2()?,
                    RakClientState::HandshakeCompleted => {}
                }
            } else {
                debug!(
                    "RakClient connection failed after {} attempts",
                    self.attempts
                );
                return Err(RakClientError::ConnectionFailed);
            }
        }

        Ok(())
    }

    fn send_open_connection_request_1(&mut self) -> Result<(), RakClientError> {
        let idx = self.attempts / (self.config.conn_attempt_max / self.config.mtu_sizes.len());
        let mtu = self.config.mtu_sizes[idx];

        let req = OpenConnectionRequest1 {
            protocol: self.config.protocol,
            mtu,
        };

        let mut buf = Vec::with_capacity(req.size_hint());
        req.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakClientOutput::SocketDatagram(buf, self.addr));

        Ok(())
    }

    fn handle_open_connection_reply_1(
        &mut self,
        buf: &mut Cursor<&[u8]>,
    ) -> Result<(), RakClientError> {
        let reply = OpenConnectionReply1::deserialize(buf)?;

        self.mtu = reply.mtu;
        self.state = RakClientState::Handshake2;

        self.send_open_connection_request_2()?;

        Ok(())
    }

    fn send_open_connection_request_2(&mut self) -> Result<(), RakClientError> {
        let req = OpenConnectionRequest2 {
            cookie: self.cookie,
            addr: self.addr,
            mtu: self.mtu,
            client: self.config.guid,
        };

        let mut buf = Vec::with_capacity(req.size_hint());
        req.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakClientOutput::SocketDatagram(buf, self.addr));

        Ok(())
    }

    fn handle_open_connection_reply_2(
        &mut self,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakClientError> {
        let reply = OpenConnectionReply2::deserialize(buf)?;

        if (reply.security) {
            debug!("RakClient failed to connect due to security exception");
            return Err(RakClientError::SecurityUnsupported);
        }

        self.mtu = reply.mtu;
        self.state = RakClientState::HandshakeCompleted;

        debug!(
            "establishing connection to {} with mtu size of {}",
            self.addr, self.mtu
        );

        let mut session = RakSession::new(
            RakSessionId(0),
            self.addr,
            self.config.guid,
            self.mtu,
            |_| {},
        );

        let req = ConnectionRequest {
            security: false,
            client_timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
            client_guid: self.config.guid,
        };

        let mut buf = Vec::with_capacity(req.size_hint());
        req.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        session.handle(RakSessionInput::Send(
            buf,
            RakReliability::ReliableOrdered,
            RakPriority::Immediate,
            now,
        ))?;

        while let Some(msg) = session.poll() {
            match msg {
                RakSessionOutput::Datagram(buf, addr) => self
                    .output
                    .push_back(RakClientOutput::SocketDatagram(buf, addr)),
                _ => {}
            }
        }

        self.session = Some(session);

        Ok(())
    }

    fn handle_connection_request_accepted(
        session: &mut RakSession,
        addr: SocketAddr,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakClientError> {
        let acc = ConnectionRequestAccepted::deserialize(buf)?;

        session.state = RakSessionState::Connected;

        let incoming = NewIncomingConnection {
            server_address: addr,
            internal_addresses: vec![
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
                10
            ],
            incoming_timestamp: acc.timestamp,
            server_timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
        };

        let mut buf = Vec::with_capacity(incoming.size_hint());
        incoming.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        session.handle(RakSessionInput::Send(
            buf,
            RakReliability::ReliableOrdered,
            RakPriority::Immediate,
            now,
        ))?;

        Ok(())
    }
}
