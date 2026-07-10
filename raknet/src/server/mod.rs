pub mod config;
pub mod error;
pub mod input;
pub mod output;

use crate::protocol::codec::RakCodec;
use crate::protocol::packets::connection_request::ConnectionRequest;
use crate::protocol::packets::connection_request_accepted::ConnectionRequestAccepted;
use crate::protocol::packets::incompatible_protocol::IncompatibleProtocol;
use crate::protocol::packets::new_incoming_connection::NewIncomingConnection;
use crate::protocol::packets::open_connection_reply_1::OpenConnectionReply1;
use crate::protocol::packets::open_connection_reply_2::OpenConnectionReply2;
use crate::protocol::packets::open_connection_request_1::OpenConnectionRequest1;
use crate::protocol::packets::open_connection_request_2::OpenConnectionRequest2;
use crate::protocol::packets::unconnected_ping::UnconnectedPing;
use crate::protocol::packets::unconnected_pong::UnconnectedPong;
use crate::sans::Sans;
use crate::server::error::RakServerError;
use crate::server::input::RakServerInput;
use crate::session::input::RakSessionInput;
use crate::session::output::RakSessionOutput;
use crate::session::state::RakSessionState;
use crate::session::{RakSession, RakSessionId};
use crate::types::priority::RakPriority;
use crate::types::reliability::RakReliability;
use crate::util::socket_addr::get_overhead;
use crate::util::{constants, flags, packet_id};
use config::RakServerConfig;
use output::RakServerOutput;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

pub struct RakServer {
    addr: SocketAddr,
    config: RakServerConfig,

    session_id: RakSessionId,
    session_map: HashMap<SocketAddr, RakSessionId>,
    session_temp: HashMap<SocketAddr, RakSession>,

    output: VecDeque<RakServerOutput>,
}

impl Sans for RakServer {
    type Input = RakServerInput;
    type Output = RakServerOutput;
    type Error = RakServerError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            RakServerInput::Datagram(buf, addr, now) => {
                let Some(&header) = buf.first() else {
                    return Ok(());
                };

                match header & flags::VALID {
                    0 => self.handle_offline_datagram(&buf, addr)?,
                    _ => self.handle_online_datagram(buf, addr, now)?,
                }
            }
            RakServerInput::SetMaxConnections(n) => {
                self.config.max_connections = n;
            }
            RakServerInput::SetMessage(msg) => {
                self.config.message = msg;
            }
        };
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl RakServer {
    pub fn new(config: RakServerConfig, addr: SocketAddr) -> Self {
        Self {
            config,
            addr,

            session_id: RakSessionId(0),
            session_map: HashMap::new(),
            session_temp: HashMap::new(),

            output: VecDeque::new(),
        }
    }

    fn handle_offline_datagram(
        &mut self,
        buf: &[u8],
        addr: SocketAddr,
    ) -> Result<(), RakServerError> {
        if let Some(&id) = buf.first() {
            let mut cursor = Cursor::new(buf);
            match id {
                packet_id::UNCONNECTED_PING => self.handle_unconnected_ping(&mut cursor, addr)?,
                packet_id::OPEN_CONNECTION_REQUEST_1 => {
                    self.handle_open_connection_request_1(&mut cursor, addr)?
                }
                packet_id::OPEN_CONNECTION_REQUEST_2 => {
                    self.handle_open_connection_request_2(&mut cursor, addr)?
                }
                _ => debug!(
                    "received unknown offline packet from {}, id: {:#04X}",
                    addr, id
                ),
            }
        }
        Ok(())
    }

    fn handle_online_datagram(
        &mut self,
        buf: Box<[u8]>,
        addr: SocketAddr,
        now: SystemTime,
    ) -> Result<(), RakServerError> {
        if let Entry::Occupied(mut entry) = self.session_temp.entry(addr) {
            let mut success = false;

            let session = entry.get_mut();

            session.handle(RakSessionInput::Datagram(buf, now))?;

            while let Some(msg) = session.poll() {
                match msg {
                    RakSessionOutput::Datagram(buf, addr) => self
                        .output
                        .push_back(RakServerOutput::SocketDatagram(buf, addr)),
                    RakSessionOutput::Packet(buf) => {
                        if let Some(&b) = buf.first() {
                            let mut cursor = Cursor::new(buf.as_ref());
                            match b {
                                packet_id::CONNECTION_REQUEST => Self::handle_connection_request(
                                    session,
                                    addr,
                                    &mut cursor,
                                    now,
                                )?,
                                packet_id::NEW_INCOMING_CONNECTION => {
                                    Self::handle_new_incoming_connection(
                                        session,
                                        addr,
                                        &mut cursor,
                                    )?;

                                    success = true;
                                    break;
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

            if success {
                let session = entry.remove();
                self.output
                    .push_back(RakServerOutput::SessionConnected(Box::new(session)));
            }

            return Ok(());
        }

        if let Some(&id) = self.session_map.get(&addr) {
            self.output
                .push_back(RakServerOutput::SessionDatagram(buf, id));
        }
        Ok(())
    }

    fn handle_unconnected_ping(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        addr: SocketAddr,
    ) -> Result<(), RakServerError> {
        let ping = UnconnectedPing::deserialize(cursor)?;

        let pong = UnconnectedPong {
            timestamp: ping.timestamp,
            guid: self.config.guid,
            message: self.config.message.clone(),
        };

        let mut buf = Vec::with_capacity(UnconnectedPong::size_hint(&pong));
        UnconnectedPong::serialize(&pong, &mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakServerOutput::SocketDatagram(buf, addr));
        Ok(())
    }

    fn handle_open_connection_request_1(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        addr: SocketAddr,
    ) -> Result<(), RakServerError> {
        let request = OpenConnectionRequest1::deserialize(cursor)?;

        let req_protocol = request.protocol;
        if req_protocol != constants::PROTOCOL {
            let incompatible = IncompatibleProtocol {
                protocol: constants::PROTOCOL,
                guid: self.config.guid,
            };

            debug!(
                "refusing connection from {} due to incompatible protocol {}, expected {}",
                addr,
                req_protocol,
                constants::PROTOCOL
            );

            let mut buf = Vec::with_capacity(IncompatibleProtocol::size_hint(&incompatible));
            IncompatibleProtocol::serialize(&incompatible, &mut buf)?;
            let buf = buf.into_boxed_slice();

            self.output
                .push_back(RakServerOutput::SocketDatagram(buf, addr));

            return Ok(());
        }

        let reply = OpenConnectionReply1 {
            guid: self.config.guid,
            cookie: None,
            mtu: (request.mtu + constants::UDP_HEADER_SIZE + get_overhead(&addr))
                .clamp(self.config.min_mtu_size, self.config.max_mtu_size),
        };

        let mut buf = Vec::with_capacity(OpenConnectionReply1::size_hint(&reply));
        OpenConnectionReply1::serialize(&reply, &mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakServerOutput::SocketDatagram(buf, addr));

        Ok(())
    }

    fn handle_open_connection_request_2(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        addr: SocketAddr,
    ) -> Result<(), RakServerError> {
        let request = OpenConnectionRequest2::deserialize(cursor)?;

        if request.addr.port() != self.addr.port() {
            return Err(RakServerError::RefusingConnection(format!(
                "refusing connection from {} due to port mismatch",
                addr
            )));
        }

        let mtu = request.mtu;

        if !(self.config.min_mtu_size..=self.config.max_mtu_size).contains(&mtu) {
            return Err(RakServerError::RefusingConnection(format!(
                "refusing connection from {} due to invalid mtu size",
                addr
            )));
        }

        if self.session_map.contains_key(&addr) {
            return Err(RakServerError::RefusingConnection(format!(
                "refusing connection from {} due to existing connection",
                addr
            )));
        }

        debug!(
            "establishing connection from {} with mtu size of {}",
            addr, mtu
        );

        let reply = OpenConnectionReply2::new(self.config.guid, addr, mtu, false);

        let mut buf = Vec::with_capacity(OpenConnectionReply2::size_hint(&reply));
        OpenConnectionReply2::serialize(&reply, &mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakServerOutput::SocketDatagram(buf, addr));

        let id = self.session_id;
        self.session_id.0 += 1;

        self.session_map.insert(addr, id);
        self.session_temp.insert(
            addr,
            RakSession::new(id, addr, request.client, request.mtu, |_| ()),
        );
        Ok(())
    }

    fn handle_connection_request(
        session: &mut RakSession,
        addr: SocketAddr,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakServerError> {
        let request = ConnectionRequest::deserialize(buf)?;

        debug!("handling connection request from {}", addr);

        let accepted = ConnectionRequestAccepted {
            client_address: addr,
            system_index: 0,
            system_addresses: vec![],
            request_timestamp: request.client_timestamp,
            timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
        };

        let mut buf = Vec::with_capacity(ConnectionRequestAccepted::size_hint(&accepted));
        ConnectionRequestAccepted::serialize(&accepted, &mut buf)?;
        let buf = buf.into_boxed_slice();

        let reliability = RakReliability::ReliableOrdered;
        let priority = RakPriority::Immediate;
        session.handle(RakSessionInput::Send(buf, reliability, priority, now))?;
        Ok(())
    }

    fn handle_new_incoming_connection(
        session: &mut RakSession,
        addr: SocketAddr,
        buf: &mut Cursor<&[u8]>,
    ) -> Result<(), RakServerError> {
        let _ = NewIncomingConnection::deserialize(buf)?;

        debug!("handling new incoming connection from {}", addr);

        session.state = RakSessionState::Connected;

        Ok(())
    }
}
