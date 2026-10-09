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
use crate::protocol::packets::unconnected_ping::UnconnectedPing;
use crate::protocol::packets::unconnected_pong::UnconnectedPong;
use crate::sans::Sans;
use crate::session::RakSessionId;
use crate::util::{constants, packet_id};
use std::cmp::min;
use std::collections::VecDeque;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

#[derive(Clone, Debug)]
pub struct RakClient {
    config: RakClientConfig,

    state: RakClientState,
    attempts: usize,
    mtu: u16,
    cookie: Option<i32>,
    session: Option<RakSession>,

    connect_started: SystemTime,
    last_attempt: SystemTime,

    output: VecDeque<RakClientOutput>,
}

impl Sans for RakClient {
    type Input = RakClientInput;
    type Output = RakClientOutput;
    type Error = RakClientError;

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            RakClientInput::Ping(addr, now) => {
                if !matches!(self.state, RakClientState::Unconnected) {
                    return Ok(());
                }

                let ping = UnconnectedPing {
                    timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
                    client: self.config.guid,
                };

                let mut buf = Vec::with_capacity(ping.size_hint());
                ping.serialize(&mut buf)?;
                let buf = buf.into_boxed_slice();

                self.output
                    .push_back(RakClientOutput::SocketDatagram(buf, addr))
            }
            RakClientInput::Connect(remote, now) => {
                if !matches!(self.state, RakClientState::Unconnected) {
                    return Ok(());
                }

                self.state = RakClientState::Handshake1(remote);
                self.attempts = 0;
                self.connect_started = now;
                self.last_attempt = now
                    .checked_sub(self.config.conn_attempt_interval)
                    .unwrap_or(now);

                self.handle_timeout(now)?;
            }
            RakClientInput::Datagram(buf, addr, now) => match self.state {
                RakClientState::HandshakeCompleted(remote) => {
                    if remote != addr {
                        return Ok(());
                    }

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
                                                        remote,
                                                        &mut cursor,
                                                        now,
                                                    )?;
                                                    success = Some(true);
                                                }
                                                packet_id::CONNECTION_ATTEMPT_FAILED => {
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
                                debug!("connection attempt failed");
                                return Err(RakClientError::ConnectionAttemptFailed);
                            }
                        }
                    }
                }
                RakClientState::Unconnected => {
                    if let Some(&b) = buf.first() {
                        let mut cursor = Cursor::new(buf.as_ref());
                        if b == packet_id::UNCONNECTED_PONG {
                            let pong = UnconnectedPong::deserialize(&mut cursor)?;

                            self.output.push_back(RakClientOutput::Pong(
                                addr,
                                pong.message,
                                UNIX_EPOCH + Duration::from_millis(pong.timestamp),
                            ))
                        }
                    }
                }
                RakClientState::Handshake1(remote) | RakClientState::Handshake2(remote) => {
                    if remote != addr {
                        return Ok(());
                    }

                    if let Some(&b) = buf.first() {
                        let mut cursor = Cursor::new(buf.as_ref());
                        match b {
                            packet_id::OPEN_CONNECTION_REPLY_1 => {
                                self.handle_open_connection_reply_1(remote, &mut cursor)?
                            }
                            packet_id::OPEN_CONNECTION_REPLY_2 => {
                                self.handle_open_connection_reply_2(remote, &mut cursor, now)?
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
            RakClientInput::Disconnect => {
                self.state = RakClientState::Unconnected;
                self.session = None;
            }
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl RakClient {
    pub fn new(config: RakClientConfig) -> Self {
        Self {
            config,
            state: RakClientState::Unconnected,
            attempts: 0,
            mtu: 0,
            cookie: None,
            session: None,
            connect_started: SystemTime::now(),
            last_attempt: SystemTime::now(),
            output: VecDeque::new(),
        }
    }

    fn handle_timeout(&mut self, now: SystemTime) -> Result<(), RakClientError> {
        let connected =
            matches!(self.state, RakClientState::HandshakeCompleted(_)) && self.session.is_none();
        if connected || matches!(self.state, RakClientState::Unconnected) {
            self.output
                .push_back(RakClientOutput::Wait(self.config.conn_attempt_interval));

            return Ok(());
        }

        if now >= self.connect_started + self.config.conn_attempt_timeout {
            debug!(
                "RakClient connection failed after {:?}",
                self.config.conn_attempt_timeout
            );
            return Err(RakClientError::ConnectionFailed);
        }

        if now >= self.last_attempt + self.config.conn_attempt_interval {
            if self.attempts < self.config.conn_attempt_max {
                match self.state {
                    RakClientState::Handshake1(addr) => {
                        self.send_open_connection_request_1(addr)?;
                        self.attempts += 1;
                        self.last_attempt = now;
                    }
                    RakClientState::Handshake2(addr) => {
                        self.send_open_connection_request_2(addr)?;
                        self.attempts += 1;
                        self.last_attempt = now;
                    }
                    _ => {}
                }
            } else {
                debug!(
                    "RakClient connection failed after {} attempts",
                    self.attempts
                );
                return Err(RakClientError::ConnectionFailed);
            }
        }

        let timeout = self.connect_started + self.config.conn_attempt_timeout;
        let next = match self.state {
            RakClientState::HandshakeCompleted(_) => timeout,
            _ => min(
                self.last_attempt + self.config.conn_attempt_interval,
                timeout,
            ),
        };

        let duration = next.duration_since(now).unwrap_or(Duration::from_secs(0));

        self.output.push_back(RakClientOutput::Wait(duration));

        Ok(())
    }

    fn send_open_connection_request_1(&mut self, addr: SocketAddr) -> Result<(), RakClientError> {
        let index = self.attempts.min(constants::MTU_SIZES.len() - 1);
        let mtu = constants::MTU_SIZES[constants::MTU_SIZES.len() - 1 - index]
            .clamp(self.config.min_mtu_size, self.config.max_mtu_size);

        let req = OpenConnectionRequest1 {
            protocol: self.config.protocol,
            mtu,
        };

        let mut buf = Vec::with_capacity(req.size_hint());
        req.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakClientOutput::SocketDatagram(buf, addr));

        Ok(())
    }

    fn handle_open_connection_reply_1(
        &mut self,
        addr: SocketAddr,
        buf: &mut Cursor<&[u8]>,
    ) -> Result<(), RakClientError> {
        let reply = OpenConnectionReply1::deserialize(buf)?;

        self.mtu = self.negotiated_mtu(reply.mtu)?;
        self.cookie = reply.cookie;
        self.state = RakClientState::Handshake2(addr);

        self.send_open_connection_request_2(addr)?;

        Ok(())
    }

    fn negotiated_mtu(&self, mtu: u16) -> Result<u16, RakClientError> {
        if mtu < self.config.min_mtu_size.max(constants::MIN_MTU_SIZE) {
            debug!("RakClient refusing server mtu size of {}", mtu);
            return Err(RakClientError::InvalidMtu(mtu));
        }
        Ok(mtu.min(self.config.max_mtu_size))
    }

    fn send_open_connection_request_2(&mut self, addr: SocketAddr) -> Result<(), RakClientError> {
        let req = OpenConnectionRequest2 {
            cookie: self.cookie,
            addr,
            mtu: self.mtu,
            client: self.config.guid,
        };

        let mut buf = Vec::with_capacity(req.size_hint());
        req.serialize(&mut buf)?;
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakClientOutput::SocketDatagram(buf, addr));

        Ok(())
    }

    fn handle_open_connection_reply_2(
        &mut self,
        addr: SocketAddr,
        buf: &mut Cursor<&[u8]>,
        now: SystemTime,
    ) -> Result<(), RakClientError> {
        let reply = OpenConnectionReply2::deserialize(buf)?;

        if reply.security {
            debug!("RakClient failed to connect due to security exception");
            return Err(RakClientError::SecurityUnsupported);
        }

        self.mtu = self.negotiated_mtu(reply.mtu)?;
        self.state = RakClientState::HandshakeCompleted(addr);

        debug!(
            "establishing connection to {} with mtu size of {}",
            addr, self.mtu
        );

        let mut session =
            RakSession::new(RakSessionId(0), addr, self.config.guid, self.mtu, |_| {});

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
            if let RakSessionOutput::Datagram(buf, addr) = msg {
                self.output
                    .push_back(RakClientOutput::SocketDatagram(buf, addr))
            }
        }

        self.session = Some(session);

        Ok(())
    }

    /// Takes over a session from another client, continuing its protocol state rather
    /// than handshaking the peer again.
    pub fn adopt(&mut self, session: RakSession) -> Result<(), RakClientError> {
        if !matches!(self.state, RakClientState::Unconnected) {
            return Err(RakClientError::AlreadyConnected);
        }

        let addr = session.addr;

        self.mtu = session.mtu;
        self.state = RakClientState::HandshakeCompleted(addr);

        debug!("adopting a session with {} at mtu {}", addr, self.mtu);

        self.output
            .push_back(RakClientOutput::SessionConnected(Box::new(session)));

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

#[cfg(test)]
mod tests {
    use super::*;

    fn last_datagram_len(client: &mut RakClient) -> u16 {
        let mut len = 0;
        while let Some(RakClientOutput::SocketDatagram(buf, _)) = client.poll() {
            len = buf.len() as u16;
        }
        len
    }

    #[test]
    fn mtu_negotiation_starts_high_and_shrinks() {
        let mut client = RakClient::new(RakClientConfig::default());
        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();

        client.attempts = 0;
        client.send_open_connection_request_1(addr).unwrap();
        assert_eq!(last_datagram_len(&mut client), constants::MAX_MTU_SIZE);

        client.attempts = 1;
        client.send_open_connection_request_1(addr).unwrap();
        assert_eq!(last_datagram_len(&mut client), 1200);

        client.attempts = 2;
        client.send_open_connection_request_1(addr).unwrap();
        assert_eq!(last_datagram_len(&mut client), constants::MIN_MTU_SIZE);

        client.attempts = 9;
        client.send_open_connection_request_1(addr).unwrap();
        assert_eq!(last_datagram_len(&mut client), constants::MIN_MTU_SIZE);
    }

    #[test]
    fn overall_connect_timeout_fails_regardless_of_attempts() {
        let mut client = RakClient::new(RakClientConfig {
            conn_attempt_timeout: Duration::from_millis(100),
            conn_attempt_interval: Duration::from_millis(1000),
            conn_attempt_max: 100,
            ..RakClientConfig::default()
        });

        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let start = SystemTime::now();

        client.handle(RakClientInput::Connect(addr, start)).unwrap();

        let result = client.handle(RakClientInput::Update(start + Duration::from_millis(200)));

        assert!(matches!(result, Err(RakClientError::ConnectionFailed)));
    }

    fn last_wait(client: &mut RakClient) -> Option<Duration> {
        let mut wait = None;
        while let Some(out) = client.poll() {
            if let RakClientOutput::Wait(duration) = out {
                wait = Some(duration);
            }
        }
        wait
    }

    #[test]
    fn connected_client_schedules_a_wait_instead_of_spinning() {
        let mut client = RakClient::new(RakClientConfig::default());
        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let start = SystemTime::now();

        client.handle(RakClientInput::Connect(addr, start)).unwrap();
        last_wait(&mut client);
        client.state = RakClientState::HandshakeCompleted(addr);

        for elapsed in [Duration::from_secs(2), Duration::from_secs(20)] {
            let result = client.handle(RakClientInput::Update(start + elapsed));
            assert!(
                result.is_ok(),
                "update {elapsed:?} after connecting failed: {result:?}"
            );

            let wait = last_wait(&mut client);
            assert!(
                wait.is_some_and(|w| w > Duration::ZERO),
                "update {elapsed:?} after connecting scheduled {wait:?}"
            );
        }
    }

    #[test]
    fn disconnect_input_allows_reconnect() {
        let mut client = RakClient::new(RakClientConfig::default());
        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();

        client.state = RakClientState::HandshakeCompleted(addr);

        client
            .handle(RakClientInput::Connect(addr, SystemTime::now()))
            .unwrap();
        assert!(matches!(
            client.state,
            RakClientState::HandshakeCompleted(_)
        ));

        client.handle(RakClientInput::Disconnect).unwrap();
        assert!(matches!(client.state, RakClientState::Unconnected));

        client
            .handle(RakClientInput::Connect(addr, SystemTime::now()))
            .unwrap();
        assert!(matches!(client.state, RakClientState::Handshake1(_)));
    }

    fn encoded(packet: impl RakCodec) -> Box<[u8]> {
        let mut buf = Vec::with_capacity(packet.size_hint());
        packet.serialize(&mut buf).unwrap();
        buf.into_boxed_slice()
    }

    fn reply_1(mtu: u16) -> Box<[u8]> {
        encoded(OpenConnectionReply1 {
            guid: 1,
            cookie: None,
            mtu,
        })
    }

    fn reply_2(addr: SocketAddr, mtu: u16) -> Box<[u8]> {
        encoded(OpenConnectionReply2::new(1, addr, mtu, false))
    }

    #[test]
    fn reply_1_below_the_minimum_mtu_is_rejected() {
        let mut client = RakClient::new(RakClientConfig::default());
        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        client.state = RakClientState::Handshake1(addr);

        let result = client.handle(RakClientInput::Datagram(
            reply_1(20),
            addr,
            SystemTime::now(),
        ));

        assert!(
            matches!(result, Err(RakClientError::InvalidMtu(20))),
            "got {result:?}"
        );
    }

    #[test]
    fn reply_2_below_the_minimum_mtu_is_rejected() {
        let mut client = RakClient::new(RakClientConfig::default());
        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        client.state = RakClientState::Handshake2(addr);

        let result = client.handle(RakClientInput::Datagram(
            reply_2(addr, 20),
            addr,
            SystemTime::now(),
        ));

        assert!(
            matches!(result, Err(RakClientError::InvalidMtu(20))),
            "got {result:?}"
        );
        assert!(client.session.is_none());
    }

    #[test]
    fn reply_2_above_the_maximum_mtu_is_clamped() {
        let mut client = RakClient::new(RakClientConfig::default());
        let addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        client.state = RakClientState::Handshake2(addr);

        client
            .handle(RakClientInput::Datagram(
                reply_2(addr, u16::MAX),
                addr,
                SystemTime::now(),
            ))
            .unwrap();

        assert_eq!(client.mtu, constants::MAX_MTU_SIZE);
        while let Some(out) = client.poll() {
            if let RakClientOutput::SocketDatagram(buf, _) = out {
                assert!(buf.len() <= constants::MAX_MTU_SIZE as usize);
            }
        }
    }
}
