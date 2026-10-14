pub mod config;
pub mod error;
pub mod input;
pub mod output;

use crate::protocol::codec::{RakCodec, RakCodecHelper};
use crate::protocol::packets::already_connected::AlreadyConnected;
use crate::protocol::packets::connection_request::ConnectionRequest;
use crate::protocol::packets::connection_request_accepted::ConnectionRequestAccepted;
use crate::protocol::packets::incompatible_protocol::IncompatibleProtocol;
use crate::protocol::packets::ip_recently_connected::IpRecentlyConnected;
use crate::protocol::packets::new_incoming_connection::NewIncomingConnection;
use crate::protocol::packets::no_free_incoming_connections::NoFreeIncomingConnections;
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
use rand::random;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

const RECENTLY_CONNECTED_COOLDOWN: Duration = Duration::from_millis(5000);
const OFFLINE_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const PENDING_CONNECTION_TIMEOUT: Duration = Duration::from_millis(10_000);
const COOKIE_ROTATION_INTERVAL: Duration = Duration::from_secs(2);

pub struct RakServer {
    addr: SocketAddr,
    config: RakServerConfig,

    session_id: RakSessionId,
    session_map: HashMap<SocketAddr, RakSessionId>,
    session_addr: HashMap<RakSessionId, SocketAddr>,
    session_temp: HashMap<SocketAddr, (SystemTime, RakSession)>,
    recently_disconnected: HashMap<SocketAddr, SystemTime>,

    offline_window: SystemTime,
    offline_total: i32,
    offline_per_ip: HashMap<IpAddr, i32>,

    online_window: SystemTime,
    online_per_ip: HashMap<IpAddr, i32>,
    blocked: HashMap<IpAddr, SystemTime>,

    cookie_key: RandomState,
    cookie_salts: [u64; 2],
    cookie_rotated: SystemTime,

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
                if self.is_blocked(addr.ip(), now) {
                    return Ok(());
                }

                match header & flags::VALID {
                    0 => self.handle_offline_datagram(&buf, addr, now)?,
                    _ => self.handle_online_datagram(buf, addr, now)?,
                }
            }
            RakServerInput::Block(ip, duration, now) => {
                self.blocked.insert(ip.to_canonical(), now + duration);
            }
            RakServerInput::Unblock(ip) => {
                self.blocked.remove(&ip.to_canonical());
            }
            RakServerInput::SetMaxConnections(n) => {
                self.config.max_connections = n;
            }
            RakServerInput::SetMessage(msg) => {
                self.config.message = msg;
            }
            RakServerInput::RemoveSession(id, now) => {
                if let Some(addr) = self.session_addr.remove(&id) {
                    self.session_map.remove(&addr);
                    self.session_temp.remove(&addr);
                    self.recently_disconnected.insert(addr, now);
                }

                self.recently_disconnected
                    .retain(|_, &mut disconnected_at| {
                        now.duration_since(disconnected_at).unwrap_or_default()
                            < RECENTLY_CONNECTED_COOLDOWN
                    });
            }
            RakServerInput::Update(now) => {
                self.rotate_cookie_salt(now);
                self.blocked.retain(|_, until| now < *until);
                self.evict_stale_temp_sessions(now);
                self.tick_temp_sessions(now)?;
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
            session_addr: HashMap::new(),
            session_temp: HashMap::new(),
            recently_disconnected: HashMap::new(),

            offline_window: SystemTime::UNIX_EPOCH,
            offline_total: 0,
            offline_per_ip: HashMap::new(),
            online_window: SystemTime::UNIX_EPOCH,
            online_per_ip: HashMap::new(),
            blocked: HashMap::new(),

            cookie_key: RandomState::new(),
            cookie_salts: [random(), random()],
            cookie_rotated: SystemTime::UNIX_EPOCH,

            output: VecDeque::new(),
        }
    }

    /// Takes over a session from another `RakServer`, continuing its protocol state
    /// rather than handshaking the peer again.
    ///
    /// The session is given a fresh local [`RakSessionId`], since the two servers count
    /// ids independently, and is emitted as [`RakServerOutput::SessionConnected`] so it
    /// arrives through the same `poll()` path as one this server handshaked itself.
    pub fn adopt(&mut self, mut session: RakSession) {
        let id = self.session_id.increment();

        let addr = session.addr;
        session.id = id;

        self.session_map.insert(addr, id);
        self.session_addr.insert(id, addr);

        self.output
            .push_back(RakServerOutput::SessionConnected(Box::new(session)));
    }

    fn rotate_cookie_salt(&mut self, now: SystemTime) {
        let elapsed = now.duration_since(self.cookie_rotated).unwrap_or_default();

        if elapsed >= COOKIE_ROTATION_INTERVAL * 2 {
            self.cookie_salts = [random(), random()];
            self.cookie_rotated = now;
        } else if elapsed >= COOKIE_ROTATION_INTERVAL {
            self.cookie_salts = [random(), self.cookie_salts[0]];
            self.cookie_rotated = now;
        }
    }

    fn cookie(&self, salt: u64, addr: SocketAddr) -> i32 {
        self.cookie_key
            .hash_one((salt, addr.ip().to_canonical(), addr.port())) as i32
    }

    fn cookie_valid(&self, cookie: Option<i32>, addr: SocketAddr) -> bool {
        cookie.is_some_and(|cookie| {
            self.cookie_salts
                .iter()
                .any(|&salt| self.cookie(salt, addr) == cookie)
        })
    }

    fn established_count(&self) -> usize {
        self.session_map
            .len()
            .saturating_sub(self.session_temp.len())
    }

    fn counts_for_ip(&self, ip: IpAddr) -> (usize, usize) {
        let ip = ip.to_canonical();
        let mut pending = 0;
        let mut established = 0;
        for addr in self.session_map.keys() {
            if addr.ip().to_canonical() != ip {
                continue;
            }
            match self.session_temp.contains_key(addr) {
                true => pending += 1,
                false => established += 1,
            }
        }
        (pending, established)
    }

    fn forward_datagrams(&mut self, session: &mut RakSession) {
        while let Some(msg) = session.poll() {
            if let RakSessionOutput::Datagram(buf, addr) = msg {
                self.output
                    .push_back(RakServerOutput::SocketDatagram(buf, addr));
            }
        }
    }

    fn forget(&mut self, addr: SocketAddr) {
        self.session_temp.remove(&addr);
        if let Some(id) = self.session_map.remove(&addr) {
            self.session_addr.remove(&id);
        }
    }

    fn rate_limited(&mut self, addr: SocketAddr, now: SystemTime) -> bool {
        if now.duration_since(self.offline_window).unwrap_or_default() >= OFFLINE_RATE_LIMIT_WINDOW
        {
            self.offline_window = now;
            self.offline_total = 0;
            self.offline_per_ip.clear();
        }

        self.offline_total += 1;
        if self.offline_total > self.config.total_packet_limit {
            return true;
        }

        let count = self
            .offline_per_ip
            .entry(addr.ip().to_canonical())
            .or_insert(0);
        *count += 1;

        *count > self.config.packet_limit
    }

    fn online_rate_limited(&mut self, ip: IpAddr, now: SystemTime) -> bool {
        if now.duration_since(self.online_window).unwrap_or_default()
            >= constants::ONLINE_RATE_LIMIT_WINDOW
        {
            self.online_window = now;
            self.online_per_ip.clear();
        }

        let count = self.online_per_ip.entry(ip.to_canonical()).or_insert(0);
        *count += 1;
        *count > self.config.online_packet_limit
    }

    fn is_blocked(&mut self, ip: IpAddr, now: SystemTime) -> bool {
        let ip = ip.to_canonical();
        match self.blocked.get(&ip) {
            Some(&until) if now < until => true,
            Some(_) => {
                self.blocked.remove(&ip);
                false
            }
            None => false,
        }
    }

    fn tick_temp_sessions(&mut self, now: SystemTime) -> Result<(), RakServerError> {
        let mut closed = Vec::new();

        for (&addr, (_, session)) in self.session_temp.iter_mut() {
            session.handle(RakSessionInput::Update(now))?;

            while let Some(msg) = session.poll() {
                match msg {
                    RakSessionOutput::Datagram(buf, to) => self
                        .output
                        .push_back(RakServerOutput::SocketDatagram(buf, to)),
                    RakSessionOutput::Disconnected(..) => closed.push(addr),
                    _ => {}
                }
            }
        }

        for addr in closed {
            self.forget(addr);
        }
        Ok(())
    }

    fn evict_stale_temp_sessions(&mut self, now: SystemTime) {
        let stale: Vec<SocketAddr> = self
            .session_temp
            .iter()
            .filter(|(_, (created, _))| {
                now.duration_since(*created).unwrap_or_default() >= PENDING_CONNECTION_TIMEOUT
            })
            .map(|(&addr, _)| addr)
            .collect();

        for addr in stale {
            debug!("evicting stale pending connection from {}", addr);

            self.forget(addr);
        }
    }

    fn handle_offline_datagram(
        &mut self,
        buf: &[u8],
        addr: SocketAddr,
        now: SystemTime,
    ) -> Result<(), RakServerError> {
        if self.rate_limited(addr, now) {
            return Ok(());
        }

        if let Some(&id) = buf.first() {
            let mut cursor = Cursor::new(buf);
            match id {
                packet_id::UNCONNECTED_PING => self.handle_unconnected_ping(&mut cursor, addr)?,
                packet_id::OPEN_CONNECTION_REQUEST_1 => {
                    self.handle_open_connection_request_1(&mut cursor, addr, now)?
                }
                packet_id::OPEN_CONNECTION_REQUEST_2 => {
                    self.handle_open_connection_request_2(&mut cursor, addr, now)?
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
        if self.online_rate_limited(addr.ip(), now) {
            debug!(
                "blocking {} for exceeding the online packet limit",
                addr.ip()
            );
            self.blocked
                .insert(addr.ip().to_canonical(), now + self.config.block_duration);
            return Ok(());
        }

        let full = self.established_count() >= self.config.max_connections;

        if let Entry::Occupied(mut entry) = self.session_temp.entry(addr) {
            let mut success = false;
            let mut closed = false;

            let (_, session) = entry.get_mut();

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
                    RakSessionOutput::Disconnected(..) => closed = true,
                    RakSessionOutput::Wait(_) => {}
                }
            }

            if closed {
                debug!("pending connection from {} closed during handshake", addr);

                entry.remove();
                self.forget(addr);
                return Ok(());
            }

            if success {
                let (_, mut session) = entry.remove();

                if full {
                    debug!("dropping connection from {} due to max connections", addr);

                    session.handle(RakSessionInput::DisconnectNow(now))?;
                    self.forward_datagrams(&mut session);
                    self.forget(addr);
                    return Ok(());
                }

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

        self.output
            .push_back(RakServerOutput::SocketDatagram(pong.serialized()?, addr));
        Ok(())
    }

    fn handle_open_connection_request_1(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        addr: SocketAddr,
        now: SystemTime,
    ) -> Result<(), RakServerError> {
        let request = OpenConnectionRequest1::deserialize(cursor)?;

        let req_protocol = request.protocol;
        if !self.config.protocols.contains(&req_protocol) {
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

            self.output.push_back(RakServerOutput::SocketDatagram(
                incompatible.serialized()?,
                addr,
            ));

            return Ok(());
        }

        if let Some(&disconnected_at) = self.recently_disconnected.get(&addr)
            && now.duration_since(disconnected_at).unwrap_or_default() < RECENTLY_CONNECTED_COOLDOWN
        {
            debug!("refusing connection from {} due to recent disconnect", addr);

            let recently = IpRecentlyConnected {
                guid: self.config.guid,
            };

            self.output.push_back(RakServerOutput::SocketDatagram(
                recently.serialized()?,
                addr,
            ));

            return Ok(());
        }

        self.rotate_cookie_salt(now);

        let reply1 = OpenConnectionReply1 {
            guid: self.config.guid,
            cookie: self
                .config
                .cookies
                .then(|| self.cookie(self.cookie_salts[0], addr)),
            mtu: (request.mtu + constants::UDP_HEADER_SIZE + get_overhead(&addr))
                .clamp(self.config.min_mtu_size, self.config.max_mtu_size),
        };

        self.output
            .push_back(RakServerOutput::SocketDatagram(reply1.serialized()?, addr));

        Ok(())
    }

    fn handle_open_connection_request_2(
        &mut self,
        cursor: &mut Cursor<&[u8]>,
        addr: SocketAddr,
        now: SystemTime,
    ) -> Result<(), RakServerError> {
        let request = OpenConnectionRequest2::deserialize(cursor)?;

        if self.config.cookies {
            self.rotate_cookie_salt(now);

            if !self.cookie_valid(request.cookie, addr) {
                debug!(
                    "ignoring connection request from {} with an invalid cookie",
                    addr
                );
                return Ok(());
            }
        }

        if self.config.require_dialled_port && request.addr.port() != self.addr.port() {
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
            debug!(
                "refusing connection from {} due to existing connection",
                addr
            );

            let already = AlreadyConnected {
                guid: self.config.guid,
            };

            self.output
                .push_back(RakServerOutput::SocketDatagram(already.serialized()?, addr));

            return Ok(());
        }

        let (pending_from_ip, established_from_ip) = self.counts_for_ip(addr.ip());
        if self.established_count() >= self.config.max_connections
            || self.session_temp.len() >= self.config.max_pending_connections
            || pending_from_ip >= self.config.max_pending_per_ip
            || pending_from_ip + established_from_ip >= self.config.max_connections_per_ip
        {
            debug!("refusing connection from {} due to max connections", addr);

            let no_free = NoFreeIncomingConnections {
                guid: self.config.guid,
            };

            self.output
                .push_back(RakServerOutput::SocketDatagram(no_free.serialized()?, addr));

            return Ok(());
        }

        debug!(
            "establishing connection from {} with mtu size of {}",
            addr, mtu
        );

        let reply2 = OpenConnectionReply2::new(self.config.guid, addr, mtu, false);

        self.output
            .push_back(RakServerOutput::SocketDatagram(reply2.serialized()?, addr));

        let id = self.session_id.increment();

        self.session_map.insert(addr, id);
        self.session_addr.insert(id, addr);
        let max_ordering_channels = self.config.max_ordering_channels;
        self.session_temp.insert(
            addr,
            (
                now,
                RakSession::new(id, addr, request.client, request.mtu, |conf| {
                    conf.ordering_channels = max_ordering_channels;
                }),
            ),
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
            system_addresses: vec![SocketAddr::new(unspecified_ip_like(addr), 0); 10],
            request_timestamp: request.client_timestamp,
            timestamp: now.duration_since(UNIX_EPOCH)?.as_millis() as u64,
        };

        session.handle(RakSessionInput::Send(
            accepted.serialized()?,
            RakReliability::ReliableOrdered,
            RakPriority::Immediate,
            now,
        ))?;

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

fn unspecified_ip_like(addr: SocketAddr) -> IpAddr {
    match addr {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(server: &mut RakServer) -> Vec<RakServerOutput> {
        let mut out = Vec::new();
        while let Some(o) = server.poll() {
            out.push(o);
        }
        out
    }

    fn first_byte(output: &RakServerOutput) -> Option<u8> {
        match output {
            RakServerOutput::SocketDatagram(buf, _) => buf.first().copied(),
            _ => None,
        }
    }

    fn request_1(protocol: u8) -> Box<[u8]> {
        let req = OpenConnectionRequest1 { protocol, mtu: 100 };
        req.serialized().unwrap()
    }

    fn reply_cookie(server: &mut RakServer) -> Option<i32> {
        drain(server).into_iter().find_map(|out| match out {
            RakServerOutput::SocketDatagram(buf, _)
                if buf.first() == Some(&packet_id::OPEN_CONNECTION_REPLY_1) =>
            {
                OpenConnectionReply1::deserialize(&mut buf.as_ref())
                    .unwrap()
                    .cookie
            }
            _ => None,
        })
    }

    fn request_2(server_addr: SocketAddr, client: u64, cookie: Option<i32>) -> Box<[u8]> {
        let req = OpenConnectionRequest2 {
            cookie,
            addr: server_addr,
            mtu: constants::MIN_MTU_SIZE,
            client,
        };
        req.serialized().unwrap()
    }

    use crate::client::RakClient;
    use crate::client::config::RakClientConfig;
    use crate::client::input::RakClientInput;
    use crate::client::output::RakClientOutput;

    fn connect_all(
        server: &mut RakServer,
        server_addr: SocketAddr,
        client_addrs: &[SocketAddr],
        now: SystemTime,
    ) -> Vec<RakSession> {
        let mut clients: Vec<(SocketAddr, Option<RakClient>)> = client_addrs
            .iter()
            .map(|&addr| {
                let mut client = RakClient::new(RakClientConfig::default());
                client
                    .handle(RakClientInput::Connect(server_addr, now))
                    .unwrap();
                (addr, Some(client))
            })
            .collect();

        let mut connected = Vec::new();
        loop {
            let mut sent = false;
            for (addr, client) in &mut clients {
                let Some(client) = client else { continue };
                while let Some(out) = client.poll() {
                    if let RakClientOutput::SocketDatagram(buf, _) = out {
                        sent = true;
                        let _ = server.handle(RakServerInput::Datagram(buf, *addr, now));
                    }
                }
            }
            if !sent {
                return connected;
            }

            for out in drain(server) {
                match out {
                    RakServerOutput::SocketDatagram(buf, to) => {
                        let Some((_, slot)) = clients.iter_mut().find(|(addr, _)| *addr == to)
                        else {
                            continue;
                        };
                        if let Some(client) = slot
                            && client
                                .handle(RakClientInput::Datagram(buf, server_addr, now))
                                .is_err()
                        {
                            *slot = None;
                        }
                    }
                    RakServerOutput::SessionConnected(session) => connected.push(*session),
                    _ => {}
                }
            }
        }
    }

    fn connect(
        server: &mut RakServer,
        server_addr: SocketAddr,
        client_addr: SocketAddr,
        now: SystemTime,
    ) -> Option<RakSession> {
        connect_all(server, server_addr, &[client_addr], now).pop()
    }

    fn open_pending(server: &mut RakServer, server_addr: SocketAddr, client_addr: SocketAddr) {
        let now = SystemTime::now();
        server
            .handle(RakServerInput::Datagram(
                request_1(constants::PROTOCOL),
                client_addr,
                now,
            ))
            .unwrap();
        let cookie = reply_cookie(server);
        server
            .handle(RakServerInput::Datagram(
                request_2(server_addr, 1, cookie),
                client_addr,
                now,
            ))
            .unwrap();
    }

    #[test]
    fn a_client_completes_the_handshake() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);

        let session = connect(
            &mut server,
            server_addr,
            "127.0.0.1:2".parse().unwrap(),
            SystemTime::now(),
        );

        assert!(session.is_some());
    }

    #[test]
    fn pending_handshakes_do_not_use_up_connection_slots() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(
            RakServerConfig {
                max_connections: 1,
                ..Default::default()
            },
            server_addr,
        );

        open_pending(&mut server, server_addr, "127.0.0.1:1".parse().unwrap());
        drain(&mut server);

        let session = connect(
            &mut server,
            server_addr,
            "127.0.0.1:2".parse().unwrap(),
            SystemTime::now(),
        );

        assert!(
            session.is_some(),
            "a half-open handshake must not take the only connection slot"
        );
    }

    #[test]
    fn pending_handshakes_are_capped() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(
            RakServerConfig {
                max_pending_connections: 1,
                ..Default::default()
            },
            server_addr,
        );

        open_pending(&mut server, server_addr, "127.0.0.1:1".parse().unwrap());
        drain(&mut server);
        open_pending(&mut server, server_addr, "127.0.0.1:2".parse().unwrap());

        let outputs = drain(&mut server);
        assert!(
            outputs
                .iter()
                .any(|o| first_byte(o) == Some(packet_id::NO_FREE_INCOMING_CONNECTIONS))
        );
        assert_eq!(server.session_temp.len(), 1);
    }

    #[test]
    fn one_ip_cannot_hold_more_than_its_pending_slots() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let per_ip = server.config.max_pending_per_ip as u16;

        for port in 1..=per_ip {
            open_pending(
                &mut server,
                server_addr,
                SocketAddr::from(([127, 0, 0, 1], port)),
            );
        }
        drain(&mut server);
        open_pending(
            &mut server,
            server_addr,
            SocketAddr::from(([127, 0, 0, 1], per_ip + 1)),
        );

        assert!(
            drain(&mut server)
                .iter()
                .any(|o| first_byte(o) == Some(packet_id::NO_FREE_INCOMING_CONNECTIONS))
        );
        assert_eq!(server.session_temp.len(), per_ip as usize);

        open_pending(&mut server, server_addr, "127.0.0.2:1".parse().unwrap());
        assert_eq!(server.session_temp.len(), per_ip as usize + 1);
    }

    #[test]
    fn one_ip_cannot_hold_more_than_its_connection_slots() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(
            RakServerConfig {
                max_connections_per_ip: 1,
                ..Default::default()
            },
            server_addr,
        );
        let now = SystemTime::now();

        let clients = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "127.0.0.2:1".parse().unwrap(),
        ];
        let sessions = connect_all(&mut server, server_addr, &clients, now);

        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().any(|s| s.addr.ip() == clients[2].ip()));
    }

    fn online_datagram() -> Box<[u8]> {
        Box::new([flags::VALID, 0, 0, 0])
    }

    fn session_datagrams(server: &mut RakServer) -> usize {
        drain(server)
            .iter()
            .filter(|o| matches!(o, RakServerOutput::SessionDatagram(..)))
            .count()
    }

    #[test]
    fn a_flood_of_online_datagrams_blocks_the_ip_for_a_while() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();
        let flooder: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let bystander: SocketAddr = "127.0.0.2:1".parse().unwrap();
        connect_all(&mut server, server_addr, &[flooder, bystander], now);
        drain(&mut server);
        let now = now + Duration::from_secs(1);

        let limit = server.config.online_packet_limit as usize;
        for _ in 0..limit * 2 {
            server
                .handle(RakServerInput::Datagram(online_datagram(), flooder, now))
                .unwrap();
        }
        assert_eq!(session_datagrams(&mut server), limit);

        let later = now + Duration::from_secs(1);
        for addr in [flooder, bystander] {
            server
                .handle(RakServerInput::Datagram(online_datagram(), addr, later))
                .unwrap();
        }
        assert_eq!(
            session_datagrams(&mut server),
            1,
            "only the bystander gets through"
        );

        let unblocked = now + server.config.block_duration;
        server
            .handle(RakServerInput::Datagram(
                online_datagram(),
                flooder,
                unblocked,
            ))
            .unwrap();
        assert_eq!(session_datagrams(&mut server), 1);
    }

    #[test]
    fn expired_blocks_are_pruned_on_update() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        server
            .handle(RakServerInput::Block(
                "127.0.0.9".parse().unwrap(),
                Duration::from_secs(1),
                now,
            ))
            .unwrap();
        server
            .handle(RakServerInput::Update(now + Duration::from_secs(2)))
            .unwrap();

        assert!(server.blocked.is_empty());
    }

    #[test]
    fn a_blocked_ip_is_ignored_until_unblocked() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();
        let client: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ping = || {
            let mut buf = Vec::new();
            UnconnectedPing {
                timestamp: 0,
                client: 1,
            }
            .serialize(&mut buf)
            .unwrap();
            buf.into_boxed_slice()
        };

        server
            .handle(RakServerInput::Block(
                client.ip(),
                Duration::from_secs(60),
                now,
            ))
            .unwrap();
        server
            .handle(RakServerInput::Datagram(ping(), client, now))
            .unwrap();
        assert!(drain(&mut server).is_empty());

        server.handle(RakServerInput::Unblock(client.ip())).unwrap();
        server
            .handle(RakServerInput::Datagram(ping(), client, now))
            .unwrap();
        assert!(
            drain(&mut server)
                .iter()
                .any(|o| first_byte(o) == Some(packet_id::UNCONNECTED_PONG))
        );
    }

    #[test]
    fn established_connections_never_exceed_max() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(
            RakServerConfig {
                max_connections: 1,
                ..Default::default()
            },
            server_addr,
        );
        let now = SystemTime::now();

        let clients = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];

        let sessions = connect_all(&mut server, server_addr, &clients, now);

        assert_eq!(sessions.len(), 1);
        assert_eq!(server.established_count(), 1);
        assert!(server.session_temp.is_empty());
    }

    #[test]
    fn pending_session_closed_during_handshake_frees_its_slot() {
        use crate::protocol::packets::frame_set::FrameSet;
        use crate::protocol::types::frame::Frame;

        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);

        open_pending(&mut server, server_addr, client_addr);
        drain(&mut server);

        let mut frame = Frame::new(RakReliability::ReliableOrdered, Box::new([0xFE]));
        frame.order_index = 100_000;
        let set = FrameSet::new(0, vec![frame], false, true, false);

        server
            .handle(RakServerInput::Datagram(
                set.serialized().unwrap(),
                client_addr,
                SystemTime::now(),
            ))
            .unwrap();

        assert!(!server.session_temp.contains_key(&client_addr));
        assert!(!server.session_map.contains_key(&client_addr));
    }

    fn cookie_for(server: &mut RakServer, client_addr: SocketAddr, now: SystemTime) -> Option<i32> {
        server
            .handle(RakServerInput::Datagram(
                request_1(constants::PROTOCOL),
                client_addr,
                now,
            ))
            .unwrap();
        reply_cookie(server)
    }

    fn accepts_request_2(
        server: &mut RakServer,
        server_addr: SocketAddr,
        client_addr: SocketAddr,
        cookie: Option<i32>,
        now: SystemTime,
    ) -> bool {
        server
            .handle(RakServerInput::Datagram(
                request_2(server_addr, 1, cookie),
                client_addr,
                now,
            ))
            .unwrap();
        drain(server)
            .iter()
            .any(|o| first_byte(o) == Some(packet_id::OPEN_CONNECTION_REPLY_2))
            && server.session_temp.contains_key(&client_addr)
    }

    #[test]
    fn reply_1_carries_a_cookie_by_default() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);

        let cookie = cookie_for(
            &mut server,
            "127.0.0.1:1".parse().unwrap(),
            SystemTime::now(),
        );

        assert!(cookie.is_some());
    }

    #[test]
    fn request_2_without_a_cookie_is_ignored() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        cookie_for(&mut server, client_addr, now);

        assert!(!accepts_request_2(
            &mut server,
            server_addr,
            client_addr,
            None,
            now
        ));
    }

    #[test]
    fn request_2_with_another_addresses_cookie_is_ignored() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let spoofed_addr: SocketAddr = "127.0.0.2:1".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        let cookie = cookie_for(&mut server, client_addr, now);

        assert!(!accepts_request_2(
            &mut server,
            server_addr,
            spoofed_addr,
            cookie,
            now
        ));
        assert!(accepts_request_2(
            &mut server,
            server_addr,
            client_addr,
            cookie,
            now
        ));
    }

    #[test]
    fn cookie_survives_one_rotation_but_not_two() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        let recent: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cookie = cookie_for(&mut server, recent, now);
        let later = now + COOKIE_ROTATION_INTERVAL + COOKIE_ROTATION_INTERVAL / 2;
        assert!(accepts_request_2(
            &mut server,
            server_addr,
            recent,
            cookie,
            later
        ));

        let stale: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let cookie = cookie_for(&mut server, stale, later);
        let much_later = later + COOKIE_ROTATION_INTERVAL * 2;
        assert!(!accepts_request_2(
            &mut server,
            server_addr,
            stale,
            cookie,
            much_later
        ));
    }

    #[test]
    fn cookies_can_be_disabled() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut server = RakServer::new(
            RakServerConfig {
                cookies: false,
                ..Default::default()
            },
            server_addr,
        );
        let now = SystemTime::now();

        assert_eq!(cookie_for(&mut server, client_addr, now), None);
        assert!(accepts_request_2(
            &mut server,
            server_addr,
            client_addr,
            None,
            now
        ));
    }

    #[test]
    fn rate_limits_offline_packets_per_ip() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut server = RakServer::new(
            RakServerConfig {
                packet_limit: 2,
                ..Default::default()
            },
            server_addr,
        );

        let ping = UnconnectedPing {
            timestamp: 0,
            client: 1,
        };

        let buf = ping.serialized().unwrap();

        let now = SystemTime::now();
        for _ in 0..5 {
            server
                .handle(RakServerInput::Datagram(buf.clone(), client_addr, now))
                .unwrap();
        }

        assert_eq!(drain(&mut server).len(), 2);
    }

    #[test]
    fn rate_limit_is_shared_by_every_port_of_an_ip() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();

        let mut server = RakServer::new(
            RakServerConfig {
                packet_limit: 2,
                ..Default::default()
            },
            server_addr,
        );

        let ping = UnconnectedPing {
            timestamp: 0,
            client: 1,
        };

        let buf = ping.serialized().unwrap();

        let now = SystemTime::now();
        for port in 1..=5 {
            let client_addr = SocketAddr::from(([127, 0, 0, 1], port));
            server
                .handle(RakServerInput::Datagram(buf.clone(), client_addr, now))
                .unwrap();
        }

        assert_eq!(drain(&mut server).len(), 2);
    }

    #[test]
    fn already_connected_reply_on_duplicate_request() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        server
            .handle(RakServerInput::Datagram(
                request_1(constants::PROTOCOL),
                client_addr,
                now,
            ))
            .unwrap();
        let cookie = reply_cookie(&mut server);

        server
            .handle(RakServerInput::Datagram(
                request_2(server_addr, 1, cookie),
                client_addr,
                now,
            ))
            .unwrap();
        drain(&mut server);

        server
            .handle(RakServerInput::Datagram(
                request_2(server_addr, 1, cookie),
                client_addr,
                now,
            ))
            .unwrap();

        let outputs = drain(&mut server);
        assert!(
            outputs
                .iter()
                .any(|o| first_byte(o) == Some(packet_id::ALREADY_CONNECTED))
        );
    }

    #[test]
    fn ip_recently_connected_reply_after_disconnect() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        server
            .handle(RakServerInput::Datagram(
                request_1(constants::PROTOCOL),
                client_addr,
                now,
            ))
            .unwrap();
        let cookie = reply_cookie(&mut server);

        server
            .handle(RakServerInput::Datagram(
                request_2(server_addr, 1, cookie),
                client_addr,
                now,
            ))
            .unwrap();
        drain(&mut server);

        let id = *server.session_map.get(&client_addr).unwrap();
        server
            .handle(RakServerInput::RemoveSession(id, now))
            .unwrap();

        server
            .handle(RakServerInput::Datagram(
                request_1(constants::PROTOCOL),
                client_addr,
                now,
            ))
            .unwrap();

        let outputs = drain(&mut server);
        assert!(
            outputs
                .iter()
                .any(|o| first_byte(o) == Some(packet_id::IP_RECENTLY_CONNECTED))
        );
    }

    #[test]
    fn adopted_session_continues_on_a_second_server() {
        let peer_addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();

        // A session whose sequence state has advanced past its initial values.
        let mut server_a = RakServer::new(
            RakServerConfig::default(),
            "127.0.0.1:19160".parse().unwrap(),
        );
        let id_on_a = RakSessionId(7);
        server_a.session_map.insert(peer_addr, id_on_a);
        server_a.session_addr.insert(id_on_a, peer_addr);

        let mut session = RakSession::new(
            id_on_a,
            peer_addr,
            0xDEAD_BEEF,
            constants::MAX_MTU_SIZE,
            |_| {},
        );
        let now = SystemTime::now();
        session
            .handle(RakSessionInput::Send(
                b"hello".to_vec().into_boxed_slice(),
                RakReliability::ReliableOrdered,
                RakPriority::Immediate,
                now,
            ))
            .unwrap();
        let before_seq = session.outbound_rel;
        assert!(
            before_seq > 0,
            "sending a reliable frame must advance the sequence counter"
        );

        // A separate instance whose id counter is already past server A's, so reusing
        // the incoming id would collide.
        let mut server_b = RakServer::new(
            RakServerConfig::default(),
            "127.0.0.1:19161".parse().unwrap(),
        );
        server_b.session_id = RakSessionId(id_on_a.0 + 100);

        server_b.adopt(session);

        let outputs = drain(&mut server_b);
        let adopted = outputs.into_iter().find_map(|o| match o {
            RakServerOutput::SessionConnected(session) => Some(*session),
            _ => None,
        });
        let adopted = adopted.expect("adopt must emit SessionConnected");

        assert_eq!(
            adopted.outbound_rel, before_seq,
            "sequence state must carry over unchanged"
        );
        assert_ne!(
            adopted.id, id_on_a,
            "a colliding id from another server must not be reused as-is"
        );
        assert_eq!(
            *server_b.session_map.get(&peer_addr).unwrap(),
            adopted.id,
            "future datagrams from the peer must route to the adopted session's new id"
        );

        server_b
            .handle(RakServerInput::Datagram(
                b"\xffnoise".to_vec().into_boxed_slice(),
                peer_addr,
                now,
            ))
            .unwrap();
        let routed = drain(&mut server_b);
        assert!(
            routed
                .iter()
                .any(|o| matches!(o, RakServerOutput::SessionDatagram(_, id) if *id == adopted.id)),
            "a datagram from the adopted session's peer must be routed by its new id"
        );
    }

    #[test]
    fn evicts_stale_pending_connection() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();

        server
            .handle(RakServerInput::Datagram(
                request_1(constants::PROTOCOL),
                client_addr,
                now,
            ))
            .unwrap();
        let cookie = reply_cookie(&mut server);

        server
            .handle(RakServerInput::Datagram(
                request_2(server_addr, 1, cookie),
                client_addr,
                now,
            ))
            .unwrap();
        drain(&mut server);

        assert!(server.session_temp.contains_key(&client_addr));

        let later = now + PENDING_CONNECTION_TIMEOUT;
        server.handle(RakServerInput::Update(later)).unwrap();

        assert!(!server.session_temp.contains_key(&client_addr));
        assert!(!server.session_map.contains_key(&client_addr));
    }

    #[test]
    fn pending_session_acks_and_resends_connection_request_accepted() {
        let server_addr: SocketAddr = "127.0.0.1:19132".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let mut server = RakServer::new(RakServerConfig::default(), server_addr);
        let now = SystemTime::now();
        let mut client = RakClient::new(RakClientConfig::default());
        client
            .handle(RakClientInput::Connect(server_addr, now))
            .unwrap();

        loop {
            let mut sent = false;
            while let Some(out) = client.poll() {
                if let RakClientOutput::SocketDatagram(buf, _) = out {
                    sent = true;
                    server
                        .handle(RakServerInput::Datagram(buf, client_addr, now))
                        .unwrap();
                }
            }
            if !sent {
                break;
            }
            for out in drain(&mut server) {
                if let RakServerOutput::SocketDatagram(buf, _) = out
                    && buf.first().is_some_and(|b| b & flags::VALID == 0)
                {
                    client
                        .handle(RakClientInput::Datagram(buf, server_addr, now))
                        .unwrap();
                }
            }
        }
        assert!(server.session_temp.contains_key(&client_addr));

        server
            .handle(RakServerInput::Update(now + Duration::from_millis(20)))
            .unwrap();
        let acked = drain(&mut server).iter().any(|out| {
            matches!(out, RakServerOutput::SocketDatagram(buf, _)
                if buf.first().is_some_and(|b| b & flags::ACK != 0))
        });
        assert!(
            acked,
            "pending session never acknowledged the ConnectionRequest"
        );

        server
            .handle(RakServerInput::Update(now + Duration::from_millis(2100)))
            .unwrap();
        let resent = drain(&mut server).iter().any(|out| {
            matches!(out, RakServerOutput::SocketDatagram(buf, _)
                if buf.first().is_some_and(|b| b & flags::VALID != 0 && b & flags::ACK == 0 && b & flags::NACK == 0))
        });
        assert!(
            resent,
            "pending session never resent ConnectionRequestAccepted"
        );
    }

    fn accepted_reply_to(client_addr: SocketAddr) -> ConnectionRequestAccepted {
        use crate::protocol::packets::frame_set::FrameSet;

        let now = SystemTime::now();
        let mut session = RakSession::new(
            RakSessionId(0),
            client_addr,
            0,
            constants::MAX_MTU_SIZE,
            |_| {},
        );
        let request = ConnectionRequest {
            client_guid: 1,
            client_timestamp: 2,
            security: false,
        };
        let mut buf = Vec::new();
        request.serialize(&mut buf).unwrap();
        RakServer::handle_connection_request(
            &mut session,
            client_addr,
            &mut Cursor::new(&buf),
            now,
        )
        .unwrap();
        session.tick(now).unwrap();

        std::iter::from_fn(|| session.poll())
            .find_map(|out| match out {
                RakSessionOutput::Datagram(buf, _) => Some(buf),
                _ => None,
            })
            .map(|buf| FrameSet::deserialize(&mut Cursor::new(buf.as_ref())).unwrap())
            .map(|set| {
                ConnectionRequestAccepted::deserialize(&mut set.frames[0].payload.as_ref()).unwrap()
            })
            .unwrap()
    }

    #[test]
    fn connection_request_accepted_carries_ten_system_addresses_of_the_client_family() {
        for client_addr in ["127.0.0.1:2", "[::1]:2"] {
            let client_addr: SocketAddr = client_addr.parse().unwrap();
            let accepted = accepted_reply_to(client_addr);

            assert_eq!(accepted.client_address, client_addr);
            assert_eq!(accepted.system_addresses.len(), 10);
            assert!(
                accepted
                    .system_addresses
                    .iter()
                    .all(|addr| addr.is_ipv4() == client_addr.is_ipv4())
            );
            assert_eq!(accepted.request_timestamp, 2);
        }
    }
}
