use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use raknet::prelude::RakServerInput::{SetMaxConnections, SetMessage};
use raknet::prelude::{RakServer as RakServerIntl, RakSession as RakSessionIntl, *};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime};
use tracing::debug;

const MAX_DATAGRAMS_PER_TICK: usize = 1024;

pub struct RakServerPlugin;

impl Plugin for RakServerPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<RakServerEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(RakServerSet)
                .run_if(resource_exists::<RakServer>),
        );
    }
}

impl RakServerPlugin {
    fn update(mut server: ResMut<RakServer>, mut events: MessageWriter<RakServerEvent>) {
        server.update();

        while let Some(event) = server.next_event() {
            events.write(event);
        }
    }
}

/// PreUpdate set containing RakServerPlugin's update system. Order your own
/// systems `.after(RakServerSet)` to see this tick's events/received data.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RakServerSet;

#[derive(Message, Clone, Copy, Debug)]
pub enum RakServerEvent {
    SessionConnected {
        id: RakSessionId,
        addr: SocketAddr,
        guid: u64,
    },
    SessionDisconnected {
        id: RakSessionId,
        reason: RakDisconnectReason,
    },
}

#[derive(Resource)]
pub struct RakServer {
    intl: RakServerIntl,
    socket: UdpSocket,
    sessions: HashMap<RakSessionId, RakSessionIntl>,
    received: VecDeque<(RakSessionId, Box<[u8]>)>,
    events: VecDeque<RakServerEvent>,
    buffer: Box<[u8]>,
}

impl RakServer {
    pub fn new<T>(addr: SocketAddr, conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut RakServerConfig),
    {
        let mut config = RakServerConfig::default();
        conf(&mut config);

        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            socket,
            buffer: vec![0; config.max_mtu_size as usize].into_boxed_slice(),
            sessions: HashMap::new(),
            received: VecDeque::new(),
            events: VecDeque::new(),
            intl: RakServerIntl::new(config, addr),
        })
    }

    pub fn set_message<T>(&mut self, val: T)
    where
        T: Into<Box<[u8]>>,
    {
        let _ = self.intl.handle(SetMessage(val.into()));
    }

    pub fn set_max_connections(&mut self, val: usize) {
        let _ = self.intl.handle(SetMaxConnections(val));
    }

    pub fn send<T>(
        &mut self,
        id: RakSessionId,
        buf: T,
        reliability: RakReliability,
        priority: RakPriority,
    ) -> Result<(), RakSessionError>
    where
        T: Into<Box<[u8]>>,
    {
        let now = SystemTime::now();
        let mut disconnected = Vec::new();

        {
            let Some(session) = self.sessions.get_mut(&id) else {
                return Err(RakSessionError::Closed);
            };

            session.handle(RakSessionInput::Send(
                buf.into(),
                reliability,
                priority,
                now,
            ))?;

            drain_session(session, &self.socket, &mut self.received, &mut disconnected);
        }

        self.remove_sessions(disconnected, now);

        Ok(())
    }

    pub fn broadcast<T>(&mut self, buf: T, reliability: RakReliability, priority: RakPriority)
    where
        T: Into<Box<[u8]>>,
    {
        let buf: Box<[u8]> = buf.into();
        let now = SystemTime::now();
        let mut disconnected = Vec::new();

        for session in self.sessions.values_mut() {
            let _ = session.handle(RakSessionInput::Send(
                buf.clone(),
                reliability,
                priority.clone(),
                now,
            ));

            drain_session(session, &self.socket, &mut self.received, &mut disconnected);
        }

        self.remove_sessions(disconnected, now);
    }

    pub fn recv(&mut self) -> Option<(RakSessionId, Box<[u8]>)> {
        self.received.pop_front()
    }

    pub fn disconnect(&mut self, id: RakSessionId) {
        let now = SystemTime::now();
        let mut disconnected = Vec::new();

        {
            let Some(session) = self.sessions.get_mut(&id) else {
                return;
            };

            let _ = session.handle(RakSessionInput::Disconnect(now));

            drain_session(session, &self.socket, &mut self.received, &mut disconnected);
        }

        self.remove_sessions(disconnected, now);
    }

    pub fn sessions(&self) -> impl Iterator<Item = RakSessionId> + '_ {
        self.sessions.keys().copied()
    }

    pub fn rtt(&self, id: RakSessionId) -> Option<Duration> {
        self.sessions.get(&id).map(RakSessionIntl::rtt)
    }

    pub fn next_event(&mut self) -> Option<RakServerEvent> {
        self.events.pop_front()
    }

    fn remove_sessions(&mut self, ids: Vec<(RakSessionId, RakDisconnectReason)>, now: SystemTime) {
        for (id, reason) in ids {
            self.sessions.remove(&id);
            let _ = self.intl.handle(RakServerInput::RemoveSession(id, now));
            self.events
                .push_back(RakServerEvent::SessionDisconnected { id, reason });
        }
    }

    pub fn update(&mut self) {
        let now = SystemTime::now();

        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match self.socket.recv_from(&mut self.buffer) {
                Ok((len, addr)) => {
                    if let Err(e) = self.intl.handle(RakServerInput::Datagram(
                        self.buffer[..len].into(),
                        addr,
                        now,
                    )) {
                        debug!("server failed to handle inbound datagram: {e}");
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                _ => {}
            }
        }

        if let Err(e) = self.intl.handle(RakServerInput::Update(now)) {
            debug!("server failed to update: {e}");
        }

        while let Some(output) = self.intl.poll() {
            match output {
                RakServerOutput::SocketDatagram(buf, addr) => {
                    let _ = self.socket.send_to(&buf, addr);
                }
                RakServerOutput::SessionDatagram(buf, id) => {
                    if let Some(session) = self.sessions.get_mut(&id) {
                        let _ = session.handle(RakSessionInput::Datagram(buf, now));
                    } else {
                        debug!("no session found with id {id:?}");
                    }
                }
                RakServerOutput::SessionConnected(session) => {
                    debug!("session {:?} connected", session.id);

                    self.events.push_back(RakServerEvent::SessionConnected {
                        id: session.id,
                        addr: session.addr,
                        guid: session.guid,
                    });

                    self.sessions.insert(session.id, *session);
                }
            }
        }

        let mut disconnected = Vec::new();
        for session in self.sessions.values_mut() {
            let _ = session.handle(RakSessionInput::Update(now));

            drain_session(session, &self.socket, &mut self.received, &mut disconnected);
        }

        self.remove_sessions(disconnected, now);
    }
}

impl Drop for RakServer {
    fn drop(&mut self) {
        let now = SystemTime::now();

        for session in self.sessions.values_mut() {
            let _ = session.handle(RakSessionInput::Disconnect(now));

            while let Some(output) = session.poll() {
                if let RakSessionOutput::Datagram(buf, addr) = output {
                    let _ = self.socket.send_to(&buf, addr);
                }
            }
        }
    }
}

fn drain_session(
    session: &mut RakSessionIntl,
    socket: &UdpSocket,
    received: &mut VecDeque<(RakSessionId, Box<[u8]>)>,
    disconnected: &mut Vec<(RakSessionId, RakDisconnectReason)>,
) {
    let id = session.id;
    while let Some(output) = session.poll() {
        match output {
            RakSessionOutput::Datagram(buf, addr) => {
                let _ = socket.send_to(&buf, addr);
            }
            RakSessionOutput::Packet(buf) => received.push_back((id, buf)),
            RakSessionOutput::Disconnected(id, reason) => disconnected.push((id, reason)),
            RakSessionOutput::Wait(_) => {}
        }
    }
}
