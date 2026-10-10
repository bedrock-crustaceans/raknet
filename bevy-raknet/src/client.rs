use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use raknet::prelude::{RakClient as RakClientIntl, RakSession as RakSessionIntl, *};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime};
use tracing::debug;

const MAX_DATAGRAMS_PER_TICK: usize = 1024;

pub struct RakClientPlugin;

impl Plugin for RakClientPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<RakClientEvent>();
        app.add_systems(
            PreUpdate,
            Self::update
                .in_set(RakClientSet)
                .run_if(resource_exists::<RakClient>),
        );
    }
}

impl RakClientPlugin {
    fn update(mut client: ResMut<RakClient>, mut events: MessageWriter<RakClientEvent>) {
        client.update();

        while let Some(event) = client.next_event() {
            events.write(event);
        }
    }
}

/// PreUpdate set containing RakClientPlugin's update system. Order your own
/// systems `.after(RakClientSet)` to see this tick's events/received data.
#[derive(SystemSet, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RakClientSet;

#[derive(Message, Clone, Copy, Debug)]
pub enum RakClientEvent {
    Connected,
    Disconnected { reason: RakDisconnectReason },
}

#[derive(Resource)]
pub struct RakClient {
    intl: RakClientIntl,
    socket: UdpSocket,
    session: Option<RakSessionIntl>,
    received: VecDeque<Box<[u8]>>,
    pongs: VecDeque<(SocketAddr, Box<[u8]>, SystemTime)>,
    events: VecDeque<RakClientEvent>,
    buffer: Box<[u8]>,
}

impl RakClient {
    pub fn new<T>(conf: T) -> std::io::Result<Self>
    where
        T: FnOnce(&mut RakClientConfig),
    {
        let mut config = RakClientConfig::default();
        conf(&mut config);

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            buffer: vec![0; config.max_mtu_size as usize].into_boxed_slice(),
            socket,
            session: None,
            received: VecDeque::new(),
            pongs: VecDeque::new(),
            events: VecDeque::new(),
            intl: RakClientIntl::new(config),
        })
    }

    pub fn connect(&mut self, addr: SocketAddr) {
        let _ = self
            .intl
            .handle(RakClientInput::Connect(addr, SystemTime::now()));
    }

    pub fn ping(&mut self, addr: SocketAddr) {
        let _ = self
            .intl
            .handle(RakClientInput::Ping(addr, SystemTime::now()));
    }

    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.session.as_ref().map(RakSessionIntl::rtt)
    }

    pub fn send<T>(
        &mut self,
        buf: T,
        reliability: RakReliability,
        priority: RakPriority,
    ) -> Result<(), RakSessionError>
    where
        T: Into<Box<[u8]>>,
    {
        let Some(session) = self.session.as_mut() else {
            return Err(RakSessionError::Closed);
        };

        session.handle(RakSessionInput::Send(
            buf.into(),
            reliability,
            priority,
            SystemTime::now(),
        ))?;

        if let Some(reason) = drain_session(session, &self.socket, &mut self.received) {
            self.session = None;
            let _ = self.intl.handle(RakClientInput::Disconnect);
            self.events
                .push_back(RakClientEvent::Disconnected { reason });
        }

        Ok(())
    }

    pub fn recv(&mut self) -> Option<Box<[u8]>> {
        self.received.pop_front()
    }

    pub fn recv_pong(&mut self) -> Option<(SocketAddr, Box<[u8]>, SystemTime)> {
        self.pongs.pop_front()
    }

    /// Starts closing the session. Keep calling `update` until the disconnected event
    /// arrives so queued data is sent and acknowledged.
    pub fn disconnect(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };

        let _ = session.handle(RakSessionInput::Disconnect(SystemTime::now()));

        if let Some(reason) = drain_session(session, &self.socket, &mut self.received) {
            self.session = None;
            let _ = self.intl.handle(RakClientInput::Disconnect);
            self.events
                .push_back(RakClientEvent::Disconnected { reason });
        }
    }

    pub fn next_event(&mut self) -> Option<RakClientEvent> {
        self.events.pop_front()
    }

    pub fn update(&mut self) {
        let now = SystemTime::now();

        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match self.socket.recv_from(&mut self.buffer) {
                Ok((len, addr)) => {
                    if let Err(e) = self.intl.handle(RakClientInput::Datagram(
                        self.buffer[..len].into(),
                        addr,
                        now,
                    )) {
                        debug!("client failed to handle inbound datagram: {e}");
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                _ => {}
            }
        }

        if let Err(e) = self.intl.handle(RakClientInput::Update(now)) {
            debug!("client failed to handle update: {e}");
        }

        while let Some(output) = self.intl.poll() {
            match output {
                RakClientOutput::SocketDatagram(buf, addr) => {
                    let _ = self.socket.send_to(&buf, addr);
                }
                RakClientOutput::SessionDatagram(buf) => {
                    if let Some(session) = self.session.as_mut() {
                        let _ = session.handle(RakSessionInput::Datagram(buf, now));
                    }
                }
                RakClientOutput::SessionConnected(session) => {
                    debug!("session connected");

                    self.session = Some(*session);
                    self.events.push_back(RakClientEvent::Connected);
                }
                RakClientOutput::Wait(_) => {}
                RakClientOutput::Pong(addr, msg, time) => self.pongs.push_back((addr, msg, time)),
            }
        }

        if let Some(session) = self.session.as_mut() {
            let _ = session.handle(RakSessionInput::Update(now));

            if let Some(reason) = drain_session(session, &self.socket, &mut self.received) {
                self.session = None;
                let _ = self.intl.handle(RakClientInput::Disconnect);
                self.events
                    .push_back(RakClientEvent::Disconnected { reason });
            }
        }
    }
}

impl Drop for RakClient {
    fn drop(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };

        let _ = session.handle(RakSessionInput::DisconnectNow(SystemTime::now()));

        while let Some(output) = session.poll() {
            if let RakSessionOutput::Datagram(buf, addr) = output {
                let _ = self.socket.send_to(&buf, addr);
            }
        }
    }
}

fn drain_session(
    session: &mut RakSessionIntl,
    socket: &UdpSocket,
    received: &mut VecDeque<Box<[u8]>>,
) -> Option<RakDisconnectReason> {
    let mut disconnected = None;
    while let Some(output) = session.poll() {
        match output {
            RakSessionOutput::Datagram(buf, addr) => {
                let _ = socket.send_to(&buf, addr);
            }
            RakSessionOutput::Packet(buf) => received.push_back(buf),
            RakSessionOutput::Disconnected(_, reason) => disconnected = Some(reason),
            RakSessionOutput::Wait(_) => {}
        }
    }
    disconnected
}
