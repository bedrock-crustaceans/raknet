use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use raknet::prelude::RakServerInput::{SetMaxConnections, SetMessage};
use raknet::prelude::{RakServer as RakServerIntl, RakSession as RakSessionIntl, *};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::SystemTime;
use tracing::debug;

pub struct RakServerPlugin;

impl Plugin for RakServerPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(PreUpdate, Self::update.run_if(resource_exists::<RakServer>));
    }
}

impl RakServerPlugin {
    fn update(mut server: ResMut<RakServer>) {
        server.update();
    }
}

#[derive(Resource)]
pub struct RakServer {
    intl: RakServerIntl,
    socket: UdpSocket,
    sessions: HashMap<RakSessionId, RakSessionIntl>,
    buffer: Box<[u8]>,
}

impl RakServer {
    pub fn new<T>(addr: SocketAddr, conf: T) -> Self
    where
        T: FnOnce(&mut RakServerConfig),
    {
        let mut config = RakServerConfig::default();
        conf(&mut config);

        let socket = UdpSocket::bind(addr).unwrap();

        Self {
            socket,
            buffer: vec![0; config.max_mtu_size as usize].into_boxed_slice(),
            sessions: HashMap::new(),
            intl: RakServerIntl::new(config, addr),
        }
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

    fn update(&mut self) {
        loop {
            match self.socket.recv_from(&mut self.buffer) {
                Ok((len, addr)) => {
                    match self.intl.handle(RakServerInput::Datagram(
                        self.buffer[..len].into(),
                        addr,
                        SystemTime::now(),
                    )) {
                        Ok(_) => {}
                        Err(e) => debug!("server failed to handle inbound datagram: {e}"),
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                _ => {}
            }
        }

        while let Some(output) = self.intl.poll() {
            match output {
                RakServerOutput::SocketDatagram(buf, addr) => {
                    let _ = self.socket.send_to(&buf, addr);
                }
                RakServerOutput::SessionDatagram(buf, id) => {
                    if let Some(session) = self.sessions.get_mut(&id) {
                        let now = SystemTime::now();

                        let _ = session.handle(RakSessionInput::Datagram(buf, now));
                    } else {
                        debug!("no session found with id {id:?}");
                    }
                }
                RakServerOutput::SessionConnected(session) => {
                    debug!("session {:?} connected", session.id);

                    self.sessions.insert(session.id, *session);
                }
            }
        }
    }
}
