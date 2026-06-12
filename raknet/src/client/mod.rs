pub mod config;
pub mod input;
pub mod output;
pub mod state;

use crate::client::config::RakClientConfig;
use crate::client::input::RakClientInput;
use crate::client::output::RakClientOutput;
use crate::protocol::codec::RakCodec;
use crate::protocol::packets::open_connection_request_1::OpenConnectionRequest1;
use crate::sans::Sans;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::SystemTime;

pub struct RakClient {
    addr: SocketAddr,
    config: RakClientConfig,

    attempts: usize,

    output: VecDeque<RakClientOutput>,
}

impl Sans for RakClient {
    type Input = RakClientInput;
    type Output = RakClientOutput;
    type Error = ();

    fn handle(&mut self, msg: Self::Input) -> Result<(), Self::Error> {
        match msg {
            RakClientInput::Datagram(buf, addr) => {
                todo!()
            }
            RakClientInput::Update(now) => self.handle_timeout(now),
        }
        Ok(())
    }

    fn poll(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }
}

impl RakClient {
    fn handle_timeout(&mut self, now: SystemTime) {}

    fn send_open_connection_request_1(&mut self) {
        let idx = self.attempts / (self.config.conn_attempt_max / self.config.mtu_sizes.len());
        let mtu = self.config.mtu_sizes[idx];

        let req = OpenConnectionRequest1 {
            protocol: self.config.protocol,
            mtu,
        };

        let mut buf = Vec::with_capacity(req.size_hint());
        req.serialize(&mut buf).unwrap();
        let buf = buf.into_boxed_slice();

        self.output
            .push_back(RakClientOutput::Datagram(buf, self.addr));
    }
}
