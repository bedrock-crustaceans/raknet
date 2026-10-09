use crate::session::RakSession;
use raknet::prelude::RakSession as RakSessionIntl;
use tokio::sync::oneshot;

pub enum RakServerMsg {
    SetMessage(Box<[u8]>),
    SetMaxConnections(usize),
    Stop,
    Adopt(Box<RakSessionIntl>, oneshot::Sender<RakSession>),
}
