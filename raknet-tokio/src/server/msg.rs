use crate::session::RakSession;
use raknet::prelude::RakSession as RakSessionIntl;
use tokio::sync::oneshot;

pub enum RakServerMsg {
    SetMessage(Box<[u8]>),
    SetMaxConnections(usize),
    Stop,
    /// A session resumed from another server. Replied to directly rather than through
    /// `accept()`, so the caller gets this session and not a concurrent handshake.
    Adopt(RakSessionIntl, oneshot::Sender<RakSession>),
}
