#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum RakSessionState {
    Connected,
    Disconnected,
}
