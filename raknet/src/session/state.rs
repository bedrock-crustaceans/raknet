#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, facet::Facet)]
#[repr(u8)]
pub enum RakSessionState {
    Connected,
    Disconnected,
}
