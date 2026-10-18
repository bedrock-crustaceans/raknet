#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RakPriority {
    /// Sends directly, bypassing congestion and receive-window scheduling.
    /// Use a queued priority for sustained reliable application traffic.
    Immediate,
    High,
    Normal,
    Low,
}
