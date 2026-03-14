#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RakPriority {
    Immediate = 0,
    High = 1,
    Normal = 2,
    Low = 3,
}

impl RakPriority {
    #[inline]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}
