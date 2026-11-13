/// Upload priority class. A lower index uploads first and is evicted last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Class {
    /// Position, state changes and the vital set.
    P0 = 0,
    /// Everything else that is recorded.
    P1 = 1,
    /// Raw PGN capture.
    P2 = 2,
}

impl Class {
    pub const ALL: [Class; 3] = [Class::P0, Class::P1, Class::P2];

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn from_u8(v: u8) -> Option<Class> {
        match v {
            0 => Some(Class::P0),
            1 => Some(Class::P1),
            2 => Some(Class::P2),
            _ => None,
        }
    }

    pub fn from_u32(v: u32) -> Option<Class> {
        u8::try_from(v).ok().and_then(Class::from_u8)
    }
}
