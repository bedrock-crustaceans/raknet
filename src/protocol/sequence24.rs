use std::cmp::Ordering;
use std::ops::Add;

use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;
use super::primitives::U24Le;

const MODULO: u32 = 1 << 24;
const MASK: u32 = MODULO - 1;
const HALF: u32 = MODULO / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sequence24(u32);

impl Sequence24 {
    pub fn new(value: u32) -> Self {
        Self(value & MASK)
    }

    pub fn value(self) -> u32 {
        self.0 & MASK
    }

    pub fn next(self) -> Self {
        Self::new(self.value() + 1)
    }

    pub fn prev(self) -> Self {
        if self.value() == 0 {
            Self::new(MASK)
        } else {
            Self::new(self.value() - 1)
        }
    }

    pub fn distance_to(self, newer: Sequence24) -> u32 {
        let cur = self.value();
        let target = newer.value();
        if target >= cur {
            target - cur
        } else {
            MODULO - cur + target
        }
    }
}

impl Ord for Sequence24 {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.value() as i32;
        let b = other.value() as i32;
        let delta = a.wrapping_sub(b);

        if delta == 0 {
            Ordering::Equal
        } else if (delta > 0 && delta < HALF as i32) || (delta < 0 && delta < -(HALF as i32)) {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }
}

impl PartialOrd for Sequence24 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Add for Sequence24 {
    type Output = Sequence24;

    fn add(self, rhs: Self) -> Self::Output {
        Sequence24::new((self.value() + rhs.value()) % MODULO)
    }
}

impl Add<i32> for Sequence24 {
    type Output = Sequence24;

    fn add(self, rhs: i32) -> Self::Output {
        let mut value = self.value() as i32 + rhs;
        value %= MODULO as i32;
        if value < 0 {
            value += MODULO as i32;
        }
        Sequence24::new(value as u32)
    }
}

impl RaknetCodec for Sequence24 {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        U24Le(self.value()).encode_raknet(dst)
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        Ok(Sequence24::new(U24Le::decode_raknet(src)?.0))
    }
}
