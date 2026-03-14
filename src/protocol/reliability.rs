use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::codec::RaknetCodec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reliability {
    Unreliable = 0,
    UnreliableSequenced = 1,
    Reliable = 2,
    ReliableOrdered = 3,
    ReliableSequenced = 4,
    UnreliableWithAckReceipt = 5,
    ReliableWithAckReceipt = 6,
    ReliableOrderedWithAckReceipt = 7,
}

#[derive(Debug, Clone, Copy)]
struct ReliabilityProps {
    reliable: bool,
    ordered: bool,
    sequenced: bool,
    with_ack_receipt: bool,
}

const RELIABILITY_PROPS: [ReliabilityProps; 8] = [
    ReliabilityProps {
        reliable: false,
        ordered: false,
        sequenced: false,
        with_ack_receipt: false,
    },
    ReliabilityProps {
        reliable: false,
        ordered: false,
        sequenced: true,
        with_ack_receipt: false,
    },
    ReliabilityProps {
        reliable: true,
        ordered: false,
        sequenced: false,
        with_ack_receipt: false,
    },
    ReliabilityProps {
        reliable: true,
        ordered: true,
        sequenced: false,
        with_ack_receipt: false,
    },
    ReliabilityProps {
        reliable: true,
        ordered: false,
        sequenced: true,
        with_ack_receipt: false,
    },
    ReliabilityProps {
        reliable: false,
        ordered: false,
        sequenced: false,
        with_ack_receipt: true,
    },
    ReliabilityProps {
        reliable: true,
        ordered: false,
        sequenced: false,
        with_ack_receipt: true,
    },
    ReliabilityProps {
        reliable: true,
        ordered: true,
        sequenced: false,
        with_ack_receipt: true,
    },
];

impl Reliability {
    #[inline]
    fn props(self) -> &'static ReliabilityProps {
        &RELIABILITY_PROPS[self as usize]
    }

    #[inline]
    pub fn is_reliable(self) -> bool {
        self.props().reliable
    }

    #[inline]
    pub fn is_ordered(self) -> bool {
        self.props().ordered
    }

    #[inline]
    pub fn is_sequenced(self) -> bool {
        self.props().sequenced
    }

    #[inline]
    pub fn is_with_ack_receipt(self) -> bool {
        self.props().with_ack_receipt
    }
}

impl TryFrom<u8> for Reliability {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unreliable),
            1 => Ok(Self::UnreliableSequenced),
            2 => Ok(Self::Reliable),
            3 => Ok(Self::ReliableOrdered),
            4 => Ok(Self::ReliableSequenced),
            5 => Ok(Self::UnreliableWithAckReceipt),
            6 => Ok(Self::ReliableWithAckReceipt),
            7 => Ok(Self::ReliableOrderedWithAckReceipt),
            _ => Err(DecodeError::UnknownReliability(value)),
        }
    }
}

impl RaknetCodec for Reliability {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        dst.put_u8(*self as u8);
        Ok(())
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if !src.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        Self::try_from(src.get_u8())
    }
}
