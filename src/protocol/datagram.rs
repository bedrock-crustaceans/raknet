use bytes::{Buf, BufMut};

use crate::error::{DecodeError, EncodeError};

use super::ack::AckNackPayload;
use super::codec::RaknetCodec;
use super::constants::{DatagramFlags, RAKNET_DATAGRAM_HEADER_SIZE};
use super::frame::Frame;
use super::sequence24::Sequence24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramKind {
    Data,
    Ack,
    Nack,
}

#[derive(Debug, Clone)]
pub enum DatagramPayload {
    Frames(Vec<Frame>),
    Ack(AckNackPayload),
    Nack(AckNackPayload),
}

impl DatagramPayload {
    fn kind(&self) -> DatagramKind {
        match self {
            Self::Frames(_) => DatagramKind::Data,
            Self::Ack(_) => DatagramKind::Ack,
            Self::Nack(_) => DatagramKind::Nack,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatagramHeader {
    pub flags: DatagramFlags,
    pub sequence: Sequence24,
}

impl RaknetCodec for DatagramHeader {
    fn encode_raknet(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        self.flags.bits().encode_raknet(dst)?;
        self.sequence.encode_raknet(dst)
    }

    fn decode_raknet(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if src.remaining() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }

        let raw_flags = u8::decode_raknet(src)?;
        let (flags, kind) = decode_datagram_flags(raw_flags)?;
        if kind != DatagramKind::Data {
            return Err(DecodeError::InvalidDatagramFlags(raw_flags));
        }
        let sequence = Sequence24::decode_raknet(src)?;

        Ok(Self { flags, sequence })
    }
}

#[derive(Debug, Clone)]
pub struct Datagram {
    pub header: DatagramHeader,
    pub payload: DatagramPayload,
}

impl Datagram {
    pub fn encoded_size(&self) -> usize {
        match &self.payload {
            DatagramPayload::Frames(frames) => {
                RAKNET_DATAGRAM_HEADER_SIZE + frames.iter().map(Frame::encoded_size).sum::<usize>()
            }
            DatagramPayload::Ack(payload) | DatagramPayload::Nack(payload) => {
                1 + payload.encoded_size()
            }
        }
    }

    pub fn encode(&self, dst: &mut impl BufMut) -> Result<(), EncodeError> {
        validate_flags_for_payload(self.header.flags, &self.payload)?;

        match &self.payload {
            DatagramPayload::Frames(frames) => {
                self.header.encode_raknet(dst)?;
                for frame in frames {
                    frame.encode_raknet(dst)?;
                }
            }
            DatagramPayload::Ack(payload) | DatagramPayload::Nack(payload) => {
                self.header.flags.bits().encode_raknet(dst)?;
                payload.encode_raknet(dst)?;
            }
        }
        Ok(())
    }

    pub fn decode(src: &mut impl Buf) -> Result<Self, DecodeError> {
        if !src.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }

        let raw_flags = src.get_u8();
        let (flags, kind) = decode_datagram_flags(raw_flags)?;

        match kind {
            DatagramKind::Ack => Ok(Self {
                header: DatagramHeader {
                    flags,
                    sequence: Sequence24::new(0),
                },
                payload: DatagramPayload::Ack(AckNackPayload::decode_raknet(src)?),
            }),
            DatagramKind::Nack => Ok(Self {
                header: DatagramHeader {
                    flags,
                    sequence: Sequence24::new(0),
                },
                payload: DatagramPayload::Nack(AckNackPayload::decode_raknet(src)?),
            }),
            DatagramKind::Data => {
                let sequence = Sequence24::decode_raknet(src)?;
                let header = DatagramHeader { flags, sequence };

                let mut frames = Vec::new();
                while src.has_remaining() {
                    frames.push(Frame::decode_raknet(src)?);
                }

                Ok(Self {
                    header,
                    payload: DatagramPayload::Frames(frames),
                })
            }
        }
    }
}

fn decode_datagram_flags(raw_flags: u8) -> Result<(DatagramFlags, DatagramKind), DecodeError> {
    let Some(flags) = DatagramFlags::from_bits(raw_flags) else {
        return Err(DecodeError::InvalidDatagramFlags(raw_flags));
    };

    if !flags.contains(DatagramFlags::VALID) {
        return Err(DecodeError::InvalidDatagramFlags(raw_flags));
    }

    let has_ack = flags.contains(DatagramFlags::ACK);
    let has_nack = flags.contains(DatagramFlags::NACK);
    if has_ack && has_nack {
        return Err(DecodeError::InvalidDatagramFlags(raw_flags));
    }

    if has_ack || has_nack {
        let control_extras = DatagramFlags::PACKET_PAIR
            | DatagramFlags::CONTINUOUS_SEND
            | DatagramFlags::HAS_B_AND_AS;
        if flags.intersects(control_extras) {
            return Err(DecodeError::InvalidDatagramFlags(raw_flags));
        }

        return Ok((
            flags,
            if has_ack {
                DatagramKind::Ack
            } else {
                DatagramKind::Nack
            },
        ));
    }

    Ok((flags, DatagramKind::Data))
}

fn validate_flags_for_payload(
    flags: DatagramFlags,
    payload: &DatagramPayload,
) -> Result<(), EncodeError> {
    let raw_flags = flags.bits();
    let (_, decoded_kind) = decode_datagram_flags(raw_flags)
        .map_err(|_| EncodeError::InvalidDatagramFlags(raw_flags))?;

    if decoded_kind != payload.kind() {
        return Err(EncodeError::InvalidDatagramFlags(raw_flags));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ack::SequenceRange;

    fn sample_ack_payload() -> AckNackPayload {
        AckNackPayload {
            ranges: vec![SequenceRange {
                start: Sequence24::new(7),
                end: Sequence24::new(7),
            }],
        }
    }

    #[test]
    fn decode_rejects_unknown_datagram_bits() {
        let mut src = &b"\x83\0\0\0"[..];
        let err = Datagram::decode(&mut src).expect_err("unknown bit must be rejected");
        assert!(matches!(err, DecodeError::InvalidDatagramFlags(0x83)));
    }

    #[test]
    fn decode_rejects_ack_without_valid_flag() {
        let mut src = &b"\x40\0\0"[..];
        let err = Datagram::decode(&mut src).expect_err("ack without valid bit must be rejected");
        assert!(matches!(err, DecodeError::InvalidDatagramFlags(0x40)));
    }

    #[test]
    fn decode_rejects_control_with_data_only_bits() {
        let mut src = &b"\xC8\0\0"[..];
        let err =
            Datagram::decode(&mut src).expect_err("control datagram must not carry data-only bits");
        assert!(matches!(err, DecodeError::InvalidDatagramFlags(0xC8)));
    }

    #[test]
    fn decode_accepts_valid_ack_flags() {
        let payload = sample_ack_payload();
        let mut encoded = Vec::new();
        payload
            .encode_raknet(&mut encoded)
            .expect("ack payload encode");

        let mut src = vec![0xC0];
        src.extend(encoded);
        let decoded = Datagram::decode(&mut src.as_slice()).expect("ack datagram should decode");

        match decoded.payload {
            DatagramPayload::Ack(decoded_payload) => assert_eq!(decoded_payload, payload),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_payload_and_flag_mismatch() {
        let datagram = Datagram {
            header: DatagramHeader {
                flags: DatagramFlags::VALID | DatagramFlags::ACK,
                sequence: Sequence24::new(12),
            },
            payload: DatagramPayload::Frames(Vec::new()),
        };

        let mut out = Vec::new();
        let err = datagram
            .encode(&mut out)
            .expect_err("invalid payload/flags mismatch must fail");
        assert!(matches!(err, EncodeError::InvalidDatagramFlags(0xC0)));
    }
}
