use std::net::SocketAddr;

use bytes::Buf;

use crate::error::DecodeError;
use crate::protocol::codec::RaknetCodec;
use crate::protocol::constants::Magic;

#[derive(Debug, Clone)]
pub struct OpenConnectionRequest1 {
    pub protocol_version: u8,
    pub mtu: u16,
    pub magic: Magic,
}

#[derive(Debug, Clone)]
pub struct OpenConnectionReply1 {
    pub server_guid: u64,
    pub mtu: u16,
    pub cookie: Option<u32>,
    pub magic: Magic,
}

#[derive(Debug, Clone)]
pub struct OpenConnectionRequest2 {
    pub server_addr: SocketAddr,
    pub mtu: u16,
    pub client_guid: u64,
    pub cookie: Option<u32>,
    pub client_proof: bool,
    pub parse_path: Request2ParsePath,
    pub magic: Magic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request2ParsePath {
    StrictNoCookie,
    StrictWithCookie,
    AmbiguousPreferredNoCookie,
    AmbiguousPreferredWithCookie,
    LegacyHeuristic,
}

#[derive(Debug, Clone)]
pub struct OpenConnectionReply2 {
    pub server_guid: u64,
    pub server_addr: SocketAddr,
    pub mtu: u16,
    pub use_encryption: bool,
    pub magic: Magic,
}

pub(super) fn decode_request_1(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<OpenConnectionRequest1, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let protocol_version = u8::decode_raknet(src)?;
    let padding_len = src.remaining();
    let _ = src.copy_to_bytes(padding_len);

    let mtu = (padding_len + 18) as u16;
    Ok(OpenConnectionRequest1 {
        protocol_version,
        mtu,
        magic,
    })
}

pub(super) fn decode_reply_1(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<OpenConnectionReply1, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;
    let has_cookie = bool::decode_raknet(src)?;
    let cookie = if has_cookie {
        Some(u32::decode_raknet(src)?)
    } else {
        None
    };
    let mtu = u16::decode_raknet(src)?;

    Ok(OpenConnectionReply1 {
        server_guid,
        mtu,
        cookie,
        magic,
    })
}

pub(super) fn decode_request_2(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<OpenConnectionRequest2, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let remaining = src.copy_to_bytes(src.remaining());
    let body = &remaining[..];

    let strict_no_cookie = parse_request_2_candidate(body, false, true);
    let strict_with_cookie = parse_request_2_candidate(body, true, true);

    match (strict_no_cookie, strict_with_cookie) {
        (Ok(candidate), Err(_)) => {
            Ok(candidate.into_request(magic, Request2ParsePath::StrictNoCookie))
        }
        (Err(_), Ok(candidate)) => {
            Ok(candidate.into_request(magic, Request2ParsePath::StrictWithCookie))
        }
        (Ok(no_cookie), Ok(with_cookie)) => {
            let path = if matches!(body.first().copied(), Some(4 | 6)) {
                Request2ParsePath::AmbiguousPreferredNoCookie
            } else {
                Request2ParsePath::AmbiguousPreferredWithCookie
            };
            let chosen = match path {
                Request2ParsePath::AmbiguousPreferredNoCookie => no_cookie,
                Request2ParsePath::AmbiguousPreferredWithCookie => with_cookie,
                _ => unreachable!("ambiguous path must choose one strict candidate"),
            };
            Ok(chosen.into_request(magic, path))
        }
        (Err(_), Err(_)) => {
            let legacy = parse_request_2_legacy(body)?;
            Ok(legacy.into_request(magic, Request2ParsePath::LegacyHeuristic))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Request2Candidate {
    server_addr: SocketAddr,
    mtu: u16,
    client_guid: u64,
    cookie: Option<u32>,
    client_proof: bool,
}

impl Request2Candidate {
    fn into_request(self, magic: Magic, parse_path: Request2ParsePath) -> OpenConnectionRequest2 {
        OpenConnectionRequest2 {
            server_addr: self.server_addr,
            mtu: self.mtu,
            client_guid: self.client_guid,
            cookie: self.cookie,
            client_proof: self.client_proof,
            parse_path,
            magic,
        }
    }
}

fn parse_request_2_candidate(
    mut body: &[u8],
    with_cookie: bool,
    strict_bool: bool,
) -> Result<Request2Candidate, DecodeError> {
    let mut cookie = None;
    let mut client_proof = false;

    if with_cookie {
        if body.len() < 5 {
            return Err(DecodeError::UnexpectedEof);
        }
        cookie = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
        let raw_proof = body[4];
        if strict_bool && raw_proof > 1 {
            return Err(DecodeError::InvalidRequest2Layout);
        }
        client_proof = raw_proof == 1;
        body = &body[5..];
    }

    let server_addr = SocketAddr::decode_raknet(&mut body)?;
    let mtu = u16::decode_raknet(&mut body)?;
    let client_guid = u64::decode_raknet(&mut body)?;
    if !body.is_empty() {
        return Err(DecodeError::InvalidRequest2Layout);
    }

    Ok(Request2Candidate {
        server_addr,
        mtu,
        client_guid,
        cookie,
        client_proof,
    })
}

fn parse_request_2_legacy(body: &[u8]) -> Result<Request2Candidate, DecodeError> {
    let mut with_cookie = false;
    if let Some(first) = body.first().copied()
        && first != 4
        && first != 6
    {
        with_cookie = true;
    }
    parse_request_2_candidate(body, with_cookie, false)
}

pub(super) fn decode_reply_2(
    src: &mut impl Buf,
    expected_magic: Magic,
) -> Result<OpenConnectionReply2, DecodeError> {
    let magic = super::validate_magic(Magic::decode_raknet(src)?, expected_magic)?;
    let server_guid = u64::decode_raknet(src)?;
    let server_addr = SocketAddr::decode_raknet(src)?;
    let mtu = u16::decode_raknet(src)?;
    let use_encryption = bool::decode_raknet(src)?;

    Ok(OpenConnectionReply2 {
        server_guid,
        server_addr,
        mtu,
        use_encryption,
        magic,
    })
}
