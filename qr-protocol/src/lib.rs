//! Binary codec for the draft signing-flow protocol described in `ENCODING.md`.
//!
//! The crate is `no_std` plus `alloc` and pulls no dependency of its own, so a
//! bare-metal signer can vendor it as-is. Enable `bitcoin` for conversions to and
//! from the `bitcoin` types, and `ffi` for the C binding.

// Every field of this protocol was introduced in version 1. A field added in a later
// version is appended at the end of its message body and carries a `// since vN`
// marker, so decoding stops cleanly at the end of the fields this parser knows and
// whatever follows belongs to a newer version.

// A `staticlib` needs a global allocator and a panic handler, which a library cannot
// supply, so the C consumer links this rlib from its own staticlib crate.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub type ErrorCode = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: &'static str,
}

macro_rules! c_string {
    ($s:literal) => {
        concat!($s, "\0")
    };
}

macro_rules! error_info {
    ($code:literal, $message:literal) => {
        ErrorInfo {
            code: $code,
            message: c_string!($message),
        }
    };
}

/// Derives `Display` and `Error` from an `info` method returning `ErrorInfo`.
/// The message carries a trailing nul so the C binding can hand out the same literal.
macro_rules! error_display {
    ($ty:ty) => {
        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let message = self.info().message;
                f.write_str(&message[..message.len() - 1])
            }
        }

        impl core::error::Error for $ty {}
    };
}

pub mod decode;
pub mod encode;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod reader;
pub mod request;
pub mod response;
pub mod types;

use alloc::vec::Vec;

const MAGIC: &[u8; 6] = b"BIPXXX";
const VERSION: u8 = 1;
const DIRECTION_RESPONSE: u8 = 0x80;
const DIRECTION_REQUEST: u8 = 0x0;
const STATUS_ERROR: u8 = 0x40;
const STATUS_OK: u8 = 0x0;
const TYPE_MASK: u8 = 0x3f;
pub const MODEL_LEN: usize = 16;
pub const ERROR_MESSAGE_LEN: usize = 32;
pub const REQUEST_ID_LEN: usize = 2;
pub const MAX_DESCRIPTOR_ALIAS: usize = 32;
pub const MAX_BYTES: usize = 512 * 1024;
pub const MAX_VEC: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(pub [u8; REQUEST_ID_LEN]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub body: request::Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: RequestId,
    pub body: response::Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    GetXpubs,
    RegisterDescriptor,
    AddressVerification,
    Signing,
    GetSpDescriptor,
}

impl MessageType {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<MessageType> for u8 {
    fn from(message_type: MessageType) -> Self {
        match message_type {
            MessageType::GetXpubs => 0x01,
            MessageType::RegisterDescriptor => 0x02,
            MessageType::AddressVerification => 0x03,
            MessageType::Signing => 0x04,
            MessageType::GetSpDescriptor => 0x05,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = decode::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::GetXpubs),
            0x02 => Ok(Self::RegisterDescriptor),
            0x03 => Ok(Self::AddressVerification),
            0x04 => Ok(Self::Signing),
            0x05 => Ok(Self::GetSpDescriptor),
            _ => Err(decode::Error::UnknownMessageType(value)),
        }
    }
}

// Shared by both directions: a request asks for a kind, a response announces one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignResponseKind {
    Psbt,
    Signatures,
}

impl SignResponseKind {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<SignResponseKind> for u8 {
    fn from(kind: SignResponseKind) -> Self {
        match kind {
            SignResponseKind::Psbt => 0x01,
            SignResponseKind::Signatures => 0x02,
        }
    }
}

impl TryFrom<u8> for SignResponseKind {
    type Error = decode::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Psbt),
            0x02 => Ok(Self::Signatures),
            _ => Err(decode::Error::UnknownSignResponseKind(value)),
        }
    }
}

pub fn encode_request(request: &Request) -> Result<Vec<u8>, encode::Error> {
    encode::encode_request(request)
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>, encode::Error> {
    encode::encode_response(response)
}

pub fn decode(bytes: &[u8]) -> Result<Message, decode::Error> {
    decode::decode(bytes)
}

#[cfg(all(test, feature = "bitcoin"))]
mod tests {
    use crate::{
        decode, encode_request, encode_response, request, response, Message, MessageType, Request,
        RequestId, Response,
    };
    use alloc::{string::ToString, vec};
    use bitcoin::{absolute, transaction, Psbt, Transaction};

    fn id() -> RequestId {
        RequestId([1, 2])
    }

    fn psbt() -> alloc::vec::Vec<u8> {
        Psbt::from_unsigned_tx(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
        .unwrap()
        .serialize()
    }

    #[test]
    fn get_xpubs_request_round_trips() {
        let request = Request {
            id: id(),
            body: request::Body::GetXpubs(request::GetXpubs {
                derivation_paths: vec![(&"m/48'/0'/0'/2'"
                    .parse::<bitcoin::bip32::DerivationPath>()
                    .unwrap())
                    .into()],
            }),
        };
        let encoded = encode_request(&request).unwrap();
        assert_eq!(decode(&encoded).unwrap(), Message::Request(request));
    }

    #[test]
    fn sp_descriptor_round_trips() {
        let request = Request {
            id: id(),
            body: request::Body::GetSpDescriptor(request::GetSpDescriptor {}),
        };
        let encoded = encode_request(&request).unwrap();
        assert_eq!(decode(&encoded).unwrap(), Message::Request(request));

        let response = Response {
            id: id(),
            body: response::Body::SpDescriptor(response::SpDescriptor {
                descriptor: "sp(scan,spend)".to_string(),
            }),
        };
        let encoded = encode_response(&response).unwrap();
        assert_eq!(decode(&encoded).unwrap(), Message::Response(response));
    }

    #[test]
    fn signing_response_round_trips() {
        let response = Response {
            id: id(),
            body: response::Body::Signed(response::Signed::Psbt(psbt())),
        };
        let encoded = encode_response(&response).unwrap();
        assert_eq!(decode(&encoded).unwrap(), Message::Response(response));
    }

    #[test]
    fn error_response_round_trips() {
        let response = Response {
            id: id(),
            body: response::Body::Error(response::ErrorBody {
                message_type: MessageType::Signing,
                error: response::Error::MalformedRequest,
                message: "bad request".to_string(),
            }),
        };
        let encoded = encode_response(&response).unwrap();
        assert_eq!(decode(&encoded).unwrap(), Message::Response(response));
    }
}
