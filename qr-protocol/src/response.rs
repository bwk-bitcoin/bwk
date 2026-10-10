use alloc::{string::String, vec::Vec};

use crate::{
    types::{Fingerprint, PublicKey, Xpub},
    MessageType,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Xpubs(Xpubs),
    Registration(Registration),
    AddressUri(AddressUri),
    Signed(Signed),
    SpDescriptor(SpDescriptor),
    Error(ErrorBody),
}

impl Body {
    pub fn message_type(&self) -> MessageType {
        self.into()
    }
}

impl From<&Body> for MessageType {
    fn from(body: &Body) -> Self {
        match body {
            Body::Xpubs(_) => Self::GetXpubs,
            Body::Registration(_) => Self::RegisterDescriptor,
            Body::AddressUri(_) => Self::AddressVerification,
            Body::Signed(_) => Self::Signing,
            Body::SpDescriptor(_) => Self::GetSpDescriptor,
            Body::Error(e) => e.message_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xpubs {
    pub xpubs: Vec<Xpub>,
    pub fingerprint: Fingerprint,
    pub model: String,
    pub version: FirmwareVersion,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpDescriptor {
    pub descriptor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u32,
    pub flag: ReleaseFlag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseFlag {
    Stable,
    Alpha,
    Beta,
    ReleaseCandidate,
    Unknown(u8),
}

impl ReleaseFlag {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<ReleaseFlag> for u8 {
    fn from(flag: ReleaseFlag) -> Self {
        match flag {
            ReleaseFlag::Stable => 0x00,
            ReleaseFlag::Alpha => 0x01,
            ReleaseFlag::Beta => 0x02,
            ReleaseFlag::ReleaseCandidate => 0x03,
            ReleaseFlag::Unknown(value) => value,
        }
    }
}

impl From<u8> for ReleaseFlag {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Stable,
            0x01 => Self::Alpha,
            0x02 => Self::Beta,
            0x03 => Self::ReleaseCandidate,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub descriptor_alias: String,
    pub registered: Option<bool>,
    pub stored: Option<bool>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressUri {
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    /// A serialized PSBT v0 or v2, carried without being parsed.
    Psbt(Vec<u8>),
    Signatures(Vec<SignatureEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureEntry {
    Ecdsa {
        input_index: u32,
        public_key: PublicKey,
        signature: Vec<u8>,
    },
    TapKey {
        input_index: u32,
        signature: Vec<u8>,
    },
    TapScript {
        input_index: u32,
        xonly_public_key: [u8; 32],
        tap_leaf_hash: [u8; 32],
        signature: Vec<u8>,
    },
}

impl SignatureEntry {
    pub fn value(&self) -> u8 {
        match self {
            Self::Ecdsa { .. } => SIGNATURE_ECDSA,
            Self::TapKey { .. } => SIGNATURE_TAP_KEY,
            Self::TapScript { .. } => SIGNATURE_TAP_SCRIPT,
        }
    }
}

pub const SIGNATURE_ECDSA: u8 = 0x01;
pub const SIGNATURE_TAP_KEY: u8 = 0x02;
pub const SIGNATURE_TAP_SCRIPT: u8 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorBody {
    pub message_type: MessageType,
    pub error: Error,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UserDeclined,
    UnsupportedVersion,
    MalformedRequest,
    UnknownDescriptorAlias,
    DescriptorRegistrationFailed,
    UnsupportedDescriptorForm,
    InvalidProof,
    AddressMismatch,
    NothingToSign,
    InvalidPsbt,
    InternalError,
    Vendor,
    Unknown(u8),
}

impl Error {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<Error> for u8 {
    fn from(error: Error) -> Self {
        match error {
            Error::UserDeclined => 0x01,
            Error::UnsupportedVersion => 0x02,
            Error::MalformedRequest => 0x03,
            Error::UnknownDescriptorAlias => 0x04,
            Error::DescriptorRegistrationFailed => 0x05,
            Error::UnsupportedDescriptorForm => 0x06,
            Error::InvalidProof => 0x07,
            Error::AddressMismatch => 0x08,
            Error::NothingToSign => 0x09,
            Error::InvalidPsbt => 0x0a,
            Error::InternalError => 0x0b,
            Error::Vendor => 0xff,
            Error::Unknown(value) => value,
        }
    }
}

impl From<u8> for Error {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::UserDeclined,
            0x02 => Self::UnsupportedVersion,
            0x03 => Self::MalformedRequest,
            0x04 => Self::UnknownDescriptorAlias,
            0x05 => Self::DescriptorRegistrationFailed,
            0x06 => Self::UnsupportedDescriptorForm,
            0x07 => Self::InvalidProof,
            0x08 => Self::AddressMismatch,
            0x09 => Self::NothingToSign,
            0x0a => Self::InvalidPsbt,
            0x0b => Self::InternalError,
            0xff => Self::Vendor,
            value => Self::Unknown(value),
        }
    }
}
