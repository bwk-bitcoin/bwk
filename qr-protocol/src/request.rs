use alloc::{string::String, vec::Vec};

use crate::{decode, musig, types::DerivationPath, MessageType, SignResponseKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    GetKeys(GetKeys),
    RegisterDescriptor(RegisterDescriptor),
    VerifyAddress(VerifyAddress),
    Sign(Sign),
    PrepareMusig(PrepareMusig),
    SignMusig(SignMusig),
}

impl Body {
    pub fn message_type(&self) -> MessageType {
        self.into()
    }
}

impl From<&Body> for MessageType {
    fn from(body: &Body) -> Self {
        match body {
            Body::GetKeys(_) => Self::GetKeys,
            Body::RegisterDescriptor(_) => Self::RegisterDescriptor,
            Body::VerifyAddress(_) => Self::AddressVerification,
            Body::Sign(_) => Self::Signing,
            Body::PrepareMusig(_) => Self::MusigPreparation,
            Body::SignMusig(_) => Self::MusigSigning,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetKeys {
    pub keys: Vec<KeyRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequest {
    pub derivation_path: DerivationPath,
    pub kind: KeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Public,
    Private,
}

impl KeyKind {
    pub fn value(self) -> u8 {
        self.into()
    }
}

impl From<KeyKind> for u8 {
    fn from(kind: KeyKind) -> Self {
        match kind {
            KeyKind::Public => 0x00,
            KeyKind::Private => 0x01,
        }
    }
}

impl TryFrom<u8> for KeyKind {
    type Error = decode::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Public),
            0x01 => Ok(Self::Private),
            _ => Err(decode::Error::UnknownKeyKind(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDescriptor {
    pub descriptor_alias: String,
    // NOTE: `descriptor` being None means it's a registration check
    pub descriptor: Option<DescriptorBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyAddress {
    pub descriptor_alias: String,
    pub derivation_path: DerivationPath,
    pub address: Option<String>,
    pub descriptor: Option<DescriptorBody>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign {
    pub descriptors: Vec<Descriptor>,
    /// A serialized PSBT v0 or v2, carried without being parsed.
    pub psbt: Vec<u8>,
    pub want_kind: Option<SignResponseKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub alias: String,
    pub descriptor: Option<DescriptorBody>,
    pub proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusigDerivation {
    pub keychain: u32,
    pub index: u32,
}

impl MusigDerivation {
    pub fn validate(&self) -> Result<(), musig::Error> {
        if self.index >= musig::HARDENED_INDEX {
            return Err(musig::Error::HardenedIndex);
        }
        Ok(())
    }
}

/// Transaction-independent preparation. The descriptor body must be present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareMusig {
    pub descriptor: Descriptor,
    pub session_id: [u8; 32],
    pub max_inputs: u8,
    pub derivations: Vec<MusigDerivation>,
}

impl PrepareMusig {
    pub fn validate(&self) -> Result<(), musig::Error> {
        musig::validate_input_coverage(self.max_inputs)?;
        if self.descriptor.descriptor.is_none() {
            return Err(musig::Error::MissingDescriptor);
        }
        musig::validate_derivations(&self.derivations)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMusig {
    pub session_id: [u8; 32],
    pub attempt_id: [u8; 32],
    /// A serialized PSBT v0 or v2, carried without being parsed.
    pub psbt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorBody {
    Bip380(String),
    Bip388 {
        keys: Vec<String>,
        policy: String,
    },
    /// A silent payment account's keys, as `<fingerprint>|<spend_path>|<scan_path>`
    /// (e.g. `73c5da0a|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0`): enough for the signer to
    /// rebuild the account's `sp()` descriptor from its seed, with no secret on the wire.
    SpKeys(String),
}

impl DescriptorBody {
    pub fn value(&self) -> u8 {
        match self {
            Self::Bip380(_) => DESCRIPTOR_BIP380,
            Self::Bip388 { .. } => DESCRIPTOR_BIP388,
            Self::SpKeys(_) => DESCRIPTOR_SP_KEYS,
        }
    }
}

pub const DESCRIPTOR_BIP380: u8 = 0x01;
pub const DESCRIPTOR_BIP388: u8 = 0x02;
pub const DESCRIPTOR_SP_KEYS: u8 = 0x03;
