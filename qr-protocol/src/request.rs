use alloc::{string::String, vec::Vec};

use crate::{types::DerivationPath, MessageType, SignResponseKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    GetXpubs(GetXpubs),
    RegisterDescriptor(RegisterDescriptor),
    VerifyAddress(VerifyAddress),
    Sign(Sign),
    GetSpDescriptor(GetSpDescriptor),
}

impl Body {
    pub fn message_type(&self) -> MessageType {
        self.into()
    }
}

impl From<&Body> for MessageType {
    fn from(body: &Body) -> Self {
        match body {
            Body::GetXpubs(_) => Self::GetXpubs,
            Body::RegisterDescriptor(_) => Self::RegisterDescriptor,
            Body::VerifyAddress(_) => Self::AddressVerification,
            Body::Sign(_) => Self::Signing,
            Body::GetSpDescriptor(_) => Self::GetSpDescriptor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetXpubs {
    pub derivation_paths: Vec<DerivationPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSpDescriptor {}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorBody {
    Bip380(String),
    Bip388 { keys: Vec<String>, policy: String },
}

impl DescriptorBody {
    pub fn value(&self) -> u8 {
        match self {
            Self::Bip380(_) => DESCRIPTOR_BIP380,
            Self::Bip388 { .. } => DESCRIPTOR_BIP388,
        }
    }
}

pub const DESCRIPTOR_BIP380: u8 = 0x01;
pub const DESCRIPTOR_BIP388: u8 = 0x02;
