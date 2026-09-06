//! A rust implementation of BIP352: Silent Payments. This library
//! can be used to add silent payment support to wallets.
//!
//! This library is split up in two parts: sending and receiving.
//!
//! Source: adapted from SPDK's vendored `silentpayments` implementation,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.
#![allow(non_snake_case)]

pub use secp256k1;

use secp256k1::{PublicKey, SecretKey};

#[derive(Clone, Copy, Debug)]
pub struct PartialSecret(SecretKey);

impl PartialSecret {
    pub fn as_inner(&self) -> &SecretKey {
        &self.0
    }
}

impl From<SecretKey> for PartialSecret {
    fn from(secret: SecretKey) -> Self {
        Self(secret)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SharedSecret(PublicKey);

impl SharedSecret {
    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }
}

impl From<PublicKey> for SharedSecret {
    fn from(point: PublicKey) -> Self {
        Self(point)
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SpVersion(u8);

impl SpVersion {
    pub const V0: Self = Self(0);

    pub fn as_u8(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for SpVersion {
    type Error = error::Error;

    fn try_from(version: u8) -> Result<Self, Self::Error> {
        if version == Self::V0.0 {
            Ok(Self::V0)
        } else {
            Err(error::Error::UnsupportedVersion(version.into()))
        }
    }
}

pub mod error;

pub mod receiving;
pub mod sending;
pub mod utils;
