//! BIP-390 musig() descriptors: parse through the token form, print standard.

#![allow(dead_code, unused_variables)]

use bwk_keys::{
    keys::OXpub,
    musig::{DefiniteMusigKey, MusigKey},
};

use crate::descriptor::Error;

pub type MusigDescriptor = miniscript::Descriptor<MusigKey>;
pub type DefiniteMusigDescriptor = miniscript::Descriptor<DefiniteMusigKey>;

/// Checks the checksum, rewrites to the token form, parses, enforces musig() in tr() only.
pub fn parse_musig_descriptor(s: &str) -> Result<MusigDescriptor, Error> {
    todo!()
}

/// Standard BIP-390 text, with its checksum when `checksum`.
pub fn musig_descriptor_to_string(descriptor: &MusigDescriptor, checksum: bool) -> String {
    todo!()
}

/// `musig(K1,...,Kn)` to `musig|K1|...|Kn|`, everything else verbatim, no checksum.
pub fn to_token_form(s: &str) -> Result<String, Error> {
    todo!()
}

/// The inverse of `to_token_form`.
pub fn to_bip390_form(s: &str) -> String {
    todo!()
}

/// `tr(musig(cosigners...)/<0;1>/*)`, key path only, cosigners in the given order.
pub fn musig_tr(cosigners: &[OXpub]) -> Result<MusigDescriptor, Error> {
    todo!()
}
