//! MuSig2 helpers the compiler and the reader call.

use bwk_keys::musig::{MusigAggregate, MusigKey};
use miniscript::{Miniscript, Tap};

use crate::{OXpub, PolicyError};

/// `musig(keys...)/<start;start+1>/*`, participants in the given order.
pub fn musig_key(keys: &[OXpub], start: u32) -> Result<MusigKey, PolicyError> {
    let _ = (keys, start);
    todo!()
}

/// `pk(musig(keys...)/<start;start+1>/*)`.
pub fn musig_leaf(keys: &[OXpub], start: u32) -> Result<Miniscript<MusigKey, Tap>, PolicyError> {
    let _ = (keys, start);
    todo!()
}

/// The participants of an aggregate-then-derive musig() and its zone index.
pub fn musig_participants(aggregate: &MusigAggregate) -> Result<(Vec<OXpub>, u32), PolicyError> {
    let _ = aggregate;
    todo!()
}
