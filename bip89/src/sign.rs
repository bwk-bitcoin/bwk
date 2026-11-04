//! BIP89 DelegatorSign. The caller passes the 32-byte message to sign (for
//! taproot spends, the sighash) and fresh aux randomness; the tweak should be
//! verified first (input verification), since the delegator cannot tell a
//! genuine tweak from any other scalar.

use crate::{backend::BitcoinBackend, bip340, tweak::tweak_secret, Error};

/// Adds `tweak` to the delegator's base secret and signs `msg` with the
/// tweaked secret under BIP340.
pub fn delegator_sign<B: BitcoinBackend>(
    c: &B,
    tweak: &[u8; 32],
    secret: &[u8; 32],
    msg: &[u8; 32],
    aux: &[u8; 32],
) -> Result<[u8; 64], Error> {
    let tweaked_secret = tweak_secret(c, secret, tweak)?;
    bip340::sign(c, &tweaked_secret, msg, aux)
}
