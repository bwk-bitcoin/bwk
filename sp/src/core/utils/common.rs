//! Source: adapted from SPDK's vendored `silentpayments` implementation,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.

use crate::core::{
    error::Error,
    secp256k1::{PublicKey, Scalar, SecretKey, SECP256K1},
    utils::hash::SharedSecretHash,
};
use bitcoin_hashes::Hash;

pub fn calculate_t_n(ecdh_shared_secret: &PublicKey, k: u32) -> Result<SecretKey, Error> {
    let hash = SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

pub fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey, Error> {
    // Use the shared global secp context: a fresh `Secp256k1::new()` here is called
    // once per tweak in the scan hot path, and the per-call context allocation
    // (16 threads, millions of tweaks) dominates the EC work it wraps.
    let P_n = B_spend.add_exp_tweak(SECP256K1, &t_n)?;

    Ok(P_n)
}
