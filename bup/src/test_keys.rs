//! Deterministic signer keys for tests.

use miniscript::bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
    NetworkKind,
};

use crate::OXpub;

/// A mainnet master key from `[seed; 32]`, origin its own fingerprint, no path.
pub(crate) fn test_key(seed: u8) -> OXpub {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NetworkKind::Main, &[seed; 32]).unwrap();
    OXpub::new(
        Some((xpriv.fingerprint(&secp), DerivationPath::master())),
        Xpub::from_priv(&secp, &xpriv),
    )
}

/// `test_key(1)` to `test_key(count)`.
pub(crate) fn test_keys(count: u8) -> Vec<OXpub> {
    (1..=count).map(test_key).collect()
}
