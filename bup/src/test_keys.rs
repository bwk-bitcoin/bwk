//! Deterministic signer keys for tests.

#[cfg(feature = "musig")]
use miniscript::bitcoin::bip32::DerivationPath;
use miniscript::bitcoin::{
    bip32::{Xpriv, Xpub},
    secp256k1::Secp256k1,
    NetworkKind,
};

use crate::key_role::{bip87_account_path, Bip87Account};
#[cfg(feature = "musig")]
use crate::OXpub;

/// A mainnet master key from `[seed; 32]`, origin its own fingerprint, no path.
#[cfg(feature = "musig")]
pub(crate) fn test_key(seed: u8) -> OXpub {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NetworkKind::Main, &[seed; 32]).unwrap();
    OXpub::new(
        Some((xpriv.fingerprint(&secp), DerivationPath::master())),
        Xpub::from_priv(&secp, &xpriv),
    )
}

/// `test_key(1)` to `test_key(count)`.
#[cfg(feature = "musig")]
pub(crate) fn test_keys(count: u8) -> Vec<OXpub> {
    (1..=count).map(test_key).collect()
}

/// A testnet BIP-87 account from the master key `[seed; 32]`.
pub(crate) fn test_account(seed: u8, account: u32) -> Bip87Account {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap();
    let path = bip87_account_path(NetworkKind::Test, account);
    let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap());
    Bip87Account::new(master.fingerprint(&secp), path, xpub).unwrap()
}
