//! The BIP39 seed a hot silent-payment account and its signers are built
//! from.

use bitcoin::{bip32, secp256k1::Secp256k1, Network};
use bwk_sign::bip39;
use zeroize::Zeroizing;

use crate::receiver::error::Error;

/// Length in bytes of a BIP39 seed.
pub const SEED_LEN: usize = 64;

/// A BIP39 seed: the 64 bytes BIP39's PBKDF2 derives from a mnemonic and its
/// passphrase.
///
/// The mnemonic's wordlist and the passphrase are already folded into these
/// bytes, so whatever is built from a `Seed` is independent of the language
/// and of the passphrase: a wallet whose mnemonic is not English, or that has
/// a passphrase, gets the same standard BIP352 keys as any other BIP352
/// software. The seed of an English mnemonic without passphrase builds exactly
/// what the mnemonic builds.
///
/// The bytes are wiped on drop, each clone its own, and `Debug` never prints
/// them. The keys derived from them (`Xpriv`, `SecretKey`) are `Copy` and are
/// not wiped.
#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    /// Copies a BIP39 seed out of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SeedLength`] unless `bytes` is exactly [`SEED_LEN`]
    /// bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SEED_LEN {
            return Err(Error::SeedLength(bytes.len()));
        }
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        seed.copy_from_slice(bytes);
        Ok(Self(seed))
    }

    /// The BIP39 seed of `mnemonic` under `passphrase`.
    pub fn from_mnemonic(mnemonic: &bip39::Mnemonic, passphrase: &str) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        *seed = mnemonic.to_seed(passphrase);
        Self(seed)
    }

    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }

    /// The BIP32 master key of this seed.
    pub fn master_xpriv(&self, network: Network) -> Result<bip32::Xpriv, Error> {
        bip32::Xpriv::new_master(network, self.as_bytes()).map_err(|_| Error::SeedDerivation)
    }

    /// The BIP32 master fingerprint of this seed.
    pub fn fingerprint(&self, network: Network) -> Result<bip32::Fingerprint, Error> {
        Ok(self.master_xpriv(network)?.fingerprint(&Secp256k1::new()))
    }
}

impl From<[u8; SEED_LEN]> for Seed {
    fn from(bytes: [u8; SEED_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}
