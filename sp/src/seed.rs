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

#[cfg(all(test, feature = "mnemonic"))]
mod tests {
    use std::str::FromStr;

    use bitcoin::{bip32::ChildNumber, Network};

    use super::*;
    use crate::receiver::{bip39::Mnemonic, SpReceiver};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon about";

    fn mnemonic() -> Mnemonic {
        Mnemonic::from_str(MNEMONIC).unwrap()
    }

    #[test]
    fn from_slice_takes_exactly_64_bytes() {
        let bytes = mnemonic().to_seed("");
        assert_eq!(Seed::from_slice(&bytes).unwrap().as_bytes(), &bytes);
        assert_eq!(Seed::from(bytes).as_bytes(), &bytes);
        for len in [0, 16, 32, 63, 65, 128] {
            assert!(matches!(
                Seed::from_slice(&vec![1u8; len]),
                Err(Error::SeedLength(l)) if l == len
            ));
        }
    }

    #[test]
    fn debug_hides_the_bytes() {
        let seed = Seed::from([0xab; SEED_LEN]);
        assert_eq!(format!("{seed:?}"), "Seed(..)");
    }

    #[test]
    fn english_seed_matches_the_mnemonic() {
        let network = Network::Signet;
        let account = ChildNumber::from_hardened_idx(0).unwrap();
        let seed = Seed::from_slice(&mnemonic().to_seed("")).unwrap();

        let from_words = SpReceiver::new_from_mnemonic(mnemonic(), network).unwrap();
        let from_seed = SpReceiver::new_from_seed(&seed, network, account).unwrap();
        assert_eq!(from_seed.get_scan_key(), from_words.get_scan_key());
        assert_eq!(
            from_seed.try_get_secret_spend_key().unwrap(),
            from_words.try_get_secret_spend_key().unwrap()
        );
        assert_eq!(
            from_seed.get_receiving_address(),
            from_words.get_receiving_address()
        );
        // What the mnemonic derived before it went through the seed.
        assert_eq!(seed.fingerprint(network).unwrap().to_string(), "73c5da0a");
        assert_eq!(
            from_seed.get_receiving_address().to_string(),
            "tsp1qqdpels3srq45dlezqvk20t3dlueftry6p5thc7msjm0s6jm3g84jzq5rxzzunfck6d45va2jcqxk42\
             9agt3e4klf3vzmcgp3zqthryhhqgnz4k3n"
        );
    }

    #[test]
    fn a_passphrase_changes_the_receiver() {
        let network = Network::Signet;
        let account = ChildNumber::from_hardened_idx(0).unwrap();
        let plain =
            SpReceiver::new_from_seed(&Seed::from_mnemonic(&mnemonic(), ""), network, account)
                .unwrap();
        let with_passphrase = SpReceiver::new_from_seed(
            &Seed::from_mnemonic(&mnemonic(), "TREZOR"),
            network,
            account,
        )
        .unwrap();
        assert_ne!(
            with_passphrase.get_receiving_address(),
            plain.get_receiving_address()
        );
    }
}
