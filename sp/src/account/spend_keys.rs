//! Extended private keys a spend draws BIP32 input keys from.
//!
//! A [`KeyRing`] resolves the `(master fingerprint, full path)` origin a PSBT
//! input carries to a secret key, from master keys or from keys rooted at an
//! account path (e.g. `m/86'/0'/0'`), so a caller can hold an account key
//! without holding the master key it was derived from.

use std::collections::BTreeMap;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv},
    secp256k1::{Secp256k1, SecretKey, Signing},
};

/// An extended private key rooted at `origin_path` under the master key
/// whose fingerprint is `master_fingerprint`.
///
/// With an empty `origin_path`, `xpriv` is the master key itself.
#[derive(Clone)]
pub struct OriginXpriv {
    pub master_fingerprint: Fingerprint,
    pub origin_path: DerivationPath,
    pub xpriv: Xpriv,
}

impl OriginXpriv {
    /// Derive the secret key at `path`, a full path from the master, if this
    /// key is an ancestor of it.
    fn derive<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        fingerprint: &Fingerprint,
        path: &DerivationPath,
    ) -> Option<SecretKey> {
        if *fingerprint != self.master_fingerprint {
            return None;
        }
        let origin: &[ChildNumber] = self.origin_path.as_ref();
        let full: &[ChildNumber] = path.as_ref();
        let suffix = full.strip_prefix(origin)?;
        self.xpriv
            .derive_priv(secp, &DerivationPath::from(suffix.to_vec()))
            .ok()
            .map(|k| k.private_key)
    }
}

impl std::fmt::Debug for OriginXpriv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginXpriv")
            .field("master_fingerprint", &self.master_fingerprint)
            .field("origin_path", &self.origin_path)
            .finish_non_exhaustive()
    }
}

/// The extended private keys a spend may draw BIP32 input keys from, looked
/// up by the `(master fingerprint, full path)` origin a PSBT input carries.
#[derive(Clone, Default, Debug)]
pub struct KeyRing {
    keys: Vec<OriginXpriv>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// A ring of master xprivs, keyed by their own fingerprint.
    pub fn from_masters(masters: BTreeMap<Fingerprint, Xpriv>) -> Self {
        Self {
            keys: masters
                .into_iter()
                .map(|(master_fingerprint, xpriv)| OriginXpriv {
                    master_fingerprint,
                    origin_path: DerivationPath::master(),
                    xpriv,
                })
                .collect(),
        }
    }

    pub fn push(&mut self, key: OriginXpriv) {
        self.keys.push(key);
    }

    pub fn extend(&mut self, mut other: KeyRing) {
        self.keys.append(&mut other.keys);
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The secret key at `path` under `fingerprint`, from the first key of
    /// the ring that is an ancestor of it.
    pub fn derive<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        fingerprint: &Fingerprint,
        path: &DerivationPath,
    ) -> Option<SecretKey> {
        self.keys
            .iter()
            .find_map(|key| key.derive(secp, fingerprint, path))
    }
}

impl Drop for KeyRing {
    fn drop(&mut self) {
        for key in &mut self.keys {
            key.xpriv.private_key.non_secure_erase();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn master() -> Xpriv {
        Xpriv::new_master(bitcoin::Network::Testnet, &[7u8; 32]).unwrap()
    }

    #[test]
    fn an_account_key_derives_the_same_child_as_the_master() {
        let secp = Secp256k1::new();
        let master = master();
        let fingerprint = master.fingerprint(&secp);
        let account_path = DerivationPath::from_str("m/86'/1'/0'").unwrap();
        let account = master.derive_priv(&secp, &account_path).unwrap();
        let child = DerivationPath::from_str("m/86'/1'/0'/1/5").unwrap();

        let mut ring = KeyRing::new();
        ring.push(OriginXpriv {
            master_fingerprint: fingerprint,
            origin_path: account_path,
            xpriv: account,
        });

        let expected = master.derive_priv(&secp, &child).unwrap().private_key;
        assert_eq!(ring.derive(&secp, &fingerprint, &child), Some(expected));
    }

    #[test]
    fn an_account_key_derives_nothing_outside_its_account() {
        let secp = Secp256k1::new();
        let master = master();
        let fingerprint = master.fingerprint(&secp);
        let account_path = DerivationPath::from_str("m/86'/1'/0'").unwrap();
        let account = master.derive_priv(&secp, &account_path).unwrap();

        let mut ring = KeyRing::new();
        ring.push(OriginXpriv {
            master_fingerprint: fingerprint,
            origin_path: account_path,
            xpriv: account,
        });

        let other_account = DerivationPath::from_str("m/86'/1'/1'/0/0").unwrap();
        let other_purpose = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
        assert_eq!(ring.derive(&secp, &fingerprint, &other_account), None);
        assert_eq!(ring.derive(&secp, &fingerprint, &other_purpose), None);
    }

    #[test]
    fn a_key_derives_nothing_under_another_master() {
        let secp = Secp256k1::new();
        let ring = KeyRing::from_masters(BTreeMap::from([(
            Fingerprint::from([1, 2, 3, 4]),
            master(),
        )]));
        let path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
        let fingerprint = master().fingerprint(&secp);
        assert_eq!(ring.derive(&secp, &fingerprint, &path), None);
    }

    #[test]
    fn debug_output_carries_no_key() {
        let secp = Secp256k1::new();
        let master = master();
        let ring = KeyRing::from_masters(BTreeMap::from([(master.fingerprint(&secp), master)]));
        let rendered = format!("{ring:?}");
        assert!(!rendered.contains(&master.to_string()));
        assert!(!rendered.contains(&master.private_key.display_secret().to_string()));
    }
}
