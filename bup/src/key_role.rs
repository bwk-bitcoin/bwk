//! Key role (business installer `KeyType`) in the last unhardened origin step R.

use std::fmt;

use miniscript::{
    bitcoin::{
        bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
        secp256k1::Secp256k1,
        NetworkKind,
    },
    DescriptorPublicKey,
};

use crate::OXpub;

pub const BIP87_PURPOSE: u32 = 87;
const BIP87_COIN_MAINNET: u32 = 0;
const BIP87_COIN_TESTNET: u32 = 1;
/// Bits of R holding the role; the bits above hold the occurrence index.
pub const KEY_ROLE_BITS: u32 = 4;
pub const KEY_ROLE_MASK: u32 = (1 << KEY_ROLE_BITS) - 1;
/// Largest occurrence index keeping R unhardened.
pub const KEY_ROLE_MAX_INDEX: u32 = (1 << (31 - KEY_ROLE_BITS)) - 1;

/// Role of a key, as liana-connect's `ws_business::models::KeyType`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum KeyType {
    Internal,
    External,
    Cosigner,
    SafetyNet,
}

impl KeyType {
    pub const ALL: [KeyType; 4] = [
        Self::Internal,
        Self::External,
        Self::Cosigner,
        Self::SafetyNet,
    ];

    /// Its role nibble (0 to 3).
    pub const fn nibble(self) -> u32 {
        match self {
            Self::Internal => 0,
            Self::External => 1,
            Self::Cosigner => 2,
            Self::SafetyNet => 3,
        }
    }

    /// R for this role at occurrence `index`.
    pub fn child_index(self, index: u32) -> Result<u32, KeyRoleError> {
        if index > KEY_ROLE_MAX_INDEX {
            return Err(KeyRoleError::IndexOutOfRange);
        }
        Ok((index << KEY_ROLE_BITS) | self.nibble())
    }

    /// The role and occurrence index in R, None for a reserved nibble.
    pub fn from_child_index(r: u32) -> Option<(Self, u32)> {
        ChildNumber::from_normal_idx(r).ok()?;
        let role = Self::ALL
            .into_iter()
            .find(|role| role.nibble() == r & KEY_ROLE_MASK)?;
        Some((role, r >> KEY_ROLE_BITS))
    }
}

/// "Internal", "External", "Cosigner", "Safety Net".
impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Self::Internal => "Internal",
            Self::External => "External",
            Self::Cosigner => "Cosigner",
            Self::SafetyNet => "Safety Net",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRoleError {
    /// The account path is not `87'/coin'/account'`, all hardened.
    NotBip87Account,
    /// `coin'` does not match the xpub's network.
    NetworkMismatch,
    /// Occurrence index above `KEY_ROLE_MAX_INDEX`.
    IndexOutOfRange,
    Derivation(String),
}

impl fmt::Display for KeyRoleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotBip87Account => {
                write!(f, "origin path is not 87'/coin'/account', all hardened")
            }
            Self::NetworkMismatch => write!(f, "coin type does not match the xpub network"),
            Self::IndexOutOfRange => {
                write!(f, "key role occurrence index above {KEY_ROLE_MAX_INDEX}")
            }
            Self::Derivation(e) => write!(f, "key role derivation failed: {e}"),
        }
    }
}

impl std::error::Error for KeyRoleError {}

/// `m/87'/coin'/account'` for `network`. Panics if `account` does not fit a hardened
/// index.
pub fn bip87_account_path(network: NetworkKind, account: u32) -> DerivationPath {
    let coin = match network {
        NetworkKind::Main => BIP87_COIN_MAINNET,
        NetworkKind::Test => BIP87_COIN_TESTNET,
    };
    [BIP87_PURPOSE, coin, account]
        .into_iter()
        .map(|i| ChildNumber::from_hardened_idx(i).expect("BIP-87 step fits a hardened index"))
        .collect()
}

/// The network kind and account number of `87'/coin'/account'`, all hardened, None for
/// any other path.
fn bip87_account(path: &[ChildNumber]) -> Option<(NetworkKind, u32)> {
    let [ChildNumber::Hardened { index: purpose }, ChildNumber::Hardened { index: coin }, ChildNumber::Hardened { index: account }] =
        path
    else {
        return None;
    };
    if *purpose != BIP87_PURPOSE {
        return None;
    }
    let network = match *coin {
        BIP87_COIN_MAINNET => NetworkKind::Main,
        BIP87_COIN_TESTNET => NetworkKind::Test,
        _ => return None,
    };
    Some((network, *account))
}

/// The role and index of a `87'/coin'/account'/R` origin path, None for any other.
fn role_of_origin(path: &DerivationPath) -> Option<(KeyType, u32)> {
    let [account @ .., ChildNumber::Normal { index: r }] = path.as_ref() else {
        return None;
    };
    bip87_account(account)?;
    KeyType::from_child_index(*r)
}

/// A BIP-87 account xpub, fetched once per key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip87Account {
    fingerprint: Fingerprint,
    path: DerivationPath,
    xpub: Xpub,
}

impl Bip87Account {
    /// Checks `path` is `87'/coin'/account'` (any hardened account) and `coin'`
    /// matches `xpub`'s network.
    pub fn new(
        fingerprint: Fingerprint,
        path: DerivationPath,
        xpub: Xpub,
    ) -> Result<Self, KeyRoleError> {
        let (network, _) = bip87_account(path.as_ref()).ok_or(KeyRoleError::NotBip87Account)?;
        if network != xpub.network {
            return Err(KeyRoleError::NetworkMismatch);
        }
        Ok(Self {
            fingerprint,
            path,
            xpub,
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    pub fn account(&self) -> u32 {
        let (_, account) =
            bip87_account(self.path.as_ref()).expect("path checked by Bip87Account::new");
        account
    }

    /// `[fp/87'/coin'/account'/R]xpub`, R = `(index << 4) | role`, xpub the child R.
    pub fn role_key(&self, key_type: KeyType, index: u32) -> Result<OXpub, KeyRoleError> {
        let r = key_type.child_index(index)?;
        let child =
            ChildNumber::from_normal_idx(r).map_err(|e| KeyRoleError::Derivation(e.to_string()))?;
        let xkey = self
            .xpub
            .ckd_pub(&Secp256k1::verification_only(), child)
            .map_err(|e| KeyRoleError::Derivation(e.to_string()))?;
        Ok(OXpub::new(
            Some((self.fingerprint, self.path.child(child))),
            xkey,
        ))
    }
}

/// The role in `key`'s origin: origin path `87'/coin'/account'/R` with any hardened
/// account and a known role nibble in R; None otherwise. Returns the role and index.
pub fn key_type(key: &OXpub) -> Option<(KeyType, u32)> {
    let (_, path) = key.origin.as_ref()?;
    role_of_origin(path)
}

/// Same, for a plain descriptor key.
pub fn key_type_of(key: &DescriptorPublicKey) -> Option<(KeyType, u32)> {
    let origin = match key {
        DescriptorPublicKey::Single(k) => &k.origin,
        DescriptorPublicKey::XPub(k) => &k.origin,
        DescriptorPublicKey::MultiXPub(k) => &k.origin,
    };
    let (_, path) = origin.as_ref()?;
    role_of_origin(path)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{
        bitcoin::{
            bip32::{DerivationPath, Xpriv, Xpub},
            secp256k1::Secp256k1,
            NetworkKind,
        },
        DescriptorPublicKey,
    };

    use crate::{
        key_role::{
            bip87_account_path, key_type, key_type_of, Bip87Account, KeyRoleError, KeyType,
            KEY_ROLE_MAX_INDEX,
        },
        test_keys::test_account,
        OXpub,
    };

    fn path(s: &str) -> DerivationPath {
        DerivationPath::from_str(s).unwrap()
    }

    fn master(seed: u8) -> Xpriv {
        Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap()
    }

    /// The xpub at `path` under `master(seed)`.
    fn xpub_at(seed: u8, p: &str) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &master(seed).derive_priv(&secp, &path(p)).unwrap())
    }

    fn mainnet_xpub() -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(
            &secp,
            &Xpriv::new_master(NetworkKind::Main, &[1; 32]).unwrap(),
        )
    }

    /// `test_account(1, 0)`'s role key re-rooted at origin path `p`.
    fn key_with_origin(p: &str) -> OXpub {
        let key = test_account(1, 0).role_key(KeyType::Cosigner, 0).unwrap();
        let (fp, _) = key.origin.unwrap();
        OXpub::new(Some((fp, path(p))), key.xkey)
    }

    #[test]
    fn key_type_nibbles_follow_the_table() {
        assert_eq!(KeyType::ALL.map(KeyType::nibble), [0, 1, 2, 3]);
    }

    #[test]
    fn child_index_packs_index_above_role() {
        assert_eq!(KeyType::Internal.child_index(0), Ok(0));
        assert_eq!(KeyType::Cosigner.child_index(0), Ok(2));
        assert_eq!(KeyType::Cosigner.child_index(1), Ok(18));
        assert_eq!(KeyType::SafetyNet.child_index(2), Ok(35));
        assert_eq!(
            KeyType::External.child_index(KEY_ROLE_MAX_INDEX),
            Ok(0x7FFF_FFF1)
        );
    }

    #[test]
    fn child_index_rejects_index_above_max() {
        assert_eq!(
            KeyType::Internal.child_index(KEY_ROLE_MAX_INDEX + 1),
            Err(KeyRoleError::IndexOutOfRange)
        );
    }

    #[test]
    fn from_child_index_round_trips() {
        for role in KeyType::ALL {
            for i in [0, 1, 7, KEY_ROLE_MAX_INDEX] {
                let r = role.child_index(i).unwrap();
                assert_eq!(KeyType::from_child_index(r), Some((role, i)));
            }
        }
    }

    #[test]
    fn from_child_index_reserved_or_hardened_is_none() {
        for nibble in 4..16 {
            assert_eq!(KeyType::from_child_index(nibble), None);
            assert_eq!(KeyType::from_child_index((3 << 4) | nibble), None);
        }
        assert_eq!(KeyType::from_child_index(0x8000_0002), None);
    }

    #[test]
    fn key_type_display() {
        assert_eq!(KeyType::Internal.to_string(), "Internal");
        assert_eq!(KeyType::External.to_string(), "External");
        assert_eq!(KeyType::Cosigner.to_string(), "Cosigner");
        assert_eq!(KeyType::SafetyNet.to_string(), "Safety Net");
    }

    #[test]
    fn bip87_account_path_per_network() {
        assert_eq!(
            bip87_account_path(NetworkKind::Main, 0),
            path("m/87'/0'/0'")
        );
        assert_eq!(
            bip87_account_path(NetworkKind::Test, 5),
            path("m/87'/1'/5'")
        );
    }

    #[test]
    fn bip87_account_new_checks_path_and_network() {
        let fp = master(1).fingerprint(&Secp256k1::new());
        let account =
            Bip87Account::new(fp, path("m/87'/1'/0'"), xpub_at(1, "m/87'/1'/0'")).unwrap();
        assert_eq!(account.fingerprint(), fp);
        assert_eq!(account.path(), &path("m/87'/1'/0'"));
        assert_eq!(account.account(), 0);
        let account =
            Bip87Account::new(fp, path("m/87'/1'/7'"), xpub_at(1, "m/87'/1'/7'")).unwrap();
        assert_eq!(account.account(), 7);

        let testnet = xpub_at(1, "m/87'/1'/0'");
        for p in [
            "m/84'/1'/0'",
            "m/87'/1'",
            "m/87'/1'/0'/0",
            "m/87'/1'/0",
            "m/87'/2'/0'",
        ] {
            assert_eq!(
                Bip87Account::new(fp, path(p), testnet),
                Err(KeyRoleError::NotBip87Account),
                "{p}"
            );
        }
        assert_eq!(
            Bip87Account::new(fp, path("m/87'/0'/0'"), testnet),
            Err(KeyRoleError::NetworkMismatch)
        );
        assert_eq!(
            Bip87Account::new(fp, path("m/87'/1'/0'"), mainnet_xpub()),
            Err(KeyRoleError::NetworkMismatch)
        );
    }

    #[test]
    fn role_key_derives_child_r() {
        let fp = master(1).fingerprint(&Secp256k1::new());
        let key = test_account(1, 0).role_key(KeyType::Cosigner, 1).unwrap();
        assert_eq!(key.origin, Some((fp, path("m/87'/1'/0'/18"))));
        assert_eq!(key.xkey, xpub_at(1, "m/87'/1'/0'/18"));

        let key = test_account(1, 3).role_key(KeyType::Cosigner, 1).unwrap();
        assert_eq!(key.origin, Some((fp, path("m/87'/1'/3'/18"))));

        assert_eq!(
            test_account(1, 0).role_key(KeyType::Internal, KEY_ROLE_MAX_INDEX + 1),
            Err(KeyRoleError::IndexOutOfRange)
        );
    }

    #[test]
    fn key_type_reads_role_from_origin() {
        let key = test_account(1, 0).role_key(KeyType::SafetyNet, 2).unwrap();
        assert_eq!(key_type(&key), Some((KeyType::SafetyNet, 2)));
        let key = test_account(1, 9).role_key(KeyType::SafetyNet, 2).unwrap();
        assert_eq!(key_type(&key), Some((KeyType::SafetyNet, 2)));

        assert_eq!(key_type(&OXpub::new(None, key.xkey)), None);
        for p in [
            "m/87'/1'/0'",
            "m/84'/1'/0'/2",
            "m/87'/1'/0'/5",
            "m/87'/1'/0'/2'",
            "m/87'/1'/0/2",
        ] {
            assert_eq!(key_type(&key_with_origin(p)), None, "{p}");
        }
    }

    #[test]
    fn key_type_of_reads_descriptor_keys() {
        let key = test_account(1, 0).role_key(KeyType::Cosigner, 1).unwrap();
        let (fp, _) = key.origin.unwrap();
        let xkey = key.xkey;
        let parse = |s: String| DescriptorPublicKey::from_str(&s).unwrap();

        let multi = parse(format!("[{fp}/87h/1h/0h/18]{xkey}/<0;1>/*"));
        assert!(matches!(multi, DescriptorPublicKey::MultiXPub(_)));
        assert_eq!(key_type_of(&multi), Some((KeyType::Cosigner, 1)));

        let xpub = parse(format!("[{fp}/87h/1h/0h/18]{xkey}/0/*"));
        assert!(matches!(xpub, DescriptorPublicKey::XPub(_)));
        assert_eq!(key_type_of(&xpub), Some((KeyType::Cosigner, 1)));

        let single = parse(format!("[{fp}/87'/1'/0'/3]{}", xkey.public_key));
        assert!(matches!(single, DescriptorPublicKey::Single(_)));
        assert_eq!(key_type_of(&single), Some((KeyType::SafetyNet, 0)));

        let bare = parse(format!("{xkey}/<0;1>/*"));
        assert_eq!(key_type_of(&bare), None);
    }
}
