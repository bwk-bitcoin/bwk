// Each integration binary includes this module and uses a different subset.
#![allow(dead_code)]

#[cfg(feature = "bitcoin")]
use bitcoin::bip32;
use bwk_qr_protocol::request;
#[cfg(feature = "bitcoin")]
use bwk_qr_protocol::types::{DerivationPath, ExtendedKey};

#[cfg(feature = "bitcoin")]
pub fn path(path: &str) -> DerivationPath {
    (&path.parse::<bip32::DerivationPath>().unwrap()).into()
}

#[cfg(feature = "bitcoin")]
pub fn bitcoin_xpub() -> bip32::Xpub {
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        .parse()
        .unwrap()
}

// the private key of bitcoin_xpub(), BIP-32 test vector 1's master key
#[cfg(feature = "bitcoin")]
pub fn bitcoin_xpriv() -> bip32::Xpriv {
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        .parse()
        .unwrap()
}

#[cfg(feature = "bitcoin")]
pub fn xpub() -> ExtendedKey {
    (&bitcoin_xpub()).into()
}

#[cfg(feature = "bitcoin")]
pub fn xpriv() -> ExtendedKey {
    (&bitcoin_xpriv()).into()
}

#[cfg(feature = "bitcoin")]
pub fn key_request(path_text: &str, kind: request::KeyKind) -> request::KeyRequest {
    request::KeyRequest {
        derivation_path: path(path_text),
        kind,
    }
}

pub fn bip380() -> request::DescriptorBody {
    request::DescriptorBody::Bip380("wpkh([00000000/84h/1h/0h]xpub/0/*)".to_string())
}

pub fn sp_keys() -> request::DescriptorBody {
    request::DescriptorBody::SpKeys("73c5da0a|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0".to_string())
}

pub fn bip388() -> request::DescriptorBody {
    request::DescriptorBody::Bip388 {
        keys: vec![
            "[00000000/48h/1h/0h/2h]xpub".to_string(),
            "[11111111/48h/1h/0h/2h]xpub".to_string(),
        ],
        policy: "wsh(sortedmulti(2,@0/**,@1/**))".to_string(),
    }
}
