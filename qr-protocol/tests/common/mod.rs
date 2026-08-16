// Each integration binary includes this module and uses a different subset.
#![allow(dead_code)]

#[cfg(feature = "bitcoin")]
use bitcoin::bip32;
use bwk_qr_protocol::request;
#[cfg(feature = "bitcoin")]
use bwk_qr_protocol::types::{DerivationPath, Xpub};

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

#[cfg(feature = "bitcoin")]
pub fn xpub() -> Xpub {
    (&bitcoin_xpub()).into()
}

pub fn bip380() -> request::DescriptorBody {
    request::DescriptorBody::Bip380("wpkh([00000000/84h/1h/0h]xpub/0/*)".to_string())
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
