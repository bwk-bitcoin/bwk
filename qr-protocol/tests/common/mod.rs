// Each integration binary includes this module and uses a different subset.
#![allow(dead_code)]

use bitcoin::bip32;
use bwk_qr_protocol::types::{DerivationPath, Xpub};

pub fn path(path: &str) -> DerivationPath {
    (&path.parse::<bip32::DerivationPath>().unwrap()).into()
}

pub fn bitcoin_xpub() -> bip32::Xpub {
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        .parse()
        .unwrap()
}

pub fn xpub() -> Xpub {
    (&bitcoin_xpub()).into()
}
