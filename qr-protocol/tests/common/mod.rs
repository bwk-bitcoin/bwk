// Each integration binary includes this module and uses a different subset.
#![allow(dead_code)]

#[cfg(feature = "bitcoin")]
use bitcoin::bip32;
use bwk_qr_protocol::{
    request,
    types::{DerivationPath, Fingerprint, PublicKey, SecretKey, SECRET_KEY_LEN},
};
#[cfg(feature = "bitcoin")]
use bwk_qr_protocol::{response, types::ExtendedKey};

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

// 73c5da0a, spend m/352'/1'/0'/0'/0, scan m/352'/1'/0'/1'/0
pub fn sp_keys() -> request::DescriptorBody {
    sp_keys_with(request::Scan::Path(DerivationPath(vec![
        0x8000_0160,
        0x8000_0001,
        0x8000_0000,
        0x8000_0001,
        0,
    ])))
}

// the scan private key of the BIP-352 test vectors' labelled receiver
pub const FOREIGN_SCAN_KEY: [u8; SECRET_KEY_LEN] = [
    0x0f, 0x69, 0x4e, 0x06, 0x80, 0x28, 0xa7, 0x17, 0xf8, 0xaf, 0x6b, 0x94, 0x11, 0xf9, 0xa1, 0x33,
    0xdd, 0x35, 0x65, 0x25, 0x87, 0x14, 0xcc, 0x22, 0x65, 0x94, 0xb3, 0x4d, 0xb9, 0x0c, 0x1f, 0x2c,
];

// 73c5da0a, spend m/352'/1'/0'/0'/0, scan key FOREIGN_SCAN_KEY
pub fn sp_foreign_scan_keys() -> request::DescriptorBody {
    sp_keys_with(request::Scan::Key(SecretKey(FOREIGN_SCAN_KEY)))
}

pub fn sp_keys_with(scan: request::Scan) -> request::DescriptorBody {
    request::DescriptorBody::SpKeys(request::SpKeys {
        fingerprint: Fingerprint([0x73, 0xc5, 0xda, 0x0a]),
        spend_path: DerivationPath(vec![0x8000_0160, 0x8000_0001, 0x8000_0000, 0x8000_0000, 0]),
        scan,
    })
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

#[cfg(feature = "bitcoin")]
pub fn xpub_key() -> PublicKey {
    (&bitcoin::PublicKey::new(bitcoin_xpub().public_key))
        .try_into()
        .unwrap()
}

// The codec does not check points, so any 33 bytes stand for an aggregate key.
pub fn aggregate(prefix: u8, fill: u8) -> PublicKey {
    let mut key = [fill; 33];
    key[0] = prefix;
    PublicKey(key)
}

// Two slots of one participant: input 0 on the key path, input 1 on a script path.
#[cfg(feature = "bitcoin")]
pub fn musig_pub_nonces() -> Vec<response::SignatureEntry> {
    vec![
        response::SignatureEntry::MusigPubNonce {
            input_index: 0,
            participant: xpub_key(),
            aggregate: aggregate(0x02, 0x11),
            leaf_hash: None,
            nonce: [0x22; 66],
        },
        response::SignatureEntry::MusigPubNonce {
            input_index: 1,
            participant: xpub_key(),
            aggregate: aggregate(0x03, 0x33),
            leaf_hash: Some([0x44; 32]),
            nonce: [0x55; 66],
        },
    ]
}

#[cfg(feature = "bitcoin")]
pub fn musig_partial_sigs() -> Vec<response::SignatureEntry> {
    vec![
        response::SignatureEntry::MusigPartialSig {
            input_index: 0,
            participant: xpub_key(),
            aggregate: aggregate(0x02, 0x11),
            leaf_hash: None,
            signature: [0x66; 32],
        },
        response::SignatureEntry::MusigPartialSig {
            input_index: 1,
            participant: xpub_key(),
            aggregate: aggregate(0x03, 0x33),
            leaf_hash: Some([0x44; 32]),
            signature: [0x77; 32],
        },
    ]
}

#[cfg(feature = "bitcoin")]
pub fn sp_share(
    scope: response::SpScope,
    scan_key: PublicKey,
    fill: u8,
) -> response::SignatureEntry {
    response::SignatureEntry::SpEcdhShare {
        scope,
        scan_key,
        share: aggregate(0x02, fill),
    }
}

#[cfg(feature = "bitcoin")]
pub fn sp_proof(
    scope: response::SpScope,
    scan_key: PublicKey,
    fill: u8,
) -> response::SignatureEntry {
    response::SignatureEntry::SpDleqProof {
        scope,
        scan_key,
        proof: [fill; 64],
    }
}

// One signer owns both inputs and pays two scan keys: a global pair per scan key.
#[cfg(feature = "bitcoin")]
pub fn sp_global_send() -> Vec<response::SignatureEntry> {
    let scan_a = aggregate(0x02, 0x5a);
    let scan_b = aggregate(0x03, 0x5b);
    vec![
        response::SignatureEntry::TapKey {
            input_index: 0,
            signature: vec![0x01; 64],
        },
        response::SignatureEntry::TapKey {
            input_index: 1,
            signature: vec![0x02; 64],
        },
        sp_share(response::SpScope::Global, scan_a, 0xa0),
        sp_proof(response::SpScope::Global, scan_a, 0xb0),
        sp_share(response::SpScope::Global, scan_b, 0xa1),
        sp_proof(response::SpScope::Global, scan_b, 0xb1),
    ]
}

// The signer owns inputs 0 and 2 of a transaction paying one scan key: a pair per input.
#[cfg(feature = "bitcoin")]
pub fn sp_per_input_send() -> Vec<response::SignatureEntry> {
    let scan = aggregate(0x02, 0x5a);
    vec![
        response::SignatureEntry::TapKey {
            input_index: 0,
            signature: vec![0x01; 64],
        },
        sp_share(response::SpScope::Input(0), scan, 0xa0),
        sp_proof(response::SpScope::Input(0), scan, 0xb0),
        response::SignatureEntry::TapKey {
            input_index: 2,
            signature: vec![0x03; 64],
        },
        sp_share(response::SpScope::Input(2), scan, 0xa2),
        sp_proof(response::SpScope::Input(2), scan, 0xb2),
    ]
}
