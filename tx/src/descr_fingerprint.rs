use std::fmt::Display;

use bwk_descriptor::descriptor::Descriptor;
use miniscript::descriptor::checksum::desc_checksum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("failed to compute descriptor checksum: {0}")]
    Checksum(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DescrFingerprint([u8; 8]);

impl DescrFingerprint {
    pub fn new(value: &Descriptor) -> Result<Self, Error> {
        let body = value.to_string_no_checksum();
        let checksum = desc_checksum(&body).map_err(|e| Error::Checksum(e.to_string()))?;
        let fg: [u8; 8] = checksum
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Checksum(checksum.clone()))?;
        Ok(DescrFingerprint(fg))
    }
}

impl Display for DescrFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bwk_descriptor::{descriptor::Descriptor, sp_key::SpScanKey};
    use miniscript::bitcoin::{secp256k1::Secp256k1, NetworkKind};

    use crate::descr_fingerprint::DescrFingerprint;

    fn scan_key(spend_seed: u8) -> SpScanKey {
        let secp = Secp256k1::new();
        let scan_key = miniscript::bitcoin::secp256k1::SecretKey::from_slice(&[0xab; 32]).unwrap();
        let spend_key = miniscript::bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &miniscript::bitcoin::secp256k1::SecretKey::from_slice(&[spend_seed; 32]).unwrap(),
        );
        SpScanKey {
            scan_key,
            spend_key,
            network: NetworkKind::Main,
        }
    }

    #[test]
    fn miniscript_fingerprint_unchanged() {
        let raw_descr = "wsh(or_d(pk([9d69155f/48'/1'/0'/2']tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<0;1>/*),and_v(v:pkh([9d69155f/48'/1'/0'/2']tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<2;3>/*),older(52596))))#gx5f42wh";
        let descr = Descriptor::from_str(raw_descr).unwrap();
        let descr_fg = DescrFingerprint::new(&descr).unwrap();
        assert_eq!("gx5f42wh", descr_fg.to_string());
    }

    #[test]
    fn fingerprint_matches_the_rendered_checksum() {
        let raw_descr = "wsh(or_d(pk([9d69155f/48'/1'/0'/2']tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<0;1>/*),and_v(v:pkh([9d69155f/48'/1'/0'/2']tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<2;3>/*),older(52596))))#gx5f42wh";
        let descr = Descriptor::from_str(raw_descr).unwrap();
        let fg = DescrFingerprint::new(&descr).unwrap();
        let rendered = descr.to_string();
        let expected = rendered.rsplit('#').next().unwrap();
        assert_eq!(expected, fg.to_string());
    }

    #[test]
    fn sp_descriptor_fingerprint() {
        let key = scan_key(0x01);
        let raw_descr = format!("sp({key})");
        let descr = Descriptor::from_str(&raw_descr).unwrap();
        let fg = DescrFingerprint::new(&descr).unwrap();
        let rendered = descr.to_string();
        let expected = rendered.rsplit('#').next().unwrap();
        assert_eq!(expected, fg.to_string());
    }

    #[test]
    fn distinct_descriptors_distinct_fingerprints() {
        let descr_a = Descriptor::from_str(&format!("sp({})", scan_key(0x01))).unwrap();
        let descr_b = Descriptor::from_str(&format!("sp({})", scan_key(0x02))).unwrap();
        let fg_a = DescrFingerprint::new(&descr_a).unwrap();
        let fg_b = DescrFingerprint::new(&descr_b).unwrap();
        assert_ne!(fg_a, fg_b);
    }
}
