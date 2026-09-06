use std::{fmt, str::FromStr};

use miniscript::{
    bitcoin::{
        secp256k1::{All, PublicKey, Secp256k1, SecretKey},
        NetworkKind,
    },
    descriptor::{
        checksum::{desc_checksum, Formatter},
        DefiniteDescriptorKey, DescriptorPublicKey, DescriptorSecretKey, SinglePubKey, Wildcard,
    },
    expression::Tree,
};

use crate::sp_key::SpKey;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("not an sp() descriptor")]
    NotSp,
    #[error("sp() takes 1 or 2 key expressions, found {0}")]
    ArgCount(usize),
    #[error("nested expressions are not allowed in sp(): {0}")]
    NestedExpression(String),
    #[error(transparent)]
    SpKey(#[from] crate::sp_key::Error),
    #[error("scan key must be a single private key expression")]
    ScanKeyNotPrivate,
    #[error("scan key must not be a wildcard or multipath expression")]
    ScanKeyNotSingle,
    #[error("spend key must not be a wildcard or multipath expression")]
    SpendKeyNotSingle,
    #[error("uncompressed keys are not allowed in sp()")]
    Uncompressed,
    #[error("x-only keys are not allowed in sp()")]
    XOnly,
    #[error("invalid key expression: {0}")]
    Key(String),
    #[error("invalid checksum: expected {expected}, found {found}")]
    Checksum { expected: String, found: String },
    #[error("invalid expression tree: {0}")]
    Tree(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendKey {
    Public(DescriptorPublicKey),
    Secret(DescriptorSecretKey),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpDescriptor {
    Packed(SpKey),
    Split {
        scan: DescriptorSecretKey,
        spend: SpendKey,
    },
}

fn secret_key_singleness(secret: &DescriptorSecretKey, not_single: Error) -> Result<(), Error> {
    match secret {
        DescriptorSecretKey::Single(single) => {
            if !single.key.compressed {
                return Err(Error::Uncompressed);
            }
            Ok(())
        }
        DescriptorSecretKey::XPrv(xprv) => {
            if xprv.wildcard != Wildcard::None {
                return Err(not_single);
            }
            Ok(())
        }
        DescriptorSecretKey::MultiXPrv(_) => Err(not_single),
    }
}

fn parse_scan_key(name: &str) -> Result<DescriptorSecretKey, Error> {
    let scan = DescriptorSecretKey::from_str(name).map_err(|_| Error::ScanKeyNotPrivate)?;
    secret_key_singleness(&scan, Error::ScanKeyNotSingle)?;
    Ok(scan)
}

fn parse_spend_key(name: &str) -> Result<SpendKey, Error> {
    match DescriptorPublicKey::from_str(name) {
        Ok(public) => {
            match &public {
                DescriptorPublicKey::Single(single) => match single.key {
                    SinglePubKey::FullKey(pk) => {
                        if !pk.compressed {
                            return Err(Error::Uncompressed);
                        }
                    }
                    SinglePubKey::XOnly(_) => return Err(Error::XOnly),
                },
                DescriptorPublicKey::XPub(xpub) => {
                    if xpub.wildcard != Wildcard::None {
                        return Err(Error::SpendKeyNotSingle);
                    }
                }
                DescriptorPublicKey::MultiXPub(_) => return Err(Error::SpendKeyNotSingle),
            }
            Ok(SpendKey::Public(public))
        }
        Err(e) => {
            let secret =
                DescriptorSecretKey::from_str(name).map_err(|_| Error::Key(e.to_string()))?;
            secret_key_singleness(&secret, Error::SpendKeyNotSingle)?;
            Ok(SpendKey::Secret(secret))
        }
    }
}

fn derive_secret_key(
    secp: &Secp256k1<All>,
    secret: &DescriptorSecretKey,
) -> Result<SecretKey, Error> {
    match secret {
        DescriptorSecretKey::Single(single) => Ok(single.key.inner),
        DescriptorSecretKey::XPrv(xprv) => Ok(xprv
            .xkey
            .derive_priv(secp, &xprv.derivation_path)
            .map_err(|e| Error::Key(e.to_string()))?
            .private_key),
        DescriptorSecretKey::MultiXPrv(_) => {
            unreachable!("multipath secret keys are rejected at parse time")
        }
    }
}

impl FromStr for SpDescriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '#');
        let body = parts.next().expect("splitn always yields one part");
        if let Some(found) = parts.next() {
            let expected = desc_checksum(body).map_err(|e| Error::Tree(e.to_string()))?;
            if found != expected {
                return Err(Error::Checksum {
                    expected,
                    found: found.to_string(),
                });
            }
        }

        let top = Tree::from_str(body).map_err(|e| Error::Tree(e.to_string()))?;
        if top.name != "sp" {
            return Err(Error::NotSp);
        }
        for arg in &top.args {
            if !arg.args.is_empty() {
                return Err(Error::NestedExpression(arg.name.to_string()));
            }
        }

        match top.args.len() {
            1 => Ok(SpDescriptor::Packed(SpKey::from_str(top.args[0].name)?)),
            2 => {
                let scan = parse_scan_key(top.args[0].name)?;
                let spend = parse_spend_key(top.args[1].name)?;
                Ok(SpDescriptor::Split { scan, spend })
            }
            n => Err(Error::ArgCount(n)),
        }
    }
}

impl SpDescriptor {
    pub fn scan_secret_key(&self, secp: &Secp256k1<All>) -> Result<SecretKey, Error> {
        match self {
            SpDescriptor::Packed(key) => Ok(key.scan_secret_key()),
            SpDescriptor::Split { scan, .. } => derive_secret_key(secp, scan),
        }
    }

    pub fn spend_public_key(&self, secp: &Secp256k1<All>) -> Result<PublicKey, Error> {
        match self {
            SpDescriptor::Packed(key) => Ok(key.spend_public_key(secp)),
            SpDescriptor::Split {
                spend: SpendKey::Public(dpk),
                ..
            } => {
                let definite = DefiniteDescriptorKey::new(dpk.clone()).ok_or_else(|| {
                    Error::Key("spend key has a wildcard or hardened derivation step".to_string())
                })?;
                let pk = definite
                    .derive_public_key(secp)
                    .map_err(|e| Error::Key(e.to_string()))?;
                Ok(pk.inner)
            }
            SpDescriptor::Split {
                spend: SpendKey::Secret(dsk),
                ..
            } => {
                let sk = derive_secret_key(secp, dsk)?;
                Ok(PublicKey::from_secret_key(secp, &sk))
            }
        }
    }

    pub fn spend_secret_key(&self, secp: &Secp256k1<All>) -> Result<Option<SecretKey>, Error> {
        match self {
            SpDescriptor::Packed(SpKey::Scan(_)) => Ok(None),
            SpDescriptor::Packed(key) => Ok(key.spend_secret_key()),
            SpDescriptor::Split {
                spend: SpendKey::Public(_),
                ..
            } => Ok(None),
            SpDescriptor::Split {
                spend: SpendKey::Secret(dsk),
                ..
            } => Ok(Some(derive_secret_key(secp, dsk)?)),
        }
    }

    pub fn is_watch_only(&self, secp: &Secp256k1<All>) -> Result<bool, Error> {
        self.spend_secret_key(secp).map(|k| k.is_none())
    }

    pub fn network_kind(&self) -> NetworkKind {
        match self {
            SpDescriptor::Packed(key) => key.network(),
            SpDescriptor::Split { scan, .. } => match scan {
                DescriptorSecretKey::Single(single) => single.key.network,
                DescriptorSecretKey::XPrv(xprv) => xprv.xkey.network,
                DescriptorSecretKey::MultiXPrv(_) => {
                    unreachable!("multipath secret keys are rejected at parse time")
                }
            },
        }
    }

    fn fmt_body<W: fmt::Write>(&self, w: &mut W) -> fmt::Result {
        match self {
            SpDescriptor::Packed(key) => write!(w, "sp({key})"),
            SpDescriptor::Split { scan, spend } => write!(w, "sp({scan},{spend})"),
        }
    }

    pub fn to_string_no_checksum(&self) -> String {
        format!("{self:#}")
    }
}

impl fmt::Display for SpDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut wrapped = Formatter::new(f);
        self.fmt_body(&mut wrapped)?;
        wrapped.write_checksum_if_not_alt()
    }
}

impl fmt::Display for SpendKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SpendKey::Public(k) => write!(f, "{k}"),
            SpendKey::Secret(k) => write!(f, "{k}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{
        bitcoin::{
            bip32::{ChildNumber, DerivationPath, Xpriv},
            secp256k1::{All, PublicKey, Secp256k1, SecretKey},
            Network, NetworkKind,
        },
        descriptor::{checksum::desc_checksum, DescriptorPublicKey},
    };

    use crate::{
        sp_descriptor::{Error, SpDescriptor, SpendKey},
        sp_key::{SpKey, SpScanKey, SpSpendKey},
    };

    fn secp() -> Secp256k1<All> {
        Secp256k1::new()
    }

    fn scan_key_fixture() -> SpScanKey {
        let secp = secp();
        let scan_key = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0xcd; 32]).unwrap());
        SpScanKey {
            scan_key,
            spend_key,
            network: NetworkKind::Main,
        }
    }

    fn spend_key_fixture() -> SpSpendKey {
        let scan_key = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let spend_key = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        SpSpendKey {
            scan_key,
            spend_key,
            network: NetworkKind::Main,
        }
    }

    #[test]
    fn packed_scan_parses() {
        let secp = secp();
        let fixture = scan_key_fixture();
        let s = format!("sp({})", SpKey::Scan(fixture.clone()));
        let descriptor = SpDescriptor::from_str(&s).unwrap();
        match &descriptor {
            SpDescriptor::Packed(SpKey::Scan(_)) => {}
            other => panic!("expected Packed(Scan(_)), got {other:?}"),
        }
        assert!(descriptor.is_watch_only(&secp).unwrap());
        assert_eq!(descriptor.spend_secret_key(&secp).unwrap(), None);
        assert_eq!(descriptor.scan_secret_key(&secp).unwrap(), fixture.scan_key);
    }

    #[test]
    fn packed_spend_parses() {
        let secp = secp();
        let fixture = spend_key_fixture();
        let s = format!("sp({})", SpKey::Spend(fixture.clone()));
        let descriptor = SpDescriptor::from_str(&s).unwrap();
        match &descriptor {
            SpDescriptor::Packed(SpKey::Spend(_)) => {}
            other => panic!("expected Packed(Spend(_)), got {other:?}"),
        }
        assert!(!descriptor.is_watch_only(&secp).unwrap());
        let expected = PublicKey::from_secret_key(&secp, &fixture.spend_key);
        assert_eq!(descriptor.spend_public_key(&secp).unwrap(), expected);
    }

    #[test]
    fn split_wif_and_pubkey_parses() {
        let secp = secp();
        let s = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,\
                  0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        let descriptor = SpDescriptor::from_str(s).unwrap();
        match &descriptor {
            SpDescriptor::Split {
                spend: SpendKey::Public(_),
                ..
            } => {}
            other => panic!("expected Split with Public spend, got {other:?}"),
        }
        assert!(descriptor.is_watch_only(&secp).unwrap());
        let expected = PublicKey::from_str(
            "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600",
        )
        .unwrap();
        assert_eq!(descriptor.spend_public_key(&secp).unwrap(), expected);
    }

    fn xprv_fixture() -> Xpriv {
        Xpriv::new_master(Network::Bitcoin, &[0x11; 64]).unwrap()
    }

    #[test]
    fn split_xprv_and_xpub_parses() {
        let secp = secp();
        let xprv = xprv_fixture();
        let fingerprint = xprv.fingerprint(&secp);
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);

        let s = format!("sp([{fingerprint}/352h/0h/0h]{xprv}/0h,{xpub}/0h)");
        let descriptor = SpDescriptor::from_str(&s).unwrap();
        match &descriptor {
            SpDescriptor::Split {
                spend: SpendKey::Public(_),
                ..
            } => {}
            other => panic!("expected Split with Public spend, got {other:?}"),
        }

        let path = DerivationPath::from(vec![ChildNumber::from_hardened_idx(0).unwrap()]);
        let expected = xprv.derive_priv(&secp, &path).unwrap().private_key;
        assert_eq!(descriptor.scan_secret_key(&secp).unwrap(), expected);
    }

    #[test]
    fn split_xprv_and_xprv_parses() {
        let secp = secp();
        let scan_xprv = xprv_fixture();
        let spend_xprv = Xpriv::new_master(Network::Bitcoin, &[0x22; 64]).unwrap();
        let fingerprint = scan_xprv.fingerprint(&secp);

        let s = format!("sp([{fingerprint}/352h/0h/0h]{scan_xprv}/0h,{spend_xprv}/0h)");
        let descriptor = SpDescriptor::from_str(&s).unwrap();
        assert!(!descriptor.is_watch_only(&secp).unwrap());

        let path = DerivationPath::from(vec![ChildNumber::from_hardened_idx(0).unwrap()]);
        let expected_sk = spend_xprv.derive_priv(&secp, &path).unwrap().private_key;
        let expected_pk = PublicKey::from_secret_key(&secp, &expected_sk);
        assert_eq!(descriptor.spend_public_key(&secp).unwrap(), expected_pk);
    }

    #[test]
    fn checksum_accepted() {
        let fixture = scan_key_fixture();
        let body = format!("sp({})", SpKey::Scan(fixture));
        let checksum = desc_checksum(&body).unwrap();
        let s = format!("{body}#{checksum}");
        assert!(SpDescriptor::from_str(&s).is_ok());
    }

    #[test]
    fn empty_args_rejected() {
        assert!(matches!(
            SpDescriptor::from_str("sp()"),
            Err(Error::SpKey(_))
        ));
    }

    #[test]
    fn xpub_single_arg_rejected() {
        let secp = secp();
        let xprv = xprv_fixture();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);
        let s = format!("sp({xpub})");
        assert!(matches!(SpDescriptor::from_str(&s), Err(Error::SpKey(_))));
    }

    #[test]
    fn two_public_keys_rejected() {
        let secp = secp();
        let xprv = xprv_fixture();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);
        let s = format!("sp({xpub},{xpub})");
        assert_eq!(SpDescriptor::from_str(&s), Err(Error::ScanKeyNotPrivate));
    }

    #[test]
    fn two_packed_keys_rejected() {
        let fixture = scan_key_fixture();
        let key_str = SpKey::Scan(fixture).to_string();
        let s = format!("sp({key_str},{key_str})");
        assert_eq!(SpDescriptor::from_str(&s), Err(Error::ScanKeyNotPrivate));
    }

    #[test]
    fn uncompressed_scan_key_rejected() {
        let s = "sp(5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss,\
                  0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        assert_eq!(SpDescriptor::from_str(s), Err(Error::Uncompressed));
    }

    #[test]
    fn xonly_spend_key_rejected() {
        let s = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,\
                  60b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        assert_eq!(SpDescriptor::from_str(s), Err(Error::XOnly));
    }

    #[test]
    fn wildcard_spend_key_rejected() {
        let secp = secp();
        let xprv = xprv_fixture();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);
        let s = format!("sp({xprv}/0h,{xpub}/0/*)");
        assert_eq!(SpDescriptor::from_str(&s), Err(Error::SpendKeyNotSingle));
    }

    #[test]
    fn multipath_scan_key_rejected() {
        let secp = secp();
        let xprv = xprv_fixture();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);
        let s = format!("sp({xprv}/<0;1>/*,{xpub})");
        assert_eq!(SpDescriptor::from_str(&s), Err(Error::ScanKeyNotSingle));
    }

    #[test]
    fn nested_expression_rejected() {
        let s = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,\
                  musig(0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,\
                  0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600))";
        assert!(matches!(
            SpDescriptor::from_str(s),
            Err(Error::NestedExpression(_))
        ));
    }

    #[test]
    fn three_args_rejected() {
        let s = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,\
                  0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,\
                  0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        assert_eq!(SpDescriptor::from_str(s), Err(Error::ArgCount(3)));
    }

    #[test]
    fn wrong_name_rejected() {
        let secp = secp();
        let xprv = xprv_fixture();
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);
        let s = format!("wpkh({xpub})");
        assert_eq!(SpDescriptor::from_str(&s), Err(Error::NotSp));
    }

    #[test]
    fn bad_checksum_rejected() {
        let fixture = scan_key_fixture();
        let d = SpDescriptor::Packed(SpKey::Scan(fixture));
        let s = d.to_string();
        let expected = desc_checksum(&d.to_string_no_checksum()).unwrap();

        let mut bad = s.clone();
        let last = bad.len() - 1;
        let flipped = if bad.as_bytes()[last] as char == 'q' {
            'p'
        } else {
            'q'
        };
        bad.replace_range(last..last + 1, &flipped.to_string());

        match SpDescriptor::from_str(&bad) {
            Err(Error::Checksum {
                expected: found_expected,
                ..
            }) => assert_eq!(found_expected, expected),
            other => panic!("expected Checksum error, got {other:?}"),
        }
    }

    #[test]
    fn display_appends_checksum() {
        let fixture = scan_key_fixture();
        let d = SpDescriptor::Packed(SpKey::Scan(fixture));
        let s = d.to_string();

        assert_eq!(s.matches('#').count(), 1);
        let checksum = s.rsplit('#').next().unwrap();
        assert_eq!(checksum.len(), 8);
        assert_eq!(checksum, desc_checksum(&d.to_string_no_checksum()).unwrap());
    }

    #[test]
    fn alternate_display_omits_checksum() {
        let fixture = scan_key_fixture();
        let d = SpDescriptor::Packed(SpKey::Scan(fixture));
        let s = format!("{d:#}");

        assert!(!s.contains('#'));
        assert!(s.starts_with("sp("));
    }

    #[test]
    fn roundtrip_packed_scan() {
        let fixture = scan_key_fixture();
        let d = SpDescriptor::Packed(SpKey::Scan(fixture));
        let s = d.to_string();

        let parsed = SpDescriptor::from_str(&s).unwrap();
        assert_eq!(parsed, d);
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn roundtrip_packed_spend() {
        let fixture = spend_key_fixture();
        let d = SpDescriptor::Packed(SpKey::Spend(fixture));
        let s = d.to_string();

        let parsed = SpDescriptor::from_str(&s).unwrap();
        assert_eq!(parsed, d);
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn roundtrip_split_wif_pubkey() {
        let s = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,\
                  0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        let d = SpDescriptor::from_str(s).unwrap();
        let rendered = d.to_string();

        let parsed = SpDescriptor::from_str(&rendered).unwrap();
        assert_eq!(parsed, d);
        assert_eq!(parsed.to_string(), rendered);
    }

    #[test]
    fn roundtrip_split_xprv_xpub() {
        let secp = secp();
        let xprv = xprv_fixture();
        let fingerprint = xprv.fingerprint(&secp);
        let xpub = miniscript::bitcoin::bip32::Xpub::from_priv(&secp, &xprv);

        let s = format!("sp([{fingerprint}/352h/0h/0h]{xprv}/0h,{xpub}/0h)");
        let d = SpDescriptor::from_str(&s).unwrap();
        let rendered = d.to_string();

        let parsed = SpDescriptor::from_str(&rendered).unwrap();
        assert_eq!(parsed, d);
        assert_eq!(parsed.to_string(), rendered);

        let no_checksum = d.to_string_no_checksum();
        assert!(no_checksum.contains(&format!("[{fingerprint}/352'/0'/0']")));
        assert!(no_checksum.ends_with("/0')"));
    }

    #[test]
    fn roundtrip_without_checksum() {
        let fixture = scan_key_fixture();
        let d = SpDescriptor::Packed(SpKey::Scan(fixture));
        let s = format!("{d:#}");

        let parsed = SpDescriptor::from_str(&s).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn checksum_covers_the_whole_body() {
        let secp = secp();
        let xprv = xprv_fixture();
        let fingerprint = xprv.fingerprint(&secp);
        let spend_xprv1 = Xpriv::new_master(Network::Bitcoin, &[0x22; 64]).unwrap();
        let spend_xprv2 = Xpriv::new_master(Network::Bitcoin, &[0x33; 64]).unwrap();

        let s1 = format!("sp([{fingerprint}/352h/0h/0h]{xprv}/0h,{spend_xprv1}/0h)");
        let s2 = format!("sp([{fingerprint}/352h/0h/0h]{xprv}/0h,{spend_xprv2}/0h)");
        let d1 = SpDescriptor::from_str(&s1).unwrap();
        let d2 = SpDescriptor::from_str(&s2).unwrap();

        let checksum1 = d1.to_string().rsplit('#').next().unwrap().to_string();
        let checksum2 = d2.to_string().rsplit('#').next().unwrap().to_string();
        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn not_top_level() {
        let fixture = scan_key_fixture();
        let s = format!("sh(sp({}))", SpKey::Scan(fixture));
        assert!(miniscript::Descriptor::<DescriptorPublicKey>::from_str(&s).is_err());
    }
}
