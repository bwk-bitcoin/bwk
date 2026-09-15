use crate::{bip389, parse_version, AddressScript, DeviceKind, Error as HWIError, HWI};
use api::btc::make_script_config_simple;
use bitbox_api::{
    btc::KeyOriginInfo,
    error::{BitBoxError, Error},
    keypath::Keypath,
    noise::{ConfigError, NoiseConfig, NoiseConfigData, NoiseConfigNoCache},
    pb::{self, BtcScriptConfig},
    usb::UsbError,
    PairedBitBox, PairingBitBox,
};
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
};
use regex::Regex;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

pub use bitbox_api as api;

#[derive(Clone)]
struct Cache(Arc<Mutex<Option<NoiseConfigData>>>);

impl bitbox_api::util::Threading for Cache {}

impl NoiseConfig for Cache {
    fn read_config(&self) -> Result<NoiseConfigData, ConfigError> {
        let noise_data = self.0.lock().map_err(|e| ConfigError(e.to_string()))?;
        if let Some(data) = noise_data.as_ref() {
            Ok(data.clone())
        } else {
            Ok(NoiseConfigData::default())
        }
    }
    fn store_config(&self, data: &NoiseConfigData) -> Result<(), ConfigError> {
        let mut noise_data = self.0.lock().map_err(|e| ConfigError(e.to_string()))?;
        *noise_data = Some(data.clone());
        Ok(())
    }
}

pub struct PairingBitbox02WithLocalCache {
    client: PairingBitBox,
    local_cache: Cache,
}

impl PairingBitbox02WithLocalCache {
    pub fn connect(
        device: hidapi::HidDevice,
        pairing_data: Option<NoiseConfigData>,
    ) -> Result<Self, HWIError> {
        let local_cache = if let Some(data) = pairing_data {
            Cache(Arc::new(Mutex::new(Some(data))))
        } else {
            Cache(Arc::new(Mutex::new(None)))
        };
        let bitbox = bitbox_api::BitBox::from_hid_device(device, Box::new(local_cache.clone()))?;
        let pairing_bitbox = bitbox.unlock_and_pair()?;
        Ok(PairingBitbox02WithLocalCache {
            client: pairing_bitbox,
            local_cache,
        })
    }

    pub fn pairing_code(&self) -> Option<String> {
        self.client.get_pairing_code()
    }

    pub fn wait_confirm(self) -> Result<(PairedBitBox, NoiseConfigData), HWIError> {
        let client = self.client.wait_confirm()?;
        let mut cache = self
            .local_cache
            .0
            .lock()
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok((
            client,
            cache
                .take()
                .expect("noise config data must be in local cache"),
        ))
    }
}

pub struct PairingBitbox02 {
    client: PairingBitBox,
}

impl PairingBitbox02 {
    pub fn connect(
        device: hidapi::HidDevice,
        pairing: Option<Box<dyn NoiseConfig>>,
    ) -> Result<Self, HWIError> {
        let noise_config = pairing.unwrap_or_else(|| Box::new(NoiseConfigNoCache {}));
        let bitbox = bitbox_api::BitBox::from_hid_device(device, noise_config)?;
        let pairing_bitbox = bitbox.unlock_and_pair()?;
        Ok(PairingBitbox02 {
            client: pairing_bitbox,
        })
    }

    pub fn pairing_code(&self) -> Option<String> {
        self.client.get_pairing_code()
    }

    pub fn wait_confirm(self) -> Result<PairedBitBox, HWIError> {
        self.client.wait_confirm().map_err(|e| e.into())
    }
}

pub struct BitBox02 {
    pub network: bitcoin::Network,
    pub display_xpub: bool,
    pub client: PairedBitBox,
    pub policy: Option<Policy>,
}

impl std::fmt::Debug for BitBox02 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitBox").finish()
    }
}

impl BitBox02 {
    pub fn from(paired_bitbox: PairedBitBox) -> Self {
        BitBox02 {
            display_xpub: false,
            network: bitcoin::Network::Bitcoin,
            client: paired_bitbox,
            policy: None,
        }
    }

    pub fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }

    pub fn display_xpub(mut self, value: bool) -> Self {
        self.display_xpub = value;
        self
    }

    pub fn with_policy(mut self, policy: &str) -> Result<Self, HWIError> {
        self.policy = Some(extract_script_config_policy(policy)?);
        Ok(self)
    }

    pub fn is_policy_registered(&self, policy: &str) -> Result<bool, HWIError> {
        let pb_network = coin_from_network(self.network);
        let policy = extract_script_config_policy(policy)?;
        self.client
            .btc_is_script_config_registered(pb_network, &policy.into(), None)
            .map_err(|e| e.into())
    }
}

impl HWI for BitBox02 {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::BitBox02
    }

    fn get_version(&self) -> Result<super::Version, HWIError> {
        let info = self
            .client
            .device_info()
            .map_err(|e| HWIError::Device(e.to_string()))?;
        parse_version(&info.version)
    }

    fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let fg = self
            .client
            .root_fingerprint()
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Fingerprint::from_str(&fg).map_err(|e| HWIError::Device(e.to_string()))
    }

    fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let fg = self
            .client
            .btc_xpub(
                if self.network == bitcoin::Network::Bitcoin {
                    pb::BtcCoin::Btc
                } else {
                    pb::BtcCoin::Tbtc
                },
                &Keypath::from(path),
                if self.network == bitcoin::Network::Bitcoin {
                    pb::btc_pub_request::XPubType::Xpub
                } else {
                    pb::btc_pub_request::XPubType::Tpub
                },
                self.display_xpub,
            )
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Xpub::from_str(&fg).map_err(|e| HWIError::Device(e.to_string()))
    }

    fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(path) => {
                self.client
                    .btc_address(
                        if self.network == bitcoin::Network::Bitcoin {
                            pb::BtcCoin::Btc
                        } else {
                            pb::BtcCoin::Tbtc
                        },
                        &Keypath::from(path),
                        &make_script_config_simple(pb::btc_script_config::SimpleType::P2tr),
                        true,
                    )
                    .map_err(HWIError::from)?;
            }
            AddressScript::Miniscript { index, change } => {
                let policy = self.policy.clone().ok_or(HWIError::MissingPolicy)?;
                let fg = self.get_master_fingerprint()?;
                let mut path = DerivationPath::master();
                for (key_index, key) in policy.pubkeys.iter().enumerate() {
                    if Some(fg) == key.master_fingerprint {
                        if let Some(p) = &key.path {
                            path = p.clone();
                        }
                        let (appended_path, wildcard) =
                            extract_first_appended_derivation_with_some_wildcard(
                                key_index,
                                &policy.template,
                            )?;
                        if appended_path.len() >= 2 {
                            path = path.extend(if *change {
                                &appended_path[1]
                            } else {
                                &appended_path[0]
                            });
                        } else if !appended_path.is_empty() {
                            path = path.extend(&appended_path[0]);
                        }
                        if wildcard == bip389::Wildcard::Hardened {
                            let child = ChildNumber::from_hardened_idx(*index)
                                .map_err(|_| HWIError::UnsupportedInput)?;
                            path = path.extend([child]);
                        } else if wildcard == bip389::Wildcard::Unhardened {
                            let child = ChildNumber::from_normal_idx(*index)
                                .map_err(|_| HWIError::UnsupportedInput)?;
                            path = path.extend([child]);
                        }
                        break;
                    }
                }
                self.client
                    .btc_address(
                        if self.network == bitcoin::Network::Bitcoin {
                            pb::BtcCoin::Btc
                        } else {
                            pb::BtcCoin::Tbtc
                        },
                        &Keypath::from(&path),
                        &policy.into(),
                        true,
                    )
                    .map_err(HWIError::from)?;
            }
        }
        Ok(())
    }

    fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, HWIError> {
        let pb_network = coin_from_network(self.network);
        let policy = extract_script_config_policy(policy)?;
        if self
            .client
            .btc_is_script_config_registered(pb_network, &policy.clone().into(), None)?
        {
            return Ok(None);
        }
        self.client
            .btc_register_script_config(
                pb_network,
                &policy.into(),
                None,
                pb::btc_register_script_config_request::XPubType::AutoXpubTpub,
                Some(name),
            )
            .map(|_| None)
            .map_err(|e| e.into())
    }

    fn is_wallet_registered(&self, _name: &str, policy: &str) -> Result<bool, HWIError> {
        let pb_network = coin_from_network(self.network);
        let policy = extract_script_config_policy(policy)?;
        self.client
            .btc_is_script_config_registered(pb_network, &policy.clone().into(), None)
            .map_err(|e| e.into())
    }

    /// Bitbox and Coldcard sign with the first bip32_derivation that matches its fingerprint.
    /// It may be useful to user utils::Bip32DerivationFilter to filter already signed derivations
    /// and derivations collusion in case of multiple spending path per outputs.
    fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let policy: Option<pb::BtcScriptConfigWithKeypath> =
            if let Some(policy) = self.policy.clone() {
                let mut path = DerivationPath::master();
                let fg = self.get_master_fingerprint()?;
                for key in &policy.pubkeys {
                    if Some(fg) == key.master_fingerprint {
                        if let Some(p) = &key.path {
                            path = p.clone();
                            break;
                        }
                    }
                }
                Some(pb::BtcScriptConfigWithKeypath {
                    script_config: Some(policy.into()),
                    keypath: Keypath::from(&path).to_vec(),
                })
            } else {
                None
            };

        self.client
            .btc_sign_psbt(
                coin_from_network(self.network),
                psbt,
                policy,
                pb::btc_sign_init_request::FormatUnit::Default,
            )
            .map_err(HWIError::from)?;

        Ok(())
    }
}

fn coin_from_network(network: bitcoin::Network) -> pb::BtcCoin {
    if network == bitcoin::Network::Bitcoin {
        pb::BtcCoin::Btc
    } else {
        pb::BtcCoin::Tbtc
    }
}

impl From<UsbError> for HWIError {
    fn from(value: UsbError) -> Self {
        HWIError::Device(value.to_string())
    }
}

impl From<Error> for HWIError {
    fn from(e: Error) -> Self {
        if let Error::BitBox(BitBoxError::UserAbort) = e {
            HWIError::UserRefused
        } else {
            HWIError::Device(e.to_string())
        }
    }
}

impl From<BitBox02> for Box<dyn HWI + Sync + Send> {
    fn from(s: BitBox02) -> Box<dyn HWI + Sync + Send> {
        Box::new(s)
    }
}

impl From<BitBox02> for Box<dyn HWI + Send> {
    fn from(s: BitBox02) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl From<BitBox02> for std::sync::Arc<dyn HWI + Sync + Send> {
    fn from(s: BitBox02) -> std::sync::Arc<dyn HWI + Sync + Send> {
        std::sync::Arc::new(s)
    }
}

pub fn extract_script_config_policy(policy: &str) -> Result<Policy, HWIError> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})").unwrap();
    let mut descriptor_template = policy.to_string();
    let mut pubkeys_str: Vec<&str> = Vec::new();
    for capture in re.find_iter(policy) {
        if !pubkeys_str.contains(&capture.as_str()) {
            pubkeys_str.push(capture.as_str());
        }
    }

    let mut pubkeys: Vec<KeyInfo> = Vec::new();
    for (i, key_str) in pubkeys_str.iter().enumerate() {
        descriptor_template = descriptor_template.replace(key_str, &format!("@{i}"));
        let pubkey = if let Ok(key) = Xpub::from_str(key_str) {
            KeyInfo {
                path: None,
                master_fingerprint: None,
                xpub: key,
            }
        } else {
            let (keysource_str, xpub_str) = key_str
                .strip_prefix('[')
                .and_then(|s| s.rsplit_once(']'))
                .ok_or(HWIError::InvalidParameter(
                    "policy",
                    "Invalid key source".to_string(),
                ))?;
            let (f_str, path_str) = keysource_str.split_once('/').unwrap_or((keysource_str, ""));
            let fingerprint = Fingerprint::from_str(f_str)
                .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?;
            let derivation_path = if path_str.is_empty() {
                DerivationPath::master()
            } else {
                DerivationPath::from_str(&format!("m/{path_str}"))
                    .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?
            };

            KeyInfo {
                xpub: Xpub::from_str(xpub_str)
                    .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?,
                path: Some(derivation_path),
                master_fingerprint: Some(fingerprint),
            }
        };
        pubkeys.push(pubkey);
    }
    // Do not include the hash in the descriptor template.
    let descriptor_template =
        if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#') {
            descriptor_template
        } else {
            &descriptor_template
        };

    //Ok(
    Ok(Policy {
        template: descriptor_template.to_string(),
        pubkeys,
    })
}

pub fn extract_first_appended_derivation_with_some_wildcard(
    key_index: usize,
    template: &str,
) -> Result<(Vec<DerivationPath>, bip389::Wildcard), HWIError> {
    let re = Regex::new(r"@\d+/[^,)]+").unwrap();
    for capture in re.find_iter(template) {
        if capture.as_str().contains(&format!("@{key_index}")) {
            if let Some((_, appended)) = capture.as_str().split_once('/') {
                let (derivations, wildcard) = bip389::parse_xkey_deriv(appended)?;
                if wildcard != bip389::Wildcard::None {
                    return Ok((derivations, wildcard));
                }
            }
        }
    }
    Ok((Vec::new(), bip389::Wildcard::None))
}

#[derive(Clone)]
pub struct Policy {
    template: String,
    pubkeys: Vec<KeyInfo>,
}

impl From<Policy> for BtcScriptConfig {
    fn from(p: Policy) -> BtcScriptConfig {
        let keys: Vec<KeyOriginInfo> = p.pubkeys.into_iter().map(|k| k.into()).collect();
        bitbox_api::btc::make_script_config_policy(&p.template, &keys)
    }
}

#[derive(Clone)]
pub struct KeyInfo {
    xpub: Xpub,
    path: Option<DerivationPath>,
    master_fingerprint: Option<Fingerprint>,
}

impl From<KeyInfo> for KeyOriginInfo {
    fn from(info: KeyInfo) -> KeyOriginInfo {
        KeyOriginInfo {
            root_fingerprint: info.master_fingerprint,
            keypath: info.path.as_ref().map(Keypath::from),
            xpub: info.xpub,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_script_config_policy() {
        let policy = extract_script_config_policy("wsh(or_d(pk([f5acc2fd/49'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/**),and_v(v:pkh(tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/**),older(100))))").unwrap();
        assert_eq!(2, policy.pubkeys.len());
        assert_eq!(
            "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/**),older(100))))",
            policy.template
        );

        let policy = extract_script_config_policy("wsh(or_d(multi(2,[b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ/<0;1>/*,[7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ/<0;1>/*),and_v(v:thresh(2,pkh([b0822927/48'/1'/0'/2']tpubDEvZxV86Br8Knbm9tWcr5Hvmg5cYTYsg92vinqH6Bie6U8ix8CsoN9W11NQygdqVwmHUJpsHXxNsi5gXn36g4xNfLWkMqPuFhRZAmMQ7jjQ/<2;3>/*),a:pkh([7fc39c07/48'/1'/0'/2']tpubDEvjgXtrUuH3Qtkapny9aE8gN847xiXsf9MDM5XueGf9nrvStqAuBSva3ajGyTvtp8Ti55FvVXsgYSXuS1tQkBeopFuodx2hRUDmQbvKxbZ/<2;3>/*),a:pkh([1a1ffd98/48'/1'/0'/2']tpubDFZqzTvGijYb13BC73CkS1er8DrP5YdzMhziN3kWCKUFaW51Yj6ggvf99YpdrkTJy4RT85mxQMHXDiFAKRxzf6BykQgT4pRRBNPshSJJcKo/<0;1>/*)),older(300))))#wp0w3hlw").unwrap();
        assert_eq!(3, policy.pubkeys.len());
        assert_eq!(
                "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<0;1>/*)),older(300))))",
                policy.template
            );
    }

    #[test]
    fn test_extract_first_appended_derivation_with_some_wildcard() {
        let (paths, wildcard) = extract_first_appended_derivation_with_some_wildcard(
            1,
            "wsh(or_d(pk(@0/**),and_v(v:pkh(@1/1/**),older(100))))",
        )
        .unwrap();
        assert_eq!(wildcard, bip389::Wildcard::Unhardened);
        assert_eq!(
            paths,
            vec![
                DerivationPath::from_str("m/1/0").unwrap(),
                DerivationPath::from_str("m/1/1").unwrap()
            ],
        );
        let (paths, wildcard) = extract_first_appended_derivation_with_some_wildcard(
            0,
            "wsh(or_d(multi(2,@0/<8;9>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/2/<3;4;5>/*)),older(300))))",
        )
        .unwrap();
        assert_eq!(wildcard, bip389::Wildcard::Unhardened);
        assert_eq!(
            paths,
            vec![
                DerivationPath::from_str("m/8").unwrap(),
                DerivationPath::from_str("m/9").unwrap(),
            ],
        );
        let (paths, wildcard) = extract_first_appended_derivation_with_some_wildcard(
            1,
            "wsh(or_d(multi(2,@0/<8;9>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/2/<3;4;5>/*)),older(300))))",
        )
        .unwrap();
        assert_eq!(wildcard, bip389::Wildcard::Unhardened);
        assert_eq!(
            paths,
            vec![
                DerivationPath::from_str("m/0").unwrap(),
                DerivationPath::from_str("m/1").unwrap(),
            ],
        );
        let (paths, wildcard) = extract_first_appended_derivation_with_some_wildcard(
            2,
            "wsh(or_d(multi(2,@0/<0;1>/*,@1/<0;1>/*),and_v(v:thresh(2,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/2/<3;4;5>/*)),older(300))))",
        )
        .unwrap();
        assert_eq!(wildcard, bip389::Wildcard::Unhardened);
        assert_eq!(
            paths,
            vec![
                DerivationPath::from_str("m/2/3").unwrap(),
                DerivationPath::from_str("m/2/4").unwrap(),
                DerivationPath::from_str("m/2/5").unwrap()
            ],
        );
    }
}
