//! BIP376 updater role: writes `PSBT_IN_SP_SPEND_BIP32_DERIVATION` on every
//! silent-payment input whenever the wallet knows a master fingerprint. A
//! signer still recognizes its own inputs by reconstructing `b_spend + tweak`
//! against the prevout; this is a hint, not a requirement, so a watch-only
//! wallet (no fingerprint) simply writes nothing here.

use bitcoin::{bip32::KeySource, secp256k1::PublicKey};
use bwk_coin::Coin;
use bwk_tx::{error::Error, recipient::SpUpdater};

/// Holds only public material: a spend public key and, optionally, the
/// `(fingerprint, path)` pair a signer can use as a hint. Never a private key.
pub struct SpInputUpdater {
    spend_pk: PublicKey,
    key_source: Option<KeySource>,
}

impl SpInputUpdater {
    pub fn new(spend_pk: PublicKey, key_source: Option<KeySource>) -> Self {
        Self {
            spend_pk,
            key_source,
        }
    }
}

impl SpUpdater for SpInputUpdater {
    fn update_sp_inputs(&self, psbt: &mut bwk_psbt::PsbtV2, coins: &[Coin]) -> Result<(), Error> {
        let Some(source) = &self.key_source else {
            return Ok(());
        };
        for (index, coin) in coins.iter().enumerate() {
            if !coin.is_sp() {
                continue;
            }
            let input = psbt.inputs.get_mut(index).ok_or(Error::Input)?;
            if input.previous_output != coin.outpoint {
                return Err(Error::Input);
            }
            bwk_psbt::sp::set_sp_input_spend_bip32_derivation(
                &mut input.psbt,
                self.spend_pk,
                source.clone(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        absolute::LockTime,
        bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpriv, Xpub},
        hashes::Hash,
        secp256k1::{PublicKey, Secp256k1, SecretKey},
        transaction, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid,
    };
    use bwk_coin::{Coin, CoinSpendInfo, CoinStatus, KeyChain};
    use bwk_tx::{error::Error, recipient::SpUpdater};
    use miniscript::{Descriptor, DescriptorPublicKey};

    use crate::account::updater::SpInputUpdater;

    fn public_key(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
    }

    fn outpoint(byte: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: 0,
        }
    }

    fn sp_coin(outpoint: OutPoint, tweak: [u8; 32]) -> Coin {
        Coin {
            txout: TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            },
            outpoint,
            height: Some(1),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            status: CoinStatus::Confirmed,
            label: None,
            satisfaction_size: 0,
            spend_info: CoinSpendInfo::Sp { tweak },
        }
    }

    fn bip32_coin(outpoint: OutPoint) -> Coin {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(bitcoin::Network::Regtest, &[7u8; 32]).unwrap();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let descriptor =
            Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({xpub}/<0;1>/*)")).unwrap();
        Coin {
            txout: TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            },
            outpoint,
            height: Some(1),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            status: CoinStatus::Confirmed,
            label: None,
            satisfaction_size: 0,
            spend_info: CoinSpendInfo::Bip32 {
                coin_path: (KeyChain::Receive, 0),
                descriptor,
            },
        }
    }

    fn psbt_input(outpoint: OutPoint) -> bwk_psbt::Input {
        bwk_psbt::Input {
            previous_output: outpoint,
            sequence: Sequence::MAX,
            required_time_lock_time: None,
            required_height_lock_time: None,
            psbt: bitcoin::psbt::Input::default(),
        }
    }

    fn empty_psbt(inputs: Vec<bwk_psbt::Input>) -> bwk_psbt::PsbtV2 {
        bwk_psbt::PsbtV2 {
            tx_version: transaction::Version::TWO,
            fallback_lock_time: Some(LockTime::ZERO),
            tx_modifiable: None,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs,
            outputs: vec![],
        }
    }

    fn key_source() -> KeySource {
        (
            Fingerprint::from([9u8; 4]),
            DerivationPath::from(vec![ChildNumber::from_hardened_idx(0).unwrap()]),
        )
    }

    #[test]
    fn writes_derivation_for_sp_inputs() {
        let sp_outpoint = outpoint(1);
        let bip32_outpoint = outpoint(2);
        let sp_coin = sp_coin(sp_outpoint, [3u8; 32]);
        let bip32_coin = bip32_coin(bip32_outpoint);
        let mut psbt = empty_psbt(vec![psbt_input(sp_outpoint), psbt_input(bip32_outpoint)]);

        let spend_pk = public_key(4);
        let source = key_source();
        let updater = SpInputUpdater::new(spend_pk, Some(source.clone()));

        updater
            .update_sp_inputs(&mut psbt, &[sp_coin, bip32_coin])
            .unwrap();

        assert_eq!(
            bwk_psbt::sp::sp_input_spend_bip32_derivation(&psbt.inputs[0].psbt, spend_pk),
            Ok(Some(source))
        );
        assert_eq!(
            bwk_psbt::sp::sp_input_spend_bip32_derivation(&psbt.inputs[1].psbt, spend_pk),
            Ok(None)
        );
    }

    #[test]
    fn skips_when_fingerprint_unknown() {
        let coin_outpoint = outpoint(1);
        let coin = sp_coin(coin_outpoint, [3u8; 32]);
        let mut psbt = empty_psbt(vec![psbt_input(coin_outpoint)]);
        let spend_pk = public_key(4);
        let updater = SpInputUpdater::new(spend_pk, None);

        updater.update_sp_inputs(&mut psbt, &[coin]).unwrap();

        assert_eq!(
            bwk_psbt::sp::sp_input_spend_bip32_derivation(&psbt.inputs[0].psbt, spend_pk),
            Ok(None)
        );
    }

    #[test]
    fn rejects_misaligned_coins() {
        let coin_outpoint = outpoint(1);
        let psbt_outpoint = outpoint(9);
        let coin = sp_coin(coin_outpoint, [3u8; 32]);
        let mut psbt = empty_psbt(vec![psbt_input(psbt_outpoint)]);
        let spend_pk = public_key(4);
        let updater = SpInputUpdater::new(spend_pk, Some(key_source()));

        let result = updater.update_sp_inputs(&mut psbt, &[coin]);

        assert!(matches!(result, Err(Error::Input)));
        assert_eq!(
            bwk_psbt::sp::sp_input_spend_bip32_derivation(&psbt.inputs[0].psbt, spend_pk),
            Ok(None)
        );
    }
}
