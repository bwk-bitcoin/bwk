//! BIP375 generator + BIP376 signer role: holds `b_spend` and completes a
//! PSBTv2's silent-payment fields (ECDH shares, DLEQ proofs, output scripts)
//! before signing the inputs it can prove it owns.

use std::{collections::BTreeSet, str::FromStr};

use bitcoin::{
    bip32::{self, ChildNumber},
    hashes::Hash,
    secp256k1::{All, Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    Network, TapSighashType,
};

use crate::{
    account::{bip375, AccountError},
    core::dleq,
    receiver::{bip39, derive_spend_key},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid mnemonic: {0}")]
    Mnemonic(bip39::Error),
    #[error("key derivation failed")]
    Derivation,
    #[error("psbtv2 error: {0}")]
    PsbtV2(AccountError),
    #[error("failed to generate aux randomness: {0}")]
    AuxRand(getrandom::Error),
    #[error("dleq proof generation failed")]
    Dleq,
    #[error("sighash computation failed: {0}")]
    Sighash(bitcoin::sighash::TaprootError),
}

/// Reconstructs a taproot signing key by tweaking `b_spend`, negating for
/// parity, and matching the result against `script_pubkey`. Shared by
/// [`SpSigner`] (tweak read from the PSBTv2 input) and
/// [`crate::account::Account::sign_sp_inputs`] (tweak read from the coin
/// store).
pub fn reconstruct_signing_key(
    b_spend: SecretKey,
    tweak: SecretKey,
    script_pubkey: &bitcoin::Script,
    secp: &Secp256k1<All>,
) -> Option<SecretKey> {
    let candidate = b_spend.add_tweak(&tweak.into()).ok()?;
    let (x_only, parity) = candidate.public_key(secp).x_only_public_key();
    let signing_key = match parity {
        Parity::Odd => candidate.negate(),
        Parity::Even => candidate,
    };

    if !script_pubkey.is_p2tr() {
        return None;
    }
    let bytes = script_pubkey.as_bytes();
    (bytes.len() == 34 && bytes[2..34] == x_only.serialize()).then_some(signing_key)
}

/// Signs a single taproot key-spend input (no taproot tweak: SP outputs use
/// `dangerous_assume_tweaked()`). Shared by [`SpSigner`] and
/// [`crate::account::Account::sign_sp_inputs`].
pub fn sign_taproot_key_spend(
    cache: &mut SighashCache<&bitcoin::Transaction>,
    prevouts: &[bitcoin::TxOut],
    idx: usize,
    sk: &SecretKey,
    secp: &Secp256k1<All>,
    aux_rand: &[u8; 32],
) -> Result<Signature, bitcoin::sighash::TaprootError> {
    let sighash = cache.taproot_key_spend_signature_hash(
        idx,
        &Prevouts::All(prevouts),
        TapSighashType::Default,
    )?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = Keypair::from_secret_key(secp, sk);
    let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);
    Ok(Signature {
        signature,
        sighash_type: TapSighashType::Default,
    })
}

/// Writes a per-input ECDH share and DLEQ proof for `sk` against every
/// `scan_key`. Shared by [`SpSigner::write_shares`]'s per-input branch and
/// [`crate::account::Account::add_bip32_sp_shares`] for BIP32-owned inputs.
pub fn write_input_ecdh_share(
    input_psbt: &mut bitcoin::psbt::Input,
    scan_keys: &BTreeSet<PublicKey>,
    sk: SecretKey,
    aux_rand: [u8; 32],
    secp: &Secp256k1<All>,
) -> Option<()> {
    for &scan_key in scan_keys {
        let share = scan_key.mul_tweak(secp, &Scalar::from(sk)).ok()?;
        let proof = dleq::generate_proof(sk, scan_key, aux_rand, bip375::generator(), None)?;
        bwk_psbt::sp::set_sp_input_ecdh_share(input_psbt, scan_key, share);
        bwk_psbt::sp::set_sp_input_dleq(input_psbt, scan_key, *proof.as_bytes());
    }
    Some(())
}

pub struct SpSigner {
    b_spend: SecretKey,
    network: Network,
}

impl SpSigner {
    pub fn from_mnemonic(
        mnemonic: &str,
        network: Network,
        account: ChildNumber,
    ) -> Result<Self, Error> {
        let mnemonic = bip39::Mnemonic::from_str(mnemonic).map_err(Error::Mnemonic)?;
        let secp = Secp256k1::new();
        let seed = mnemonic.to_seed("");
        let master = bip32::Xpriv::new_master(network, &seed).map_err(|_| Error::Derivation)?;
        let b_spend =
            derive_spend_key(&master, &secp, network, account).map_err(|_| Error::Derivation)?;
        Ok(Self { b_spend, network })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Reconstructs the signing key for `input` if `b_spend`, tweaked by its
    /// `PSBT_IN_SP_TWEAK`, reproduces the prevout's taproot output key.
    fn reconstruct(&self, input: &bwk_psbt::Input, secp: &Secp256k1<All>) -> Option<SecretKey> {
        let tweak = bwk_psbt::sp::sp_input_tweak(&input.psbt).ok().flatten()?;
        let tweak = SecretKey::from_slice(&tweak).ok()?;
        let script = bip375::input_script_pubkey(input).ok().flatten()?;
        reconstruct_signing_key(self.b_spend, tweak, &script, secp)
    }

    /// Whether `owned` covers every BIP352-eligible input in `psbt`, meaning
    /// this signer can compute a single global ECDH share for the whole
    /// transaction rather than a per-input share for just its own inputs.
    fn owns_all_eligible_inputs(
        psbt: &bwk_psbt::PsbtV2,
        owned: &[(usize, SecretKey)],
    ) -> Result<bool, Error> {
        for (i, input) in psbt.inputs.iter().enumerate() {
            let eligible = bip375::eligible_input_pubkey(input).map_err(Error::PsbtV2)?;
            if eligible.is_some() && !owned.iter().any(|(idx, _)| *idx == i) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn sum_keys(mut keys: impl Iterator<Item = SecretKey>) -> Result<SecretKey, Error> {
        keys.try_fold(None::<SecretKey>, |acc, sk| match acc {
            Some(sum) => sum.add_tweak(&Scalar::from(sk)).map(Some),
            None => Ok(Some(sk)),
        })
        .map_err(|_| Error::Derivation)?
        .ok_or(Error::Derivation)
    }

    /// Writes either one global ECDH share/proof per scan key (if `owned`
    /// covers every eligible input) or a per-input share/proof for each
    /// owned input (leaving the rest for another signer to contribute).
    fn write_shares(
        psbt: &mut bwk_psbt::PsbtV2,
        owned: &[(usize, SecretKey)],
        secp: &Secp256k1<All>,
    ) -> Result<(), Error> {
        let scan_keys = bip375::scan_keys(psbt).map_err(Error::PsbtV2)?;
        if scan_keys.is_empty() {
            return Ok(());
        }
        let owns_all = Self::owns_all_eligible_inputs(psbt, owned)?;

        let mut aux_rand = [0u8; 32];
        getrandom::getrandom(&mut aux_rand).map_err(Error::AuxRand)?;

        if owns_all {
            let sum = Self::sum_keys(owned.iter().map(|(_, sk)| *sk))?;
            for scan_key in scan_keys {
                let share = scan_key
                    .mul_tweak(secp, &Scalar::from(sum))
                    .map_err(|_| Error::Derivation)?;
                let proof =
                    dleq::generate_proof(sum, scan_key, aux_rand, bip375::generator(), None)
                        .ok_or(Error::Dleq)?;
                bwk_psbt::sp::set_sp_global_ecdh_share_v2(psbt, scan_key, share);
                bwk_psbt::sp::set_sp_global_dleq_v2(psbt, scan_key, *proof.as_bytes());
            }
        } else {
            for (idx, sk) in owned {
                write_input_ecdh_share(
                    &mut psbt.inputs[*idx].psbt,
                    &scan_keys,
                    *sk,
                    aux_rand,
                    secp,
                )
                .ok_or(Error::Dleq)?;
            }
        }
        Ok(())
    }

    fn sign_inputs(
        psbt: &mut bwk_psbt::PsbtV2,
        owned: &[(usize, SecretKey)],
        secp: &Secp256k1<All>,
    ) -> Result<(), Error> {
        if owned.is_empty() {
            return Ok(());
        }
        let tx = psbt.unsigned_tx().map_err(|_| Error::Derivation)?;
        let prevouts: Vec<bitcoin::TxOut> = psbt
            .inputs
            .iter()
            .map(|input| input.psbt.witness_utxo.clone().ok_or(Error::Derivation))
            .collect::<Result<_, _>>()?;
        let mut cache = SighashCache::new(&tx);

        let mut aux_rand = [0u8; 32];
        getrandom::getrandom(&mut aux_rand).map_err(Error::AuxRand)?;

        for (idx, sk) in owned {
            let signature =
                sign_taproot_key_spend(&mut cache, &prevouts, *idx, sk, secp, &aux_rand)
                    .map_err(Error::Sighash)?;
            psbt.inputs[*idx].psbt.tap_key_sig = Some(signature);
        }
        Ok(())
    }

    pub fn sign(&self, psbt: &mut bwk_psbt::PsbtV2) -> Result<(), Error> {
        let secp = Secp256k1::new();
        let owned: Vec<(usize, SecretKey)> = psbt
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| self.reconstruct(input, &secp).map(|sk| (i, sk)))
            .collect();

        Self::write_shares(psbt, &owned, &secp)?;
        bip375::complete_output_scripts(psbt).map_err(Error::PsbtV2)?;
        Self::sign_inputs(psbt, &owned, &secp)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute,
        hashes::Hash,
        key::TweakedPublicKey,
        secp256k1::{Secp256k1, SecretKey},
        transaction, Network, OutPoint, ScriptBuf, Sequence, TxOut, Txid, XOnlyPublicKey,
    };

    use crate::{account::bip375, signer::SpSigner};

    fn signer() -> SpSigner {
        SpSigner {
            b_spend: SecretKey::from_slice(&[7u8; 32]).unwrap(),
            network: Network::Regtest,
        }
    }

    fn p2tr_input(outpoint_byte: u8, tweak: [u8; 32], x_only: XOnlyPublicKey) -> bwk_psbt::Input {
        let script =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(x_only));
        let mut psbt_input = bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: script,
            }),
            ..Default::default()
        };
        bwk_psbt::sp::set_sp_input_tweak(&mut psbt_input, tweak);
        bwk_psbt::Input {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([outpoint_byte; 32]),
                vout: 0,
            },
            sequence: Sequence::MAX,
            required_time_lock_time: None,
            required_height_lock_time: None,
            psbt: psbt_input,
        }
    }

    /// An input whose tweak reconstructs against `signer`'s `b_spend`.
    fn owned_input(signer: &SpSigner, tweak_byte: u8, outpoint_byte: u8) -> bwk_psbt::Input {
        let secp = Secp256k1::new();
        let tweak = SecretKey::from_slice(&[tweak_byte; 32]).unwrap();
        let candidate = signer.b_spend.add_tweak(&tweak.into()).unwrap();
        let (x_only, _) = candidate.public_key(&secp).x_only_public_key();
        p2tr_input(outpoint_byte, tweak.secret_bytes(), x_only)
    }

    /// An input carrying a tweak that reconstructs to an unrelated key, so it
    /// never matches `signer`'s `b_spend`.
    fn foreign_input(outpoint_byte: u8) -> bwk_psbt::Input {
        let secp = Secp256k1::new();
        let unrelated = SecretKey::from_slice(&[99u8; 32]).unwrap();
        let (x_only, _) = unrelated.public_key(&secp).x_only_public_key();
        let tweak = SecretKey::from_slice(&[42u8; 32]).unwrap();
        p2tr_input(outpoint_byte, tweak.secret_bytes(), x_only)
    }

    fn empty_psbt(inputs: Vec<bwk_psbt::Input>) -> bwk_psbt::PsbtV2 {
        bwk_psbt::PsbtV2 {
            tx_version: transaction::Version::TWO,
            fallback_lock_time: Some(absolute::LockTime::ZERO),
            tx_modifiable: None,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs,
            outputs: vec![],
        }
    }

    #[test]
    fn signs_only_its_own_inputs() {
        let signer = signer();
        let mut psbt = empty_psbt(vec![owned_input(&signer, 1, 1), foreign_input(2)]);

        signer.sign(&mut psbt).unwrap();

        assert!(psbt.inputs[0].psbt.tap_key_sig.is_some());
        assert!(psbt.inputs[1].psbt.tap_key_sig.is_none());
    }

    #[test]
    fn generates_shares_and_scripts() {
        let signer = signer();
        let mut psbt = empty_psbt(vec![owned_input(&signer, 3, 5)]);

        let secp = Secp256k1::new();
        let scan_key = SecretKey::from_slice(&[11u8; 32])
            .unwrap()
            .public_key(&secp);
        let spend_key = SecretKey::from_slice(&[12u8; 32])
            .unwrap()
            .public_key(&secp);
        let mut output = bitcoin::psbt::Output::default();
        bwk_psbt::sp::set_sp_v0_output(&mut output, scan_key, spend_key, None);
        psbt.outputs.push(bwk_psbt::Output {
            amount: bitcoin::Amount::from_sat(1_000),
            script_pubkey: None,
            psbt: output,
        });

        signer.sign(&mut psbt).unwrap();

        assert!(bwk_psbt::sp::sp_global_ecdh_share_v2(&psbt, scan_key)
            .unwrap()
            .is_some());
        assert!(bwk_psbt::sp::sp_global_dleq_v2(&psbt, scan_key)
            .unwrap()
            .is_some());
        assert!(psbt.outputs[0].script_pubkey.is_some());
        bip375::validate(&psbt).unwrap();
    }
}
