//! BIP375 helpers: stateless and key-free reasoning about a `PsbtV2`'s
//! inputs. This module holds no private key, coin store or account state; it
//! only answers questions about a PSBT, which is what lets the wallet verify
//! a signer's work without being able to do the signer's job.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{key::TapTweak, Script, ScriptBuf};

use crate::{
    account::AccountError,
    core::{
        secp256k1::{PublicKey, Scalar, Secp256k1},
        utils::hash::calculate_input_hash,
    },
};

const SIGHASH_ALL: u32 = 1;
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Resolves the prevout script an input spends, checking `witness_utxo` and
/// `non_witness_utxo` agree when both are present. `Ok(None)` means the PSBT
/// does not say what the prevout is, distinct from the prevout being
/// ineligible.
pub fn input_script_pubkey(input: &bwk_psbt::Input) -> Result<Option<ScriptBuf>, AccountError> {
    let non_witness = if let Some(tx) = &input.psbt.non_witness_utxo {
        if tx.compute_txid() != input.previous_output.txid {
            return Err(AccountError::PsbtV2);
        }
        tx.output
            .get(input.previous_output.vout as usize)
            .ok_or(AccountError::PsbtV2)
            .map(Some)?
    } else {
        None
    };
    if let Some(txout) = &input.psbt.witness_utxo {
        if non_witness.is_some_and(|non_witness| non_witness != txout) {
            return Err(AccountError::PsbtV2);
        }
        return Ok(Some(txout.script_pubkey.clone()));
    }
    if let Some(txout) = non_witness {
        return Ok(Some(txout.script_pubkey.clone()));
    }
    Ok(None)
}

/// Whether `script` is one of the four BIP352-eligible script types. A P2SH
/// script requires the `redeem_script` to actually commit to `script`; an
/// uncommitted redeem script is an error, not a `false`, since it means the
/// PSBT is claiming something false about an input it is about to spend.
pub fn eligible_script(
    script: &Script,
    redeem_script: Option<&ScriptBuf>,
) -> Result<bool, AccountError> {
    if script.is_p2pkh() || script.is_p2wpkh() || script.is_p2tr() {
        return Ok(true);
    }
    if !script.is_p2sh() {
        return Ok(false);
    }
    let Some(redeem_script) = redeem_script else {
        return Ok(false);
    };
    if ScriptBuf::new_p2sh(&redeem_script.script_hash()).as_script() != script {
        return Err(AccountError::PsbtV2);
    }
    Ok(redeem_script.is_p2wpkh())
}

pub fn eligible_input_script(input: &bwk_psbt::Input) -> Result<bool, AccountError> {
    match input_script_pubkey(input)? {
        Some(script) => eligible_script(&script, input.psbt.redeem_script.as_ref()),
        None => Ok(false),
    }
}

/// Whether `pubkey` reproduces `script`, checked against the actual script
/// bytes rather than trusted from the PSBT's own claim.
pub fn bip32_pubkey_matches_script(
    pubkey: PublicKey,
    script: &Script,
    redeem_script: Option<&ScriptBuf>,
) -> bool {
    let pubkey = bitcoin::PublicKey::new(pubkey);
    if script.is_p2pkh() {
        return ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()).as_script() == script;
    }
    if script.is_p2wpkh() {
        return pubkey
            .wpubkey_hash()
            .is_ok_and(|hash| ScriptBuf::new_p2wpkh(&hash).as_script() == script);
    }
    script.is_p2sh()
        && redeem_script.is_some_and(|redeem_script| {
            pubkey.wpubkey_hash().is_ok_and(|hash| {
                ScriptBuf::new_p2wpkh(&hash).as_script() == redeem_script.as_script()
                    && ScriptBuf::new_p2sh(&redeem_script.script_hash()).as_script() == script
            })
        })
}

/// Recovers the eligible input's public key, or `Ok(None)` when the input's
/// script type is not one BIP352 sums.
pub fn eligible_input_pubkey(input: &bwk_psbt::Input) -> Result<Option<PublicKey>, AccountError> {
    let Some(script) = input_script_pubkey(input)? else {
        return Err(AccountError::PsbtV2);
    };
    if !eligible_script(&script, input.psbt.redeem_script.as_ref())? {
        return Ok(None);
    }
    // A P2TR input whose internal key is the NUMS point H is provably
    // script-path-only and BIP352 excludes it. But the claim must be checked
    // against the script, not trusted: a false claim would silently remove a
    // real input from the sum and let an attacker redirect the payment.
    if script.is_p2tr()
        && input
            .psbt
            .tap_internal_key
            .is_some_and(|key| key.serialize() == NUMS_H)
    {
        let bytes = script.as_bytes();
        return if bytes[2..34] == NUMS_H {
            Ok(None)
        } else {
            Err(AccountError::PsbtV2)
        };
    }
    // BIP352 defines the taproot input key as the even-parity lift of the
    // output key, read from the script. Never from bip32_derivation: a PSBT
    // can carry arbitrary derivation entries, and trusting one here hands an
    // attacker control of the input hash.
    if script.is_p2tr() {
        let bytes = script.as_bytes();
        let mut pubkey = [0; 33];
        pubkey[0] = 0x02;
        pubkey[1..].copy_from_slice(&bytes[2..34]);
        return PublicKey::from_slice(&pubkey)
            .map(Some)
            .map_err(|_| AccountError::PsbtV2);
    }
    let candidates = input
        .psbt
        .bip32_derivation
        .keys()
        .copied()
        .chain(input.psbt.partial_sigs.keys().map(|pubkey| pubkey.inner))
        .collect::<BTreeSet<_>>();
    for pubkey in candidates {
        if bip32_pubkey_matches_script(pubkey, &script, input.psbt.redeem_script.as_ref()) {
            return Ok(Some(pubkey));
        }
    }
    // A candidate that does not reproduce the script is not merely skipped:
    // the PSBT is claiming a key for this input that the script disagrees
    // with.
    Err(AccountError::PsbtV2)
}

pub fn eligible_pubkey_sum(psbt: &bwk_psbt::PsbtV2) -> Result<PublicKey, AccountError> {
    let mut sum: Option<PublicKey> = None;
    for input in &psbt.inputs {
        let Some(pubkey) = eligible_input_pubkey(input)? else {
            continue;
        };
        sum = Some(match sum {
            Some(current) => current.combine(&pubkey).map_err(|_| AccountError::PsbtV2)?,
            None => pubkey,
        });
    }
    sum.ok_or(AccountError::PsbtV2)
}

/// BIP352 takes the smallest outpoint over all inputs, but sums the public
/// keys of eligible inputs only: the two sets are not the same.
pub fn input_hash(psbt: &bwk_psbt::PsbtV2) -> Result<Scalar, AccountError> {
    let outpoints = psbt
        .inputs
        .iter()
        .map(|input| input.previous_output)
        .collect::<Vec<_>>();
    calculate_input_hash(&outpoints, eligible_pubkey_sum(psbt)?).map_err(|_| AccountError::PsbtV2)
}

pub fn validate_input_eligibility(
    psbt: &bwk_psbt::PsbtV2,
    require_sighash_all: bool,
) -> Result<(), AccountError> {
    for input in &psbt.inputs {
        // BIP352 does not define an input key for segwit v2+, so such an
        // input can neither be included nor safely ignored.
        if input_script_pubkey(input)?
            .and_then(|script| script.witness_version())
            .is_some_and(|version| version.to_num() > 1)
        {
            return Err(AccountError::PsbtV2);
        }
        // Any sighash flag other than ALL would let a signer alter the
        // outputs after the silent-payment scripts were derived from them.
        if require_sighash_all
            && input
                .psbt
                .sighash_type
                .is_some_and(|sighash| sighash.to_u32() != SIGHASH_ALL)
        {
            return Err(AccountError::PsbtV2);
        }
    }
    Ok(())
}

pub fn scan_keys(psbt: &bwk_psbt::PsbtV2) -> Result<BTreeSet<PublicKey>, AccountError> {
    psbt.outputs
        .iter()
        .try_fold(BTreeSet::new(), |mut keys, output| {
            if let Some(info) =
                bwk_psbt::sp::sp_v0_output(&output.psbt).map_err(|_| AccountError::PsbtV2)?
            {
                keys.insert(info.scan_key);
            }
            Ok(keys)
        })
}

/// The sender's combined ECDH share for `scan_key`: the global share if the
/// sender published one, otherwise the sum of every eligible input's
/// per-input share. A missing per-input share is an error, not a zero: the
/// resulting sum would be wrong and the payment undiscoverable.
pub fn combined_share(
    psbt: &bwk_psbt::PsbtV2,
    scan_key: PublicKey,
) -> Result<PublicKey, AccountError> {
    if let Some(share) =
        bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, scan_key).map_err(|_| AccountError::PsbtV2)?
    {
        return Ok(share);
    }
    let mut combined: Option<PublicKey> = None;
    for input in &psbt.inputs {
        if eligible_input_pubkey(input)?.is_none() {
            continue;
        }
        let share = bwk_psbt::sp::sp_input_ecdh_share(&input.psbt, scan_key)
            .map_err(|_| AccountError::PsbtV2)?
            .ok_or(AccountError::PsbtV2)?;
        combined = Some(match combined {
            Some(current) => current.combine(&share).map_err(|_| AccountError::PsbtV2)?,
            None => share,
        });
    }
    combined.ok_or(AccountError::PsbtV2)
}

/// The P2TR script for every silent-payment output the PSBT already has
/// enough information to derive. When `require_all` is `false`, a group
/// still missing its share is skipped rather than rejected, as long as none
/// of its outputs already carry a script: a PSBT with no share yet for one
/// recipient is incomplete, not invalid.
pub fn output_scripts(
    psbt: &bwk_psbt::PsbtV2,
    input_hash: Scalar,
    require_all: bool,
) -> Result<Vec<(usize, ScriptBuf)>, AccountError> {
    let mut groups: BTreeMap<PublicKey, Vec<(usize, PublicKey)>> = BTreeMap::new();
    for (index, output) in psbt.outputs.iter().enumerate() {
        if let Some(info) =
            bwk_psbt::sp::sp_v0_output(&output.psbt).map_err(|_| AccountError::PsbtV2)?
        {
            groups
                .entry(info.scan_key)
                .or_default()
                .push((index, info.spend_key));
        }
    }

    let secp = Secp256k1::new();
    let mut scripts = Vec::new();
    for (scan_key, mut outputs) in groups {
        let share = match combined_share(psbt, scan_key) {
            Ok(share) => share
                .mul_tweak(&secp, &input_hash)
                .map_err(|_| AccountError::PsbtV2)?,
            Err(_)
                if !require_all
                    && outputs
                        .iter()
                        .all(|(index, _)| psbt.outputs[*index].script_pubkey.is_none()) =>
            {
                continue
            }
            Err(err) => return Err(err),
        };
        // BIP352 assigns k = 0, 1, 2, ... within a scan-key group, and the
        // sender and receiver must agree on the order regardless of how the
        // outputs are laid out in the transaction. Sorting on the spend key
        // first, with the output index as tiebreak, is that agreed order.
        outputs.sort_by_key(|(index, spend_key)| (*spend_key, *index));
        for (k, (index, spend_key)) in outputs.into_iter().enumerate() {
            let tweak = crate::core::utils::common::calculate_t_n(&share, k as u32)
                .map_err(|_| AccountError::PsbtV2)?;
            let output_key = crate::core::utils::common::calculate_P_n(&spend_key, tweak.into())
                .map_err(|_| AccountError::PsbtV2)?;
            let (xonly, _) = output_key.x_only_public_key();
            // P_k is already BIP352's final output key; applying the usual
            // taproot tweak on top of it would produce a script the
            // recipient can never find.
            scripts.push((
                index,
                ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()),
            ));
        }
    }
    Ok(scripts)
}

pub fn fill_output_scripts(
    psbt: &mut bwk_psbt::PsbtV2,
    input_hash: Scalar,
) -> Result<(), AccountError> {
    for (index, script) in output_scripts(psbt, input_hash, true)? {
        match &psbt.outputs[index].script_pubkey {
            // A signer must never silently overwrite a script another party
            // already committed to.
            Some(existing) if existing != &script => return Err(AccountError::PsbtV2),
            Some(_) => {}
            None => psbt.outputs[index].script_pubkey = Some(script),
        }
    }
    // Every silent-payment script here depends on the exact input set (via
    // the input hash) and the exact output set (via k's position within its
    // group), so completion must freeze both.
    psbt.tx_modifiable = Some(bwk_psbt::TxModifiable::none());
    Ok(())
}

pub fn complete_output_scripts(psbt: &mut bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    let scan_keys = scan_keys(psbt)?;
    if scan_keys.is_empty() {
        return Ok(());
    }
    validate_input_eligibility(psbt, true)?;
    let input_hash = input_hash(psbt)?;
    fill_output_scripts(psbt, input_hash)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, hashes::Hash, key::TapTweak, psbt::PsbtSighashType, secp256k1::Secp256k1,
        transaction, Amount, Network, OutPoint, PublicKey as BitcoinPublicKey, ScriptBuf, Sequence,
        TapSighashType, TxOut,
    };
    use secp256k1::{PublicKey, Scalar, SecretKey};

    use crate::{
        account::{
            bip375::{
                complete_output_scripts, eligible_input_pubkey, eligible_script, input_hash,
                input_script_pubkey, validate_input_eligibility, NUMS_H,
            },
            AccountError,
        },
        core::utils::hash::calculate_input_hash,
        receiver::{SpReceiver, SpendKey},
    };

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn even_secret(byte: u8) -> SecretKey {
        let secp = Secp256k1::new();
        let secret = secret(byte);
        let (_, parity) = secret.x_only_public_key(&secp);
        if parity == secp256k1::Parity::Odd {
            secret.negate()
        } else {
            secret
        }
    }

    fn nums_pubkey() -> PublicKey {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[1..].copy_from_slice(&NUMS_H);
        PublicKey::from_slice(&bytes).unwrap()
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

    fn input_with(psbt: bitcoin::psbt::Input, previous_output: OutPoint) -> bwk_psbt::Input {
        bwk_psbt::Input {
            previous_output,
            sequence: Sequence::MAX,
            required_time_lock_time: None,
            required_height_lock_time: None,
            psbt,
        }
    }

    fn p2tr_witness_utxo(pubkey: PublicKey) -> bitcoin::psbt::Input {
        let (xonly, _) = pubkey.x_only_public_key();
        bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked()),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn p2tr_key_comes_from_the_script_not_bip32_derivation() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &even_secret(1));
        let key_b = PublicKey::from_secret_key(&secp, &even_secret(2));
        let mut psbt_input = p2tr_witness_utxo(key_a);
        psbt_input.bip32_derivation.insert(
            key_b,
            (bitcoin::bip32::Fingerprint::default(), Default::default()),
        );
        let input = input_with(psbt_input, OutPoint::null());

        let result = eligible_input_pubkey(&input).unwrap();

        assert_eq!(result, Some(key_a));
    }

    #[test]
    fn eligible_input_pubkey_excludes_committed_taproot_nums_input() {
        let nums = nums_pubkey();
        let mut psbt_input = p2tr_witness_utxo(nums);
        psbt_input.tap_internal_key = Some(nums.x_only_public_key().0);
        let input = input_with(psbt_input, OutPoint::null());

        let result = eligible_input_pubkey(&input).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn eligible_input_pubkey_rejects_uncommitted_taproot_nums_internal_key() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &even_secret(1));
        let nums = nums_pubkey();
        let mut psbt_input = p2tr_witness_utxo(key_a);
        psbt_input.tap_internal_key = Some(nums.x_only_public_key().0);
        let input = input_with(psbt_input, OutPoint::null());

        let result = eligible_input_pubkey(&input);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    fn p2wpkh_input(script_key: PublicKey, bip32_key: PublicKey) -> bwk_psbt::Input {
        let hash = BitcoinPublicKey::new(script_key).wpubkey_hash().unwrap();
        let mut psbt_input = bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&hash),
            }),
            ..Default::default()
        };
        psbt_input.bip32_derivation.insert(
            bip32_key,
            (bitcoin::bip32::Fingerprint::default(), Default::default()),
        );
        input_with(psbt_input, OutPoint::null())
    }

    #[test]
    fn accepts_p2wpkh_input_with_matching_bip32_key() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &secret(1));
        let input = p2wpkh_input(key_a, key_a);

        let result = eligible_input_pubkey(&input).unwrap();

        assert_eq!(result, Some(key_a));
    }

    #[test]
    fn rejects_p2wpkh_input_with_unrelated_bip32_key() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &secret(1));
        let key_b = PublicKey::from_secret_key(&secp, &secret(2));
        let input = p2wpkh_input(key_a, key_b);

        let result = eligible_input_pubkey(&input);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn eligible_script_rejects_uncommitted_p2sh_redeem_script() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &secret(1));
        let wpkh_redeem =
            ScriptBuf::new_p2wpkh(&BitcoinPublicKey::new(key_a).wpubkey_hash().unwrap());
        let script_pubkey = ScriptBuf::new_p2sh(&wpkh_redeem.script_hash());
        let unrelated_redeem = ScriptBuf::new_p2pkh(&BitcoinPublicKey::new(key_a).pubkey_hash());

        let result = eligible_script(&script_pubkey, Some(&unrelated_redeem));

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    fn op_return_tx() -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    fn segwit_v2_script() -> ScriptBuf {
        ScriptBuf::from_bytes([vec![0x52, 0x20], vec![0; 32]].concat())
    }

    #[test]
    fn input_script_pubkey_rejects_mismatched_non_witness_utxo() {
        let tx = op_return_tx();
        let psbt_input = bitcoin::psbt::Input {
            non_witness_utxo: Some(tx),
            ..Default::default()
        };
        let input = input_with(psbt_input, OutPoint::null());

        let result = input_script_pubkey(&input);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn input_script_pubkey_rejects_conflicting_utxos() {
        let tx = op_return_tx();
        let previous_output = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };
        let psbt_input = bitcoin::psbt::Input {
            non_witness_utxo: Some(tx),
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }),
            ..Default::default()
        };
        let input = input_with(psbt_input, previous_output);

        let result = input_script_pubkey(&input);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn validate_input_eligibility_rejects_segwit_v2() {
        let psbt_input = bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: segwit_v2_script(),
            }),
            ..Default::default()
        };
        let input = input_with(psbt_input, OutPoint::null());
        let psbt = empty_psbt(vec![input]);

        let result = validate_input_eligibility(&psbt, true);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn validate_input_eligibility_rejects_non_sighash_all() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &even_secret(1));
        let mut psbt_input = p2tr_witness_utxo(key_a);
        psbt_input.sighash_type = Some(PsbtSighashType::from(TapSighashType::Single));
        let input = input_with(psbt_input, OutPoint::null());
        let psbt = empty_psbt(vec![input]);

        let strict = validate_input_eligibility(&psbt, true);
        let lenient = validate_input_eligibility(&psbt, false);

        assert!(matches!(strict, Err(AccountError::PsbtV2)));
        assert!(lenient.is_ok());
    }

    #[test]
    fn input_hash_uses_all_outpoints_but_only_eligible_keys() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &even_secret(1));
        let nums = nums_pubkey();

        let outpoint_a = OutPoint::null();
        let outpoint_b = OutPoint {
            txid: bitcoin::Txid::from_byte_array([1; 32]),
            vout: 1,
        };

        let input_a = input_with(p2tr_witness_utxo(key_a), outpoint_a);
        let mut nums_psbt_input = p2tr_witness_utxo(nums);
        nums_psbt_input.tap_internal_key = Some(nums.x_only_public_key().0);
        let input_b = input_with(nums_psbt_input, outpoint_b);

        let psbt = empty_psbt(vec![input_a, input_b]);

        let expected = calculate_input_hash(&[outpoint_a, outpoint_b], key_a).unwrap();

        assert_eq!(input_hash(&psbt).unwrap(), expected);
    }

    fn sp_output(scan_key: PublicKey, spend_key: PublicKey) -> bwk_psbt::Output {
        let mut psbt = bitcoin::psbt::Output::default();
        bwk_psbt::sp::set_sp_v0_output(&mut psbt, scan_key, spend_key, None);
        bwk_psbt::Output {
            amount: Amount::from_sat(1_000),
            script_pubkey: None,
            psbt,
        }
    }

    fn set_global_share(
        psbt: &mut bwk_psbt::PsbtV2,
        scan_key: PublicKey,
        input_secret: SecretKey,
    ) -> PublicKey {
        let share = scan_key
            .mul_tweak(&Secp256k1::new(), &Scalar::from(input_secret))
            .unwrap();
        bwk_psbt::sp::set_sp_global_ecdh_share_v2(psbt, scan_key, share);
        share
    }

    fn set_input_share(input: &mut bitcoin::psbt::Input, scan_key: PublicKey, secret: SecretKey) {
        let share = scan_key
            .mul_tweak(&Secp256k1::new(), &Scalar::from(secret))
            .unwrap();
        bwk_psbt::sp::set_sp_input_ecdh_share(input, scan_key, share);
    }

    fn psbt() -> (bwk_psbt::PsbtV2, PublicKey) {
        let secp = Secp256k1::new();
        let input_secret = even_secret(5);
        let input_pubkey = PublicKey::from_secret_key(&secp, &input_secret);
        let scan_key = PublicKey::from_secret_key(&secp, &secret(6));
        let spend_key = PublicKey::from_secret_key(&secp, &secret(7));

        let input = input_with(p2tr_witness_utxo(input_pubkey), OutPoint::null());

        let mut psbt = empty_psbt(vec![input]);
        psbt.outputs = vec![sp_output(scan_key, spend_key)];

        set_global_share(&mut psbt, scan_key, input_secret);
        (psbt, scan_key)
    }

    fn receiver(scan: SecretKey, spend: SecretKey) -> SpReceiver {
        SpReceiver::new(scan, SpendKey::Secret(spend), Network::Regtest).unwrap()
    }

    fn receiver_discovers(
        psbt: &bwk_psbt::PsbtV2,
        receiver: &SpReceiver,
        eligible_pubkeys: &[PublicKey],
    ) -> bool {
        let (first, rest) = eligible_pubkeys.split_first().unwrap();
        let sum = rest
            .iter()
            .try_fold(*first, |sum, key| sum.combine(key))
            .unwrap();
        let outpoints = psbt
            .inputs
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>();
        let input_hash = calculate_input_hash(&outpoints, sum).unwrap();
        let tweak_data = sum.mul_tweak(&Secp256k1::new(), &input_hash).unwrap();
        let shared_secret = crate::core::receiving::calculate_ecdh_shared_secret(
            &tweak_data,
            &receiver.get_scan_key(),
        );
        let output_keys = psbt
            .outputs
            .iter()
            .filter_map(|output| output.script_pubkey.as_ref())
            .filter(|script| script.is_p2tr())
            .map(|script| bitcoin::XOnlyPublicKey::from_slice(&script.as_bytes()[2..]).unwrap())
            .collect::<Vec<_>>();
        !receiver
            .receiver
            .scan_transaction(shared_secret, &output_keys)
            .unwrap()
            .is_empty()
    }

    #[test]
    fn completes_missing_output_scripts() {
        let (mut psbt, _) = psbt();

        complete_output_scripts(&mut psbt).unwrap();

        assert!(psbt.outputs[0].script_pubkey.as_ref().unwrap().is_p2tr());
        assert_eq!(psbt.tx_modifiable.unwrap().bits(), 0);
    }

    #[test]
    fn completed_output_is_discoverable_by_the_receiver() {
        let secp = Secp256k1::new();
        let input_pubkey = PublicKey::from_secret_key(&secp, &even_secret(5));
        let (mut psbt, _) = psbt();
        let receiver = receiver(secret(6), secret(7));

        complete_output_scripts(&mut psbt).unwrap();

        assert!(receiver_discovers(&psbt, &receiver, &[input_pubkey]));
    }

    #[test]
    fn k_counter_follows_spend_key_order_within_a_scan_key() {
        let secp = Secp256k1::new();
        let input_secret = even_secret(5);
        let input_pubkey = PublicKey::from_secret_key(&secp, &input_secret);
        let scan_key = PublicKey::from_secret_key(&secp, &secret(6));

        let spend_a = (secret(7), PublicKey::from_secret_key(&secp, &secret(7)));
        let spend_b = (secret(8), PublicKey::from_secret_key(&secp, &secret(8)));
        let (first, second) = if spend_a.1 < spend_b.1 {
            (spend_a, spend_b)
        } else {
            (spend_b, spend_a)
        };

        let input = input_with(p2tr_witness_utxo(input_pubkey), OutPoint::null());
        let mut psbt = empty_psbt(vec![input]);
        // Added in the reverse of sorted order: index 0 carries the
        // higher-sorting spend key, index 1 the lower.
        psbt.outputs = vec![sp_output(scan_key, second.1), sp_output(scan_key, first.1)];
        let share = set_global_share(&mut psbt, scan_key, input_secret);

        complete_output_scripts(&mut psbt).unwrap();

        let computed_input_hash = input_hash(&psbt).unwrap();
        let shared = share.mul_tweak(&secp, &computed_input_hash).unwrap();
        let expected_script = |spend_key: PublicKey, k: u32| {
            let tweak = crate::core::utils::common::calculate_t_n(&shared, k).unwrap();
            let output_key =
                crate::core::utils::common::calculate_P_n(&spend_key, tweak.into()).unwrap();
            ScriptBuf::new_p2tr_tweaked(output_key.x_only_public_key().0.dangerous_assume_tweaked())
        };

        assert_eq!(
            psbt.outputs[1].script_pubkey.as_ref().unwrap(),
            &expected_script(first.1, 0)
        );
        assert_eq!(
            psbt.outputs[0].script_pubkey.as_ref().unwrap(),
            &expected_script(second.1, 1)
        );

        let receiver_first = receiver(secret(6), first.0);
        let mut receiver_second = receiver(secret(6), second.0);
        // `first` always lands on k=0 (it sorts first), so its own receiver
        // finds it immediately. `second` lands on k=1, and BIP352 scanning
        // never skips a gap on its own key alone; registering the label that
        // reconciles k=0's foreign output lets `second`'s receiver walk past
        // it and reach its own output at k=1.
        let label_offset = first.0.add_tweak(&Scalar::from(second.0.negate())).unwrap();
        receiver_second
            .receiver
            .add_label(crate::core::receiving::Label::from(Scalar::from(
                label_offset,
            )))
            .unwrap();
        assert!(receiver_discovers(&psbt, &receiver_first, &[input_pubkey]));
        assert!(receiver_discovers(&psbt, &receiver_second, &[input_pubkey]));
    }

    #[test]
    fn refuses_to_overwrite_a_conflicting_script() {
        let secp = Secp256k1::new();
        let other_key = PublicKey::from_secret_key(&secp, &even_secret(9));
        let (mut psbt, _) = psbt();
        psbt.outputs[0].script_pubkey = Some(ScriptBuf::new_p2tr_tweaked(
            other_key.x_only_public_key().0.dangerous_assume_tweaked(),
        ));

        let result = complete_output_scripts(&mut psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn accepts_a_matching_preset_script() {
        let (mut psbt, _) = psbt();
        complete_output_scripts(&mut psbt).unwrap();
        let script = psbt.outputs[0].script_pubkey.clone();
        psbt.tx_modifiable = None;

        let result = complete_output_scripts(&mut psbt);

        assert!(result.is_ok());
        assert_eq!(psbt.outputs[0].script_pubkey, script);
    }

    fn two_input_psbt_with_per_input_shares(
        scan_key: PublicKey,
        set_share_for_second_input: bool,
    ) -> (bwk_psbt::PsbtV2, PublicKey, PublicKey) {
        let secp = Secp256k1::new();
        let secret_a = even_secret(10);
        let secret_b = even_secret(11);
        let pubkey_a = PublicKey::from_secret_key(&secp, &secret_a);
        let pubkey_b = PublicKey::from_secret_key(&secp, &secret_b);
        let spend_key = PublicKey::from_secret_key(&secp, &secret(7));

        let mut psbt_input_a = p2tr_witness_utxo(pubkey_a);
        set_input_share(&mut psbt_input_a, scan_key, secret_a);

        let mut psbt_input_b = p2tr_witness_utxo(pubkey_b);
        if set_share_for_second_input {
            set_input_share(&mut psbt_input_b, scan_key, secret_b);
        }

        let input_a = input_with(psbt_input_a, OutPoint::null());
        let input_b = input_with(
            psbt_input_b,
            OutPoint {
                txid: bitcoin::Txid::from_byte_array([1; 32]),
                vout: 1,
            },
        );

        let mut psbt = empty_psbt(vec![input_a, input_b]);
        psbt.outputs = vec![sp_output(scan_key, spend_key)];

        (psbt, pubkey_a, pubkey_b)
    }

    #[test]
    fn sums_per_input_shares_when_no_global_share() {
        let secp = Secp256k1::new();
        let scan_key = PublicKey::from_secret_key(&secp, &secret(6));
        let (mut psbt, pubkey_a, pubkey_b) = two_input_psbt_with_per_input_shares(scan_key, true);

        complete_output_scripts(&mut psbt).unwrap();

        let receiver = receiver(secret(6), secret(7));
        assert!(receiver_discovers(&psbt, &receiver, &[pubkey_a, pubkey_b]));
    }

    #[test]
    fn rejects_missing_per_input_share() {
        let secp = Secp256k1::new();
        let scan_key = PublicKey::from_secret_key(&secp, &secret(6));
        let (mut psbt, _, _) = two_input_psbt_with_per_input_shares(scan_key, false);

        let result = complete_output_scripts(&mut psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn no_silent_payment_output_is_a_no_op() {
        let secp = Secp256k1::new();
        let key_a = PublicKey::from_secret_key(&secp, &even_secret(1));
        let input = input_with(p2tr_witness_utxo(key_a), OutPoint::null());
        let mut psbt = empty_psbt(vec![input]);
        let (xonly, _) = key_a.x_only_public_key();
        psbt.outputs = vec![bwk_psbt::Output {
            amount: Amount::from_sat(1_000),
            script_pubkey: Some(ScriptBuf::new_p2tr_tweaked(
                xonly.dangerous_assume_tweaked(),
            )),
            psbt: bitcoin::psbt::Output::default(),
        }];
        psbt.tx_modifiable =
            Some(bwk_psbt::TxModifiable::try_from(bwk_psbt::TxModifiable::INPUTS).unwrap());
        let before = psbt.tx_modifiable;

        complete_output_scripts(&mut psbt).unwrap();

        assert_eq!(psbt.tx_modifiable, before);
    }
}
