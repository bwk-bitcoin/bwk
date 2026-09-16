//! BIP375 helpers: stateless and key-free reasoning about a `PsbtV2`'s
//! inputs. This module holds no private key, coin store or account state; it
//! only answers questions about a PSBT, which is what lets the wallet verify
//! a signer's work without being able to do the signer's job.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{key::TapTweak, Script, ScriptBuf};

use crate::{
    account::AccountError,
    core::{
        dleq::{self, DleqProof},
        secp256k1::{constants::ONE, PublicKey, Scalar, Secp256k1, SecretKey},
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

/// The secp256k1 base point `G`. BIP375 fixes the DLEQ generator to `G`, so
/// this is the only place a `SecretKey` appears outside the test module, and
/// it is a public constant, not key material.
pub fn generator() -> PublicKey {
    let one = SecretKey::from_slice(&ONE).expect("one is a valid secret key");
    PublicKey::from_secret_key(&Secp256k1::new(), &one)
}

pub fn verify_proof(
    public: PublicKey,
    scan_key: PublicKey,
    share: PublicKey,
    proof: [u8; 64],
) -> Result<(), AccountError> {
    if dleq::verify_proof(
        public,
        scan_key,
        share,
        DleqProof::from(proof),
        generator(),
        None,
    ) {
        Ok(())
    } else {
        Err(AccountError::PsbtV2)
    }
}

/// Rejects a share with no matching proof, or a proof with no matching
/// share, at both the global and per-input scopes. An unpaired share is a
/// claim nobody backed; an unpaired proof is either a mistake or an attempt
/// to make the map counts look right.
pub fn validate_share_maps(psbt: &bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    let shares = bwk_psbt::sp::sp_global_ecdh_shares_v2(psbt).map_err(|_| AccountError::PsbtV2)?;
    let proofs = bwk_psbt::sp::sp_global_dleqs_v2(psbt).map_err(|_| AccountError::PsbtV2)?;
    for share in &shares {
        bwk_psbt::sp::sp_global_dleq_v2(psbt, share.scan_key)
            .map_err(|_| AccountError::PsbtV2)?
            .ok_or(AccountError::PsbtV2)?;
    }
    for proof in &proofs {
        bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, proof.scan_key)
            .map_err(|_| AccountError::PsbtV2)?
            .ok_or(AccountError::PsbtV2)?;
    }
    for input in &psbt.inputs {
        bwk_psbt::sp::sp_input_ecdh_shares(&input.psbt).map_err(|_| AccountError::PsbtV2)?;
        bwk_psbt::sp::sp_input_dleqs(&input.psbt).map_err(|_| AccountError::PsbtV2)?;
    }
    Ok(())
}

/// A share or proof on an input claims that input contributes to the sum, so
/// that input must be eligible and have a recoverable public key. A share on
/// an ineligible input is skipped, not fatal: a sender may attach shares
/// before knowing which inputs survive selection.
pub fn validate_input_share_pairs(psbt: &bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    for input in &psbt.inputs {
        let shares =
            bwk_psbt::sp::sp_input_ecdh_shares(&input.psbt).map_err(|_| AccountError::PsbtV2)?;
        let proofs = bwk_psbt::sp::sp_input_dleqs(&input.psbt).map_err(|_| AccountError::PsbtV2)?;
        if !shares.is_empty() || !proofs.is_empty() {
            if !eligible_input_script(input)? {
                continue;
            }
            if !input_script_pubkey(input)?.is_some_and(|script| script.is_p2tr())
                && input.psbt.bip32_derivation.is_empty()
            {
                return Err(AccountError::PsbtV2);
            }
            if eligible_input_pubkey(input)?.is_none() {
                return Err(AccountError::PsbtV2);
            }
        }
        for share in &shares {
            bwk_psbt::sp::sp_input_dleq(&input.psbt, share.scan_key)
                .map_err(|_| AccountError::PsbtV2)?
                .ok_or(AccountError::PsbtV2)?;
        }
        for proof in &proofs {
            bwk_psbt::sp::sp_input_ecdh_share(&input.psbt, proof.scan_key)
                .map_err(|_| AccountError::PsbtV2)?
                .ok_or(AccountError::PsbtV2)?;
        }
    }
    Ok(())
}

/// The global proof is over the sum of eligible input public keys, not any
/// single key: the global share is the sender's combined ECDH contribution
/// across every eligible input, so that is what the proof must attest to.
pub fn validate_global_share(
    psbt: &bwk_psbt::PsbtV2,
    scan_key: PublicKey,
) -> Result<(), AccountError> {
    let share = bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, scan_key)
        .map_err(|_| AccountError::PsbtV2)?
        .ok_or(AccountError::PsbtV2)?;
    let proof = bwk_psbt::sp::sp_global_dleq_v2(psbt, scan_key)
        .map_err(|_| AccountError::PsbtV2)?
        .ok_or(AccountError::PsbtV2)?;
    verify_proof(eligible_pubkey_sum(psbt)?, scan_key, share, proof)
}

pub fn validate_input_shares(
    psbt: &bwk_psbt::PsbtV2,
    scan_key: PublicKey,
) -> Result<(), AccountError> {
    for input in &psbt.inputs {
        let Some(pubkey) = eligible_input_pubkey(input)? else {
            continue;
        };
        let share = bwk_psbt::sp::sp_input_ecdh_share(&input.psbt, scan_key)
            .map_err(|_| AccountError::PsbtV2)?
            .ok_or(AccountError::PsbtV2)?;
        let proof = bwk_psbt::sp::sp_input_dleq(&input.psbt, scan_key)
            .map_err(|_| AccountError::PsbtV2)?
            .ok_or(AccountError::PsbtV2)?;
        verify_proof(pubkey, scan_key, share, proof)?;
    }
    Ok(())
}

/// A read-only validation of a half-built PSBT must not demand shares that
/// have not been supplied yet, so the per-input fallback only kicks in once
/// an output has actually been computed from them.
pub fn validate_scan_key(psbt: &bwk_psbt::PsbtV2, scan_key: PublicKey) -> Result<(), AccountError> {
    if bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, scan_key)
        .map_err(|_| AccountError::PsbtV2)?
        .is_some()
    {
        validate_global_share(psbt, scan_key)
    } else if has_computed_output(psbt, scan_key)? {
        validate_input_shares(psbt, scan_key)
    } else {
        Ok(())
    }
}

/// Completion is about to act on whatever shares exist, so unlike
/// `validate_scan_key` it always falls back to the per-input shares.
pub fn validate_scan_key_for_completion(
    psbt: &bwk_psbt::PsbtV2,
    scan_key: PublicKey,
) -> Result<(), AccountError> {
    if bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, scan_key)
        .map_err(|_| AccountError::PsbtV2)?
        .is_some()
    {
        validate_global_share(psbt, scan_key)
    } else {
        validate_input_shares(psbt, scan_key)
    }
}

pub fn has_computed_output(
    psbt: &bwk_psbt::PsbtV2,
    scan_key: PublicKey,
) -> Result<bool, AccountError> {
    psbt.outputs.iter().try_fold(false, |found, output| {
        let info = bwk_psbt::sp::sp_v0_output(&output.psbt).map_err(|_| AccountError::PsbtV2)?;
        Ok(found
            || info.is_some_and(|info| info.scan_key == scan_key) && output.script_pubkey.is_some())
    })
}

pub fn has_any_computed_output(psbt: &bwk_psbt::PsbtV2) -> Result<bool, AccountError> {
    psbt.outputs.iter().try_fold(false, |found, output| {
        let info = bwk_psbt::sp::sp_v0_output(&output.psbt).map_err(|_| AccountError::PsbtV2)?;
        Ok::<bool, AccountError>(found || (info.is_some() && output.script_pubkey.is_some()))
    })
}

pub fn has_any_share_for_scan_keys(
    psbt: &bwk_psbt::PsbtV2,
    scan_keys: &BTreeSet<PublicKey>,
) -> Result<bool, AccountError> {
    for scan_key in scan_keys {
        if bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, *scan_key)
            .map_err(|_| AccountError::PsbtV2)?
            .is_some()
        {
            return Ok(true);
        }
        for input in &psbt.inputs {
            if bwk_psbt::sp::sp_input_ecdh_share(&input.psbt, *scan_key)
                .map_err(|_| AccountError::PsbtV2)?
                .is_some()
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Recomputes every silent-payment script and rejects any mismatch with what
/// is already written. This is where a lying signer is caught: it can
/// publish a valid proof for a share and still write the wrong script.
/// `require_all` is `false`, since a group with no share yet and no computed
/// script is incomplete, not invalid.
pub fn validate_output_scripts(psbt: &bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    if !has_any_computed_output(psbt)? {
        return Ok(());
    }
    let input_hash = input_hash(psbt)?;
    for (index, script) in output_scripts(psbt, input_hash, false)? {
        if psbt.outputs[index]
            .script_pubkey
            .as_ref()
            .is_some_and(|actual| actual != &script)
        {
            return Err(AccountError::PsbtV2);
        }
    }
    Ok(())
}

pub fn validate(psbt: &bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    let scan_keys = scan_keys(psbt)?;
    if scan_keys.is_empty() {
        return Ok(());
    }
    validate_share_maps(psbt)?;
    validate_input_share_pairs(psbt)?;
    validate_input_eligibility(psbt, true)?;
    // A PSBT with no computed output and no share for any scan key is simply
    // an unstarted build, not an invalid one.
    if !has_any_computed_output(psbt)? && !has_any_share_for_scan_keys(psbt, &scan_keys)? {
        return Ok(());
    }
    for scan_key in scan_keys {
        validate_scan_key(psbt, scan_key)?;
    }
    validate_output_scripts(psbt)
}

/// Verifies a PSBT a signer just handed back. Runs on the returned bytes
/// alone: no coin store, no key material, no remembered outgoing PSBT, since
/// the account keeps none. `validate` alone is not enough here, since it
/// deliberately returns `Ok` on a half-built PSBT; a signer that returned the
/// PSBT untouched, with silent-payment outputs still lacking scripts, must
/// fail this check rather than pass it.
pub fn verify_signed(psbt: &bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    psbt.validate()
        .map_err(|_| AccountError::Bip375("psbt failed structural validation".to_string()))?;
    validate(psbt).map_err(|_| {
        AccountError::Bip375("output script or DLEQ proof validation failed".to_string())
    })?;

    let keys = scan_keys(psbt)?;
    if keys.is_empty() {
        return Ok(());
    }
    for output in &psbt.outputs {
        if bwk_psbt::sp::sp_v0_output(&output.psbt)
            .map_err(|_| AccountError::PsbtV2)?
            .is_some()
            && output.script_pubkey.is_none()
        {
            return Err(AccountError::Bip375("output missing script".to_string()));
        }
    }
    for scan_key in &keys {
        if !has_any_share_for_scan_keys(psbt, &BTreeSet::from([*scan_key]))? {
            return Err(AccountError::Bip375(
                "share missing for scan key".to_string(),
            ));
        }
    }
    if psbt.tx_modifiable != Some(bwk_psbt::TxModifiable::none()) {
        return Err(AccountError::Bip375("tx_modifiable not frozen".to_string()));
    }
    Ok(())
}

pub fn complete_output_scripts(psbt: &mut bwk_psbt::PsbtV2) -> Result<(), AccountError> {
    let scan_keys = scan_keys(psbt)?;
    if scan_keys.is_empty() {
        return Ok(());
    }
    validate_input_eligibility(psbt, true)?;
    validate_share_maps(psbt)?;
    validate_input_share_pairs(psbt)?;
    for scan_key in scan_keys {
        validate_scan_key_for_completion(psbt, scan_key)?;
    }
    let input_hash = input_hash(psbt)?;
    fill_output_scripts(psbt, input_hash)?;
    validate_output_scripts(psbt)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use bitcoin::{
        absolute,
        bip32::{DerivationPath, Fingerprint},
        hashes::Hash,
        key::TapTweak,
        psbt::PsbtSighashType,
        secp256k1::Secp256k1,
        transaction, Amount, Network, OutPoint, PublicKey as BitcoinPublicKey, ScriptBuf, Sequence,
        TapSighashType, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
    };
    use bwk_psbt::sp::{PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE};
    use secp256k1::{PublicKey, Scalar, SecretKey};

    use crate::{
        account::{
            bip375::{
                complete_output_scripts, eligible_input_pubkey, eligible_script, generator,
                input_hash, input_script_pubkey, validate, validate_input_eligibility,
                verify_signed, NUMS_H,
            },
            AccountError,
        },
        core::{dleq, utils::hash::calculate_input_hash},
        receiver::SpReceiver,
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
        let proof =
            dleq::generate_proof(input_secret, scan_key, [3; 32], generator(), None).unwrap();
        bwk_psbt::sp::set_sp_global_ecdh_share_v2(psbt, scan_key, share);
        bwk_psbt::sp::set_sp_global_dleq_v2(psbt, scan_key, *proof.as_bytes());
        share
    }

    fn set_input_share(input: &mut bitcoin::psbt::Input, scan_key: PublicKey, secret: SecretKey) {
        let share = scan_key
            .mul_tweak(&Secp256k1::new(), &Scalar::from(secret))
            .unwrap();
        let proof = dleq::generate_proof(secret, scan_key, [3; 32], generator(), None).unwrap();
        bwk_psbt::sp::set_sp_input_ecdh_share(input, scan_key, share);
        bwk_psbt::sp::set_sp_input_dleq(input, scan_key, *proof.as_bytes());
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

    fn receiver(scan: SecretKey, spend: PublicKey) -> SpReceiver {
        SpReceiver::new(scan, spend, Network::Regtest).unwrap()
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
        let receiver = receiver(secret(6), PublicKey::from_secret_key(&secp, &secret(7)));

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

        let receiver_first = receiver(secret(6), first.1);
        let mut receiver_second = receiver(secret(6), second.1);
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

    #[test]
    fn verify_signed_accepts_a_completed_psbt() {
        let (mut psbt, _) = psbt();
        complete_output_scripts(&mut psbt).unwrap();

        assert!(verify_signed(&psbt).is_ok());
    }

    #[test]
    fn verify_signed_rejects_an_untouched_psbt() {
        let (psbt, _) = psbt();

        let result = verify_signed(&psbt);

        assert!(result.is_err());
    }

    #[test]
    fn verify_signed_rejects_a_tampered_script() {
        let secp = Secp256k1::new();
        let other_key = PublicKey::from_secret_key(&secp, &even_secret(9));
        let (mut psbt, _) = psbt();
        complete_output_scripts(&mut psbt).unwrap();
        psbt.outputs[0].script_pubkey = Some(ScriptBuf::new_p2tr_tweaked(
            other_key.x_only_public_key().0.dangerous_assume_tweaked(),
        ));

        let result = verify_signed(&psbt);

        assert!(matches!(result, Err(AccountError::Bip375(_))));
    }

    #[test]
    fn verify_signed_rejects_a_bad_proof() {
        let (mut psbt, scan_key) = psbt();
        complete_output_scripts(&mut psbt).unwrap();
        let mut proof = bwk_psbt::sp::sp_global_dleq_v2(&psbt, scan_key)
            .unwrap()
            .unwrap();
        proof[0] ^= 0xff;
        bwk_psbt::sp::set_sp_global_dleq_v2(&mut psbt, scan_key, proof);

        let result = verify_signed(&psbt);

        assert!(result.is_err());
    }

    #[test]
    fn verify_signed_rejects_unfrozen_tx() {
        let (mut psbt, _) = psbt();
        complete_output_scripts(&mut psbt).unwrap();
        psbt.tx_modifiable = Some(bwk_psbt::TxModifiable::try_from(1).unwrap());

        let result = verify_signed(&psbt);

        assert!(result.is_err());
    }

    #[test]
    fn verify_signed_passes_non_sp_psbt() {
        let secp = Secp256k1::new();
        let input_pubkey = PublicKey::from_secret_key(&secp, &even_secret(5));
        let input = input_with(p2tr_witness_utxo(input_pubkey), OutPoint::null());
        let mut psbt = empty_psbt(vec![input]);
        psbt.outputs = vec![bwk_psbt::Output {
            amount: Amount::from_sat(1_000),
            script_pubkey: Some(ScriptBuf::new_op_return([])),
            psbt: bitcoin::psbt::Output::default(),
        }];

        assert!(verify_signed(&psbt).is_ok());
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

        let receiver = receiver(secret(6), PublicKey::from_secret_key(&secp, &secret(7)));
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

    fn remove_global(psbt: &mut bwk_psbt::PsbtV2, type_value: u8, scan_key: PublicKey) {
        psbt.unknown.remove(&bitcoin::psbt::raw::Key {
            type_value,
            key: scan_key.serialize().to_vec(),
        });
    }

    fn spending_tx(script_pubkey: ScriptBuf) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey,
            }],
        }
    }

    #[test]
    fn rejects_missing_global_dleq() {
        let (mut psbt, scan_key) = psbt();
        remove_global(&mut psbt, PSBT_GLOBAL_SP_DLEQ, scan_key);

        let result = complete_output_scripts(&mut psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_orphan_global_dleq() {
        let (mut psbt, scan_key) = psbt();
        remove_global(&mut psbt, PSBT_GLOBAL_SP_ECDH_SHARE, scan_key);

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_orphan_input_share() {
        let (mut psbt, scan_key) = psbt();
        remove_global(&mut psbt, PSBT_GLOBAL_SP_ECDH_SHARE, scan_key);
        remove_global(&mut psbt, PSBT_GLOBAL_SP_DLEQ, scan_key);
        let secp = Secp256k1::new();
        let share = scan_key
            .mul_tweak(&secp, &Scalar::from(even_secret(5)))
            .unwrap();
        bwk_psbt::sp::set_sp_input_ecdh_share(&mut psbt.inputs[0].psbt, scan_key, share);

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_orphan_input_dleq() {
        let (mut psbt, scan_key) = psbt();
        remove_global(&mut psbt, PSBT_GLOBAL_SP_ECDH_SHARE, scan_key);
        remove_global(&mut psbt, PSBT_GLOBAL_SP_DLEQ, scan_key);
        let proof =
            dleq::generate_proof(even_secret(5), scan_key, [3; 32], generator(), None).unwrap();
        bwk_psbt::sp::set_sp_input_dleq(&mut psbt.inputs[0].psbt, scan_key, *proof.as_bytes());

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_forged_global_share() {
        let secp = Secp256k1::new();
        let (mut psbt, scan_key) = psbt();
        let unrelated_secret = secret(42);
        let forged_share = scan_key
            .mul_tweak(&secp, &Scalar::from(unrelated_secret))
            .unwrap();
        bwk_psbt::sp::set_sp_global_ecdh_share_v2(&mut psbt, scan_key, forged_share);

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_tampered_output_script() {
        let secp = Secp256k1::new();
        let (mut psbt, _) = psbt();
        complete_output_scripts(&mut psbt).unwrap();
        let unrelated_key = PublicKey::from_secret_key(&secp, &even_secret(99));
        let (xonly, _) = unrelated_key.x_only_public_key();
        psbt.outputs[0].script_pubkey = Some(ScriptBuf::new_p2tr_tweaked(
            xonly.dangerous_assume_tweaked(),
        ));

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_non_taproot_input_with_unrelated_bip32_key() {
        let secp = Secp256k1::new();
        let input_secret = secret(10);
        let input_pubkey = PublicKey::from_secret_key(&secp, &input_secret);
        let scan_secret = secret(12);
        let scan_key = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend_secret = secret(13);
        let spend_key = PublicKey::from_secret_key(&secp, &spend_secret);
        let input_script =
            ScriptBuf::new_p2wpkh(&BitcoinPublicKey::new(input_pubkey).wpubkey_hash().unwrap());

        let build_psbt = |share_secret: SecretKey| {
            let share_pubkey = PublicKey::from_secret_key(&secp, &share_secret);
            let mut input_psbt = bitcoin::psbt::Input {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: input_script.clone(),
                }),
                ..Default::default()
            };
            input_psbt.bip32_derivation.insert(
                share_pubkey,
                (Fingerprint::default(), DerivationPath::default()),
            );
            set_input_share(&mut input_psbt, scan_key, share_secret);

            let mut psbt = empty_psbt(vec![input_with(input_psbt, OutPoint::null())]);
            psbt.outputs = vec![sp_output(scan_key, spend_key)];
            psbt
        };

        let mut unrelated = build_psbt(secret(11));
        assert!(matches!(
            eligible_input_pubkey(&unrelated.inputs[0]),
            Err(AccountError::PsbtV2)
        ));
        assert!(matches!(
            complete_output_scripts(&mut unrelated),
            Err(AccountError::PsbtV2)
        ));

        let mut matching = build_psbt(input_secret);
        assert_eq!(
            eligible_input_pubkey(&matching.inputs[0]).unwrap(),
            Some(input_pubkey)
        );
        complete_output_scripts(&mut matching).unwrap();
        validate(&matching).unwrap();

        let receiver = receiver(scan_secret, spend_key);
        assert!(receiver_discovers(&matching, &receiver, &[input_pubkey]));
    }

    #[test]
    fn rejects_initial_psbt_with_ineligible_input() {
        let (mut psbt, scan_key) = psbt();
        remove_global(&mut psbt, PSBT_GLOBAL_SP_ECDH_SHARE, scan_key);
        remove_global(&mut psbt, PSBT_GLOBAL_SP_DLEQ, scan_key);
        psbt.inputs[0]
            .psbt
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = segwit_v2_script();

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_segwit_v2_from_non_witness_utxo() {
        let (mut psbt, _) = psbt();
        psbt.inputs[0].psbt.witness_utxo = None;
        psbt.inputs[0].psbt.non_witness_utxo = Some(spending_tx(segwit_v2_script()));

        let result = validate(&psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_conflicting_witness_and_non_witness_utxo() {
        let (mut psbt, _) = psbt();
        let secp = Secp256k1::new();
        let real_pubkey = PublicKey::from_secret_key(&secp, &even_secret(8));
        let (xonly, _) = real_pubkey.x_only_public_key();
        let non_witness_utxo = spending_tx(ScriptBuf::new_p2tr_tweaked(
            xonly.dangerous_assume_tweaked(),
        ));
        psbt.inputs[0].previous_output = OutPoint {
            txid: non_witness_utxo.compute_txid(),
            vout: 0,
        };
        psbt.inputs[0].psbt.non_witness_utxo = Some(non_witness_utxo);
        let receiver = receiver(secret(6), PublicKey::from_secret_key(&secp, &secret(7)));

        let result = complete_output_scripts(&mut psbt);
        if result.is_ok() {
            assert!(!receiver_discovers(&psbt, &receiver, &[real_pubkey]));
        }
        assert!(
            matches!(result, Err(AccountError::PsbtV2)),
            "completion returned {result:?}"
        );
    }

    #[test]
    fn rejects_uncommitted_p2sh_redeem_script() {
        let (mut psbt, _) = psbt();
        let secp = Secp256k1::new();
        let input_pubkey = PublicKey::from_secret_key(&secp, &secret(8));
        let bitcoin_pubkey = BitcoinPublicKey::new(input_pubkey);
        let real_redeem_script = bitcoin_pubkey
            .wpubkey_hash()
            .map(|hash| ScriptBuf::new_p2wpkh(&hash))
            .unwrap();
        let script_pubkey = ScriptBuf::new_p2sh(&real_redeem_script.script_hash());
        let unrelated_pubkey = BitcoinPublicKey::new(PublicKey::from_secret_key(&secp, &secret(9)));
        let mut input_psbt = bitcoin::psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey,
            }),
            redeem_script: Some(ScriptBuf::new_p2pkh(&unrelated_pubkey.pubkey_hash())),
            ..Default::default()
        };
        input_psbt.bip32_derivation.insert(
            input_pubkey,
            (Fingerprint::default(), DerivationPath::default()),
        );
        psbt.inputs.push(input_with(
            input_psbt,
            OutPoint {
                txid: Txid::from_byte_array([15; 32]),
                vout: 0,
            },
        ));

        let result = complete_output_scripts(&mut psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn rejects_uncommitted_taproot_nums_internal_key() {
        let (mut psbt, _) = psbt();
        let secp = Secp256k1::new();
        let input_pubkey = PublicKey::from_secret_key(&secp, &even_secret(8));
        let mut input_psbt = p2tr_witness_utxo(input_pubkey);
        input_psbt.tap_internal_key = Some(XOnlyPublicKey::from_slice(&NUMS_H).unwrap());
        psbt.inputs.push(input_with(
            input_psbt,
            OutPoint {
                txid: Txid::from_byte_array([16; 32]),
                vout: 0,
            },
        ));

        let result = complete_output_scripts(&mut psbt);

        assert!(matches!(result, Err(AccountError::PsbtV2)));
    }

    #[test]
    fn excludes_committed_taproot_nums_input() {
        let (mut psbt, _) = psbt();
        let nums = PublicKey::from_slice(&{
            let mut bytes = [0u8; 33];
            bytes[0] = 0x02;
            bytes[1..].copy_from_slice(&NUMS_H);
            bytes
        })
        .unwrap();
        let mut input_psbt = p2tr_witness_utxo(nums);
        input_psbt.tap_internal_key = Some(nums.x_only_public_key().0);
        psbt.inputs.push(input_with(
            input_psbt,
            OutPoint {
                txid: Txid::from_byte_array([17; 32]),
                vout: 0,
            },
        ));

        assert!(matches!(eligible_input_pubkey(&psbt.inputs[1]), Ok(None)));
        complete_output_scripts(&mut psbt).unwrap();
        validate(&psbt).unwrap();
    }

    #[test]
    fn p2tr_eligible_key_comes_from_script() {
        let (mut psbt, _) = psbt();
        let secp = Secp256k1::new();
        let wrong = PublicKey::from_secret_key(&secp, &secret(9));
        psbt.inputs[0]
            .psbt
            .bip32_derivation
            .insert(wrong, (Fingerprint::default(), DerivationPath::default()));

        complete_output_scripts(&mut psbt).unwrap();
        validate(&psbt).unwrap();
    }

    #[test]
    fn bip375_vectors() {
        const VALID: &[&str] = &[
            "cHNidP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEBAQYBAAABDiBSJ0jrF3ZNKMpJSBXsjUnn0w1SvHNCLHyG63TjlwVylAEPBAAAAAABAFUCAAAAAfTCEtWu0ef2/2M/LOCcZHxXvt2TAxTZjed1A9WOlAszAAAAAAD/////AaCGAQAAAAAAGXapFB4q14ctMpQTpW3wlovjOCIngxY7iKwAAAAAIgICyBe7dSGvw16pbzv7Jw5utQ3f+lVgYnuWH+wA8pllCL9HMEQCIDnBDcvHz0XG2UNW/1DBK42GqVUM8DcXPZzr94cU5nx1AiBxlVpC7SBTJDIHI8TwFCXc6J9CX4NwKEy0J2z9tt6jrAEBAwQBAAAAIgYCyBe7dSGvw16pbzv7Jw5utQ3f+lVgYnuWH+wA8pllCL8IAAAAgAAAAAABEAT+////Ih0Cekh/wZ+3aYd7h0LW6hgRjzxOcrHqjG3mAqetSkHb4GghA+yk/xG3KOLg9gzmIilDpv9VudlfYnv5qZ0IS8hy1QpbIh4Cekh/wZ+3aYd7h0LW6hgRjzxOcrHqjG3mAqetSkHb4GhAihOzmFVF9yvW6JcUrrkJs+NUqEKpu4tWzQ7e0h34oZlZizEiikngvX6VzhBT98WyistUOmhwdgDjzomCLuMgIQABAwgYcwEAAAAAAAEEIlEg4UDSh7RbRs1OqvpDdwYVcLq+g9G4vJUKdKn+oJIz16YBCUICekh/wZ+3aYd7h0LW6hgRjzxOcrHqjG3mAqetSkHb4GgDYeGx6d5eQssgB/fKVLng1X7ROTj61W0/GeV1E6j84DkA",
        ];
        const INVALID: &[&str] = &[
            "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",
        ];

        for vector in VALID {
            let bytes = Base64::decode_vec(vector).unwrap();
            let psbt = bwk_psbt::PsbtV2::deserialize(&bytes).unwrap();
            validate(&psbt).unwrap();
        }
        for vector in INVALID {
            let bytes = Base64::decode_vec(vector).unwrap();
            let invalid = bwk_psbt::PsbtV2::deserialize(&bytes)
                .map_err(|_| ())
                .and_then(|psbt| validate(&psbt).map_err(|_| ()))
                .is_err();
            assert!(invalid);
        }
    }
}
