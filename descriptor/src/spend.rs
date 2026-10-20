//! Transaction-independent spending requirements. No signer/device discovery is used.

use std::fmt;

use bwk_keys::nums;
#[cfg(feature = "musig")]
use bwk_psbt::musig::{PSBT_IN_MUSIG2_PARTIAL_SIG, PSBT_IN_MUSIG2_PUB_NONCE};
use miniscript::{
    bitcoin::{
        absolute,
        hashes::{hash160, ripemd160, sha256, Hash},
        relative, BlockHash, Sequence, Transaction,
    },
    descriptor::{ShInner, SinglePubKey, Wsh, WshInner},
    hash256,
    policy::{semantic::Policy, Liftable},
    Descriptor, DescriptorPublicKey, Miniscript, ScriptContext, Tap, Terminal,
};

#[cfg(not(feature = "musig"))]
use crate::wallet::WalletKeyExt;
use crate::wallet::{WalletDefiniteKey, WalletDescriptor, WalletDescriptorExt, WalletKey};

/// Witness count, signature length and a 65-byte non-default-sighash signature.
const KEY_SATISFACTION_WU: u64 = 67;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("descriptor: {0}")]
    Descriptor(String),
    #[error("incompatible locktime units")]
    IncompatibleLocks,
    #[error("unknown spending variant")]
    UnknownVariant,
    #[error("invalid input index")]
    InputIndex,
    #[error("transaction does not meet spending requirements")]
    TransactionLocks,
    #[error("confirmation is above the supplied tip")]
    ConfirmationAboveTip,
    #[error("input prevout or script does not match the descriptor")]
    InputMismatch,
    #[error("path selection must precede signing")]
    AlreadySigned,
}

/// Stable within the original, underived descriptor, not a derived tapleaf hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Path {
    Key,
    Leaf(usize),
    Script,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId {
    pub policy: sha256::Hash,
    pub path: Path,
    pub alternative: usize,
}

impl fmt::Display for PathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:?}:{}", self.policy, self.path, self.alternative)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preimage {
    Sha256(sha256::Hash),
    Hash256(hash256::Hash),
    Ripemd160(ripemd160::Hash),
    Hash160(hash160::Hash),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Locks {
    pub absolute: Option<absolute::LockTime>,
    pub relative: Option<relative::LockTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    Mature,
    Immature,
    Unknown,
}

impl Maturity {
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Immature, _) | (_, Self::Immature) => Self::Immature,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Mature,
        }
    }

    fn from_met(met: bool) -> Self {
        if met {
            Self::Mature
        } else {
            Self::Immature
        }
    }
}

/// The confirmation must belong to `ChainContext::tip`, not an earlier snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    Unknown,
    Unconfirmed,
    Confirmed {
        height: u32,
        /// BIP68 uses the MTP of the block BEFORE the confirmation block.
        previous_mtp: Option<u32>,
    },
}

/// A coherent chain snapshot, supplied again after every reorg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainContext {
    pub tip: BlockHash,
    pub height: u32,
    /// BIP113 uses tip MTP, not wall-clock time or the next block's timestamp.
    pub median_time_past: Option<u32>,
    pub confirmation: Confirmation,
}

impl Locks {
    pub fn merge(self, other: Self) -> Result<Self, Error> {
        let absolute = match (self.absolute, other.absolute) {
            (Some(a), Some(b)) if a.is_same_unit(b) => {
                Some(if a.to_consensus_u32() >= b.to_consensus_u32() {
                    a
                } else {
                    b
                })
            }
            (Some(_), Some(_)) => return Err(Error::IncompatibleLocks),
            (a, b) => a.or(b),
        };
        let relative = match (self.relative, other.relative) {
            (Some(a), Some(b)) if a.is_same_unit(b) => {
                Some(if a.to_consensus_u32() >= b.to_consensus_u32() {
                    a
                } else {
                    b
                })
            }
            (Some(_), Some(_)) => return Err(Error::IncompatibleLocks),
            (a, b) => a.or(b),
        };
        Ok(Self { absolute, relative })
    }

    /// Timelock eligibility for the block after the supplied tip. This does not
    /// assert that the coin is unspent, coinbase-mature, or that signers are online.
    pub fn maturity(self, context: Option<&ChainContext>) -> Result<Maturity, Error> {
        let Some(context) = context else {
            return Ok(if self == Self::default() {
                Maturity::Mature
            } else {
                Maturity::Unknown
            });
        };
        if let Confirmation::Confirmed { height, .. } = context.confirmation {
            if height > context.height {
                return Err(Error::ConfirmationAboveTip);
            }
        }
        let absolute = match self.absolute {
            None => Maturity::Mature,
            Some(absolute::LockTime::Blocks(height)) => {
                Maturity::from_met(context.height >= height.to_consensus_u32())
            }
            Some(absolute::LockTime::Seconds(time)) => {
                context.median_time_past.map_or(Maturity::Unknown, |mtp| {
                    Maturity::from_met(mtp > time.to_consensus_u32())
                })
            }
        };
        Ok(absolute.and(self.relative_maturity(context)))
    }

    fn relative_maturity(self, context: &ChainContext) -> Maturity {
        let Some(lock) = self.relative else {
            return Maturity::Mature;
        };
        let (height, previous_mtp) = match context.confirmation {
            Confirmation::Unknown => return Maturity::Unknown,
            // Unconfirmed inputs are treated as confirmed in the candidate block.
            Confirmation::Unconfirmed => (u64::from(context.height) + 1, context.median_time_past),
            Confirmation::Confirmed {
                height,
                previous_mtp,
            } => (u64::from(height), previous_mtp),
        };
        match lock {
            relative::LockTime::Blocks(blocks) => Maturity::from_met(
                u64::from(context.height) + 1 >= height + u64::from(blocks.value()),
            ),
            relative::LockTime::Time(time) => match (context.median_time_past, previous_mtp) {
                (Some(tip), Some(previous)) => Maturity::from_met(
                    u64::from(tip) >= u64::from(previous) + (u64::from(time.value()) << 9),
                ),
                _ => Maturity::Unknown,
            },
        }
    }

    /// Validate one input independently. Different inputs may use different CSV
    /// units; their CLTV requirements must all agree with the transaction locktime.
    pub fn validate_transaction(self, tx: &Transaction, input: usize) -> Result<(), Error> {
        let input = tx.input.get(input).ok_or(Error::InputIndex)?;
        if let Some(lock) = self.absolute {
            if input.sequence.is_final()
                || !lock.is_same_unit(tx.lock_time)
                || tx.lock_time.to_consensus_u32() < lock.to_consensus_u32()
            {
                return Err(Error::TransactionLocks);
            }
        }
        if let Some(lock) = self.relative {
            let sequence = input
                .sequence
                .to_relative_lock_time()
                .ok_or(Error::TransactionLocks)?;
            if tx.version.0 < 2
                || !lock.is_same_unit(sequence)
                || sequence.to_consensus_u32() < lock.to_consensus_u32()
            {
                return Err(Error::TransactionLocks);
            }
        }
        Ok(())
    }

    /// Apply constraints before signing. Refuses conflicting existing CLTV units;
    /// updates only the selected input's sequence and transaction-wide locks.
    pub fn apply(self, tx: &mut Transaction, input: usize) -> Result<(), Error> {
        let current = tx.input.get(input).ok_or(Error::InputIndex)?.sequence;
        let absolute = Locks {
            absolute: (tx.lock_time != absolute::LockTime::ZERO).then_some(tx.lock_time),
            relative: None,
        }
        .merge(Locks {
            absolute: self.absolute,
            relative: None,
        })?
        .absolute;
        let sequence = match self.relative {
            Some(lock) => {
                let merged = Locks {
                    absolute: None,
                    relative: current.to_relative_lock_time(),
                }
                .merge(Locks {
                    absolute: None,
                    relative: Some(lock),
                })?;
                Sequence::from_consensus(
                    merged
                        .relative
                        .ok_or(Error::TransactionLocks)?
                        .to_consensus_u32(),
                )
            }
            None if self.absolute.is_some() && current.is_final() => {
                Sequence::ENABLE_LOCKTIME_NO_RBF
            }
            None => current,
        };
        if self.relative.is_some() && tx.version.0 < 2 {
            tx.version = miniscript::bitcoin::transaction::Version::TWO;
        }
        if let Some(lock) = absolute {
            tx.lock_time = lock;
        }
        tx.input[input].sequence = sequence;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requirements {
    /// Each WalletKey is required. A MuSig key requires every aggregate participant.
    /// Keys retain origins and derivation expressions, not just fingerprints.
    pub keys: Vec<WalletKey>,
    pub preimages: Vec<Preimage>,
    pub locks: Locks,
}

impl Requirements {
    fn merge(&self, other: &Self) -> Result<Self, Error> {
        let mut result = self.clone();
        result.locks = result.locks.merge(other.locks)?;
        for key in &other.keys {
            if !result.keys.contains(key) {
                result.keys.push(key.clone());
            }
        }
        for preimage in &other.preimages {
            if !result.preimages.contains(preimage) {
                result.preimages.push(preimage.clone());
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendVariant {
    pub id: PathId,
    pub requirements: Requirements,
    /// Conservative added weight in WU over an input with empty scriptSig and
    /// empty witness, plus one WU for the witness count. Includes scripts and
    /// control block, excludes base input, transaction marker/flag and outputs.
    /// This is the maximum for the selected leaf/script, NOT a minimum for the
    /// alternative. Signatures may include a non-default sighash byte; no annex.
    pub satisfaction_wu: u64,
}

/// Full underived policy context for hardware registration and stable path IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendVariants {
    pub descriptor: WalletDescriptor,
    pub variants: Vec<SpendVariant>,
}

/// Restrict one PSBT input without touching any other input's scripts or origins.
/// The PSBT must be unsigned and populated by the descriptor/coin input exporter.
/// A leaf restriction does not enforce a particular satisfaction within that leaf:
/// the coordinator must retain `id` and use its requirements when signing/finalizing.
#[cfg(feature = "musig")]
pub fn restrict_variant(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
    id: &PathId,
    psbt: &mut miniscript::bitcoin::Psbt,
    input_index: usize,
) -> Result<(), Error> {
    let exported = spend_variants(descriptor, keychain, index)?;
    let variant = exported
        .variants
        .iter()
        .find(|variant| &variant.id == id)
        .ok_or(Error::UnknownVariant)?;
    ensure_unsigned(psbt)?;
    let paths = descriptor
        .single_paths()
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    let definite = paths
        .get(keychain)
        .ok_or(Error::UnknownVariant)?
        .derive_at(index)
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    let input = psbt.inputs.get(input_index).ok_or(Error::InputIndex)?;
    validate_prevout(psbt, input_index, &definite.script_pubkey())?;
    let mut tx = psbt.unsigned_tx.clone();
    variant.requirements.locks.apply(&mut tx, input_index)?;
    let mut input = input.clone();
    match (&definite, id.path) {
        (Descriptor::Tr(tr), Path::Key) => {
            crate::restrict::restrict_input_to_key_path(&mut input, tr)
        }
        (Descriptor::Tr(tr), Path::Leaf(position)) => {
            let (_, ms) = tr
                .iter_scripts()
                .nth(position)
                .ok_or(Error::UnknownVariant)?;
            if !input.tap_scripts.values().any(|(script, version)| {
                script == &ms.encode()
                    && *version == miniscript::bitcoin::taproot::LeafVersion::TapScript
            }) {
                return Err(Error::InputMismatch);
            }
            crate::restrict::restrict_input_to_leaf(&mut input, ms);
        }
        (_, Path::Script) => {}
        _ => return Err(Error::UnknownVariant),
    }
    psbt.unsigned_tx = tx;
    psbt.inputs[input_index] = input;
    Ok(())
}

#[cfg(feature = "musig")]
fn ensure_unsigned(psbt: &miniscript::bitcoin::Psbt) -> Result<(), Error> {
    if psbt.inputs.iter().any(|input| {
        !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
            || input.unknown.keys().any(|key| {
                matches!(
                    key.type_value,
                    PSBT_IN_MUSIG2_PUB_NONCE | PSBT_IN_MUSIG2_PARTIAL_SIG
                )
            })
    }) {
        return Err(Error::AlreadySigned);
    }
    Ok(())
}

#[cfg(feature = "musig")]
fn validate_prevout(
    psbt: &miniscript::bitcoin::Psbt,
    input_index: usize,
    script: &miniscript::bitcoin::Script,
) -> Result<(), Error> {
    let input = psbt.inputs.get(input_index).ok_or(Error::InputIndex)?;
    let txin = psbt
        .unsigned_tx
        .input
        .get(input_index)
        .ok_or(Error::InputIndex)?;
    let prevout = input
        .witness_utxo
        .as_ref()
        .or_else(|| {
            input
                .non_witness_utxo
                .as_ref()
                .filter(|tx| tx.compute_txid() == txin.previous_output.txid)
                .and_then(|tx| tx.output.get(txin.previous_output.vout as usize))
        })
        .ok_or(Error::InputMismatch)?;
    if prevout.script_pubkey.as_script() != script {
        return Err(Error::InputMismatch);
    }
    Ok(())
}

/// Export every logical satisfaction without inspecting devices or coin maturity.
/// Hash preimages are requirements, never assumed available. Impossible NUMS
/// signatures are excluded. Unliftable Miniscript returns an explicit error.
pub fn spend_variants(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
) -> Result<SpendVariants, Error> {
    let single = descriptor
        .single_paths()
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    let definite = single
        .get(keychain)
        .ok_or(Error::UnknownVariant)?
        .derive_at(index)
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    let policy_text =
        crate::descriptor::Descriptor::from(descriptor.clone()).to_string_no_checksum();
    let policy = sha256::Hash::hash(policy_text.as_bytes());
    let mut variants = Vec::new();
    match (descriptor, &definite) {
        (Descriptor::Tr(template), Descriptor::Tr(derived)) => {
            append_requirements(
                &mut variants,
                policy,
                Path::Key,
                alternatives(&Policy::Key(template.internal_key().clone()))?,
                KEY_SATISFACTION_WU,
            );
            for (position, ((_, template), (depth, derived))) in template
                .iter_scripts()
                .zip(derived.iter_scripts())
                .enumerate()
            {
                let requirements = script_alternatives(template)?;
                if requirements.is_empty() {
                    continue;
                }
                append_requirements(
                    &mut variants,
                    policy,
                    Path::Leaf(position),
                    requirements,
                    leaf_satisfaction_wu(derived, depth)?,
                );
            }
        }
        _ => {
            let weight = definite
                .max_weight_to_satisfy()
                .map_err(|e| Error::Descriptor(e.to_string()))?
                .to_wu()
                + 1;
            append_requirements(
                &mut variants,
                policy,
                Path::Script,
                descriptor_alternatives(descriptor)?,
                weight,
            );
        }
    }
    Ok(SpendVariants {
        descriptor: descriptor.clone(),
        variants,
    })
}

fn leaf_satisfaction_wu(ms: &Miniscript<WalletDefiniteKey, Tap>, depth: u8) -> Result<u64, Error> {
    let script = ms.script_size();
    let elements = ms
        .max_satisfaction_witness_elements()
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    let satisfaction = ms
        .max_satisfaction_size()
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    let control = miniscript::bitcoin::taproot::TAPROOT_CONTROL_BASE_SIZE
        + miniscript::bitcoin::taproot::TAPROOT_CONTROL_NODE_SIZE * usize::from(depth);
    Ok((miniscript::bitcoin::VarInt((elements + 1) as u64).size()
        + satisfaction
        + miniscript::bitcoin::VarInt(script as u64).size()
        + script
        + miniscript::bitcoin::VarInt(control as u64).size()
        + control) as u64)
}

fn append_requirements(
    variants: &mut Vec<SpendVariant>,
    policy: sha256::Hash,
    path: Path,
    requirements: Vec<Requirements>,
    weight: u64,
) {
    variants.extend(
        requirements
            .into_iter()
            .enumerate()
            .map(|(alternative, requirements)| SpendVariant {
                id: PathId {
                    policy,
                    path,
                    alternative,
                },
                requirements,
                satisfaction_wu: weight,
            }),
    );
}

fn is_nums(key: &WalletKey) -> bool {
    key.plain_keys().iter().any(|key| match key {
        DescriptorPublicKey::Single(key) => match key.key {
            SinglePubKey::FullKey(key) => nums::is_nums(&key.inner),
            SinglePubKey::XOnly(key) => nums::is_nums_x_only(&key),
        },
        DescriptorPublicKey::XPub(key) => nums::is_nums(&key.xkey.public_key),
        DescriptorPublicKey::MultiXPub(key) => nums::is_nums(&key.xkey.public_key),
    })
}

fn descriptor_alternatives(descriptor: &WalletDescriptor) -> Result<Vec<Requirements>, Error> {
    match descriptor {
        Descriptor::Bare(bare) => script_alternatives(bare.as_inner()),
        Descriptor::Wsh(wsh) => wsh_alternatives(wsh),
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Ms(ms) => script_alternatives(ms),
            ShInner::Wsh(wsh) => wsh_alternatives(wsh),
            _ => alternatives(
                &descriptor
                    .lift()
                    .map_err(|e| Error::Descriptor(e.to_string()))?,
            ),
        },
        _ => alternatives(
            &descriptor
                .lift()
                .map_err(|e| Error::Descriptor(e.to_string()))?,
        ),
    }
}

fn wsh_alternatives(wsh: &Wsh<WalletKey>) -> Result<Vec<Requirements>, Error> {
    match wsh.as_inner() {
        WshInner::Ms(ms) => script_alternatives(ms),
        WshInner::SortedMulti(multi) => threshold_alternatives(
            multi.k(),
            multi
                .pks()
                .iter()
                .map(|key| alternatives(&Policy::Key(key.clone()))),
        ),
    }
}

/// Policy lifting normalizes away dominated lock alternatives. Traverse script
/// branches instead so the export retains those distinct satisfaction choices.
fn script_alternatives<C: ScriptContext>(
    ms: &Miniscript<WalletKey, C>,
) -> Result<Vec<Requirements>, Error> {
    ms.lift_check()
        .map_err(|e| Error::Descriptor(e.to_string()))?;
    match &ms.node {
        Terminal::Alt(child)
        | Terminal::Swap(child)
        | Terminal::Check(child)
        | Terminal::DupIf(child)
        | Terminal::Verify(child)
        | Terminal::NonZero(child)
        | Terminal::ZeroNotEqual(child) => script_alternatives(child),
        Terminal::AndV(a, b) | Terminal::AndB(a, b) => {
            threshold_alternatives(2, [script_alternatives(a), script_alternatives(b)])
        }
        Terminal::OrB(a, b) | Terminal::OrD(a, b) | Terminal::OrC(a, b) | Terminal::OrI(a, b) => {
            threshold_alternatives(1, [script_alternatives(a), script_alternatives(b)])
        }
        Terminal::AndOr(a, b, c) => threshold_alternatives(
            1,
            [
                threshold_alternatives(2, [script_alternatives(a), script_alternatives(b)]),
                script_alternatives(c),
            ],
        ),
        Terminal::Thresh(threshold) => threshold_alternatives(
            threshold.k(),
            threshold.iter().map(|child| script_alternatives(child)),
        ),
        _ => alternatives(
            &ms.node
                .lift()
                .map_err(|e| Error::Descriptor(e.to_string()))?,
        ),
    }
}

fn threshold_alternatives(
    required: usize,
    children: impl IntoIterator<Item = Result<Vec<Requirements>, Error>>,
) -> Result<Vec<Requirements>, Error> {
    let mut choices = vec![Vec::new(); required + 1];
    choices[0].push(Requirements::default());
    for child in children {
        let child = child?;
        for count in (1..=required).rev() {
            let mut combined = Vec::new();
            for previous in &choices[count - 1] {
                for next in &child {
                    match previous.merge(next) {
                        Ok(requirement) => combined.push(requirement),
                        Err(Error::IncompatibleLocks) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            choices[count].extend(combined);
        }
    }
    Ok(choices.remove(required))
}

fn alternatives(policy: &Policy<WalletKey>) -> Result<Vec<Requirements>, Error> {
    let mut requirement = Requirements::default();
    match policy {
        Policy::Unsatisfiable => return Ok(Vec::new()),
        Policy::Trivial => {}
        Policy::Key(key) if is_nums(key) => return Ok(Vec::new()),
        Policy::Key(key) => requirement.keys.push(key.clone()),
        Policy::After(lock) => requirement.locks.absolute = Some((*lock).into()),
        Policy::Older(lock) => requirement.locks.relative = Some((*lock).into()),
        Policy::Sha256(hash) => requirement.preimages.push(Preimage::Sha256(*hash)),
        Policy::Hash256(hash) => requirement.preimages.push(Preimage::Hash256(*hash)),
        Policy::Ripemd160(hash) => requirement.preimages.push(Preimage::Ripemd160(*hash)),
        Policy::Hash160(hash) => requirement.preimages.push(Preimage::Hash160(*hash)),
        Policy::Thresh(threshold) => {
            return threshold_alternatives(
                threshold.k(),
                threshold.iter().map(|child| alternatives(child)),
            );
        }
    }
    Ok(vec![requirement])
}

#[cfg(test)]
mod tests;
