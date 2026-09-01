use miniscript::bitcoin::{self, absolute, Network, Psbt, TxOut, Weight};
use serde::{Deserialize, Serialize};

use bwk_coin::{shuffle_coins, Coin, CoinSource};

use crate::{
    coin_selection::CoinSelector,
    recipient::{FinalizationContext, PsbtOutputInfo, RecipientProvider, SpPartialSecretProvider},
    DUST_AMOUNT,
};

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum Error {
    #[error("failed to satisfy an input")]
    Satisfaction,
    #[error("fee is zero")]
    FeesNull,
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("only one output can drain the wallet")]
    SingleMax,
    #[error("address network mismatch")]
    AddressNetwork,
    #[error("failed to add an input")]
    AddInput,
    #[error("not enough funds to pay the fee")]
    NotEnoughForFee,
    #[error("derivator error")]
    Derivator,
    #[error("descriptor error")]
    Descriptor,
    #[error("invalid input")]
    Input,
    #[error("invalid output")]
    Output,
    #[error("coin selection failed")]
    CoinSelection,
    #[error("coin selection failed to cover the fee")]
    CoinSelectionFee,
    // Auto coin selection was requested (no inputs + a selector supplied) but
    // the fee is absolute (`Fees::Sats`); selection needs a per-vB feerate.
    #[error("auto coin selection requires a per-vB feerate")]
    CoinSelectionRequiresFeerate,
    #[error("no silent payment provider")]
    NoSpProvider,
    #[error("failed to compute silent payment partial secret")]
    SpPartialSecret,
    #[error("change output already added")]
    ChangeAlreadyAdded,
    #[error("pay to anchor is not supported")]
    PayToAnchor,
    #[error("recipient passed as change is not a change output")]
    NotChange,
    #[error("missing change output, {excess} sats would be lost to fees")]
    MissingChange { excess: u64 },
    #[error(
        "disproportionate fee: {fee} sats for {paid_outputs} sats of outputs \
         exceeds both {max_percent}% and {max_amount} sats"
    )]
    DisproportionateFees {
        fee: u64,
        paid_outputs: u64,
        max_percent: u8,
        max_amount: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Warning {
    ChangeUnderDust(u64),
    MaxUnderDust(u64),
    ChangeCreateDust(u64),
    MaxCreateDust(u64),
    DisproportionateFees { fee: u64, paid_outputs: u64 },
}

impl Error {
    pub fn to_warning(&self) -> Option<Warning> {
        match self {
            Error::DisproportionateFees {
                fee, paid_outputs, ..
            } => Some(Warning::DisproportionateFees {
                fee: *fee,
                paid_outputs: *paid_outputs,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Fees {
    Sats(u64),
    MilliSatsVb(u64),
}

impl Fees {
    pub fn is_null(&self) -> bool {
        match self {
            Fees::Sats(f) => *f == 0,
            Fees::MilliSatsVb(f) => *f == 0,
        }
    }
}

pub struct TxTemplate {
    pub inputs: Vec<Coin>,
    pub outputs: Vec<Box<dyn RecipientProvider>>,
    pub fees: Fees,
}

impl Clone for TxTemplate {
    fn clone(&self) -> Self {
        Self {
            inputs: self.inputs.clone(),
            outputs: self.outputs.iter().map(|o| o.clone_box()).collect(),
            fees: self.fees.clone(),
        }
    }
}

impl std::fmt::Debug for TxTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxTemplate")
            .field("inputs", &self.inputs)
            .field("outputs", &format!("[{} outputs]", self.outputs.len()))
            .field("fees", &self.fees)
            .finish()
    }
}

impl TxTemplate {
    /// Build an unsigned transaction for weight estimation.
    /// For SP outputs, uses a dummy P2TR script of correct size.
    /// For actual signing, use finalize().
    pub fn tx(&mut self) -> bitcoin::Transaction {
        use bitcoin::XOnlyPublicKey;

        let input = self.inputs.iter().cloned().map(Into::into).collect();
        let output = self
            .outputs
            .iter_mut()
            .map(|r| {
                let value = match r.amount() {
                    Amount::Value(v) => bitcoin::Amount::from_sat(v),
                    Amount::Max(Some(v)) => bitcoin::Amount::from_sat(v),
                    Amount::Max(None) => bitcoin::Amount::MAX_MONEY,
                    Amount::Anchor => bitcoin::Amount::ZERO,
                };
                let script = if r.is_silent_payment() {
                    // Dummy P2TR script for weight estimation (correct size)
                    let dummy_key = XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap();
                    bitcoin::ScriptBuf::new_p2tr_tweaked(
                        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(dummy_key),
                    )
                } else {
                    r.create_script(&FinalizationContext {
                        inputs: &[],
                        partial_secret: None,
                        network: Network::Bitcoin,
                    })
                };
                TxOut {
                    value,
                    script_pubkey: script,
                }
            })
            .collect();
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        }
    }

    fn prepare_outputs(
        &self,
        change: Option<Box<dyn RecipientProvider>>,
    ) -> Result<Vec<Box<dyn RecipientProvider>>, Error> {
        let mut outputs: Vec<Box<dyn RecipientProvider>> =
            self.outputs.iter().map(|o| o.clone_box()).collect();

        if let Some(change_output) = change {
            if !change_output.is_change() {
                return Err(Error::NotChange);
            }
            if outputs.iter().any(|o| o.is_change()) {
                return Err(Error::ChangeAlreadyAdded);
            }
            outputs.push(change_output);
        }

        Ok(outputs)
    }

    fn shuffle_maybe(
        &self,
        shuffle: bool,
        mut outputs: Vec<Box<dyn RecipientProvider>>,
    ) -> (Vec<Coin>, Vec<Box<dyn RecipientProvider>>) {
        use rand::seq::SliceRandom;

        let inputs = if shuffle {
            shuffle_coins(self.inputs.clone())
        } else {
            self.inputs.clone()
        };

        if shuffle {
            outputs.shuffle(&mut rand::rng());
        }

        (inputs, outputs)
    }

    fn compute_sp_partial_secret(
        inputs: &[Coin],
        outputs: &[Box<dyn RecipientProvider>],
        sp_provider: &dyn SpPartialSecretProvider,
    ) -> Result<Option<bitcoin::secp256k1::SecretKey>, Error> {
        let needs_sp = outputs.iter().any(|r| r.is_silent_payment());
        if !needs_sp {
            return Ok(None);
        }

        let secret = sp_provider
            .compute_partial_secret(inputs)
            .map_err(|_| Error::SpPartialSecret)?;
        Ok(Some(secret))
    }

    fn build_psbt(
        inputs: &[Coin],
        outputs: &mut [Box<dyn RecipientProvider>],
        ctx: &FinalizationContext,
    ) -> Result<Psbt, Error> {
        let tx_outputs: Vec<TxOut> = outputs
            .iter_mut()
            .map(|r| TxOut {
                value: output_bitcoin_amount(r.as_ref()),
                script_pubkey: r.create_script(ctx),
            })
            .collect();

        let tx_inputs: Vec<bitcoin::TxIn> = inputs.iter().cloned().map(Into::into).collect();

        let unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        let mut psbt = Psbt {
            unsigned_tx,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![],
            outputs: vec![],
        };

        for i in inputs {
            psbt.inputs
                .push(i.to_psbt_input().map_err(|_| Error::Input)?);
        }

        for o in outputs {
            let mut psbt_output = o.to_psbt_output().map_err(|_| Error::Output)?;
            if let PsbtOutputInfo::SilentPayment {
                scan_pubkey,
                spend_pubkey,
                label,
            } = o.psbt_output_info()
            {
                crate::psbt_sp::set_sp_v0_output(
                    &mut psbt_output,
                    scan_pubkey,
                    spend_pubkey,
                    label,
                );
            }
            psbt.outputs.push(psbt_output);
        }

        Ok(psbt)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize(
        &self,
        change: Option<Box<dyn RecipientProvider>>,
        shuffle: bool,
        sp_provider: Option<&dyn SpPartialSecretProvider>,
        network: Network,
        max_fee_percent: u8,
        max_fee_amount: u64,
        skip_checks: bool,
    ) -> Result<Psbt, Error> {
        let outputs = self.prepare_outputs(change)?;
        let (inputs, mut outputs) = self.shuffle_maybe(shuffle, outputs);

        if !skip_checks {
            check_missing_change(&inputs, &outputs, &self.fees)?;
            check_disproportionate_fee(&inputs, &outputs, max_fee_percent, max_fee_amount)?;
        }

        let partial_secret = match sp_provider {
            Some(p) => Self::compute_sp_partial_secret(&inputs, &outputs, p)?,
            None => None,
        };

        // Batch-derive SP output scripts so the k-counter is correct
        // across all outputs sharing the same scan key (BIP352).
        if let (Some(p), Some(secret)) = (sp_provider, partial_secret) {
            p.derive_sp_scripts(&mut outputs, secret);
        }

        let ctx = FinalizationContext {
            inputs: &inputs,
            partial_secret,
            network,
        };

        Self::build_psbt(&inputs, &mut outputs, &ctx)
    }
}

fn output_amount(r: &dyn RecipientProvider) -> u64 {
    match r.amount() {
        Amount::Value(v) => v,
        Amount::Max(Some(v)) => v,
        Amount::Max(None) | Amount::Anchor => 0,
    }
}

fn output_bitcoin_amount(r: &dyn RecipientProvider) -> bitcoin::Amount {
    match r.amount() {
        Amount::Value(v) => bitcoin::Amount::from_sat(v),
        Amount::Max(Some(v)) => bitcoin::Amount::from_sat(v),
        Amount::Max(None) => bitcoin::Amount::MAX_MONEY,
        Amount::Anchor => bitcoin::Amount::ZERO,
    }
}

fn sum_output_amounts(outputs: &[Box<dyn RecipientProvider>]) -> u64 {
    outputs.iter().map(|r| output_amount(r.as_ref())).sum()
}

fn check_disproportionate_fee(
    inputs: &[Coin],
    outputs: &[Box<dyn RecipientProvider>],
    max_fee_percent: u8,
    max_fee_amount: u64,
) -> Result<(), Error> {
    let sum_inputs: u64 = inputs.iter().map(|c| c.txout.value.to_sat()).sum();
    let sum_outputs: u64 = sum_output_amounts(outputs);
    let fee = sum_inputs.saturating_sub(sum_outputs);

    let paid_outputs: u64 = outputs
        .iter()
        .filter(|r| !r.is_change())
        .map(|r| output_amount(r.as_ref()))
        .sum();

    if paid_outputs == 0 {
        return Ok(());
    }

    let pct_threshold = paid_outputs * max_fee_percent as u64 / 100;
    if fee > pct_threshold && fee > max_fee_amount {
        Err(Error::DisproportionateFees {
            fee,
            paid_outputs,
            max_percent: max_fee_percent,
            max_amount: max_fee_amount,
        })
    } else {
        Ok(())
    }
}

fn check_missing_change(
    inputs: &[Coin],
    outputs: &[Box<dyn RecipientProvider>],
    fees: &Fees,
) -> Result<(), Error> {
    if outputs.iter().any(|o| o.is_change()) {
        return Ok(());
    }

    let sum_inputs: u64 = inputs.iter().map(|c| c.txout.value.to_sat()).sum();
    let sum_outputs: u64 = sum_output_amounts(outputs);
    let fee = sum_inputs.saturating_sub(sum_outputs);

    if fee <= DUST_AMOUNT {
        return Ok(());
    }

    let estimated_fee = match fees {
        Fees::Sats(f) => *f,
        Fees::MilliSatsVb(rate) => {
            let temp = TxTemplate {
                inputs: inputs.to_vec(),
                outputs: outputs.iter().map(|o| o.clone_box()).collect(),
                fees: fees.clone(),
            };
            let weight = tx_estimated_weight(&temp);
            weight.to_vbytes_ceil() * rate / 1_000
        }
    };

    let excess = fee.saturating_sub(estimated_fee);
    if excess > DUST_AMOUNT {
        Err(Error::MissingChange { excess })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Amount {
    Value(u64),
    Max(Option<u64>),
    Anchor,
}

/// Estimates the maximum possible weight of an unsigned transaction
pub fn tx_estimated_weight(tx_template: &TxTemplate) -> Weight {
    let input_weights: Vec<u64> = tx_template
        .inputs
        .iter()
        .map(|inp| inp.satisfaction_size)
        .collect();
    let output_weights: Vec<u64> = tx_template
        .outputs
        .iter()
        .map(|o| o.output_weight().to_wu())
        .collect();
    estimated_weight_raw(&input_weights, &output_weights)
}

/// Estimate transaction weight from raw input/output weights.
/// Does not require TxTemplate or descriptors.
///
/// * `input_satisfaction_weights` - satisfaction weight in WU for each input
/// * `output_weights` - weight in WU for each output
pub fn estimated_weight_raw(input_satisfaction_weights: &[u64], output_weights: &[u64]) -> Weight {
    // Fixed overhead: version(4) + locktime(4) + input_count(1) + output_count(1) = 10 bytes
    // In weight units (non-witness): 10 * 4 = 40 WU
    // Plus segwit marker+flag: 2 WU
    let mut weight = 40u64 + 2;

    for &input_sat in input_satisfaction_weights {
        // Each input has: prevout(36) + script_sig_length(1) + sequence(4) = 41 bytes = 164 WU
        weight += 164 + input_sat;
    }

    for &output_w in output_weights {
        weight += output_w;
    }

    // varint adjustment for input/output counts > 252
    if input_satisfaction_weights.len() >= 253 {
        weight += 2 * 4; // 2 extra bytes for varint, non-witness
    }
    if output_weights.len() >= 253 {
        weight += 2 * 4;
    }

    Weight::from_wu(weight)
}

#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub tx_template: TxTemplate,
    pub change: Option<bitcoin::Amount>,
    pub fees: Option<bitcoin::Amount>,
    pub warnings: Vec<Warning>,
    pub error: Option<Error>,
}

impl TransactionResult {
    pub fn from_template(tx_template: &TxTemplate) -> Self {
        TransactionResult {
            tx_template: tx_template.clone(),
            change: None,
            fees: None,
            warnings: vec![],
            error: None,
        }
    }
}

pub struct FeeResult {
    pub fees: Option<u64>,
    pub max: Option<u64>,
    pub change: Option<u64>,
    pub warnings: Vec<Warning>,
    pub error: Option<Error>,
}

pub enum Drain {
    Change,
    Max,
    None,
}

pub fn process_fees(
    fees: Fees,
    weight_wo_change: Weight,
    weight_with_change: Weight,
    sum_inputs: u64,
    sum_outputs: u64,
    drain: Drain,
) -> FeeResult {
    let mut result = FeeResult {
        fees: None,
        max: None,
        change: None,
        warnings: vec![],
        error: None,
    };
    if sum_outputs > sum_inputs {
        result.error = Some(Error::AddInput);
        return result;
    }
    let fee_allowance = sum_inputs - sum_outputs;
    #[allow(unused_parens)]
    let (fee_wo_change, fee_with_change) = match fees {
        Fees::Sats(fee) => (fee, fee),
        Fees::MilliSatsVb(fee) => {
            let wo_change = (weight_wo_change.to_vbytes_ceil() * fee / 1_000);
            let with_change = (weight_with_change.to_vbytes_ceil() * fee / 1_000);
            (wo_change, with_change)
        }
    };

    // Not enough for pay fees
    if fee_wo_change > fee_allowance {
        result.error = Some(Error::NotEnoughForFee);
        return result;
    }

    let fee = if (fee_allowance - fee_wo_change) < DUST_AMOUNT {
        // Enough for fee but not for drain
        let lost = fee_allowance - fee_wo_change;
        match drain {
            Drain::Change => {
                result.warnings.push(Warning::ChangeUnderDust(lost));
            }
            Drain::Max => {
                result.warnings.push(Warning::MaxUnderDust(lost));
            }
            Drain::None => {}
        }
        fee_allowance
    } else if (fee_allowance - fee_with_change) < DUST_AMOUNT {
        // Create a drain < DUST, so we dont
        let lost = fee_allowance - fee_wo_change;
        match drain {
            Drain::Change => {
                result.warnings.push(Warning::ChangeCreateDust(lost));
            }
            Drain::Max => {
                result.warnings.push(Warning::MaxCreateDust(lost));
            }
            Drain::None => {}
        }
        fee_allowance
    } else {
        // Enough for drain
        match drain {
            Drain::None => {
                // TODO: warning
                fee_wo_change
            }
            Drain::Change => {
                result.change = Some(fee_allowance - fee_with_change);
                fee_with_change
            }
            Drain::Max => {
                result.max = Some(fee_allowance - fee_wo_change);
                fee_wo_change
            }
        }
    };
    result.fees = Some(fee);

    result
}

fn select_inputs(
    tx_template: &TxTemplate,
    outputs_total: u64,
    maxed_output: Option<usize>,
    coin_selection: Option<(&dyn CoinSelector, &dyn CoinSource)>,
) -> Result<Vec<Coin>, Error> {
    let (selector, source) = coin_selection.ok_or(Error::NoInputs)?;
    let selected = if maxed_output.is_some() {
        source.spendable_coins()
    } else {
        let rate = match tx_template.fees {
            Fees::MilliSatsVb(rate) => rate,
            Fees::Sats(_) => return Err(Error::CoinSelectionRequiresFeerate),
        };
        let base_weight_vb = tx_estimated_weight(tx_template).to_vbytes_ceil();
        let base_fee = base_weight_vb * rate / 1000;
        let target = outputs_total + base_fee;
        selector.select_coins(source.spendable_coins(), target, rate)
    };
    if selected.is_empty() {
        return Err(Error::CoinSelection);
    }
    Ok(selected)
}

/// Preprocesses a transaction based on the provided `TransactionTemplate`.
#[allow(clippy::type_complexity)]
pub fn process_transaction(
    tx_template: TxTemplate,
    change_recipient: Option<&dyn RecipientProvider>,
    coin_selection: Option<(&dyn CoinSelector, &dyn CoinSource)>,
) -> TransactionResult {
    let mut tx_template = tx_template;
    let mut result = TransactionResult::from_template(&tx_template);

    if tx_template.fees.is_null() {
        result.error = Some(Error::FeesNull);
        return result;
    }

    // Sum the outputs before coin selection: the target is
    // outputs_total + base_fee. Only the inputs are unknown before
    // selection; the target already includes the base tx and outputs.
    let mut outputs_total = 0;
    let mut maxed_output = None;
    for (pos, o) in tx_template.outputs.iter().enumerate() {
        match o.amount() {
            Amount::Value(sat) => outputs_total += sat,
            Amount::Max(_) => {
                if maxed_output.is_some() {
                    result.error = Some(Error::SingleMax);
                    return result;
                }
                maxed_output = Some(pos);
                // NOTE: we do not add the value of the MAX output as it's expected
                // to be re-processed
            }
            Amount::Anchor => { /* anchor has 0 sats outputs */ }
        }
    }

    // Coin selection: when no inputs were provided, trigger auto coin selection
    if tx_template.inputs.is_empty() {
        match select_inputs(&tx_template, outputs_total, maxed_output, coin_selection) {
            Ok(selected) => {
                tx_template.inputs = selected.clone();
                result.tx_template.inputs = selected;
            }
            Err(e) => {
                result.error = Some(e);
                return result;
            }
        }
    }

    let inputs_total = tx_template
        .inputs
        .iter()
        .fold(0u64, |sum, coin| sum + coin.txout.value.to_sat());

    let tx_weight_wo_change = tx_estimated_weight(&tx_template);
    let tx_weight_with_change = match change_recipient {
        Some(r) => tx_weight_wo_change + r.output_weight(),
        None => tx_weight_wo_change,
    };

    let drain = match maxed_output {
        Some(_) => Drain::Max,
        None => Drain::Change,
    };

    let FeeResult {
        fees,
        max,
        change,
        warnings: mut warning,
        error,
    } = process_fees(
        tx_template.fees,
        tx_weight_wo_change,
        tx_weight_with_change,
        inputs_total,
        outputs_total,
        drain,
    );

    result.warnings.append(&mut warning);
    if let Some(error) = error {
        result.error = Some(error);
        return result;
    }

    result.fees = fees.map(bitcoin::Amount::from_sat);

    // Default thresholds: 10% and 2M sats (~$600)
    if let Err(e) =
        check_disproportionate_fee(&tx_template.inputs, &tx_template.outputs, 10, 2_000_000)
    {
        if let Some(w) = e.to_warning() {
            result.warnings.push(w);
        }
    }

    match (maxed_output, max, change) {
        (Some(pos), Some(value), None) => {
            result
                .tx_template
                .outputs
                .get_mut(pos)
                .expect("max output missing")
                .set_amount(Amount::Max(Some(value)));
        }
        (None, None, Some(change)) => result.change = Some(bitcoin::Amount::from_sat(change)),
        (None, None, None) => {}
        (_, _, _) => unreachable!(),
    }

    result
}

#[cfg(all(test, feature = "test"))]
mod test {
    use super::*;
    use crate::tx_builder::test::{
        external_recipient, funding_coin, sum_inputs, sum_outputs, tr_signer,
    };
    use bwk_coin::KeyChain;
    use miniscript::bitcoin;

    #[test]
    fn test_tr_tx() {
        let (_signer, derivator) = tr_signer();
        let descriptor = derivator.descriptor();

        let c1 = funding_coin(30_000, &derivator, 1);
        let c2 = funding_coin(50_000, &derivator, 2);

        let r1 = external_recipient(35_000);

        let template = TxTemplate {
            inputs: vec![c1, c2],
            outputs: vec![Box::new(r1)],
            fees: Fees::MilliSatsVb(1000),
        };

        // Create change recipient prototype for fee estimation
        let change_proto = crate::Recipient {
            address: descriptor
                .clone()
                .into_single_descriptors()
                .unwrap()
                .get(1)
                .unwrap()
                .at_derivation_index(0)
                .unwrap()
                .address(Network::Signet)
                .unwrap()
                .as_unchecked()
                .clone(),
            amount: Amount::Value(0),
            label: None,
            origin: Some((KeyChain::Change, 0)),
            descriptor: Some(descriptor.clone()),
        };

        let res = process_transaction(template.clone(), Some(&change_proto), None);

        assert!(res.error.is_none());
        assert_eq!(res.change, Some(bitcoin::Amount::from_sat(44_788)));
        assert_eq!(res.fees, Some(bitcoin::Amount::from_sat(212)));

        // Test finalize without change - should fail with MissingChange
        let result =
            res.tx_template
                .finalize(None, false, None, Network::Signet, 10, 2_000_000, false);
        assert!(matches!(result, Err(Error::MissingChange { .. })));

        // Test finalize with change
        let change_index = 1u32;
        let change_addr = descriptor
            .clone()
            .into_single_descriptors()
            .unwrap()
            .get(1)
            .unwrap()
            .at_derivation_index(change_index)
            .unwrap()
            .address(Network::Signet)
            .unwrap();
        let change_amount = Amount::Value(res.change.unwrap().to_sat());
        let change_recip = crate::Recipient {
            address: change_addr.as_unchecked().clone(),
            amount: change_amount.clone(),
            label: None,
            origin: Some((KeyChain::Change, change_index)),
            descriptor: Some(descriptor.clone()),
        };
        let psbt = res
            .tx_template
            .finalize(
                Some(Box::new(change_recip.clone())),
                false,
                None,
                Network::Signet,
                10,
                2_000_000,
                false,
            )
            .unwrap();
        assert_eq!(sum_inputs(&psbt), 80_000);
        assert_eq!(sum_outputs(&psbt), 80_000 - 212);

        // Test finalize returns error if change already exists in outputs
        let mut template_with_existing_change = res.tx_template.clone();
        template_with_existing_change
            .outputs
            .push(Box::new(change_recip.clone()));
        let result = template_with_existing_change.finalize(
            Some(Box::new(change_recip)),
            false,
            None,
            Network::Signet,
            10,
            2_000_000,
            false,
        );
        assert!(matches!(result, Err(Error::ChangeAlreadyAdded)));
    }

    #[test]
    fn test_disproportionate_fees() {
        let (_signer, derivator) = tr_signer();

        // 100k input, 10k output -> 90k fees
        let c1 = funding_coin(100_000, &derivator, 1);
        let r1 = external_recipient(10_000);

        let template = TxTemplate {
            inputs: vec![c1],
            outputs: vec![Box::new(r1)],
            fees: Fees::Sats(89_000),
        };

        let res = process_transaction(template.clone(), None, None);
        assert!(res.error.is_none());

        // Should fail: actual fee (90k) > 10% of paid_outputs (1k) AND > max_amount (50k)
        let result =
            res.tx_template
                .finalize(None, false, None, Network::Signet, 10, 50_000, false);
        assert!(matches!(
            result,
            Err(Error::DisproportionateFees { fee: 90000, .. })
        ));

        // Should succeed with skip_checks
        let result = res
            .tx_template
            .finalize(None, false, None, Network::Signet, 10, 50_000, true);
        assert!(result.is_ok());

        // Should succeed if only one threshold is exceeded
        let result =
            res.tx_template
                .finalize(None, false, None, Network::Signet, 10, 100_000, false);
        assert!(result.is_ok());
    }
}
