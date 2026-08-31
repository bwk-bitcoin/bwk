//! Generic, additive payment-history aggregation across several accounts.
//!
//! Each account reports, per transaction, the value of the inputs and outputs
//! *it* owns ([`TxContribution`]). [`aggregate_payments`] sums those
//! contributions per txid across every account and only then derives the
//! direction and amount, so change is netted automatically: it is just an owned
//! output, and the send amount is the owned inputs minus the owned outputs,
//! which is what was sent plus the fee.
//!
//! This layer is deliberately account-agnostic so it can combine any mix of
//! accounts (standard wallets, silent-payment wallets, ...). It depends only on
//! `bitcoin` and the local [`Payment`] type, never on a specific account crate.

use std::collections::{BTreeMap, BTreeSet};

use miniscript::bitcoin::{Transaction, Txid};

use crate::coin_store::{Payment, PaymentStatus, PaymentType};

/// One account's additive ownership inside a single transaction.
#[derive(Debug, Clone, Default)]
pub struct TxContribution {
    /// Sum of the values of the inputs this account owns.
    pub owned_in: u64,
    /// Sum of the values of the outputs this account owns.
    pub owned_out: u64,
    /// Indices of the outputs this account owns (used to detect a self-send).
    pub owned_vouts: BTreeSet<u32>,
    /// Confirmation height this account has seen for the tx.
    pub height: Option<u64>,
    /// Verification state this account has seen for the tx.
    pub status: PaymentStatus,
    /// Confirming block time this account has seen for the tx.
    pub timestamp: Option<u64>,
    /// A user label for the tx, if this account has one.
    pub label: Option<String>,
    /// The full transaction, carried by whichever account holds it.
    pub tx: Option<Transaction>,
}

/// An account that can report its per-transaction ownership for aggregation.
pub trait AccountHistory {
    /// Per-txid ownership this account contributes.
    fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution>;
}

/// Aggregate every account's contributions into a single de-duplicated payment
/// history (one entry per txid).
///
/// Direction and amount are derived only here, after summing:
/// - no owned input or output: the tx does not concern us, skipped;
/// - no owned input: `Receive`, amount is the owned outputs;
/// - own an input but netted a gain (owned outputs exceed owned inputs, a
///   payjoin-style receive): `Receive`, amount is the net gain;
/// - every output owned: `ToSelf`, amount is the owned inputs minus the owned
///   outputs (the fee);
/// - otherwise: `Send`, amount is the owned inputs minus the owned outputs
///   (what was sent plus the fee, change netted).
///
/// Sorted unconfirmed-first, then by descending height, then by txid.
pub fn aggregate_payments<'a>(
    accounts: impl IntoIterator<Item = &'a dyn AccountHistory>,
) -> Vec<Payment> {
    let mut by_txid: BTreeMap<Txid, TxContribution> = BTreeMap::new();
    for account in accounts {
        for (txid, contrib) in account.tx_contributions() {
            let f = by_txid.entry(txid).or_default();
            f.owned_in = f.owned_in.saturating_add(contrib.owned_in);
            f.owned_out = f.owned_out.saturating_add(contrib.owned_out);
            f.owned_vouts.extend(contrib.owned_vouts);
            if f.height.is_none() {
                f.height = contrib.height;
            }
            f.status = f.status.merge(contrib.status);
            if f.timestamp.is_none() {
                f.timestamp = contrib.timestamp;
            }
            if f.label.is_none() {
                f.label = contrib.label;
            }
            if f.tx.is_none() {
                f.tx = contrib.tx;
            }
        }
    }

    let mut payments: Vec<Payment> = by_txid
        .into_iter()
        .filter_map(|(txid, f)| {
            if f.owned_in == 0 && f.owned_out == 0 {
                return None;
            }
            let (payment_type, amount) = if f.owned_in == 0 {
                (PaymentType::Receive, f.owned_out)
            } else if f.owned_out > f.owned_in {
                // We own an input but netted a gain (payjoin-style receive, or a
                // cross-account transfer with external inputs): a receive, not a send.
                (PaymentType::Receive, f.owned_out - f.owned_in)
            } else {
                let outflow = f.owned_in - f.owned_out;
                match f.tx.as_ref().map(|t| t.output.len()) {
                    Some(n) if f.owned_vouts.len() == n => (PaymentType::ToSelf, outflow),
                    Some(_) => (PaymentType::Send, outflow),
                    None => {
                        log::error!(
                            "aggregate_payments: tx {txid} owns inputs but has no carried tx"
                        );
                        (PaymentType::Send, outflow)
                    }
                }
            };
            Some(Payment {
                txid: txid.to_string(),
                payment_type,
                status: f.status,
                amount,
                label: f.label.unwrap_or_default(),
                height: f.height,
                timestamp: f.timestamp,
            })
        })
        .collect();

    payments.sort_by(|a, b| match (a.height, b.height) {
        (None, None) => a.txid.cmp(&b.txid),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(ha), Some(hb)) => hb.cmp(&ha).then_with(|| a.txid.cmp(&b.txid)),
    });
    payments
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxOut};

    fn tx_with_outputs(values: &[u64]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: values
                .iter()
                .map(|v| TxOut {
                    value: Amount::from_sat(*v),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        }
    }

    struct Source(BTreeMap<Txid, TxContribution>);
    impl AccountHistory for Source {
        fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution> {
            self.0.clone()
        }
    }

    fn txid(n: u8) -> Txid {
        use miniscript::bitcoin::hashes::Hash;
        Txid::from_byte_array([n; 32])
    }

    #[test]
    fn send_nets_change_across_accounts() {
        // tx with 2 outputs (recipient + change); owned input 5_000_000 from
        // one account, owned change output 3_999_800 from another account.
        let tx = tx_with_outputs(&[1_000_000, 3_999_800]);
        let t = txid(1);
        let a = Source(BTreeMap::from([(
            t,
            TxContribution {
                owned_in: 5_000_000,
                height: Some(10),
                tx: Some(tx),
                ..Default::default()
            },
        )]));
        let b = Source(BTreeMap::from([(
            t,
            TxContribution {
                owned_out: 3_999_800,
                owned_vouts: BTreeSet::from([1]),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory, &b as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::Send));
        assert_eq!(payments[0].amount, 1_000_200);
        assert_eq!(payments[0].height, Some(10));
    }

    #[test]
    fn receive_is_owned_outputs() {
        let a = Source(BTreeMap::from([(
            txid(2),
            TxContribution {
                owned_out: 700_000,
                owned_vouts: BTreeSet::from([0]),
                height: Some(5),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::Receive));
        assert_eq!(payments[0].amount, 700_000);
    }

    #[test]
    fn all_outputs_owned_is_to_self() {
        let tx = tx_with_outputs(&[999_800]);
        let a = Source(BTreeMap::from([(
            txid(3),
            TxContribution {
                owned_in: 1_000_000,
                owned_out: 999_800,
                owned_vouts: BTreeSet::from([0]),
                tx: Some(tx),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::ToSelf));
        assert_eq!(payments[0].amount, 200);
    }

    #[test]
    fn empty_contribution_is_skipped() {
        let a = Source(BTreeMap::from([(txid(4), TxContribution::default())]));
        assert!(aggregate_payments([&a as &dyn AccountHistory]).is_empty());
    }

    #[test]
    fn net_gain_with_owned_input_is_receive() {
        // Payjoin: we own an input of 50_000 and an output of 155_000, the other
        // 10_000 output is not ours. We come out ahead, so this is a receive.
        let tx = tx_with_outputs(&[155_000, 10_000]);
        let a = Source(BTreeMap::from([(
            txid(1),
            TxContribution {
                owned_in: 50_000,
                owned_out: 155_000,
                owned_vouts: BTreeSet::from([0]),
                tx: Some(tx),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::Receive));
        assert_eq!(payments[0].amount, 105_000);
    }

    #[test]
    fn merge_precedence_first_non_none_wins() {
        let t = txid(2);
        let a = Source(BTreeMap::from([(
            t,
            TxContribution {
                owned_out: 700_000,
                owned_vouts: BTreeSet::from([0]),
                height: Some(5),
                timestamp: Some(111),
                label: Some("a".to_string()),
                ..Default::default()
            },
        )]));
        let b = Source(BTreeMap::from([(
            t,
            TxContribution {
                owned_out: 0,
                height: Some(9),
                timestamp: Some(222),
                label: Some("b".to_string()),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory, &b as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::Receive));
        assert_eq!(payments[0].amount, 700_000);
        assert_eq!(payments[0].height, Some(5));
        assert_eq!(payments[0].timestamp, Some(111));
        assert_eq!(payments[0].label, "a");
    }

    #[test]
    fn sort_order_unconfirmed_first_then_desc_height_then_txid() {
        let unconfirmed = Source(BTreeMap::from([(
            txid(1),
            TxContribution {
                owned_out: 100_000,
                owned_vouts: BTreeSet::from([0]),
                ..Default::default()
            },
        )]));
        let low = Source(BTreeMap::from([(
            txid(2),
            TxContribution {
                owned_out: 100_000,
                owned_vouts: BTreeSet::from([0]),
                height: Some(5),
                ..Default::default()
            },
        )]));
        let high = Source(BTreeMap::from([(
            txid(3),
            TxContribution {
                owned_out: 100_000,
                owned_vouts: BTreeSet::from([0]),
                height: Some(9),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([
            &unconfirmed as &dyn AccountHistory,
            &low as &dyn AccountHistory,
            &high as &dyn AccountHistory,
        ]);
        let order: Vec<&str> = payments.iter().map(|p| p.txid.as_str()).collect();
        assert_eq!(
            order,
            vec![
                txid(1).to_string(),
                txid(3).to_string(),
                txid(2).to_string(),
            ]
        );
    }

    #[test]
    fn to_self_across_accounts() {
        // 2-output self-send paying a 200 sat fee: account A owns output 0 and
        // the inputs, account B owns output 1, so together we own every output.
        let tx = tx_with_outputs(&[400_000, 599_800]);
        let t = txid(1);
        let a = Source(BTreeMap::from([(
            t,
            TxContribution {
                owned_in: 1_000_000,
                owned_out: 400_000,
                owned_vouts: BTreeSet::from([0]),
                tx: Some(tx),
                ..Default::default()
            },
        )]));
        let b = Source(BTreeMap::from([(
            t,
            TxContribution {
                owned_out: 599_800,
                owned_vouts: BTreeSet::from([1]),
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory, &b as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::ToSelf));
        assert_eq!(payments[0].amount, 200);
    }

    #[test]
    fn owns_input_but_no_carried_tx_is_send() {
        let a = Source(BTreeMap::from([(
            txid(1),
            TxContribution {
                owned_in: 5_000_000,
                ..Default::default()
            },
        )]));
        let payments = aggregate_payments([&a as &dyn AccountHistory]);
        assert_eq!(payments.len(), 1);
        assert!(matches!(payments[0].payment_type, PaymentType::Send));
        assert_eq!(payments[0].amount, 5_000_000);
    }
}
