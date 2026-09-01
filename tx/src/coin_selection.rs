use std::collections::BTreeMap;

use bitcoin::Weight;
use rand::random_range;

use bwk_coin::Coin;

/// Trait abstracting what coin selection needs from a spendable coin.
/// Implement this for any coin type to use the generic selection algorithm.
pub trait CoinCandidate {
    fn outpoint(&self) -> bitcoin::OutPoint;
    fn value_sat(&self) -> u64;
    fn satisfaction_weight(&self) -> u64;
}

impl CoinCandidate for Coin {
    fn outpoint(&self) -> bitcoin::OutPoint {
        self.outpoint
    }
    fn value_sat(&self) -> u64 {
        self.txout.value.to_sat()
    }
    fn satisfaction_weight(&self) -> u64 {
        self.satisfaction_size
    }
}

#[derive(Debug, Clone)]
pub struct Selection {
    pub spendable_amount: u64,
    pub fees: u64,
    pub outpoints: Vec<bitcoin::OutPoint>,
}

/// Fixed per-input non-witness weight in WU.
///
/// Each input occupies prevout(36 B) + script_sig_length(1 B) + sequence(4 B)
/// = 41 B in the non-witness section, so 41 * 4 = 164 WU. This must be added
/// to the satisfaction weight to match what `estimated_weight_raw` charges.
/// Omitting it caused `Selection::spendable_amount` to overstate what the
/// inputs actually leave after fees, leading to `NotEnoughForFee` after the
/// builder simulated the real tx.
const PER_INPUT_FIXED_WU: u64 = 164;

impl Selection {
    pub fn new<T: CoinCandidate>(coins: Vec<&T>, feerate: u64 /* msats/vb */) -> Self {
        let mut spendable_amount = 0;
        let mut fees = 0;
        let mut outpoints = vec![];
        for c in coins {
            let input_wu = PER_INPUT_FIXED_WU + c.satisfaction_weight();
            let fee = Weight::from_wu(input_wu).to_vbytes_ceil() * feerate / 1000;
            fees += fee;
            spendable_amount += c.value_sat() - fee;
            outpoints.push(c.outpoint());
        }

        Selection {
            spendable_amount,
            fees,
            outpoints,
        }
    }
}

pub fn fees<T: CoinCandidate>(coin: &T, feerate: u64 /* msats/vb */) -> u64 {
    let input_wu = PER_INPUT_FIXED_WU + coin.satisfaction_weight();
    Weight::from_wu(input_wu).to_vbytes_ceil() * feerate / 1000
}

// Sort out coins if fees >= spendable value
pub fn discard_dust<T: CoinCandidate>(coins: Vec<&T>, feerate: u64 /* msats/vb */) -> Vec<&T> {
    coins
        .into_iter()
        .filter(|c| {
            let fee = fees(*c, feerate);
            fee * 2 < c.value_sat()
        })
        .collect()
}

pub fn all_coins_combinations<T: CoinCandidate>(
    coins: Vec<&T>,
    feerate: u64, /* msats/vb*/
) -> Option<BTreeMap<u64, Selection>> {
    let coins = discard_dust(coins, feerate);

    let n = coins.len();
    if n == 0 || n > 20 {
        // NOTE: >20 coins is too much resources intensive
        return None;
    }

    let mut selections = BTreeMap::new();

    // Try all non-empty subsets: 1 to 2^n - 1
    for mask in 1..(1 << n) {
        let mut selected = Vec::new();
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            if (mask & (1 << i)) != 0 {
                selected.push(coins[i]);
            }
        }

        let sel = Selection::new(selected, feerate);
        selections.insert(sel.spendable_amount, sel);
    }

    Some(selections)
}

pub fn select<T: CoinCandidate>(
    coins: Vec<&T>,
    target: u64,
    feerate: u64,
    min_change: u64,
    max_change: u64,
    dust: u64,
) -> (Option<Selection>, Option<Selection>) {
    // NOTE: base tx + output fees must be included in target
    let selections = match all_coins_combinations(coins, feerate) {
        Some(s) => s,
        None => return (None, None),
    };

    // Try to get a selection where we can just drop a tiny change
    let mut selection = if let Some((_, sel)) = selections.range(target..target + dust).next() {
        Some(sel.clone())
    } else {
        None
    };

    let mut cj_selection = None;
    // FIXME: use args for max fee for CJ like
    if target > min_change && feerate < 10_000 {
        // Try to split the input into "equal" outputs amount +-10%
        let chunk_target_min = target * 90 / 100;
        let chunk_target_max = target * 110 / 100;
        let mut cj_like = vec![];
        for i in 2..6 {
            let min = chunk_target_min * i;
            let max = chunk_target_max * i;
            let candidates: Vec<_> = selections.range(min..max).collect();
            if !candidates.is_empty() {
                let index = random_range(0..candidates.len());
                cj_like.push(candidates[index]);
            }
        }
        if !cj_like.is_empty() {
            let index = random_range(0..cj_like.len());
            cj_selection = Some(cj_like[index].1.clone());
        }
    }

    if selection.is_none() {
        // Get the list of selection that match min_change < change < max_change
        let mut change_range: Vec<_> = selections
            .range(target + min_change..target + max_change)
            .collect();
        if !change_range.is_empty() {
            change_range.sort_by(|a, b| {
                a.1.outpoints
                    .len()
                    // First sort by least inputs count in order to avoid consolidation
                    .cmp(&b.1.outpoints.len())
                    // Then minimize fees
                    .then_with(|| a.1.fees.cmp(&a.1.fees))
            });
            selection = Some(change_range.first().expect("exists").1.clone());
        }
    }

    if selection.is_none() {
        // Not so good choice
        let mut sel: Vec<_> = selections.range(target + max_change..).collect();
        if !sel.is_empty() {
            sel.sort_by(|a, b| {
                a.1.outpoints
                    .len()
                    // First sort by least inputs count in order to avoid consolidation
                    .cmp(&b.1.outpoints.len())
                    // Then minimize fees
                    .then_with(|| a.1.fees.cmp(&a.1.fees))
            });
            selection = Some(sel.first().expect("exists").1.clone());
        }
    }

    if selection.is_none() {
        // Default choice
        let mut sel: Vec<_> = selections.range(target..).collect();
        if !sel.is_empty() {
            sel.sort_by(|a, b| {
                a.1.outpoints
                    .len()
                    // First sort by least inputs count in order to avoid consolidation
                    .cmp(&b.1.outpoints.len())
                    // Then minimize fees
                    .then_with(|| a.1.fees.cmp(&a.1.fees))
            });
            selection = Some(sel.first().expect("exists").1.clone());
        }
    }

    (selection, cj_selection)
}

/// Trait abstracting the coin selection strategy.
/// Implement this to provide custom selection algorithms.
pub trait CoinSelector {
    fn select_coins(&self, candidates: Vec<Coin>, target: u64, feerate: u64) -> Vec<Coin>;
}

/// Default coin selector wrapping the exhaustive algorithm.
pub struct DefaultCoinSelector {
    pub min_change: u64,
    pub max_change: u64,
    pub dust: u64,
}

impl Default for DefaultCoinSelector {
    fn default() -> Self {
        Self {
            min_change: 50_000,
            max_change: 5_000_000,
            dust: 500,
        }
    }
}

impl CoinSelector for DefaultCoinSelector {
    fn select_coins(&self, candidates: Vec<Coin>, target: u64, feerate: u64) -> Vec<Coin> {
        if candidates.is_empty() {
            return vec![];
        }
        let (selection, _) = select(
            candidates.iter().collect(),
            target,
            feerate,
            self.min_change,
            self.max_change,
            self.dust,
        );
        if let Some(sel) = selection {
            let mut coins: BTreeMap<_, _> =
                candidates.into_iter().map(|c| (c.outpoint, c)).collect();
            sel.outpoints
                .iter()
                .map(|op| coins.remove(op).expect("exists"))
                .collect()
        } else {
            vec![]
        }
    }
}
