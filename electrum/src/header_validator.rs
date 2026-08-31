//! Pure header-chain validator.
//!
//! Given a prefix of validated headers, [`validate_append`] decides whether
//! the next header can be accepted. It enforces:
//!
//! * proof-of-work,
//! * previous-block linkage,
//! * difficulty retargeting at 2016-block boundaries,
//! * median-time-past,
//! * a 2-hour future-timestamp cap,
//! * a network-pinned genesis block hash for `Bitcoin`, `Signet`, `Testnet`
//!   and `Testnet4`. `Regtest` is unpinned: its genesis is
//!   instance-specific, so there is no fixed hash to check against, but it
//!   must still satisfy proof-of-work.
//!
//! On Testnet and Testnet4 the network-agnostic checks above still run;
//! only the difficulty retarget and its min-difficulty relaxation are
//! skipped.
//!
//! The module is intentionally I/O-free and persistence-free; it does not
//! know about `HeaderStore`.

use miniscript::bitcoin::{
    block::Header, constants::genesis_block, params::Params, BlockHash, CompactTarget, Network,
};

/// A block timestamp may be at most this many seconds (2 hours) ahead of our
/// local system clock. This is a deliberate divergence from bitcoin-core's
/// network-adjusted time: Electrum gives us no peer time source to
/// cross-check against, unlike a full node's P2P connections, so we compare
/// against the local clock alone. Compare with the analogous check in
/// `ContextualCheckBlockHeader()` (pinned to commit 6574cb40):
/// https://github.com/bitcoin/bitcoin/blob/6574cb40869b96b9ffc79c19dc8f4e467d60f321/src/validation.cpp#L4139
const MAX_FUTURE_BLOCK_TIME: u64 = 7200;

/// Number of ancestor block times the median-time-past check looks at.
pub(crate) const MTP_WINDOW: usize = 11;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("proof-of-work check failed")]
    Pow,
    #[error("prev_blockhash does not match latest ancestor")]
    PrevHashMismatch,
    #[error("retarget bits do not match expected value")]
    BadRetarget,
    #[error("bits do not match previous header")]
    BitsMismatch,
    #[error("timestamp is not greater than median-time-past")]
    MtpViolation,
    #[error("timestamp is more than 2 hours in the future")]
    TimestampTooFarInFuture,
    #[error("genesis hash does not match the expected value")]
    GenesisMismatch,
    #[error("required ancestor header is missing")]
    MissingAncestor,
    #[error("raw header bytes could not be decoded")]
    MalformedHeader,
}

/// Network-pinned genesis block hash.
pub fn expected_genesis(network: Network) -> Option<BlockHash> {
    match network {
        Network::Bitcoin | Network::Signet | Network::Testnet | Network::Testnet4 => {
            Some(genesis_block(Params::new(network)).block_hash())
        }
        Network::Regtest => None,
    }
}

/// Validates that `incoming` can be appended after `ancestors`.
pub fn validate_append(
    network: Network,
    ancestors: &[Header],
    incoming_height: u32,
    incoming: &Header,
    now_secs: u64,
) -> Result<(), Error> {
    // Future cap always applies (including for genesis).
    check_future_cap(incoming, now_secs)?;

    let params = Params::new(network);

    if incoming_height == 0 {
        check_genesis(network, incoming)?;
        return check_pow(&params, incoming);
    }

    let prev = ancestors.last().ok_or(Error::MissingAncestor)?;

    check_pow(&params, incoming)?;
    check_linkage(prev, incoming)?;
    // Testnet/testnet4 relax difficulty (retarget and the 20-minute
    // min-difficulty rule); the other consensus checks above and below
    // still apply.
    if !matches!(network, Network::Testnet | Network::Testnet4) {
        check_retarget(&params, ancestors, incoming_height, prev, incoming)?;
    }
    check_mtp(network, ancestors, incoming)?;

    Ok(())
}

pub(crate) fn check_pow(params: &Params, incoming: &Header) -> Result<(), Error> {
    // Consensus: proof-of-work. Mirrors bitcoin-core `CheckProofOfWork()`
    // https://github.com/bitcoin/bitcoin/blob/6574cb40869b96b9ffc79c19dc8f4e467d60f321/src/pow.cpp#L140
    // Clamp the header's claimed target to the network's pow limit before
    // checking. A header could otherwise advertise a target *above*
    // `max_attainable_target` (i.e. easier than the network minimum) and
    // still satisfy `hash <= target`; clamping rejects such forgeries.
    let target = incoming.target().min(params.max_attainable_target);
    incoming
        .validate_pow(target)
        .map(|_| ())
        .map_err(|_| Error::Pow)
}

fn check_linkage(prev: &Header, incoming: &Header) -> Result<(), Error> {
    // Consensus: a header must connect to the chain via `prev_blockhash`.
    // bitcoin-core resolves the parent in `AcceptBlockHeader()`
    // https://github.com/bitcoin/bitcoin/blob/6574cb40869b96b9ffc79c19dc8f4e467d60f321/src/validation.cpp#L4218
    if incoming.prev_blockhash == prev.block_hash() {
        Ok(())
    } else {
        Err(Error::PrevHashMismatch)
    }
}

fn check_genesis(network: Network, incoming: &Header) -> Result<(), Error> {
    // Consensus: the height-0 header must equal the network's pinned
    // genesis hash.
    // https://github.com/bitcoin/bitcoin/blob/6574cb40869b96b9ffc79c19dc8f4e467d60f321/src/kernel/chainparams.cpp#L134
    match expected_genesis(network) {
        Some(g) if incoming.block_hash() != g => Err(Error::GenesisMismatch),
        _ => Ok(()),
    }
}

fn check_future_cap(incoming: &Header, now_secs: u64) -> Result<(), Error> {
    if (incoming.time as u64) > now_secs.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        Err(Error::TimestampTooFarInFuture)
    } else {
        Ok(())
    }
}

/// Number of blocks between difficulty retargets, derived from consensus
/// params (2016 on Bitcoin/Signet).
pub(crate) fn retarget_interval(params: &Params) -> usize {
    (params.pow_target_timespan / params.pow_target_spacing) as usize
}

fn check_retarget(
    params: &Params,
    ancestors: &[Header],
    incoming_height: u32,
    prev: &Header,
    incoming: &Header,
) -> Result<(), Error> {
    // Consensus: difficulty retarget every retarget-interval blocks, clamping
    // the recomputed timespan to [target_timespan/4, target_timespan*4].
    // Mirrors bitcoin-core `GetNextWorkRequired()` and `CalculateNextWorkRequired()`
    // https://github.com/bitcoin/bitcoin/blob/6574cb40869b96b9ffc79c19dc8f4e467d60f321/src/pow.cpp#L50
    if params.no_pow_retargeting {
        return Ok(());
    }

    let retarget_interval = retarget_interval(params);

    if incoming_height as usize % retarget_interval == 0 {
        // Boundary: need the header at the start of the previous retarget
        // period. With `ancestors` newest-last, that header sits at
        // `ancestors.len() - retarget_interval`.
        if ancestors.len() < retarget_interval {
            return Err(Error::MissingAncestor);
        }
        let period_start = &ancestors[ancestors.len() - retarget_interval];
        // Bitcoin timestamps are only MTP-constrained, so the 2016-block
        // window can run "backwards" (period_start later than prev). A
        // negative timespan must clamp to the minimum (hardest) target like
        // Bitcoin Core; casting a negative i64 straight to u64 would instead
        // wrap to the maximum (easiest).
        let raw_timespan = prev.time as i64 - period_start.time as i64;
        let actual_timespan = raw_timespan.max(0) as u64;
        // `from_next_work_required` in the `bitcoin` crate (0.32) clamps its
        // result to `params.max_attainable_target` internally (via
        // `max_transition_threshold`). We rely on that clamp here so a slow
        // 2016-block window cannot lower difficulty below the network floor.
        // If that crate is ever swapped, re-verify this assumption.
        let expected = CompactTarget::from_next_work_required(prev.bits, actual_timespan, params);
        if incoming.bits != expected {
            return Err(Error::BadRetarget);
        }
        Ok(())
    } else {
        // Non-boundary: bits must match prev. The testnet min-difficulty
        // relaxation is not handled here because `validate_append` skips the
        // whole retarget check on testnet/testnet4.
        if incoming.bits != prev.bits {
            return Err(Error::BitsMismatch);
        }
        Ok(())
    }
}

pub(crate) fn check_mtp(
    network: Network,
    ancestors: &[Header],
    incoming: &Header,
) -> Result<(), Error> {
    // Consensus: a block time must be strictly greater than the median of up
    // to the previous MTP_WINDOW block times (median-time-past). Mirrors
    // bitcoin-core `CBlockIndex::GetMedianTimePast()`, which takes the median
    // over however many ancestors exist (up to 11), so even a chain shorter
    // than the window is constrained.
    // https://github.com/bitcoin/bitcoin/blob/6574cb40869b96b9ffc79c19dc8f4e467d60f321/src/validation.cpp#L4112
    if matches!(network, Network::Regtest) {
        return Ok(());
    }
    if ancestors.is_empty() {
        return Ok(());
    }
    let window = ancestors.len().min(MTP_WINDOW);
    let mut ts: Vec<u32> = ancestors[ancestors.len() - window..]
        .iter()
        .map(|h| h.time)
        .collect();
    let median = median_time(&mut ts);
    if incoming.time <= median {
        Err(Error::MtpViolation)
    } else {
        Ok(())
    }
}

fn median_time(times: &mut [u32]) -> u32 {
    times.sort_unstable();
    times[times.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::{
        block::{Header, Version},
        hashes::Hash,
        BlockHash, CompactTarget, Network, Target, TxMerkleNode,
    };

    fn dummy_header(prev: BlockHash, bits: CompactTarget, time: u32) -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce: 0,
        }
    }

    fn now() -> u64 {
        1_700_000_000
    }

    #[test]
    fn expected_genesis_pins() {
        // Exact genesis block hashes, cross-checked against bitcoin-core
        // v31.0 src/kernel/chainparams.cpp (the `hashGenesisBlock` asserts).
        assert_eq!(
            expected_genesis(Network::Bitcoin).unwrap().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(
            expected_genesis(Network::Signet).unwrap().to_string(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
        assert_eq!(
            expected_genesis(Network::Testnet).unwrap().to_string(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
        assert_eq!(
            expected_genesis(Network::Testnet4),
            Some(genesis_block(Params::new(Network::Testnet4)).block_hash())
        );
        assert!(expected_genesis(Network::Regtest).is_none());
    }

    #[test]
    fn testnet_runs_common_checks_but_skips_retarget() {
        // Before the fix, validate_append blanket-returned Ok on testnet.
        // Now the network-agnostic checks run; only the difficulty retarget
        // (and its min-difficulty relaxation) is skipped.
        let bits = CompactTarget::from_consensus(0x1d00ffff);

        // The canonical testnet genesis is accepted.
        let g = genesis_block(Params::new(Network::Testnet)).header;
        assert_eq!(validate_append(Network::Testnet, &[], 0, &g, now()), Ok(()));

        // A bogus height-0 header is rejected: the genesis check now runs.
        let bogus_genesis = dummy_header(BlockHash::all_zeros(), bits, 1_231_006_505);
        assert_eq!(
            validate_append(Network::Testnet, &[], 0, &bogus_genesis, now()),
            Err(Error::GenesisMismatch)
        );

        // A synthetic (PoW-invalid) testnet header is rejected, not silently
        // accepted as before.
        let prev = dummy_header(BlockHash::all_zeros(), bits, 1_000_000);
        let incoming = dummy_header(prev.block_hash(), bits, 1_000_600);
        assert_eq!(
            validate_append(Network::Testnet, &[prev], 1, &incoming, now()),
            Err(Error::Pow)
        );

        // Linkage is enforced on testnet.
        let unrelated = dummy_header(BlockHash::from_byte_array([7u8; 32]), bits, 1_000_600);
        assert_eq!(
            check_linkage(&prev, &unrelated),
            Err(Error::PrevHashMismatch)
        );

        // MTP is enforced on testnet (Regtest is the only skip).
        let mut ancestors = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();
        for i in 1..=11u32 {
            let h = dummy_header(prev_hash, bits, i * 100);
            prev_hash = h.block_hash();
            ancestors.push(h);
        }
        let low = dummy_header(prev_hash, bits, 600);
        assert_eq!(
            check_mtp(Network::Testnet, &ancestors, &low),
            Err(Error::MtpViolation)
        );

        // A non-boundary bits change is tolerated on testnet: the retarget
        // check never runs, so BitsMismatch is never the rejection reason
        // (PoW is enforced ahead of it on synthetic headers).
        let relaxed = dummy_header(
            prev.block_hash(),
            CompactTarget::from_consensus(0x1d00fffe),
            1_000_600,
        );
        let res = validate_append(Network::Testnet, &[prev], 100, &relaxed, now());
        assert_ne!(res, Err(Error::BitsMismatch));
    }

    #[test]
    fn genesis_mainnet_accepts_canonical() {
        let g = genesis_block(Params::new(Network::Bitcoin)).header;
        assert_eq!(validate_append(Network::Bitcoin, &[], 0, &g, now()), Ok(()));
    }

    #[test]
    fn genesis_mainnet_rejects_bogus() {
        let bogus = dummy_header(
            BlockHash::all_zeros(),
            CompactTarget::from_consensus(0x1d00ffff),
            1_231_006_505,
        );
        assert_eq!(
            validate_append(Network::Bitcoin, &[], 0, &bogus, now()),
            Err(Error::GenesisMismatch)
        );
    }

    #[test]
    fn genesis_regtest_requires_pow() {
        // Regtest genesis is hash-unpinned, so an easy-bits header that
        // satisfies its own PoW is accepted at height 0.
        let easy = dummy_header(
            BlockHash::all_zeros(),
            CompactTarget::from_consensus(0x207fffff),
            1,
        );
        assert_eq!(
            validate_append(Network::Regtest, &[], 0, &easy, now()),
            Ok(())
        );
        // But PoW still applies: mainnet-hard bits with a zero nonce do not
        // hash below their target, so the height-0 header is rejected.
        let hard = dummy_header(
            BlockHash::all_zeros(),
            CompactTarget::from_consensus(0x1d00ffff),
            1,
        );
        assert_eq!(
            validate_append(Network::Regtest, &[], 0, &hard, now()),
            Err(Error::Pow)
        );
    }

    #[test]
    fn future_cap_rejects_three_hours_ahead() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let prev = dummy_header(BlockHash::all_zeros(), bits, 100);
        let incoming_time = (now() + 3 * 3600) as u32;
        let incoming = dummy_header(prev.block_hash(), bits, incoming_time);
        assert_eq!(
            validate_append(Network::Regtest, &[prev], 1, &incoming, now()),
            Err(Error::TimestampTooFarInFuture)
        );
    }

    #[test]
    fn future_cap_accepts_within_two_hours() {
        // Only test the future-cap sub-check; full validate_append would
        // reject due to PoW on synthetic headers.
        let bits = CompactTarget::from_consensus(0x207fffff);
        let h = dummy_header(
            BlockHash::all_zeros(),
            bits,
            (now() + MAX_FUTURE_BLOCK_TIME) as u32,
        );
        assert_eq!(check_future_cap(&h, now()), Ok(()));
    }

    #[test]
    fn mtp_rejects_timestamp_at_or_below_median() {
        // 11 ancestors with times [100, 200, ..., 1100], median = 600.
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let mut ancestors = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();
        for i in 1..=11u32 {
            let h = dummy_header(prev_hash, bits, i * 100);
            prev_hash = h.block_hash();
            ancestors.push(h);
        }
        let incoming = dummy_header(prev_hash, bits, 600);
        // Use the sub-check to avoid PoW interference.
        assert_eq!(
            check_mtp(Network::Bitcoin, &ancestors, &incoming),
            Err(Error::MtpViolation)
        );
    }

    #[test]
    fn mtp_accepts_timestamp_above_median() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let mut ancestors = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();
        for i in 1..=11u32 {
            let h = dummy_header(prev_hash, bits, i * 100);
            prev_hash = h.block_hash();
            ancestors.push(h);
        }
        let incoming = dummy_header(prev_hash, bits, 601);
        assert_eq!(check_mtp(Network::Bitcoin, &ancestors, &incoming), Ok(()));
    }

    #[test]
    fn mtp_skipped_on_regtest() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut ancestors = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();
        for i in 1..=11u32 {
            let h = dummy_header(prev_hash, bits, i * 100);
            prev_hash = h.block_hash();
            ancestors.push(h);
        }
        let incoming = dummy_header(prev_hash, bits, 50);
        assert_eq!(check_mtp(Network::Regtest, &ancestors, &incoming), Ok(()));
    }

    #[test]
    fn mtp_enforced_over_partial_window() {
        // Fewer than 11 ancestors: like Core, the median is taken over the
        // available window rather than skipped. Times [100..500], median 300.
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let mut ancestors = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();
        for i in 1..=5u32 {
            let h = dummy_header(prev_hash, bits, i * 100);
            prev_hash = h.block_hash();
            ancestors.push(h);
        }
        let low = dummy_header(prev_hash, bits, 300);
        assert_eq!(
            check_mtp(Network::Bitcoin, &ancestors, &low),
            Err(Error::MtpViolation)
        );
        let ok = dummy_header(prev_hash, bits, 301);
        assert_eq!(check_mtp(Network::Bitcoin, &ancestors, &ok), Ok(()));
    }

    #[test]
    fn mtp_skipped_with_no_ancestors() {
        // Genesis or a fresh anchor has no ancestors, so MTP cannot apply.
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let incoming = dummy_header(BlockHash::all_zeros(), bits, 1);
        assert_eq!(check_mtp(Network::Bitcoin, &[], &incoming), Ok(()));
    }

    #[test]
    fn bits_mismatch_at_non_boundary() {
        let bits_a = CompactTarget::from_consensus(0x1d00ffff);
        let bits_b = CompactTarget::from_consensus(0x1d00fffe);
        let params = Params::new(Network::Bitcoin);
        let prev = dummy_header(BlockHash::all_zeros(), bits_a, 1_000_000);
        let incoming = dummy_header(prev.block_hash(), bits_b, 1_000_600);
        // Height 100 is not a 2016 boundary, so this exercises the
        // non-boundary branch directly.
        assert_eq!(
            check_retarget(&params, &[prev], 100, &prev, &incoming),
            Err(Error::BitsMismatch)
        );
    }

    #[test]
    fn bits_match_at_non_boundary_ok() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let params = Params::new(Network::Bitcoin);
        let prev = dummy_header(BlockHash::all_zeros(), bits, 1_000_000);
        let incoming = dummy_header(prev.block_hash(), bits, 1_000_600);
        assert_eq!(
            check_retarget(&params, &[prev], 100, &prev, &incoming),
            Ok(())
        );
    }

    #[test]
    fn retarget_skipped_on_regtest() {
        let bits_a = CompactTarget::from_consensus(0x207fffff);
        let bits_b = CompactTarget::from_consensus(0x1d00ffff);
        let params = Params::new(Network::Regtest);
        let prev = dummy_header(BlockHash::all_zeros(), bits_a, 100);
        let incoming = dummy_header(prev.block_hash(), bits_b, 700);
        // With no_pow_retargeting, mismatching bits are accepted by
        // check_retarget. PoW is enforced separately.
        assert_eq!(
            check_retarget(&params, &[prev], 100, &prev, &incoming),
            Ok(())
        );
    }

    #[test]
    fn retarget_boundary_missing_ancestor() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let params = Params::new(Network::Bitcoin);
        let prev = dummy_header(BlockHash::all_zeros(), bits, 1_000_000);
        let incoming = dummy_header(prev.block_hash(), bits, 1_000_600);
        // Boundary height with fewer than 2016 ancestors.
        assert_eq!(
            check_retarget(&params, &[prev], 2016, &prev, &incoming),
            Err(Error::MissingAncestor)
        );
    }

    // Regtest never retargets, so the e2e suite cannot exercise a real
    // 2016-block boundary. This synthetic test drives the boundary branch
    // of `check_retarget` directly: a window of 2016 ancestors whose
    // `incoming.bits` exactly match the value `from_next_work_required`
    // recomputes must be accepted, and a tampered value rejected.
    #[test]
    fn retarget_boundary_accepts_expected_bits() {
        let params = Params::new(Network::Bitcoin);
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        // 2016 ancestors with a fixed 10-minute spacing.
        let mut ancestors = Vec::with_capacity(2016);
        let mut prev_hash = BlockHash::all_zeros();
        let mut t = 1_500_000_000u32;
        for _ in 0..2016 {
            let h = dummy_header(prev_hash, bits, t);
            prev_hash = h.block_hash();
            ancestors.push(h);
            t += 600;
        }
        let prev = *ancestors.last().unwrap();
        let period_start = &ancestors[0];
        let actual_timespan = (prev.time as i64 - period_start.time as i64) as u64;
        let expected = CompactTarget::from_next_work_required(prev.bits, actual_timespan, &params);

        let incoming = dummy_header(prev.block_hash(), expected, prev.time + 600);
        assert_eq!(
            check_retarget(&params, &ancestors, 2016, &prev, &incoming),
            Ok(())
        );

        // Tampered bits at the boundary are rejected.
        let wrong = CompactTarget::from_consensus(expected.to_consensus().wrapping_add(1));
        let bad = dummy_header(prev.block_hash(), wrong, prev.time + 600);
        assert_eq!(
            check_retarget(&params, &ancestors, 2016, &prev, &bad),
            Err(Error::BadRetarget)
        );
    }

    // A 2016-block window whose first block carries a LATER timestamp than
    // its last (legal: Bitcoin only enforces MTP, not monotonic
    // timestamps) yields a negative raw timespan. Bitcoin Core clamps a
    // negative nActualTimespan to the minimum (target_timespan/4), giving
    // the HARDEST target. The pre-fix code cast the negative i64 to u64,
    // wrapping to a huge positive value, which clamps to target_timespan
    // times four, the EASIEST target. This test asserts the validator now
    // expects the
    // hardest result, i.e. `from_next_work_required(prev.bits, 0, params)`
    // (a 0 timespan clamps identically to any negative one).
    #[test]
    fn retarget_boundary_negative_timespan_expects_hardest() {
        let params = Params::new(Network::Bitcoin);
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        // 2016 ancestors. period_start (index 0) is given the LATEST
        // timestamp; every later block is dated earlier, so prev.time <
        // period_start.time and the raw timespan is negative. Each header is
        // still MTP-valid because validate_append isn't exercised here; we
        // call check_retarget directly, which only reads prev.time and
        // period_start.time.
        let mut ancestors = Vec::with_capacity(2016);
        let mut prev_hash = BlockHash::all_zeros();
        // Start high so the window can run "backwards" without underflow.
        let mut t = 1_500_000_000u32 + 2016;
        for _ in 0..2016 {
            let h = dummy_header(prev_hash, bits, t);
            prev_hash = h.block_hash();
            ancestors.push(h);
            t = t.saturating_sub(1);
        }
        let prev = *ancestors.last().unwrap();
        let period_start = &ancestors[0];
        // Sanity: the window really does run backwards.
        assert!(period_start.time > prev.time);

        // The hardest result: a clamped (zero / negative) timespan.
        let hardest = CompactTarget::from_next_work_required(prev.bits, 0u64, &params);
        // The easiest result the buggy wrap would have produced: clamp at
        // target_timespan*4. They must differ, else the test proves nothing.
        let easiest = CompactTarget::from_next_work_required(
            prev.bits,
            params.pow_target_timespan * 4,
            &params,
        );
        assert_ne!(hardest, easiest, "hardest and easiest targets coincide");

        // The validator must accept the HARDEST bits at this boundary.
        let incoming = dummy_header(prev.block_hash(), hardest, prev.time + 600);
        assert_eq!(
            check_retarget(&params, &ancestors, 2016, &prev, &incoming),
            Ok(())
        );

        // ...and reject the easiest bits (what the wrapping bug expected).
        let bad = dummy_header(prev.block_hash(), easiest, prev.time + 600);
        assert_eq!(
            check_retarget(&params, &ancestors, 2016, &prev, &bad),
            Err(Error::BadRetarget)
        );
    }

    #[test]
    fn linkage_mismatch_detected() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let prev = dummy_header(BlockHash::all_zeros(), bits, 1_000_000);
        let unrelated = BlockHash::from_byte_array([7u8; 32]);
        let incoming = dummy_header(unrelated, bits, 1_000_600);
        assert_eq!(
            check_linkage(&prev, &incoming),
            Err(Error::PrevHashMismatch)
        );
    }

    #[test]
    fn pow_rejects_tampered_genesis() {
        let params = Params::new(Network::Bitcoin);
        let mut g = genesis_block(params.clone()).header;
        g.nonce ^= 1;
        assert_eq!(check_pow(&params, &g), Err(Error::Pow));
    }

    #[test]
    fn pow_accepts_canonical_genesis() {
        let params = Params::new(Network::Bitcoin);
        let g = genesis_block(params.clone()).header;
        assert_eq!(check_pow(&params, &g), Ok(()));
    }

    #[test]
    fn missing_ancestor_for_non_genesis_append() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let incoming = dummy_header(BlockHash::all_zeros(), bits, 1_000_000);
        assert_eq!(
            validate_append(Network::Bitcoin, &[], 1, &incoming, now()),
            Err(Error::MissingAncestor)
        );
    }

    #[test]
    fn median_time_picks_middle() {
        let mut ts = [11, 1, 9, 3, 7, 5, 6, 4, 8, 2, 10];
        assert_eq!(median_time(&mut ts), 6);
    }

    // Regression: a header that advertises an absurdly easy target
    // (0x207fffff, above mainnet's pow_limit) must be rejected even if its
    // hash happens to satisfy that easy target. `check_pow` clamps the
    // claimed target to `max_attainable_target` before validating.
    #[test]
    fn pow_rejects_low_difficulty_when_above_pow_limit() {
        let params = Params::new(Network::Bitcoin);
        // 0x207fffff is the regtest pow_limit; on mainnet it is far above
        // `max_attainable_target`, so any header carrying it is invalid.
        let easy = CompactTarget::from_consensus(0x207fffff);
        // A nonce of 0 over the regtest-easy target hashes below the easy
        // target with very high probability; clamping is what rejects it.
        let h = dummy_header(BlockHash::all_zeros(), easy, 1_000_000);
        assert_eq!(check_pow(&params, &h), Err(Error::Pow));
    }

    // Regression: a synthetic 2016-block window with an absurdly
    // slow timespan must still produce an expected target that does not
    // exceed `max_attainable_target` (from_next_work_required clamps
    // internally).
    #[test]
    fn retarget_result_never_exceeds_pow_limit() {
        let params = Params::new(Network::Bitcoin);
        // Start near the pow_limit so a slow window would otherwise push
        // the target above it.
        let start_bits = params.max_attainable_target.to_compact_lossy();
        // Absurdly slow window: far longer than 4x the target timespan.
        let actual_timespan = params.pow_target_timespan * 1000;
        let expected = CompactTarget::from_next_work_required(start_bits, actual_timespan, &params);
        assert!(
            Target::from_compact(expected) <= params.max_attainable_target,
            "retarget output {expected:?} exceeds pow_limit",
        );
    }
}
