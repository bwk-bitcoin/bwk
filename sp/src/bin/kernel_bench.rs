//! Single-threaded microbenchmark for the SP-scan candidate-spk EC kernel.
//!
//! Times the per-tweak path vs the batched path on the SAME in-memory tweaks,
//! single-threaded, in one process, so the clock/thermal state is identical for
//! both and the A/B *ratio* is reliable even on a throttling laptop (absolute
//! ns vary with clock; the ratio does not). No oracle, no rayon, no network.
//!
//! Usage: `cargo run --release -p bwk-sp --bin kernel_bench [N]`

use std::time::Instant;

use bitcoin_hashes::{sha256, Hash};
use bwk_sp::core::{
    receiving::{Label, Receiver},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    utils::common::Network,
    SpVersion,
};

fn main() {
    let secp = Secp256k1::new();
    let key = |domain: &str, i: usize| -> SecretKey {
        let h = sha256::Hash::hash(format!("{domain}-{i}").as_bytes());
        SecretKey::from_slice(h.as_byte_array()).expect("valid seckey")
    };

    let scan_key = key("scan", 0);
    let spend_pubkey = PublicKey::from_secret_key(&secp, &key("spend", 0));
    let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_key);
    let change_label = Label::new(scan_key, 0);
    let receiver = Receiver::new(
        SpVersion::V0,
        scan_pubkey,
        spend_pubkey,
        change_label,
        Network::Regtest,
    )
    .unwrap();
    let spend_points = receiver.candidate_spend_points().unwrap();

    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    // Serialize the tweaks once, up front, so the timed loops measure the EC
    // kernel rather than per-round point serialization.
    let tweaks: Vec<[u8; 33]> = (0..n)
        .map(|i| PublicKey::from_secret_key(&secp, &key("tweak", i)).serialize())
        .collect();

    println!("tweaks={n} spend_points={}", spend_points.len());

    // Sanity: the two paths must agree (checked once, cheaply).
    {
        let a = receiver
            .candidate_output_spks(&tweaks[0], &scan_key, &spend_points)
            .unwrap();
        let b = receiver
            .candidate_output_spks_batch(&tweaks[..1], &scan_key, &spend_points)
            .unwrap();
        assert_eq!(a, b, "per-tweak vs batch mismatch");
    }

    let mut acc = 0u64;
    let mut best_per = f64::INFINITY;
    let mut best_batch = f64::INFINITY;
    for round in 0..6 {
        let t = Instant::now();
        for tw in &tweaks {
            let r = receiver
                .candidate_output_spks(tw, &scan_key, &spend_points)
                .unwrap();
            acc = acc.wrapping_add(r[0][2] as u64);
        }
        let per_ns = t.elapsed().as_nanos() as f64 / n as f64;

        let t = Instant::now();
        let rb = receiver
            .candidate_output_spks_batch(&tweaks, &scan_key, &spend_points)
            .unwrap();
        acc = acc.wrapping_add(rb[0][2] as u64);
        let batch_ns = t.elapsed().as_nanos() as f64 / n as f64;

        best_per = best_per.min(per_ns);
        best_batch = best_batch.min(batch_ns);
        println!(
            "round {round}: per-tweak {per_ns:7.1} ns/tweak | batch {batch_ns:7.1} ns/tweak | speedup {:.3}x",
            per_ns / batch_ns
        );
    }
    println!(
        "BEST: per-tweak {best_per:.1} ns/tweak | batch {best_batch:.1} ns/tweak | speedup {:.3}x (acc={acc})",
        best_per / best_batch
    );
}
