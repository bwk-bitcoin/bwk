//! Funds-critical equivalence: the single-call candidate-spk derivation must
//! produce exactly the same SET of output spks as taking the values of
//! `get_spks_from_shared_secret`, for every tweak.
use std::collections::HashSet;

use bwk_sp::core::{
    receiving::{calculate_ecdh_shared_secret, Label, Receiver},
    secp256k1::{rand, PublicKey, Secp256k1, SecretKey},
    utils::common::Network,
    SpVersion,
};

#[test]
fn candidate_spks_match_get_spks_from_shared_secret() {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    let scan_key = SecretKey::new(&mut rng);
    let spend_key = SecretKey::new(&mut rng);
    let scan_pubkey = scan_key.public_key(&secp);
    let spend_pubkey = spend_key.public_key(&secp);

    // change label (index 0) plus a couple extra labels.
    let change_label = Label::new(scan_key, 0);
    let mut receiver = Receiver::new(
        SpVersion::V0,
        scan_pubkey,
        spend_pubkey,
        change_label,
        Network::Regtest,
    )
    .unwrap();
    receiver.add_label(Label::new(scan_key, 1)).unwrap();
    receiver.add_label(Label::new(scan_key, 2)).unwrap();

    // Spend points are constant across tweaks: compute them once.
    let spend_points = receiver.candidate_spend_points().unwrap();

    for _ in 0..200 {
        let tweak = PublicKey::from_secret_key(&secp, &SecretKey::new(&mut rng));
        let tweak_bytes = tweak.serialize();

        let fast: HashSet<[u8; 34]> = receiver
            .candidate_output_spks(&tweak_bytes, &scan_key, &spend_points)
            .unwrap()
            .into_iter()
            .collect();

        let shared_secret = calculate_ecdh_shared_secret(&tweak, &scan_key);
        let reference: HashSet<[u8; 34]> = receiver
            .get_spks_from_shared_secret(shared_secret)
            .unwrap()
            .into_values()
            .collect();

        assert_eq!(fast, reference, "candidate spk set must match exactly");
    }
}
