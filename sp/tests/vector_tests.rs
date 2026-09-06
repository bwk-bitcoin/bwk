//! Source: adapted from SPDK's vendored `silentpayments` vector tests,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.

#![allow(non_snake_case)]
mod sp_common;
#[cfg(test)]
mod tests {
    use bitcoin::{OutPoint, Txid};
    use bitcoin_hashes::{hash160, Hash};
    use bwk_sp::core::{
        receiving::Label,
        secp256k1::{Scalar, Secp256k1, SecretKey},
        sending::{calculate_ecdh_shared_secret, calculate_partial_secret},
        utils::common::{Network, SilentPaymentAddress},
        SpVersion,
    };
    use std::{collections::HashSet, str::FromStr};

    use bwk_sp::core::receiving::Receiver;

    use bwk_sp::core::sending::generate_recipient_pubkeys;

    use crate::sp_common::{
        structs::TestData,
        utils::{
            self, decode_outputs_to_check, decode_recipients, verify_and_calculate_signatures,
        },
    };

    const NETWORK: Network = Network::Mainnet;

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: TestData) {
        if tests_deleted_input_parsing(&test_case.comment) {
            return;
        }

        println!("test: {}", test_case.comment);
        let secp = Secp256k1::new();

        let mut sending_outputs: HashSet<String> = HashSet::new();
        let mut partial_secrets = Vec::new();

        for sendingtest in test_case.sending {
            let given = sendingtest.given;
            let expected = sendingtest.expected;
            let outpoints: Vec<OutPoint> = given
                .vin
                .iter()
                .map(|vin| OutPoint {
                    txid: Txid::from_str(&vin.txid).unwrap(),
                    vout: vin.vout,
                })
                .collect();
            let mut input_priv_keys = Vec::new();
            for input in given.vin {
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();
                let input_key = SecretKey::from_str(&input.private_key).unwrap();
                if let Some(input_priv_key) = sp_input_priv_key(input_key, &script_pub_key, &secp) {
                    input_priv_keys.push(input_priv_key);
                }
            }
            if input_priv_keys.is_empty() {
                continue;
            }

            // we drop the amounts from the test here, since we don't work with amounts
            // the wallet should make sure the amount sent are correct
            let silent_addresses = decode_recipients(&given.recipients);

            // as an alternative, we could first multiply each input priv key with the input hash
            // that way, we never expose the sk to our library
            let partial_secret = calculate_partial_secret(&input_priv_keys, &outpoints).unwrap();
            partial_secrets.push(partial_secret);
            let outputs = generate_recipient_pubkeys(silent_addresses, partial_secret).unwrap();

            for output_pubkeys in &outputs {
                for pubkey in output_pubkeys.1 {
                    sending_outputs.insert(hex::encode(pubkey.serialize()));
                }
            }
            assert!(expected.outputs.iter().any(|candidate_set| {
                sending_outputs
                    .iter()
                    .all(|output| candidate_set.contains(output))
            }));
        }

        for receivingtest in test_case.receiving {
            if partial_secrets.is_empty() {
                continue;
            }

            let given = receivingtest.given;
            let expected = receivingtest.expected;

            let b_scan = SecretKey::from_str(&given.key_material.scan_priv_key).unwrap();
            let b_spend = SecretKey::from_str(&given.key_material.spend_priv_key).unwrap();
            let B_spend = b_spend.public_key(&secp);
            let B_scan = b_scan.public_key(&secp);

            let change_label = Label::new(b_scan, 0);
            let mut sp_receiver =
                Receiver::new(SpVersion::V0, B_scan, B_spend, change_label, NETWORK).unwrap();

            let outputs_to_check = decode_outputs_to_check(&given.outputs);

            for label_int in &given.labels {
                let label = Label::new(b_scan, *label_int);
                sp_receiver.add_label(label).unwrap();
            }

            let mut receiving_addresses: HashSet<SilentPaymentAddress> = HashSet::new();
            receiving_addresses.insert(sp_receiver.get_receiving_address());
            if given.labels.contains(&0) {
                receiving_addresses.insert(sp_receiver.get_change_address());
            }

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            assert!(set1.is_subset(&set2));

            let ecdh_shared_secret = calculate_ecdh_shared_secret(&B_scan, partial_secrets[0]);

            let scanned_outputs_received = sp_receiver
                .scan_transaction(ecdh_shared_secret, &outputs_to_check)
                .unwrap();

            let key_tweaks: Vec<Scalar> = scanned_outputs_received
                .into_iter()
                .flat_map(|(_, map)| {
                    let mut ret: Vec<Scalar> = vec![];
                    for l in map.into_values() {
                        ret.push(l);
                    }
                    ret
                })
                .collect();

            let res = verify_and_calculate_signatures(key_tweaks, b_spend).unwrap();
            assert!(expected.outputs.len() == res.len());
            assert!(res.iter().all(|output| expected.outputs.contains(output)));
        }
    }

    fn sp_input_priv_key(
        input_key: SecretKey,
        script_pub_key: &[u8],
        secp: &Secp256k1<bwk_sp::core::secp256k1::All>,
    ) -> Option<(SecretKey, bool)> {
        match script_pub_key {
            [0x51, 0x20, ..] => Some((input_key, true)),
            [0x00, 0x14, hash @ ..] | [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac]
                if hash == compressed_pubkey_hash(input_key, secp).as_byte_array() =>
            {
                Some((input_key, false))
            }
            _ => None,
        }
    }

    fn compressed_pubkey_hash(
        input_key: SecretKey,
        secp: &Secp256k1<bwk_sp::core::secp256k1::All>,
    ) -> hash160::Hash {
        hash160::Hash::hash(&input_key.public_key(secp).serialize())
    }

    fn tests_deleted_input_parsing(comment: &str) -> bool {
        matches!(
            comment,
            "No valid inputs, sender generates no outputs"
                | "P2PKH and P2WPKH Uncompressed Keys are skipped"
                | "Pubkey extraction from malleated p2pkh"
                | "Single recipient: taproot input with NUMS point"
                | "Skip invalid P2SH inputs"
        )
    }
}
