//! Source: adapted from SPDK's vendored `silentpayments` vector-test helpers,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.

use std::str::FromStr;

use bitcoin_hashes::Hash;
use bwk_sp::core::{
    secp256k1::{Message, Scalar, SecretKey, XOnlyPublicKey},
    utils::common::SilentPaymentAddress,
};
use serde_json::from_str;

use super::structs::{OutputWithSignature, TestData};

pub fn read_file() -> Vec<TestData> {
    from_str(include_str!(
        "../resources/send_and_receive_test_vectors.json"
    ))
    .unwrap()
}

pub fn decode_outputs_to_check(outputs: &[String]) -> Vec<XOnlyPublicKey> {
    outputs
        .iter()
        .map(|x| XOnlyPublicKey::from_str(x).unwrap())
        .collect()
}

pub fn decode_recipients(recipients: &[String]) -> Vec<SilentPaymentAddress> {
    recipients
        .iter()
        .map(|sp_addr_str| sp_addr_str.as_str().try_into().unwrap())
        .collect()
}

pub fn verify_and_calculate_signatures(
    key_tweaks: Vec<Scalar>,
    b_spend: SecretKey,
) -> Result<Vec<OutputWithSignature>, bwk_sp::core::secp256k1::Error> {
    let secp = bwk_sp::core::secp256k1::Secp256k1::new();

    let msg = Message::from_digest(bitcoin_hashes::sha256::Hash::hash(b"message").to_byte_array());
    let aux = bitcoin_hashes::sha256::Hash::hash(b"random auxiliary data").to_byte_array();

    let mut res: Vec<OutputWithSignature> = vec![];
    for tweak in key_tweaks {
        // Add the tweak to the b_spend to get the final key
        let k = b_spend.add_tweak(&tweak)?;

        // get public key
        let P = k.x_only_public_key(&secp).0;

        // Sign the message with schnorr
        let sig = secp.sign_schnorr_with_aux_rand(&msg, &k.keypair(&secp), &aux);

        // Verify the message is correct
        secp.verify_schnorr(&sig, &msg, &P)?;

        // Push result to list
        res.push(OutputWithSignature {
            pub_key: P.to_string(),
            priv_key_tweak: hex::encode(tweak.to_be_bytes()),
            signature: sig.to_string(),
        });
    }
    Ok(res)
}
