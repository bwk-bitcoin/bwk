//! The sending component of silent payments.
//!
//! The [`generate_recipient_pubkeys`] function can be used to create outputs for a list of silent payment recipients.
//!
//! Using [`generate_recipient_pubkeys`] will require calculating a
//! `partial_secret` beforehand.
//! To do this, you can use [`calculate_partial_secret`](crate::core::sending::calculate_partial_secret) from the `utils` module.
//! See the [tests on github](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! for a concrete example.
//!
//! Source: adapted from SPDK's vendored `silentpayments` implementation,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.

use std::collections::HashMap;

use crate::core::{
    error::Error,
    secp256k1::{ecdh::shared_secret_point, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
    utils::{
        common::{calculate_t_n, SilentPaymentAddress},
        hash::calculate_input_hash,
    },
    PartialSecret, SharedSecret,
};
use bitcoin::OutPoint;

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// When creating the outputs for a transaction, this function should be used to generate the output keys.
///
/// This function should only be used once per transaction! If used multiple times, address reuse may occur.
///
/// # Arguments
///
/// * `recipients` - A [Vec] of silent payment addresses strings to be paid.
/// * `partial_secret` - The BIP352 partial secret for the transaction inputs.
///
/// # Returns
///
/// If successful, the function returns a [Result] wrapping a [HashMap] of silent payment addresses to a [Vec].
/// The [Vec] contains all the outputs that are associated with the silent payment address.
///
/// # Errors
///
/// This function will return an error if:
///
/// * The recipients [Vec] contains a silent payment address with an incorrect format.
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys(
    recipients: Vec<SilentPaymentAddress>,
    partial_secret: PartialSecret,
) -> Result<HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>>, Error> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<PublicKey, (SharedSecret, Vec<SilentPaymentAddress>)> =
        HashMap::new();
    for address in recipients {
        let B_scan = address.get_scan_key();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&B_scan) {
            payments.push(address);
        } else {
            let ecdh_shared_secret = calculate_ecdh_shared_secret(&B_scan, partial_secret);

            silent_payment_groups.insert(B_scan, (ecdh_shared_secret, vec![address]));
        }
    }

    let mut result: HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let (ecdh_shared_secret, recipients) = group;

        for (n, addr) in recipients.into_iter().enumerate() {
            let t_n = calculate_t_n(ecdh_shared_secret.as_inner(), n as u32)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&addr.get_spend_key())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(addr).or_default();
            entry.push(reskey_xonly);
        }
    }
    Ok(result)
}

/// Calculate the partial secret that is needed for generating the recipient pubkeys.
///
/// # Arguments
///
/// * `input_keys` - A reference to a list of tuples, each tuple containing a [SecretKey] and [bool]. The [SecretKey] is the private key used in the input, and the [bool] indicates whether this was from a taproot address.
/// * `outpoints` - The prevout outpoints used as input for this transaction.
///
/// # Returns
///
/// This function returns the partial secret, which represents the sum of all (eligible) input keys multiplied with the input hash.
///
/// # Errors
///
/// This function will error if:
///
/// * The input keys array is of length zero, or the summing results in an invalid key.
/// * The outpoints slice is empty.
pub fn calculate_partial_secret(
    input_keys: &[(SecretKey, bool)],
    outpoints: &[OutPoint],
) -> Result<PartialSecret, Error> {
    let a_sum = get_a_sum_secret_keys(input_keys)?;

    let secp = Secp256k1::signing_only();
    let A_sum = a_sum.public_key(&secp);

    let input_hash = calculate_input_hash(outpoints, A_sum)?;

    Ok(a_sum.mul_tweak(&input_hash)?.into())
}

/// Calculate the shared secret of a transaction.
///
/// Since [generate_recipient_pubkeys] calls this function internally, it is not needed for the default sending flow.
///
/// # Arguments
///
/// * `B_scan` - The scan public key used by the wallet.
/// * `partial_secret` - the sum of all (eligible) input keys multiplied with the input hash, see [calculate_partial_secret].
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to generate output keys for the recipient.
pub fn calculate_ecdh_shared_secret(
    B_scan: &PublicKey,
    partial_secret: PartialSecret,
) -> SharedSecret {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Using `shared_secret_point` to ensure the multiplication is constant time
    ss_bytes[1..].copy_from_slice(&shared_secret_point(B_scan, partial_secret.as_inner()));

    PublicKey::from_slice(&ss_bytes)
        .expect("guaranteed to be a point on the curve")
        .into()
}

fn get_a_sum_secret_keys(input: &[(SecretKey, bool)]) -> Result<SecretKey, Error> {
    let secp = crate::core::secp256k1::Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (key, is_taproot) in input {
        let (_, parity) = key.x_only_public_key(&secp);

        if *is_taproot && parity == crate::core::secp256k1::Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(*key);
        }
    }

    let (head, tail) = negated_keys.split_first().ok_or(Error::NoInputProvided)?;

    let result: SecretKey = tail
        .iter()
        .try_fold(*head, |acc, &item| acc.add_tweak(&item.into()))?;

    Ok(result)
}
