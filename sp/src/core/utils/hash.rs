//! Source: adapted from SPDK's vendored `silentpayments` implementation,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.

use crate::core::{
    error::Error,
    secp256k1::{PublicKey, Scalar, SecretKey},
};
use bitcoin::{hashes::Hash as BitcoinHash, OutPoint};
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};

sha256t_hash_newtype! {
    pub(crate) struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub(crate) struct InputsHash(_);

    pub(crate) struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub(crate) struct LabelHash(_);

    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);

}

impl InputsHash {
    pub(crate) fn from_outpoint_and_A_sum(
        smallest_outpoint: &OutPoint,
        A_sum: PublicKey,
    ) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint.txid.to_byte_array());
        eng.input(&smallest_outpoint.vout.to_le_bytes());
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }
    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl LabelHash {
    pub(crate) fn from_b_scan_and_m(b_scan: SecretKey, m: u32) -> LabelHash {
        let mut eng = LabelHash::engine();
        eng.input(&b_scan.secret_bytes());
        eng.input(&m.to_be_bytes());
        LabelHash::from_engine(eng)
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl SharedSecretHash {
    pub(crate) fn from_ecdh_and_k(ecdh: &PublicKey, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}

pub fn calculate_input_hash(outpoints: &[OutPoint], A_sum: PublicKey) -> Result<Scalar, Error> {
    let smallest_outpoint = outpoints
        .iter()
        .min_by_key(|outpoint| (outpoint.txid.to_byte_array(), outpoint.vout.to_le_bytes()));
    let smallest_outpoint = smallest_outpoint.ok_or(Error::NoOutpointsProvided)?;

    Ok(InputsHash::from_outpoint_and_A_sum(smallest_outpoint, A_sum).to_scalar())
}

#[cfg(test)]
mod tests {
    use crate::core::{
        error::Error,
        secp256k1::{Secp256k1, SecretKey},
        utils::hash::calculate_input_hash,
    };

    #[test]
    fn input_hash_rejects_empty_outpoints() {
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let sum = secret.public_key(&Secp256k1::new());

        assert!(matches!(
            calculate_input_hash(&[], sum),
            Err(Error::NoOutpointsProvided)
        ));
    }
}
