//! BIP374 discrete logarithm equality proofs.
//!
//! Source: ported as part of the SPDK silent-payment implementation.
//! See `sp/NOTICE`.

use crate::core::{
    secp256k1::{constants::CURVE_ORDER, PublicKey, Scalar, Secp256k1, SecretKey},
    utils::hash::{DleqAuxHash, DleqChallengeHash, DleqNonceHash},
};
use bitcoin_hashes::{Hash, HashEngine};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DleqProof([u8; 64]);

impl DleqProof {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for DleqProof {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

pub fn generate_proof(
    secret: SecretKey,
    base: PublicKey,
    aux_rand: [u8; 32],
    generator: PublicKey,
    message: Option<[u8; 32]>,
) -> Option<DleqProof> {
    let secp = Secp256k1::verification_only();
    let secret_scalar = Scalar::from(secret);
    let public = match generator.mul_tweak(&secp, &secret_scalar) {
        Ok(public) => public,
        Err(_) => return None,
    };
    let shared_secret = match base.mul_tweak(&secp, &secret_scalar) {
        Ok(shared_secret) => shared_secret,
        Err(_) => return None,
    };

    let mut nonce_input = secret.secret_bytes();
    let aux_hash = DleqAuxHash::hash(&aux_rand).to_byte_array();
    for (byte, aux_byte) in nonce_input.iter_mut().zip(aux_hash) {
        *byte ^= aux_byte;
    }

    let mut nonce_engine = DleqNonceHash::engine();
    nonce_engine.input(&nonce_input);
    nonce_engine.input(&public.serialize());
    nonce_engine.input(&shared_secret.serialize());
    nonce_engine.input(message.as_ref().map_or(&[], |message| message));
    let nonce = scalar(DleqNonceHash::from_engine(nonce_engine).to_byte_array());
    if nonce == Scalar::ZERO {
        return None;
    }

    let r1 = match generator.mul_tweak(&secp, &nonce) {
        Ok(r1) => r1,
        Err(_) => return None,
    };
    let r2 = match base.mul_tweak(&secp, &nonce) {
        Ok(r2) => r2,
        Err(_) => return None,
    };
    let challenge = challenge(public, base, shared_secret, generator, r1, r2, message);
    let challenge_scalar = scalar(challenge);
    let response = if challenge_scalar == Scalar::ZERO {
        nonce
    } else {
        match secret.mul_tweak(&challenge_scalar) {
            Ok(product) => match product.add_tweak(&nonce) {
                Ok(response) => Scalar::from(response),
                Err(_) => Scalar::ZERO,
            },
            Err(_) => return None,
        }
    };

    let mut proof = [0; 64];
    proof[..32].copy_from_slice(&challenge);
    proof[32..].copy_from_slice(&response.to_be_bytes());
    let proof = DleqProof(proof);
    verify_proof(public, base, shared_secret, proof, generator, message).then_some(proof)
}

pub fn verify_proof(
    public: PublicKey,
    base: PublicKey,
    shared_secret: PublicKey,
    proof: DleqProof,
    generator: PublicKey,
    message: Option<[u8; 32]>,
) -> bool {
    let secp = Secp256k1::verification_only();
    let challenge_bytes: [u8; 32] = proof.0[..32]
        .try_into()
        .expect("proof challenge is 32 bytes");
    let response_bytes: [u8; 32] = proof.0[32..]
        .try_into()
        .expect("proof response is 32 bytes");
    let Ok(response) = Scalar::from_be_bytes(response_bytes) else {
        return false;
    };
    let challenge_scalar = scalar(challenge_bytes);

    let Ok(response_generator) = generator.mul_tweak(&secp, &response) else {
        return false;
    };
    let Ok(challenge_public) = public.mul_tweak(&secp, &challenge_scalar) else {
        return false;
    };
    let Ok(r1) = response_generator.combine(&challenge_public.negate(&secp)) else {
        return false;
    };

    let Ok(response_base) = base.mul_tweak(&secp, &response) else {
        return false;
    };
    let Ok(challenge_shared_secret) = shared_secret.mul_tweak(&secp, &challenge_scalar) else {
        return false;
    };
    let Ok(r2) = response_base.combine(&challenge_shared_secret.negate(&secp)) else {
        return false;
    };

    challenge_bytes == challenge(public, base, shared_secret, generator, r1, r2, message)
}

fn challenge(
    public: PublicKey,
    base: PublicKey,
    shared_secret: PublicKey,
    generator: PublicKey,
    r1: PublicKey,
    r2: PublicKey,
    message: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut engine = DleqChallengeHash::engine();
    for point in [public, base, shared_secret, generator, r1, r2] {
        engine.input(&point.serialize());
    }
    engine.input(message.as_ref().map_or(&[], |message| message));
    DleqChallengeHash::from_engine(engine).to_byte_array()
}

fn scalar(mut bytes: [u8; 32]) -> Scalar {
    if Scalar::from_be_bytes(bytes).is_err() {
        let mut borrow = 0;
        for (byte, order_byte) in bytes.iter_mut().zip(CURVE_ORDER).rev() {
            let value = *byte as i16 - order_byte as i16 - borrow;
            *byte = value as u8;
            borrow = i16::from(value < 0);
        }
    }
    Scalar::from_be_bytes(bytes).expect("a 256-bit hash reduced by the curve order is a scalar")
}

#[cfg(test)]
mod tests {
    use crate::core::{
        dleq::{generate_proof, verify_proof, DleqProof},
        secp256k1::{PublicKey, SecretKey},
    };

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn point(hex: &str) -> PublicKey {
        PublicKey::from_slice(&hex::decode(hex).unwrap()).unwrap()
    }

    #[test]
    fn generate_proof_matches_bip374_vector() {
        let proof = generate_proof(
            SecretKey::from_slice(&bytes::<32>(
                "07ff93d43f1012a5d4a44aba55240212ed39c87b3344e46757d99f24177fc576",
            ))
            .unwrap(),
            point("02dad4b35c2379ba8334c9a5dda8f6e6d5cd575a7cc9d3ca4faaac51839daaa30f"),
            bytes("cb979b0fc8ccc7f237751e719d992fcc324b6500af33999cd54a3e5c05fb1ea4"),
            point("02cef38f55e78b321a1f785cb1c6e33dfcef9784c18bdc4e279801c449ccdfb88e"),
            Some(bytes(
                "efb07d4b382d3da1079fbf24df623ba6c2e4c764993bbfa6dd7a4fe4aaf33859",
            )),
        )
        .unwrap();

        assert_eq!(
            proof.as_bytes(),
            &bytes::<64>("7e7e934169e0bf4706e6b29e5a621c7fe199a524744a25af80071e111c0e2e94118e730d8add118dd2ee4f7d1cc183e1b87168362d1a6f85c16d8671a3fc7a8a")
        );
    }

    #[test]
    fn verify_proof_matches_bip374_vectors() {
        let generator = point("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let public = point("03611410561c35dae13135e4ad8094baac9bbcf2f4e18498181a8ff8a6d43be9d9");
        let base = point("021cb81121a00f89769903305a367ad3cc02d5b402b12c026e06ac94bde28cd608");
        let shared_secret =
            point("03d9a98624c0c74fc7eebd39ed84175f80d03c774908e75ca737a0745d1c64e20a");
        let proof = DleqProof::from(bytes("78a5544afa75bf152653fe55fb76926f2f65131bf090972a0b0b37d310c28a6bde0e7bfacc10ac12d36f55316ba134b6ba0b844a65ae05cad53c0b296c6639bb"));
        let message = Some(bytes(
            "22616bb5fb2d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794",
        ));

        assert!(verify_proof(
            public,
            base,
            shared_secret,
            proof,
            generator,
            message
        ));
        assert!(!verify_proof(
            base,
            public,
            shared_secret,
            proof,
            generator,
            message
        ));
        assert!(!verify_proof(
            public,
            base,
            shared_secret,
            proof,
            generator,
            Some(bytes(
                "22616bb5fb6d7c68270f305122f2a09e833239c4b1c9a04e285119fb606ac794"
            ))
        ));
    }
}
