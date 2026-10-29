#![cfg(feature = "rust-bitcoin")]

mod common;

use bitcoin::{
    bip32::{ChainCode, ChildNumber, Fingerprint, Xpub},
    hashes::Hash,
    key::UntweakedPublicKey,
    secp256k1::PublicKey,
    taproot::TapTweakHash,
    NetworkKind,
};
use bwk_musig::{
    nonce_agg, nonce_gen, nonce_gen_with_rand, partial_agg, partial_sign, partial_verify,
    rust_bitcoin::RustBitcoin, synthetic_xpub, Error, KeyAgg, MusigBackend, Tweak,
};

use crate::common::{hex_arr, hex_keys, public_key, verify_bip340, CounterRng};

const MSG: [u8; 32] = [0x42; 32];

/// The secret keys of the two-signer tests.
const TWO_SIGNERS: [[u8; 32]; 2] = [[1; 32], [2; 32]];

/// The public messages of one signing round, and its signature.
struct Round {
    aggnonce: [u8; 66],
    pubnonces: Vec<[u8; 66]>,
    psigs: Vec<[u8; 32]>,
    signature: [u8; 64],
}

/// KeySort then KeyAgg of the keys of `secret_keys`.
fn sorted_key_agg(secret_keys: &[[u8; 32]]) -> KeyAgg<RustBitcoin> {
    let keys = secret_keys.iter().map(public_key).collect::<Vec<_>>();
    KeyAgg::sorted(&RustBitcoin, &keys).unwrap()
}

/// One full signing round of `secret_keys` over `keyagg`: nonces bound to `msg`, every
/// share verified, then aggregated.
fn sign_round(secret_keys: &[[u8; 32]], keyagg: &KeyAgg<RustBitcoin>, msg: &[u8; 32]) -> Round {
    let mut rng = CounterRng(0);
    let keys = secret_keys.iter().map(public_key).collect::<Vec<_>>();
    let mut secnonces = Vec::new();
    let mut pubnonces = Vec::new();
    for (sk, pk) in secret_keys.iter().zip(&keys) {
        let (secnonce, pubnonce) =
            nonce_gen(&RustBitcoin, &mut rng, keyagg, pk, Some(sk), Some(msg)).unwrap();
        secnonces.push(secnonce);
        pubnonces.push(pubnonce);
    }
    let aggnonce = nonce_agg(&RustBitcoin, &pubnonces).unwrap();

    let mut psigs = Vec::new();
    for (i, secnonce) in secnonces.into_iter().enumerate() {
        let psig = partial_sign(
            &RustBitcoin,
            secnonce,
            &secret_keys[i],
            keyagg,
            &aggnonce,
            msg,
        )
        .unwrap();
        assert!(partial_verify(
            &RustBitcoin,
            &psig,
            &pubnonces[i],
            &keys[i],
            keyagg,
            &aggnonce,
            msg
        ));
        psigs.push(psig);
    }
    let signature = partial_agg(&RustBitcoin, keyagg, &aggnonce, msg, &psigs).unwrap();
    Round {
        aggnonce,
        pubnonces,
        psigs,
        signature,
    }
}

#[test]
fn two_signers_round_trip_verifies_with_rust_bitcoin() {
    let keyagg = sorted_key_agg(&TWO_SIGNERS);
    let round = sign_round(&TWO_SIGNERS, &keyagg, &MSG);
    assert!(verify_bip340(&round.signature, &MSG, &keyagg.output_key()));
}

#[test]
fn three_signers_with_bip32_and_taptweak_verify() {
    let secret_keys = [[1; 32], [2; 32], [3; 32]];
    let keyagg = sorted_key_agg(&secret_keys);

    // The BIP-32 child 0 tweak of the BIP-328 synthetic xpub, then the BIP-341 tweak
    // of the derived key with no script tree.
    let synthetic = synthetic_xpub(&keyagg.aggregate());
    let xpub = Xpub {
        network: NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: PublicKey::from_slice(&synthetic.key).unwrap(),
        chain_code: ChainCode::from(synthetic.chain_code),
    };
    let (bip32, _) = xpub
        .ckd_pub_tweak(ChildNumber::Normal { index: 0 })
        .unwrap();
    let derived = keyagg
        .with_tweaks(
            &RustBitcoin,
            &[Tweak {
                scalar: bip32.secret_bytes(),
                x_only: false,
            }],
        )
        .unwrap();
    let internal = UntweakedPublicKey::from_slice(&derived.output_key()[1..]).unwrap();
    let taptweak = Tweak {
        scalar: TapTweakHash::from_key_and_tweak(internal, None).to_byte_array(),
        x_only: true,
    };
    let output = derived.with_tweaks(&RustBitcoin, &[taptweak]).unwrap();

    let round = sign_round(&secret_keys, &output, &MSG);
    assert!(verify_bip340(&round.signature, &MSG, &output.output_key()));
    assert!(!verify_bip340(&round.signature, &MSG, &output.aggregate()));
}

#[test]
fn partial_sign_rejects_non_participant() {
    // BIP-327 sign error case 0: the signer's key 0 is not in the list `[1, 2]`.
    let sk = hex_arr("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671");
    let keys = hex_keys(&[
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
    ]);
    let aggnonce = hex_arr("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9");
    let msg = hex_arr("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF");
    let keyagg = KeyAgg::new(&RustBitcoin, &keys[1..]).unwrap();
    let (secnonce, _) = nonce_gen_with_rand(
        &RustBitcoin,
        &[7; 32],
        None,
        &keys[0],
        Some(&sk),
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        partial_sign(&RustBitcoin, secnonce, &sk, &keyagg, &aggnonce, &msg),
        Err(Error::NotParticipant)
    );
}

#[test]
fn partial_sign_rejects_foreign_secret_key() {
    let keyagg = sorted_key_agg(&TWO_SIGNERS);
    let round = sign_round(&TWO_SIGNERS, &keyagg, &MSG);
    let (secnonce, _) = nonce_gen(
        &RustBitcoin,
        &mut CounterRng(9),
        &keyagg,
        &public_key(&TWO_SIGNERS[0]),
        Some(&TWO_SIGNERS[0]),
        Some(&MSG),
    )
    .unwrap();
    assert_eq!(
        partial_sign(
            &RustBitcoin,
            secnonce,
            &TWO_SIGNERS[1],
            &keyagg,
            &round.aggnonce,
            &MSG
        ),
        Err(Error::NonceKeyMismatch)
    );
}

#[test]
fn nonce_gen_draws_fresh_randomness() {
    let sk = TWO_SIGNERS[0];
    let pk = public_key(&sk);
    let keyagg = sorted_key_agg(&TWO_SIGNERS);
    let mut rng = CounterRng(0);
    let (_, first) =
        nonce_gen(&RustBitcoin, &mut rng, &keyagg, &pk, Some(&sk), Some(&MSG)).unwrap();
    let (_, second) =
        nonce_gen(&RustBitcoin, &mut rng, &keyagg, &pk, Some(&sk), Some(&MSG)).unwrap();
    assert_ne!(first, second);
}

#[test]
fn nonce_gen_binds_message() {
    let sk = [1; 32];
    let pk = public_key(&sk);
    let pubnonce_for = |msg: &[u8; 32]| {
        nonce_gen_with_rand(
            &RustBitcoin,
            &[7; 32],
            None,
            &pk,
            Some(&sk),
            Some(msg),
            None,
        )
        .unwrap()
        .1
    };
    assert_ne!(pubnonce_for(&[1; 32]), pubnonce_for(&[2; 32]));
    assert_eq!(pubnonce_for(&[1; 32]), pubnonce_for(&[1; 32]));
}

#[test]
fn zero_rand_is_rejected() {
    let sk = [1; 32];
    let result = nonce_gen_with_rand(
        &RustBitcoin,
        &[0; 32],
        None,
        &public_key(&sk),
        Some(&sk),
        None,
        None,
    );
    assert_eq!(result.err(), Some(Error::InvalidSecNonce));
}

#[test]
fn nonce_agg_rejects_empty() {
    assert_eq!(nonce_agg(&RustBitcoin, &[]), Err(Error::NoNonces));
}

#[test]
fn partial_verify_rejects_tampered_share() {
    let keyagg = sorted_key_agg(&TWO_SIGNERS);
    let round = sign_round(&TWO_SIGNERS, &keyagg, &MSG);
    let mut tampered = round.psigs.clone();
    tampered[0][31] ^= 1;
    assert!(!partial_verify(
        &RustBitcoin,
        &tampered[0],
        &round.pubnonces[0],
        &public_key(&TWO_SIGNERS[0]),
        &keyagg,
        &round.aggnonce,
        &MSG
    ));

    let forged = partial_agg(&RustBitcoin, &keyagg, &round.aggnonce, &MSG, &tampered).unwrap();
    assert!(verify_bip340(&round.signature, &MSG, &keyagg.output_key()));
    assert!(!verify_bip340(&forged, &MSG, &keyagg.output_key()));
}

#[test]
fn partial_agg_rejects_wrong_share_count() {
    let keyagg = sorted_key_agg(&TWO_SIGNERS);
    let round = sign_round(&TWO_SIGNERS, &keyagg, &MSG);
    assert_eq!(
        partial_agg(
            &RustBitcoin,
            &keyagg,
            &round.aggnonce,
            &MSG,
            &round.psigs[..1]
        ),
        Err(Error::PartialSigCount)
    );
    assert_eq!(
        RustBitcoin.partial_agg(keyagg.cache(), &round.aggnonce, &MSG, &[]),
        Err(Error::PartialSigCount)
    );
}
