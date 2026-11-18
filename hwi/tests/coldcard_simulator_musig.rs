//! The Coldcard simulator (seed C) as a MuSig2 participant next to bwk `HotSigner`s
//! (A and B), on the bwk-bup 2-of-3 compiled to 3 `pk(musig(..))` leaves, spending
//! the leaf of A and C, and on a `musig(A,C)` key path next to a recovery leaf of B
//! (see `common::coldcard_sim` for the environment).

#![cfg(all(feature = "coldcard", feature = "ledger", feature = "musig", unix))]

mod common;

use std::{
    thread,
    time::{Duration, Instant},
};

use bitcoin::{bip32::Fingerprint, psbt::Psbt, taproot::TapLeafHash, Amount};
use bwk_bup::{KeyType, OXpub};
use bwk_descriptor::{musig::musig_descriptor_to_string, wallet::WalletDescriptor};
use bwk_hwi::{coldcard::Coldcard, Error as HWIError, HWI};
use bwk_psbt::musig::{
    musig_input_partial_sigs, musig_input_pub_nonces, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
};

use common::{
    coldcard_sim::{enroll, Approver, SimProcess},
    musig::{
        device_key, finalize_and_verify, key_path_2_of_2_with_recovery, merge_round, offline_psbt,
        policy_2_of_3, restrict_to_key_path, restrict_to_leaf, spend_leaf, without_nonces,
        HotParticipant,
    },
    SEED_A, SEED_B, SEED_C,
};

const WALLET_NAME: &str = "bwk-musig-2of3";
/// The failure story comes after the `stok` answer.
const STORY_TIMEOUT: Duration = Duration::from_secs(5);
const COIN: Amount = Amount::from_sat(100_000);

/// The simulator with the 2-of-3 enrolled, the hot participant A and the
/// descriptor.
struct Setup {
    sim: SimProcess,
    coldcard: Coldcard,
    a: HotParticipant,
    c_key: OXpub,
    descriptor: WalletDescriptor,
}

impl Setup {
    /// `with(policy_2_of_3)`.
    fn new() -> Self {
        Self::with(policy_2_of_3)
    }

    /// Starts the simulator, reads C's role key from it, compiles `policy` over A, B
    /// and C and enrolls it.
    fn with(policy: fn(&OXpub, &OXpub, &OXpub) -> WalletDescriptor) -> Self {
        let sim = SimProcess::start(SEED_C);
        let coldcard = Coldcard::connect_simulator(sim.socket()).unwrap();
        let a = HotParticipant::new(SEED_A, KeyType::Internal);
        let b = HotParticipant::new(SEED_B, KeyType::Cosigner);
        let c_key = device_key(&coldcard, KeyType::External);
        assert_eq!(c_key, HotParticipant::new(SEED_C, KeyType::External).key);
        let descriptor = policy(&a.key, &b.key, &c_key);
        let coldcard = enroll_descriptor(&sim, coldcard, &descriptor);
        Self {
            sim,
            coldcard,
            a,
            c_key,
            descriptor,
        }
    }

    /// Restarts the simulator (it forgets everything), reconnects and enrolls again.
    fn restart(&mut self) {
        self.sim.restart();
        let coldcard = Coldcard::connect_simulator(self.sim.socket()).unwrap();
        self.coldcard = enroll_descriptor(&self.sim, coldcard, &self.descriptor);
    }

    /// The receive coin at index 0, restricted to the leaf of A and C.
    fn leaf_psbt(&self) -> Psbt {
        let mut psbt = offline_psbt(&self.descriptor, 0, 0, COIN);
        restrict_to_leaf(&mut psbt, &self.descriptor, 0, 0, self.signers());
        psbt
    }

    fn signers(&self) -> [Fingerprint; 2] {
        [self.a.signer.fingerprint(), self.c_fingerprint()]
    }

    fn c_fingerprint(&self) -> Fingerprint {
        self.c_key.origin.as_ref().unwrap().0
    }

    /// The Coldcard's answer to `psbt`, every story approved.
    fn coldcard_sign(&self, psbt: &Psbt) -> Psbt {
        let approver = Approver::spawn(self.sim.socket());
        let mut answer = psbt.clone();
        self.coldcard.sign_tx(&mut answer).unwrap();
        println!("stories seen while signing: {:#?}", approver.stories());
        answer
    }

    /// The Coldcard refuses `psbt` with `MusigSession` and shows a story containing
    /// `reason`.
    fn coldcard_lost_session(&self, psbt: &Psbt, reason: &str) {
        let approver = Approver::spawn(self.sim.socket());
        let mut answer = psbt.clone();
        let result = self.coldcard.sign_tx(&mut answer);
        assert!(matches!(result, Err(HWIError::MusigSession)), "{result:?}");
        assert_eq!(&answer, psbt);
        let deadline = Instant::now() + STORY_TIMEOUT;
        while !approver
            .stories()
            .iter()
            .any(|(title, body)| title.contains(reason) || body.contains(reason))
        {
            assert!(
                Instant::now() < deadline,
                "no story with {reason:?} after {STORY_TIMEOUT:?}: {:#?}",
                approver.stories()
            );
            thread::sleep(Duration::from_millis(200));
        }
        println!(
            "stories seen on the lost session: {:#?}",
            approver.stories()
        );
    }

    /// A's answer to `psbt`.
    fn hot_sign(&self, psbt: &Psbt) -> Psbt {
        let mut answer = psbt.clone();
        self.a
            .signer
            .inner_sign(&mut answer, &self.descriptor)
            .unwrap();
        answer
    }

    /// Round 1: C and A each sign `without_nonces(master)`, answers merged after.
    fn round_1(&self, master: &mut Psbt) {
        let sent = without_nonces(master);
        let by_c = self.coldcard_sign(&sent);
        let by_a = self.hot_sign(&sent);
        merge_round(master, &by_c);
        merge_round(master, &by_a);
    }

    /// Round 2: C and A each sign `master` as it stands, answers merged after, so
    /// neither sees the other's partial signature and none aggregates.
    fn round_2(&self, master: &mut Psbt) {
        let by_c = self.coldcard_sign(master);
        let by_a = self.hot_sign(master);
        merge_round(master, &by_c);
        merge_round(master, &by_a);
    }
}

/// Enrolls `descriptor` as `WALLET_NAME`.
fn enroll_descriptor(
    sim: &SimProcess,
    coldcard: Coldcard,
    descriptor: &WalletDescriptor,
) -> Coldcard {
    let text = musig_descriptor_to_string(descriptor, false);
    enroll(sim.socket(), coldcard, WALLET_NAME, &text)
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_musig_registers() {
    let setup = Setup::new();
    let text = musig_descriptor_to_string(&setup.descriptor, false);
    println!("enrolled: {text}");
    assert!(setup
        .coldcard
        .is_wallet_registered(WALLET_NAME, &text)
        .unwrap());
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_musig_round_1_adds_only_a_nonce() {
    let setup = Setup::new();
    let sent = without_nonces(&setup.leaf_psbt());
    let answer = setup.coldcard_sign(&sent);
    let (leaf, _) = spend_leaf(&setup.descriptor, 0, 0, setup.signers());

    let input = &answer.inputs[0];
    let nonces = musig_input_pub_nonces(input).unwrap();
    assert_eq!(nonces.len(), 1);
    let participant = setup.c_key.xkey.public_key;
    assert_eq!(nonces[0].participant, participant);
    let (_, (fingerprint, _)) = &input.tap_key_origins[&participant.x_only_public_key().0];
    assert_eq!(*fingerprint, setup.c_fingerprint());
    assert_eq!(nonces[0].leaf_hash, Some(leaf));
    // pk(K) leaf: OP_PUSHBYTES_32 K OP_CHECKSIG, K the derived aggregate
    let (script, _) = input
        .tap_scripts
        .values()
        .find(|(script, version)| TapLeafHash::from_script(script, *version) == leaf)
        .unwrap();
    assert_eq!(
        nonces[0].aggregate.x_only_public_key().0.serialize(),
        script.as_bytes()[1..33]
    );

    assert!(musig_input_partial_sigs(input).unwrap().is_empty());
    assert!(input.tap_script_sigs.is_empty());
    assert!(input.tap_key_sig.is_none());
    let participants = |psbt: &Psbt| {
        psbt.inputs[0]
            .unknown
            .iter()
            .filter(|(key, _)| key.type_value == PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(participants(&answer).len(), 1);
    assert_eq!(participants(&answer), participants(&sent));
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_musig_round_2_aggregates() {
    let setup = Setup::new();
    let mut psbt = setup.leaf_psbt();
    setup.round_1(&mut psbt);
    assert_eq!(musig_input_pub_nonces(&psbt.inputs[0]).unwrap().len(), 2);
    setup.round_2(&mut psbt);
    assert_eq!(musig_input_partial_sigs(&psbt.inputs[0]).unwrap().len(), 2);
    finalize_and_verify(psbt, &setup.descriptor);
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_musig_lost_session_after_restart() {
    let mut setup = Setup::new();
    let mut psbt = setup.leaf_psbt();
    setup.round_1(&mut psbt);

    setup.restart();
    setup.coldcard_lost_session(&psbt, "musig needs restart");

    setup.round_1(&mut psbt);
    setup.round_2(&mut psbt);
    finalize_and_verify(psbt, &setup.descriptor);
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_musig_replayed_round_1_is_resign() {
    let setup = Setup::new();
    let sent = without_nonces(&setup.leaf_psbt());
    let answer = setup.coldcard_sign(&sent);
    assert_eq!(musig_input_pub_nonces(&answer.inputs[0]).unwrap().len(), 1);
    setup.coldcard_lost_session(&sent, "resign");
}

/// The key path of `musig(A,C)`, restricted as `Account::restrict_spend_path` does
/// it: the recovery leaf goes, B's origin stays with no leaf hash, and the Coldcard
/// still matches its enrolled wallet.
#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_musig_key_path_next_to_a_leaf() {
    let setup = Setup::with(key_path_2_of_2_with_recovery);
    let mut psbt = offline_psbt(&setup.descriptor, 0, 0, COIN);
    restrict_to_key_path(&mut psbt, &setup.descriptor, 0, 0);
    let b = HotParticipant::new(SEED_B, KeyType::Cosigner);
    let input = &psbt.inputs[0];
    assert!(input.tap_scripts.is_empty());
    assert!(input
        .tap_key_origins
        .values()
        .any(
            |(leaf_hashes, (fingerprint, _))| *fingerprint == b.signer.fingerprint()
                && leaf_hashes.is_empty()
        ));

    setup.round_1(&mut psbt);
    let nonces = musig_input_pub_nonces(&psbt.inputs[0]).unwrap();
    assert_eq!(nonces.len(), 2);
    assert!(nonces.iter().all(|nonce| nonce.leaf_hash.is_none()));
    setup.round_2(&mut psbt);
    assert_eq!(musig_input_partial_sigs(&psbt.inputs[0]).unwrap().len(), 2);
    finalize_and_verify(psbt, &setup.descriptor);
}
