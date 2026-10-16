#![cfg(feature = "musig")]
//! MuSig2 interop with Bitcoin Core v31 on regtest: Core holds key A, a bwk
//! `HotSigner` holds key B, key C is watch-only. Each shape spends three coins:
//! two receive coins, the first finalized by Core `finalizepsbt`, the second by
//! bwk, then a change coin finalized by Core.
//!
//! Needs a v31 `bitcoind` (older ones cannot sign MuSig2):
//! `BITCOIND_V31_EXE=/path/to/bitcoind cargo test -p bwk-sign --features musig
//! --test musig_core_interop -- --ignored --test-threads=1`

use std::{collections::BTreeSet, env, str::FromStr, sync::Arc};

use bwk_bup::{
    key_role::bip87_account_path,
    musig::{musig_key, musig_leaf},
    unspendable_internal_key, Bip87Account, KeyType, Locktime, OXpub, Path, Policy, PolicyType,
    Semantic, TapPosition,
};
use bwk_descriptor::{
    musig::musig_descriptor_to_string,
    wallet::{WalletDefiniteDescriptor, WalletDescriptor, WalletDescriptorExt},
};
use bwk_keys::musig::MusigKey;
use bwk_psbt::musig::{
    musig_input_partial_sigs, musig_input_pub_nonces, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
};
use bwk_sign::{hot_signer::HotSigner, musig::aggregate_partial_sigs};
use bwk_utils::test::{corepc_node, generate_blocks};
use miniscript::{
    bitcoin::{
        bip32::Fingerprint,
        consensus::encode::serialize_hex,
        psbt::Input,
        secp256k1::{PublicKey, Secp256k1},
        taproot::{LeafVersion, TapLeafHash},
        Address, Network, NetworkKind, Psbt, Txid,
    },
    descriptor::TapTree,
    psbt::PsbtExt,
    Descriptor,
};
use serde_json::{json, Value};

const BITCOIND_V31_EXE: &str = "BITCOIND_V31_EXE";
const MNEMONIC_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const MNEMONIC_C: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
/// Sats sent to each coin of the tested descriptor.
const COIN_SATS: u64 = 100_000;
const FEE_RATE_SAT_VB: u64 = 2;

/// A participant: its signer and its role key `[fp/87'/1'/0'/R]tpub`.
struct Participant {
    signer: HotSigner,
    key: OXpub,
}

impl Participant {
    fn new(mnemonic: &str, key_type: KeyType) -> Self {
        let signer = HotSigner::new_from_mnemonics(Network::Regtest, mnemonic).unwrap();
        let path = bip87_account_path(NetworkKind::Test, 0);
        let account = signer.xpub(&path);
        let key = Bip87Account::new(signer.fingerprint(), path, account.xkey)
            .unwrap()
            .role_key(key_type, 0)
            .unwrap();
        Self { signer, key }
    }

    fn fingerprint(&self) -> Fingerprint {
        self.signer.fingerprint()
    }

    /// The key it signs musig() with: its role key, as a public key.
    fn participant_key(&self) -> PublicKey {
        self.key.xkey.public_key
    }

    /// The tprv at this participant's role key path.
    fn role_xpriv(&self) -> String {
        let (_, path) = self.key.origin.as_ref().unwrap();
        self.signer.xpriv(path).xkey.to_string()
    }
}

/// A, B and C with the roles Internal, Cosigner and External.
fn participants() -> [Participant; 3] {
    [
        Participant::new(MNEMONIC_A, KeyType::Internal),
        Participant::new(MNEMONIC_B, KeyType::Cosigner),
        Participant::new(MNEMONIC_C, KeyType::External),
    ]
}

/// A v31 regtest node, its miner wallet (110 blocks) and the "musig" wallet
/// holding key A.
struct Core {
    node: corepc_node::Node,
    wallet: corepc_node::Client,
}

impl Core {
    fn start() -> Self {
        let exe = env::var(BITCOIND_V31_EXE)
            .unwrap_or_else(|_| panic!("set {BITCOIND_V31_EXE} to a Bitcoin Core v31 bitcoind"));
        let mut conf = corepc_node::Conf::default();
        conf.args.push("-txindex");
        conf.wallet = Some("miner".into());
        let mut node = corepc_node::Node::with_conf(exe, &conf).unwrap();
        let version = node.client.call::<Value>("getnetworkinfo", &[]).unwrap()["version"]
            .as_u64()
            .unwrap();
        assert!(version >= 310_000, "bitcoind {version} is older than v31");
        generate_blocks(&mut node.client, 110);
        let wallet = node.create_wallet("musig").unwrap();
        Self { node, wallet }
    }

    fn miner(&self, method: &str, args: &[Value]) -> Value {
        self.node.client.call(method, args).unwrap()
    }

    fn musig(&self, method: &str, args: &[Value]) -> Value {
        self.wallet.call(method, args).unwrap()
    }

    fn mine(&self, blocks: u64) {
        let address = self.miner("getnewaddress", &[]);
        self.miner("generatetoaddress", &[json!(blocks), address]);
    }

    /// Imports `text` (key A private) as the active multipath descriptor.
    fn import(&self, text: &str) {
        let info = self.musig("getdescriptorinfo", &[json!(text)]);
        let desc = format!("{text}#{}", info["checksum"].as_str().unwrap());
        let result = self.musig(
            "importdescriptors",
            &[json!([{ "desc": desc, "active": true, "range": [0, 20], "timestamp": "now" }])],
        );
        for entry in result.as_array().unwrap() {
            assert_eq!(entry["success"], json!(true), "{result}");
        }
    }

    fn derive_address(&self, public: &str, index: u32) -> String {
        let addresses = self.miner("deriveaddresses", &[json!(public), json!([index, index])]);
        // A multipath descriptor gives one list per path, receive first.
        addresses[0][0].as_str().unwrap().to_string()
    }

    /// Sends `COIN_SATS` to `address`, mines it; the outpoint.
    fn fund(&self, address: &Address) -> (Txid, u32) {
        let amount = json!(COIN_SATS as f64 / 100_000_000.0);
        let txid = self.miner("sendtoaddress", &[json!(address.to_string()), amount]);
        let txid = Txid::from_str(txid.as_str().unwrap()).unwrap();
        self.mine(1);
        let tx = self.miner("getrawtransaction", &[json!(txid.to_string()), json!(true)]);
        let vout = tx["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|out| out["scriptPubKey"]["address"] == json!(address.to_string()))
            .unwrap()["n"]
            .as_u64()
            .unwrap();
        (txid, vout as u32)
    }

    /// A PSBT spending only `outpoint` to the miner, fee taken from the output.
    fn create_psbt(&self, (txid, vout): (Txid, u32)) -> Psbt {
        let to = self.miner("getnewaddress", &[]);
        let amount = json!(COIN_SATS as f64 / 100_000_000.0);
        let funded = self.musig(
            "walletcreatefundedpsbt",
            &[
                json!([{ "txid": txid.to_string(), "vout": vout }]),
                json!([{ to.as_str().unwrap(): amount }]),
                json!(0),
                json!({
                    "add_inputs": false,
                    "subtractFeeFromOutputs": [0],
                    "fee_rate": FEE_RATE_SAT_VB,
                }),
            ],
        );
        Psbt::from_str(funded["psbt"].as_str().unwrap()).unwrap()
    }

    /// `walletprocesspsbt` with signing, without finalizing.
    fn process(&self, psbt: &Psbt) -> Psbt {
        let processed = self.musig(
            "walletprocesspsbt",
            &[
                json!(psbt.to_string()),
                json!(true),
                json!("DEFAULT"),
                json!(true),
                json!(false),
            ],
        );
        Psbt::from_str(processed["psbt"].as_str().unwrap()).unwrap()
    }

    fn finalize(&self, psbt: &Psbt) -> String {
        let finalized = self.miner("finalizepsbt", &[json!(psbt.to_string())]);
        assert_eq!(finalized["complete"], json!(true), "{finalized}");
        finalized["hex"].as_str().unwrap().to_string()
    }

    fn decode(&self, psbt: &Psbt) -> Value {
        self.miner("decodepsbt", &[json!(psbt.to_string())])
    }

    /// Broadcasts `hex`, mines a block, asserts the tx confirmed.
    fn broadcast(&self, hex: &str) {
        let txid = self.miner("sendrawtransaction", &[json!(hex)]);
        self.mine(1);
        let tx = self.miner("getrawtransaction", &[txid, json!(true)]);
        assert_eq!(tx["confirmations"], json!(1), "{tx}");
    }
}

/// The spend path a test restricts its PSBTs to.
#[derive(Clone, Copy)]
enum Spend {
    KeyPath,
    /// The leaf whose musig() participants have these fingerprints.
    Leaf([Fingerprint; 2]),
}

/// Who signs a round first.
#[derive(Clone, Copy)]
enum First {
    Core,
    Bwk,
}

/// Who finalizes and extracts.
#[derive(Clone, Copy)]
enum Finalizer {
    Core,
    Bwk,
}

/// The leaf of `signers` in the `keychain` descriptor at `index`: its hash and the
/// KeyAgg output of its musig().
fn spend_leaf(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
    signers: [Fingerprint; 2],
) -> (TapLeafHash, PublicKey) {
    let Descriptor::Tr(tr) = derived(descriptor, keychain, index) else {
        panic!("expected tr()");
    };
    let wanted: BTreeSet<Fingerprint> = signers.into_iter().collect();
    tr.iter_scripts()
        .find_map(|(_, ms)| {
            let agg = ms.iter_pk().find_map(|key| key.as_musig().cloned())?;
            let fingerprints: BTreeSet<Fingerprint> = agg
                .cosigners()
                .iter()
                .map(|key| key.master_fingerprint())
                .collect();
            (fingerprints == wanted).then(|| {
                (
                    TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript),
                    agg.aggregate(),
                )
            })
        })
        .unwrap()
}

/// `descriptor` at `index` of `keychain` (0 receive, 1 change).
fn derived(descriptor: &WalletDescriptor, keychain: usize, index: u32) -> WalletDefiniteDescriptor {
    descriptor.single_paths().unwrap()[keychain]
        .derive_at(index)
        .unwrap()
}

/// Only `leaf`: its script, the origins of its keys and the 0x1a of `aggregate`,
/// as `Account::restrict_spend_path` leaves an input.
fn keep_leaf(input: &mut Input, leaf: TapLeafHash, aggregate: PublicKey) {
    input
        .tap_scripts
        .retain(|_, (script, version)| TapLeafHash::from_script(script, *version) == leaf);
    input
        .tap_key_origins
        .retain(|_, (leaf_hashes, _)| leaf_hashes.contains(&leaf));
    for (leaf_hashes, _) in input.tap_key_origins.values_mut() {
        *leaf_hashes = vec![leaf];
    }
    input.unknown.retain(|key, _| {
        key.type_value != PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS || key.key == aggregate.serialize()
    });
}

/// The (participant, aggregate, leaf) of every 0x1b or 0x1c entry `decodepsbt`
/// lists under `field`, for input 0.
fn core_entries(decoded: &Value, field: &str) -> BTreeSet<(String, String, String)> {
    decoded["inputs"][0][field]
        .as_array()
        .unwrap_or_else(|| panic!("no {field} in {decoded}"))
        .iter()
        .map(|entry| {
            (
                entry["participant_pubkey"].as_str().unwrap().to_string(),
                entry["aggregate_pubkey"].as_str().unwrap().to_string(),
                entry["leaf_hash"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// bwk's reading of the same entries.
fn bwk_entries(
    entries: impl IntoIterator<Item = (PublicKey, PublicKey, Option<TapLeafHash>)>,
) -> BTreeSet<(String, String, String)> {
    entries
        .into_iter()
        .map(|(participant, aggregate, leaf)| {
            (
                participant.to_string(),
                aggregate.to_string(),
                leaf.map(|leaf| leaf.to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

/// Core `decodepsbt` and bwk read the same 0x1b and 0x1c entries, and every
/// partial sig of B (written by bwk) sits under an aggregate and leaf where A
/// (Core) has one too. A may have more: Core adds nonces for each leaf of A.
fn check_field_layout(core: &Core, psbt: &Psbt, a: &Participant, b: &Participant) {
    let decoded = core.decode(psbt);
    let input = &psbt.inputs[0];
    let nonces = bwk_entries(
        musig_input_pub_nonces(input)
            .unwrap()
            .into_iter()
            .map(|n| (n.participant, n.aggregate, n.leaf_hash)),
    );
    let sigs = bwk_entries(
        musig_input_partial_sigs(input)
            .unwrap()
            .into_iter()
            .map(|s| (s.participant, s.aggregate, s.leaf_hash)),
    );
    assert_eq!(core_entries(&decoded, "musig2_pubnonces"), nonces);
    assert_eq!(core_entries(&decoded, "musig2_partial_sigs"), sigs);
    let slots = |p: &Participant| -> BTreeSet<(String, String)> {
        let participant = p.participant_key().to_string();
        sigs.iter()
            .filter(|(key, _, _)| *key == participant)
            .map(|(_, aggregate, leaf)| (aggregate.clone(), leaf.clone()))
            .collect()
    };
    let bwk_slots = slots(b);
    assert!(!bwk_slots.is_empty());
    assert!(bwk_slots.is_subset(&slots(a)));
}

/// The coin a spend signs: its keychain (0 receive, 1 change) and index in
/// `descriptor`, and the path.
struct Coin<'a> {
    descriptor: &'a WalletDescriptor,
    keychain: usize,
    index: u32,
    spend: Spend,
}

impl Coin<'_> {
    /// Restricts every input of `psbt` to the spend path.
    fn restrict(&self, psbt: &mut Psbt) {
        if let Spend::Leaf(signers) = self.spend {
            let (leaf, aggregate) = spend_leaf(self.descriptor, self.keychain, self.index, signers);
            for input in &mut psbt.inputs {
                keep_leaf(input, leaf, aggregate);
            }
        }
    }

    /// One MuSig2 round, Core and the bwk signer each adding their part. Core
    /// writes every leaf of its descriptor back, so its output is restricted again.
    fn round(&self, core: &Core, b: &Participant, psbt: Psbt, first: First) -> Psbt {
        let by_core = |psbt: &Psbt| {
            let mut psbt = core.process(psbt);
            self.restrict(&mut psbt);
            psbt
        };
        let by_bwk = |mut psbt: Psbt| {
            b.signer.inner_sign(&mut psbt, self.descriptor).unwrap();
            psbt
        };
        match first {
            First::Core => by_bwk(by_core(&psbt)),
            First::Bwk => by_core(&by_bwk(psbt)),
        }
    }

    /// Funds the coin, spends it to the miner with Core and the bwk signer,
    /// finalized by `finalizer`, broadcast and confirmed.
    fn spend(
        &self,
        core: &Core,
        participants: &[Participant; 3],
        first: First,
        finalizer: Finalizer,
    ) {
        let [a, b, _] = participants;
        let address = derived(self.descriptor, self.keychain, self.index)
            .address(Network::Regtest)
            .unwrap();
        let mut psbt = core.create_psbt(core.fund(&address));
        self.restrict(&mut psbt);

        let psbt = self.round(core, b, psbt, first);
        assert!(!musig_input_pub_nonces(&psbt.inputs[0]).unwrap().is_empty());
        assert!(musig_input_partial_sigs(&psbt.inputs[0])
            .unwrap()
            .is_empty());
        let mut psbt = self.round(core, b, psbt, first);
        check_field_layout(core, &psbt, a, b);

        let hex = match finalizer {
            Finalizer::Core => core.finalize(&psbt),
            Finalizer::Bwk => {
                assert_eq!(
                    aggregate_partial_sigs(&mut psbt, self.descriptor).unwrap(),
                    1
                );
                psbt.finalize_mut(&Secp256k1::verification_only()).unwrap();
                serialize_hex(&psbt.extract_tx_unchecked_fee_rate())
            }
        };
        core.broadcast(&hex);
    }
}

/// Imports `descriptor` in Core (A private), checks Core and bwk agree on
/// receive address 0, then spends three coins through `spend`: Core first and
/// Core finalizing, bwk first and bwk finalizing, then a change coin with bwk
/// first and Core finalizing.
fn interop(descriptor: WalletDescriptor, spend: Spend) {
    let core = Core::start();
    let participants = participants();
    let public = musig_descriptor_to_string(&descriptor, false);
    let a = &participants[0];
    let a_xpub = a.key.xkey.to_string();
    assert!(public.contains(&a_xpub));
    core.import(&public.replace(&a_xpub, &a.role_xpriv()));

    let address = derived(&descriptor, 0, 0)
        .address(Network::Regtest)
        .unwrap();
    assert_eq!(
        core.derive_address(&musig_descriptor_to_string(&descriptor, true), 0),
        address.to_string()
    );

    for (keychain, index, first, finalizer) in [
        (0, 0, First::Core, Finalizer::Core),
        (0, 1, First::Bwk, Finalizer::Bwk),
        (1, 0, First::Bwk, Finalizer::Core),
    ] {
        let coin = Coin {
            descriptor: &descriptor,
            keychain,
            index,
            spend,
        };
        coin.spend(&core, &participants, first, finalizer);
    }
}

/// A tr() whose only leaf is `leaf`, under the NUMS internal key bwk-bup derives
/// from it (`placeholder` stands in for the internal key until then).
fn nums_tr(placeholder: MusigKey, leaf: TapTree<MusigKey>) -> WalletDescriptor {
    let Descriptor::Tr(tr) = Descriptor::new_tr(placeholder, Some(leaf.clone())).unwrap() else {
        panic!("expected tr()");
    };
    let nums = unspendable_internal_key(&tr).unwrap();
    Descriptor::new_tr(nums, Some(leaf)).unwrap()
}

#[test]
#[ignore = "needs BITCOIND_V31_EXE pointing at a Bitcoin Core v31 bitcoind"]
fn core_v31_musig_key_path_2_of_2() {
    let [a, b, _] = participants();
    let descriptor = Descriptor::new_tr(musig_key(&[a.key, b.key], 0).unwrap(), None).unwrap();
    interop(descriptor, Spend::KeyPath);
}

#[test]
#[ignore = "needs BITCOIND_V31_EXE pointing at a Bitcoin Core v31 bitcoind"]
fn core_v31_musig_leaf_2_of_2() {
    let [a, b, _] = participants();
    let signers = [a.fingerprint(), b.fingerprint()];
    let keys = [a.key, b.key];
    let leaf = TapTree::Leaf(Arc::new(musig_leaf(&keys, 0).unwrap()));
    let placeholder = musig_key(&keys, 2).unwrap();
    interop(nums_tr(placeholder, leaf), Spend::Leaf(signers));
}

#[test]
#[ignore = "needs BITCOIND_V31_EXE pointing at a Bitcoin Core v31 bitcoind"]
fn core_v31_musig_2_of_3_three_leaves() {
    let [a, b, c] = participants();
    let signers = [a.fingerprint(), b.fingerprint()];
    let semantic = Semantic::Multi {
        keys: vec![a.key, b.key, c.key],
        threshold: 2,
    };
    let path = Path::new(semantic, Locktime::None, TapPosition::TapTree(vec![]));
    let mut policy = Policy::new(vec![path], PolicyType::PrimaryOnly).unwrap();
    let descriptor = policy.compile().unwrap().clone();
    let Descriptor::Tr(tr) = &descriptor else {
        panic!("expected tr()");
    };
    let musig_leaves = tr
        .iter_scripts()
        .filter(|(_, ms)| ms.iter_pk().any(|key| key.is_musig()))
        .count();
    assert_eq!(musig_leaves, 3);
    interop(descriptor, Spend::Leaf(signers));
}
