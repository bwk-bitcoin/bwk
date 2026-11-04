//! Generated tweak accumulator test vectors. `regenerate_vectors` is the only
//! writer of the JSON files under `test_vectors/accumulator/`; every other
//! test in this file pins the committed files to the current code.

mod common;

use std::str::FromStr;

use bwk_bip89::{
    accumulator::{
        branch_hash, generate_tree, keys_digest, leaf_hash, leaf_nonce, policy_hash, policy_id,
        record::{
            build_tree, root_message, sign_tree_root, template_id, verify_root, RootPolicy,
            RootRecord, RootSignature,
        },
        root_hash,
        shuffle::{shuffle_key, shuffle_order, MAX_RANGE},
        tree::{verify_proof, Proof, TreeBuilder, HEIGHT},
        NONCE_TAG,
    },
    bundle::derive_bundle,
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                hashes::{sha256, sha512, Hash, HashEngine, Hmac, HmacEngine},
                secp256k1::{Secp256k1, SecretKey},
            },
            Descriptor as MsDescriptor, DescriptorPublicKey,
        },
        RustBitcoin, TemplateKey, TemplateKeyError, SUBTYPE_TWEAK,
    },
    slot::slots,
    tweak::{compute_bip32_tweak, tweak_key},
    BitcoinBackend, Bundle, Error, Xpub,
};
use common::{
    field_key, hex_arr, hex_vec, root_signature, spend_psbt, tpub, two_slot_wallet, wallet, Wallet,
    DELEGATOR_CHAIN_CODE, DELEGATOR_KEY, DELEGATOR_SECRET, OWNER1_SECRET,
};

const PRIMITIVES_JSON: &str = include_str!("../test_vectors/accumulator/primitives.json");
const TREE_JSON: &str = include_str!("../test_vectors/accumulator/tree.json");
const PROOF_JSON: &str = include_str!("../test_vectors/accumulator/proof.json");
const SLOTS_JSON: &str = include_str!("../test_vectors/accumulator/slots.json");

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Primitives {
    descriptor: String,
    template: String,
    policy_id: String,
    keys_digest: Vec<KeysDigestCase>,
    policy_hash: Vec<PolicyHashCase>,
    leaf_nonce: LeafNonceCase,
    shuffle: Vec<ShuffleCase>,
    bundle: BundleCase,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct XpubRecord {
    key: String,
    chain_code: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct KeysDigestCase {
    description: String,
    xpubs: Vec<XpubRecord>,
    sorted_records: Vec<String>,
    keys_digest: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct PolicyHashCase {
    keychain: u32,
    tree_start: u32,
    policy_hash: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct LeafNonceCase {
    keychain: u32,
    tree_start: u32,
    keys_digest: String,
    steps: Vec<LeafNonceStep>,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct LeafNonceStep {
    index: u32,
    chaincode: String,
    next_chaincode: String,
    nonce: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct ShuffleCase {
    keychain: u32,
    tree_start: u32,
    shuffle_key: String,
    order: Vec<u8>,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct BundleCase {
    keychain: u32,
    index: u32,
    entries: Vec<BundleEntry>,
    serialization: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct BundleEntry {
    base_key: String,
    chain_code: String,
    tweak_path: Vec<u32>,
    tweak: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct TreeVector {
    keychain: u32,
    tree_start: u32,
    policy_id: String,
    keys_digest: String,
    policy_hash: String,
    shuffle_key: String,
    leaves: Vec<LeafRecord>,
    order: Vec<u8>,
    levels: Vec<Vec<String>>,
    root: String,
    template_id: String,
    root_message: String,
    signer_secret: String,
    key: String,
    branch_tweak: String,
    branch_key: String,
    signature: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct LeafRecord {
    index: u32,
    nonce: String,
    leaf: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct ProofVector {
    keychain: u32,
    tree_start: u32,
    index: u32,
    bundle: String,
    root: String,
    position: u8,
    proof: String,
    leaf: String,
    trace: Vec<TraceStep>,
    negatives: Vec<Negative>,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct TraceStep {
    level: u8,
    bit: u8,
    sibling: String,
    node_before: String,
    node_after: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Negative {
    description: String,
    bundle: String,
    proof: String,
    expected: bool,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct SlotsVector {
    descriptor: String,
    template: String,
    template_id: String,
    slots: Vec<SlotRecord>,
    bundle: SlotBundleCase,
    roots: Vec<RootCase>,
    proof: SlotProofCase,
    invalid_template_keys: Vec<String>,
    invalid_psbt_keydata: Vec<String>,
    invalid_descriptors: Vec<InvalidDescriptor>,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct InvalidDescriptor {
    description: String,
    descriptor: String,
    error: String,
    key: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct SlotRecord {
    base_key: String,
    slot: u8,
    chain_code: String,
    branches: [Vec<u32>; 2],
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct SlotBundleCase {
    keychain: u32,
    index: u32,
    entries: Vec<SlotBundleEntry>,
    serialization: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct SlotBundleEntry {
    base_key: String,
    slot: u8,
    tweak_path: Vec<u32>,
    tweak: String,
    psbt_keydata: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct RootCase {
    keychain: u32,
    tree_start: u32,
    root: String,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct SlotProofCase {
    keychain: u32,
    tree_start: u32,
    index: u32,
    bundle: String,
    proof: String,
}

fn xpub_record(x: &Xpub) -> XpubRecord {
    XpubRecord {
        key: hex::encode(x.key),
        chain_code: hex::encode(x.chain_code),
    }
}

/// Mirrors the sort and dedup that `keys_digest` performs internally, so the
/// intermediate records can be recorded in the vector.
fn sorted_records(xpubs: &[Xpub]) -> Vec<[u8; 65]> {
    let mut records: Vec<[u8; 65]> = Vec::with_capacity(xpubs.len());
    for xpub in xpubs {
        let mut record = [0u8; 65];
        record[..32].copy_from_slice(&xpub.chain_code);
        record[32..].copy_from_slice(&xpub.key);
        records.push(record);
    }
    records.sort_unstable();
    records.dedup();
    records
}

fn primitives() -> Primitives {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let descriptor_bytes = c.descriptor_policy(d);
    let template_bytes = c.descriptor_template(d).unwrap();
    let descriptor = String::from_utf8(descriptor_bytes.clone()).unwrap();
    let template = String::from_utf8(template_bytes.clone()).unwrap();
    let pid = policy_id(&c, &descriptor_bytes);

    let wallet_xpubs = c.descriptor_xpubs(d).unwrap();
    let wallet_kd = keys_digest(&c, &wallet_xpubs);
    let wallet_case = KeysDigestCase {
        description: "wallet descriptor".to_string(),
        xpubs: wallet_xpubs.iter().map(xpub_record).collect(),
        sorted_records: sorted_records(&wallet_xpubs)
            .iter()
            .map(hex::encode)
            .collect(),
        keys_digest: hex::encode(wallet_kd),
    };

    let g: [u8; 33] = hex_arr("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let g2: [u8; 33] =
        hex_arr("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    let g3: [u8; 33] =
        hex_arr("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    let dup_xpubs = vec![
        Xpub {
            key: g,
            chain_code: [0x02; 32],
            branches: [vec![0], vec![1]],
        },
        Xpub {
            key: g3,
            chain_code: [0x01; 32],
            branches: [vec![0], vec![1]],
        },
        Xpub {
            key: g2,
            chain_code: [0x03; 32],
            branches: [vec![0], vec![1]],
        },
        Xpub {
            key: g3,
            chain_code: [0x01; 32],
            branches: [vec![0], vec![1]],
        },
    ];
    let dup_kd = keys_digest(&c, &dup_xpubs);
    let dup_case = KeysDigestCase {
        description: "raw record order differs from key order, with a duplicate".to_string(),
        xpubs: dup_xpubs.iter().map(xpub_record).collect(),
        sorted_records: sorted_records(&dup_xpubs).iter().map(hex::encode).collect(),
        keys_digest: hex::encode(dup_kd),
    };

    let policy_hash_cases = vec![
        PolicyHashCase {
            keychain: 0,
            tree_start: 0,
            policy_hash: hex::encode(policy_hash(&c, &pid, 0, 0)),
        },
        PolicyHashCase {
            keychain: 1,
            tree_start: 300,
            policy_hash: hex::encode(policy_hash(&c, &pid, 1, 300)),
        },
    ];

    let mut chaincode = policy_hash(&c, &pid, 1, 300);
    let mut steps = Vec::with_capacity(3);
    for index in [300u32, 301, 302] {
        let (next_chaincode, nonce) = leaf_nonce(&c, &chaincode, &wallet_kd, 1, index);
        steps.push(LeafNonceStep {
            index,
            chaincode: hex::encode(chaincode),
            next_chaincode: hex::encode(next_chaincode),
            nonce: hex::encode(nonce),
        });
        chaincode = next_chaincode;
    }
    let leaf_nonce_case = LeafNonceCase {
        keychain: 1,
        tree_start: 300,
        keys_digest: hex::encode(wallet_kd),
        steps,
    };

    let shuffle = vec![
        ShuffleCase {
            keychain: 0,
            tree_start: 0,
            shuffle_key: hex::encode(shuffle_key(&c, &pid, 0, 0)),
            order: shuffle_order(&c, &shuffle_key(&c, &pid, 0, 0)).to_vec(),
        },
        ShuffleCase {
            keychain: 1,
            tree_start: 300,
            shuffle_key: hex::encode(shuffle_key(&c, &pid, 1, 300)),
            order: shuffle_order(&c, &shuffle_key(&c, &pid, 1, 300)).to_vec(),
        },
    ];

    let mut entries = Vec::with_capacity(wallet_xpubs.len());
    for xpub in &wallet_xpubs {
        let mut tweak_path = xpub.branches[1].clone();
        tweak_path.push(305);
        let derived = compute_bip32_tweak(&c, &xpub.key, &xpub.chain_code, &tweak_path).unwrap();
        entries.push(BundleEntry {
            base_key: hex::encode(xpub.key),
            chain_code: hex::encode(xpub.chain_code),
            tweak_path,
            tweak: hex::encode(derived.tweak),
        });
    }
    let serialization = derive_bundle(&c, d, 1, 305).unwrap().to_bytes();
    let bundle = BundleCase {
        keychain: 1,
        index: 305,
        entries,
        serialization: hex::encode(serialization),
    };

    Primitives {
        descriptor,
        template,
        policy_id: hex::encode(pid),
        keys_digest: vec![wallet_case, dup_case],
        policy_hash: policy_hash_cases,
        leaf_nonce: leaf_nonce_case,
        shuffle,
        bundle,
    }
}

struct TraceBuilder {
    tree_start: u32,
    leaves: Vec<([u8; 32], [u8; 32])>,
    order: [u8; 256],
    levels: Vec<Vec<[u8; 32]>>,
}

impl TraceBuilder {
    fn new(tree_start: u32) -> Self {
        Self {
            tree_start,
            leaves: vec![([0u8; 32], [0u8; 32]); MAX_RANGE],
            order: [0u8; MAX_RANGE],
            levels: (0..=HEIGHT)
                .map(|level| vec![[0u8; 32]; MAX_RANGE >> level])
                .collect(),
        }
    }
}

impl TreeBuilder for TraceBuilder {
    type Tree = (Self, [u8; 32]);

    fn leaf(&mut self, position: u8, index: u32, hash: &[u8; 32], nonce: &[u8; 32]) {
        let offset = (index - self.tree_start) as usize;
        self.leaves[offset] = (*nonce, *hash);
        self.order[position as usize] = offset as u8;
        self.levels[0][position as usize] = *hash;
    }

    fn node(&mut self, level: u8, position: u8, hash: &[u8; 32]) {
        self.levels[level as usize][position as usize] = *hash;
    }

    fn finish(self, root: [u8; 32]) -> Self::Tree {
        (self, root)
    }
}

fn tree() -> TreeVector {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;
    let keychain = 1u32;
    let tree_start = 300u32;

    let pid = policy_id(&c, &c.descriptor_policy(d));
    let kd = keys_digest(&c, &c.descriptor_xpubs(d).unwrap());
    let ph = policy_hash(&c, &pid, keychain, tree_start);
    let sk = shuffle_key(&c, &pid, keychain, tree_start);

    let (tb, root) =
        generate_tree(&c, d, keychain, tree_start, TraceBuilder::new(tree_start)).unwrap();

    let leaves: Vec<LeafRecord> = (0..MAX_RANGE as u32)
        .map(|offset| LeafRecord {
            index: tree_start + offset,
            nonce: hex::encode(tb.leaves[offset as usize].0),
            leaf: hex::encode(tb.leaves[offset as usize].1),
        })
        .collect();
    let order = tb.order.to_vec();
    let levels: Vec<Vec<String>> = tb
        .levels
        .iter()
        .map(|level| level.iter().map(hex::encode).collect())
        .collect();

    let tid = template_id(&c, &c.descriptor_template(d).unwrap());
    let rm = root_message(&c, &tid, &root);

    let record = sign_tree_root(&c, d, &OWNER1_SECRET, keychain, tree_start).unwrap();
    let signed = root_signature(&record);
    let branch_key = tweak_key(&c, &signed.key, &signed.branch_tweak).unwrap();

    TreeVector {
        keychain,
        tree_start,
        policy_id: hex::encode(pid),
        keys_digest: hex::encode(kd),
        policy_hash: hex::encode(ph),
        shuffle_key: hex::encode(sk),
        leaves,
        order,
        levels,
        root: hex::encode(root),
        template_id: hex::encode(tid),
        root_message: hex::encode(rm),
        signer_secret: hex::encode(OWNER1_SECRET),
        key: hex::encode(signed.key),
        branch_tweak: hex::encode(signed.branch_tweak),
        branch_key: hex::encode(branch_key),
        signature: hex::encode(&signed.signature),
    }
}

fn proof() -> ProofVector {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;
    let keychain = 1u32;
    let tree_start = 300u32;
    let index = 305u32;

    let t = tree();

    let built = build_tree(&c, d, keychain, tree_start).unwrap();
    let proof = built.proof(keychain, index).unwrap();
    let proof_bytes = proof.to_bytes();
    let bundle = derive_bundle(&c, d, keychain, index).unwrap();
    let bundle_bytes = bundle.to_bytes();

    let leaf = leaf_hash(&c, &bundle, &proof.nonce);

    let mut trace = Vec::with_capacity(HEIGHT);
    let mut node = leaf;
    for level in 0..HEIGHT as u8 {
        let bit = (proof.position >> level) & 1;
        let sibling = proof.siblings[level as usize];
        let node_before = node;
        let node_after = if bit == 0 {
            branch_hash(&c, &node_before, &sibling)
        } else {
            branch_hash(&c, &sibling, &node_before)
        };
        trace.push(TraceStep {
            level,
            bit,
            sibling: hex::encode(sibling),
            node_before: hex::encode(node_before),
            node_after: hex::encode(node_after),
        });
        node = node_after;
    }

    let mut altered_tweak_bundle = bundle_bytes.clone();
    altered_tweak_bundle[64] ^= 0x01;
    let negative_tweak = Negative {
        description: "altered tweak".to_string(),
        bundle: hex::encode(&altered_tweak_bundle),
        proof: hex::encode(proof_bytes),
        expected: false,
    };

    let mut altered_sibling_proof = proof_bytes;
    altered_sibling_proof[129] ^= 0x01;
    let negative_sibling = Negative {
        description: "altered sibling".to_string(),
        bundle: hex::encode(&bundle_bytes),
        proof: hex::encode(altered_sibling_proof),
        expected: false,
    };

    let mut altered_position_proof = proof_bytes;
    altered_position_proof[32] ^= 0x01;
    let negative_position = Negative {
        description: "altered position".to_string(),
        bundle: hex::encode(&bundle_bytes),
        proof: hex::encode(altered_position_proof),
        expected: false,
    };

    let mut altered_nonce_proof = proof_bytes;
    altered_nonce_proof[0] ^= 0x01;
    let negative_nonce = Negative {
        description: "altered nonce".to_string(),
        bundle: hex::encode(&bundle_bytes),
        proof: hex::encode(altered_nonce_proof),
        expected: false,
    };

    let negatives = vec![
        negative_tweak,
        negative_sibling,
        negative_position,
        negative_nonce,
    ];
    for negative in &negatives {
        Bundle::from_bytes(&hex_vec(&negative.bundle)).unwrap();
        Proof::from_bytes(&hex_vec(&negative.proof)).unwrap();
    }

    ProofVector {
        keychain,
        tree_start,
        index,
        bundle: hex::encode(&bundle_bytes),
        root: t.root,
        position: proof.position,
        proof: hex::encode(proof_bytes),
        leaf: hex::encode(leaf),
        trace,
        negatives,
    }
}

/// The PSBT tweak field keydata `set_output_bundle` writes for `bundle`. The
/// proprietary map sorts it as the bundle sorts its entries, `P` before
/// `P || 01`.
fn psbt_keydata(c: &RustBitcoin, w: &Wallet, bundle: &Bundle) -> Vec<Vec<u8>> {
    let mut psbt = spend_psbt(w);
    c.set_output_bundle(&mut psbt, 1, bundle).unwrap();
    psbt.outputs[1]
        .proprietary
        .keys()
        .map(|key| key.key.clone())
        .collect()
}

/// `two_slot_wallet`'s descriptor without its checksum, with the delegator's
/// `<2;3>` expression replaced by `replacement`.
fn altered_descriptor(c: &RustBitcoin, w: &Wallet, replacement: &str) -> String {
    let delegator = tpub_of_delegator();
    let policy = String::from_utf8(c.descriptor_policy(&w.descriptor)).unwrap();
    let (policy, _checksum) = policy.split_once('#').unwrap();
    policy.replacen(&format!("{delegator}/<2;3>/*"), replacement, 1)
}

/// The variant name and key of a descriptor refusal that names a key.
fn refusal(error: Error) -> (String, [u8; 33]) {
    match error {
        Error::ConflictingChainCode(key) => ("ConflictingChainCode".to_string(), key),
        Error::OverlappingPaths(key) => ("OverlappingPaths".to_string(), key),
        Error::TooManySlots(key) => ("TooManySlots".to_string(), key),
        other => panic!("{other:?} names no key"),
    }
}

fn slots_vector() -> SlotsVector {
    let c = RustBitcoin::new();
    let w = two_slot_wallet();
    let d = &w.descriptor;

    let template_bytes = c.descriptor_template(d).unwrap();
    let descriptor_slots = slots(c.descriptor_xpubs(d).unwrap()).unwrap();
    let slot_records = descriptor_slots
        .iter()
        .map(|slot| SlotRecord {
            base_key: hex::encode(slot.xpub.key),
            slot: slot.number,
            chain_code: hex::encode(slot.xpub.chain_code),
            branches: slot.xpub.branches.clone(),
        })
        .collect();

    let (keychain, index) = (1u32, 305u32);
    let bundle = derive_bundle(&c, d, keychain, index).unwrap();
    let keydata = psbt_keydata(&c, &w, &bundle);
    let mut entries = Vec::with_capacity(descriptor_slots.len());
    for (slot, keydata) in descriptor_slots.iter().zip(keydata) {
        let xpub = &slot.xpub;
        let mut tweak_path = xpub.branches[keychain as usize].clone();
        tweak_path.push(index);
        let derived = compute_bip32_tweak(&c, &xpub.key, &xpub.chain_code, &tweak_path).unwrap();
        entries.push(SlotBundleEntry {
            base_key: hex::encode(xpub.key),
            slot: slot.number,
            tweak_path,
            tweak: hex::encode(derived.tweak),
            psbt_keydata: hex::encode(keydata),
        });
    }
    let bundle = SlotBundleCase {
        keychain,
        index,
        entries,
        serialization: hex::encode(bundle.to_bytes()),
    };

    let roots = [0u32, 1]
        .into_iter()
        .map(|keychain| RootCase {
            keychain,
            tree_start: 0,
            root: hex::encode(build_tree(&c, d, keychain, 0).unwrap().root),
        })
        .collect();

    let (keychain, tree_start, index) = (1u32, 0u32, 5u32);
    let proof = build_tree(&c, d, keychain, tree_start)
        .unwrap()
        .proof(keychain, index)
        .unwrap();
    let proof = SlotProofCase {
        keychain,
        tree_start,
        index,
        bundle: hex::encode(derive_bundle(&c, d, keychain, index).unwrap().to_bytes()),
        proof: hex::encode(proof.to_bytes()),
    };

    let delegator: [u8; 33] = hex_arr(DELEGATOR_KEY);
    let invalid_template_keys = ["@0", "@01", "@256"]
        .iter()
        .map(|suffix| format!("{DELEGATOR_KEY}{suffix}"))
        .collect();
    let invalid_psbt_keydata = [vec![0x00], vec![0x01, 0x00]]
        .iter()
        .map(|suffix| hex::encode([&delegator[..], suffix].concat()))
        .collect();

    let other_chain_code = tpub(
        SecretKey::from_slice(&DELEGATOR_SECRET)
            .unwrap()
            .public_key(&Secp256k1::new()),
        [0x0f; 32],
    );
    let invalid_descriptors = [
        (
            "the delegator key with another chain code on its second path",
            altered_descriptor(&c, &w, &format!("{other_chain_code}/<2;3>/*")),
        ),
        (
            "the delegator key on <0;1> and <1;2>, which share the branch 1",
            altered_descriptor(&c, &w, &format!("{}/<1;2>/*", tpub_of_delegator())),
        ),
    ]
    .into_iter()
    .map(|(description, descriptor)| {
        let parsed = MsDescriptor::<DescriptorPublicKey>::from_str(&descriptor).unwrap();
        let (error, key) = refusal(c.descriptor_xpubs(&parsed).unwrap_err());
        InvalidDescriptor {
            description: description.to_string(),
            descriptor,
            error,
            key: hex::encode(key),
        }
    })
    .collect();

    SlotsVector {
        descriptor: String::from_utf8(c.descriptor_policy(d)).unwrap(),
        template: String::from_utf8(template_bytes.clone()).unwrap(),
        template_id: hex::encode(template_id(&c, &template_bytes)),
        slots: slot_records,
        bundle,
        roots,
        proof,
        invalid_template_keys,
        invalid_psbt_keydata,
        invalid_descriptors,
    }
}

/// The delegator's extended public key in the test wallets.
fn tpub_of_delegator() -> String {
    tpub(
        SecretKey::from_slice(&DELEGATOR_SECRET)
            .unwrap()
            .public_key(&Secp256k1::new()),
        DELEGATOR_CHAIN_CODE,
    )
    .to_string()
}

#[test]
#[ignore]
fn regenerate_vectors() {
    let out = serde_json::to_string_pretty(&primitives()).unwrap();
    std::fs::write("test_vectors/accumulator/primitives.json", out + "\n").unwrap();

    let out = serde_json::to_string_pretty(&tree()).unwrap();
    std::fs::write("test_vectors/accumulator/tree.json", out + "\n").unwrap();

    let out = serde_json::to_string_pretty(&proof()).unwrap();
    std::fs::write("test_vectors/accumulator/proof.json", out + "\n").unwrap();

    let out = serde_json::to_string_pretty(&slots_vector()).unwrap();
    std::fs::write("test_vectors/accumulator/slots.json", out + "\n").unwrap();
}

#[test]
fn vectors_primitives() {
    let vectors: Primitives = serde_json::from_str(PRIMITIVES_JSON).unwrap();
    let fresh = primitives();
    assert_eq!(vectors, fresh);

    for case in &vectors.keys_digest {
        let concatenated: Vec<u8> = case
            .sorted_records
            .iter()
            .flat_map(|r| hex_vec(r))
            .collect();
        let digest = sha256::Hash::hash(&concatenated).to_byte_array();
        assert_eq!(hex::encode(digest), case.keys_digest);
    }

    let dup_case = &vectors.keys_digest[1];
    assert_eq!(dup_case.sorted_records.len(), 3);
    assert_eq!(&dup_case.sorted_records[0][..2], "01");
    assert_eq!(&dup_case.sorted_records[1][..2], "02");
    assert_eq!(&dup_case.sorted_records[2][..2], "03");

    let case = &vectors.leaf_nonce;
    let kd: [u8; 32] = hex_arr(&case.keys_digest);
    let mut prev_next_chaincode: Option<String> = None;
    for step in &case.steps {
        if let Some(prev) = &prev_next_chaincode {
            assert_eq!(prev, &step.chaincode);
        }
        let chaincode: [u8; 32] = hex_arr(&step.chaincode);
        let mut engine = HmacEngine::<sha512::Hash>::new(&chaincode);
        engine.input(NONCE_TAG);
        engine.input(&kd);
        engine.input(&case.keychain.to_be_bytes());
        engine.input(&step.index.to_be_bytes());
        let out = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();
        assert_eq!(hex::encode(&out[..32]), step.next_chaincode);
        assert_eq!(hex::encode(&out[32..]), step.nonce);
        prev_next_chaincode = Some(step.next_chaincode.clone());
    }

    for case in &vectors.shuffle {
        let mut sorted = case.order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0u8..=255).collect::<Vec<u8>>());
    }

    let bundle_case = &vectors.bundle;
    assert_eq!(
        bundle_case.serialization.len(),
        130 * bundle_case.entries.len()
    );
    let mut concatenated = String::new();
    let mut prev_key: Option<Vec<u8>> = None;
    for entry in &bundle_case.entries {
        concatenated.push_str(&entry.base_key);
        concatenated.push_str(&entry.tweak);
        let key = hex_vec(&entry.base_key);
        if let Some(prev) = &prev_key {
            assert!(prev < &key);
        }
        prev_key = Some(key);
    }
    assert_eq!(concatenated, bundle_case.serialization);
}

#[test]
fn vectors_tree() {
    let vectors: TreeVector = serde_json::from_str(TREE_JSON).unwrap();
    let fresh = tree();
    assert_eq!(vectors, fresh);

    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    assert_eq!(vectors.leaves.len(), MAX_RANGE);
    assert_eq!(vectors.order.len(), MAX_RANGE);
    assert_eq!(vectors.levels.len(), HEIGHT + 1);
    assert_eq!(vectors.levels[HEIGHT].len(), 1);

    for position in 0..MAX_RANGE {
        let offset = vectors.order[position] as usize;
        assert_eq!(vectors.levels[0][position], vectors.leaves[offset].leaf);
    }

    for level in 1..=HEIGHT {
        for position in 0..vectors.levels[level].len() {
            let left: [u8; 32] = hex_arr(&vectors.levels[level - 1][2 * position]);
            let right: [u8; 32] = hex_arr(&vectors.levels[level - 1][2 * position + 1]);
            let expected = branch_hash(&c, &left, &right);
            assert_eq!(vectors.levels[level][position], hex::encode(expected));
        }
    }

    let top: [u8; 32] = hex_arr(&vectors.levels[HEIGHT][0]);
    assert_eq!(vectors.root, hex::encode(root_hash(&c, &top)));

    let built = build_tree(&c, d, vectors.keychain, vectors.tree_start).unwrap();
    assert_eq!(vectors.root, hex::encode(built.root));

    for leaf in &vectors.leaves {
        let nonce: [u8; 32] = hex_arr(&leaf.nonce);
        let bundle = derive_bundle(&c, d, vectors.keychain, leaf.index).unwrap();
        assert_eq!(leaf.leaf, hex::encode(leaf_hash(&c, &bundle, &nonce)));
    }

    let template_id_bytes: [u8; 32] = hex_arr(&vectors.template_id);
    let root_bytes: [u8; 32] = hex_arr(&vectors.root);
    let expected_message = root_message(&c, &template_id_bytes, &root_bytes);
    assert_eq!(vectors.root_message, hex::encode(expected_message));

    let key: [u8; 33] = hex_arr(&vectors.key);
    let branch_tweak: [u8; 32] = hex_arr(&vectors.branch_tweak);
    let branch_key: [u8; 33] = hex_arr(&vectors.branch_key);
    let xpub = c
        .descriptor_xpubs(d)
        .unwrap()
        .into_iter()
        .find(|xpub| xpub.key == key)
        .unwrap();
    let branch = &xpub.branches[vectors.keychain as usize];
    let derived = compute_bip32_tweak(&c, &key, &xpub.chain_code, branch).unwrap();
    assert_eq!(derived.tweak, branch_tweak);
    assert_eq!(derived.key, branch_key);
    assert_eq!(tweak_key(&c, &key, &branch_tweak), Ok(branch_key));

    let message: [u8; 32] = hex_arr(&vectors.root_message);
    let signature = hex_vec(&vectors.signature);
    assert!(c.bip322_verify(&branch_key, &message, &signature));

    let record = RootRecord {
        keychain: vectors.keychain,
        tree_start: vectors.tree_start,
        root: root_bytes,
        signature: Some(RootSignature {
            key,
            branch_tweak,
            signature,
        }),
    };
    assert_eq!(
        verify_root(&c, &w.template, &record, RootPolicy::RequireSignature),
        Ok(())
    );
}

#[test]
fn vectors_proof() {
    let vectors: ProofVector = serde_json::from_str(PROOF_JSON).unwrap();
    let fresh = proof();
    assert_eq!(vectors, fresh);

    let c = RustBitcoin::new();

    let root: [u8; 32] = hex_arr(&vectors.root);
    let bundle = Bundle::from_bytes(&hex_vec(&vectors.bundle)).unwrap();
    let proof_bytes = hex_vec(&vectors.proof);
    let proof = Proof::from_bytes(&proof_bytes).unwrap();

    assert!(verify_proof(&c, &bundle, &proof, &root));
    assert_eq!(hex::encode(proof.to_bytes()), vectors.proof);
    assert_eq!(proof_bytes[32], vectors.position);

    let leaf: [u8; 32] = hex_arr(&vectors.leaf);
    let position = vectors.position;
    let mut node = leaf;
    for (level, step) in vectors.trace.iter().enumerate() {
        let bit = (position >> level) & 1;
        assert_eq!(step.level, level as u8);
        assert_eq!(step.bit, bit);
        assert_eq!(step.node_before, hex::encode(node));
        let sibling: [u8; 32] = hex_arr(&step.sibling);
        let node_after = if bit == 0 {
            branch_hash(&c, &node, &sibling)
        } else {
            branch_hash(&c, &sibling, &node)
        };
        assert_eq!(step.node_after, hex::encode(node_after));
        node = node_after;
    }
    assert_eq!(root_hash(&c, &node), root);

    assert_eq!(vectors.negatives.len(), 4);
    for negative in &vectors.negatives {
        assert!(!negative.expected);
        let bundle = Bundle::from_bytes(&hex_vec(&negative.bundle)).unwrap();
        let proof = Proof::from_bytes(&hex_vec(&negative.proof)).unwrap();
        assert!(!verify_proof(&c, &bundle, &proof, &root));
    }
}

#[test]
fn vectors_slots() {
    let vectors: SlotsVector = serde_json::from_str(SLOTS_JSON).unwrap();
    assert_eq!(vectors, slots_vector());

    let c = RustBitcoin::new();
    let template_digest = sha256::Hash::hash(vectors.template.as_bytes()).to_byte_array();
    assert_eq!(hex::encode(template_digest), vectors.template_id);

    let reused: Vec<&SlotRecord> = vectors.slots.iter().filter(|s| s.slot == 1).collect();
    assert_eq!(reused.len(), 2);
    for slot in reused {
        assert!(vectors.template.contains(&format!("{}@1", slot.base_key)));
        assert!(vectors.slots.iter().any(|s| s.base_key == slot.base_key
            && s.slot == 0
            && s.chain_code == slot.chain_code));
    }

    let bundle_case = &vectors.bundle;
    let mut concatenated = String::new();
    for (entry, slot) in bundle_case.entries.iter().zip(&vectors.slots) {
        assert_eq!((&entry.base_key, entry.slot), (&slot.base_key, slot.slot));
        let mut tweak_path = slot.branches[bundle_case.keychain as usize].clone();
        tweak_path.push(bundle_case.index);
        assert_eq!(entry.tweak_path, tweak_path);
        let key: [u8; 33] = hex_arr(&entry.base_key);
        let chain_code: [u8; 32] = hex_arr(&slot.chain_code);
        let derived = compute_bip32_tweak(&c, &key, &chain_code, &tweak_path).unwrap();
        assert_eq!(hex::encode(derived.tweak), entry.tweak);
        let keydata = hex_vec(&entry.psbt_keydata);
        match entry.slot {
            0 => assert_eq!(keydata, key),
            slot => assert_eq!(keydata, [&key[..], &[slot]].concat()),
        }
        concatenated.push_str(&entry.base_key);
        concatenated.push_str(&entry.tweak);
    }
    assert_eq!(concatenated, bundle_case.serialization);
    let bundle = Bundle::from_bytes(&hex_vec(&bundle_case.serialization)).unwrap();
    let mut psbt = spend_psbt(&two_slot_wallet());
    for entry in &bundle_case.entries {
        psbt.outputs[1].proprietary.insert(
            field_key(SUBTYPE_TWEAK, hex_vec(&entry.psbt_keydata)),
            hex_vec(&entry.tweak),
        );
    }
    assert_eq!(c.output_bundle(&psbt, 1), Ok(Some(bundle.clone())));
    let decoded: Vec<(String, u8)> = bundle
        .entries()
        .iter()
        .map(|e| (hex::encode(e.slot.key), e.slot.number))
        .collect();
    let expected: Vec<(String, u8)> = bundle_case
        .entries
        .iter()
        .map(|e| (e.base_key.clone(), e.slot))
        .collect();
    assert_eq!(decoded, expected);

    let proof_case = &vectors.proof;
    let root = vectors
        .roots
        .iter()
        .find(|r| r.keychain == proof_case.keychain && r.tree_start == proof_case.tree_start)
        .unwrap();
    let bundle = Bundle::from_bytes(&hex_vec(&proof_case.bundle)).unwrap();
    let proof = Proof::from_bytes(&hex_vec(&proof_case.proof)).unwrap();
    assert!(verify_proof(&c, &bundle, &proof, &hex_arr(&root.root)));

    for key in &vectors.invalid_template_keys {
        assert_eq!(TemplateKey::from_str(key), Err(TemplateKeyError::Slot));
    }
    for keydata in &vectors.invalid_psbt_keydata {
        let mut psbt = spend_psbt(&two_slot_wallet());
        psbt.outputs[1]
            .proprietary
            .insert(field_key(SUBTYPE_TWEAK, hex_vec(keydata)), vec![0x01; 32]);
        assert_eq!(c.output_bundle(&psbt, 1), Err(Error::EntryLength));
    }
    assert_eq!(vectors.invalid_descriptors.len(), 2);
    for case in &vectors.invalid_descriptors {
        let d = MsDescriptor::<DescriptorPublicKey>::from_str(&case.descriptor).unwrap();
        let (error, key) = refusal(c.descriptor_xpubs(&d).unwrap_err());
        assert_eq!(
            (error, hex::encode(key)),
            (case.error.clone(), case.key.clone())
        );
    }
}
