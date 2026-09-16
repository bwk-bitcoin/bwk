mod common;

use std::collections::HashMap;

use bwk_bip89::{
    accumulator::{
        branch_hash, generate_tree, keys_digest, leaf_hash, leaf_nonce, policy_hash, policy_id,
        record::{
            build_tree, root_message, sign_tree_root, template_id, verify_root, RootRecord,
            RootSignature,
        },
        root_hash,
        shuffle::{invert, shuffle_key, shuffle_order, SHUFFLE_TAG},
        tree::{
            sibling_position, verify_proof, NullTreeBuilder, Proof, ProofTreeBuilder, Tree,
            TreeBuilder, HEIGHT,
        },
        BRANCH_TAG, LEAF_TAG, NONCE_TAG, POLICY_TAG, ROOT_TAG,
    },
    bundle::derive_bundle,
    rust_bitcoin::{
        miniscript::bitcoin::{
            bip32::ChildNumber,
            hashes::{sha256, sha512, Hash, HashEngine, Hmac, HmacEngine},
            secp256k1::PublicKey,
        },
        RustBitcoin,
    },
    tweak::tweak_key,
    BitcoinBackend, Bundle, Entry, Error, Sha256Engine, Xpub,
};
use common::{
    hex_arr, other_template, root_signature, tpub, wallet, SliceDescriptor, VectorBackend,
    OWNER1_CHAIN_CODE, OWNER1_KEY, OWNER1_SECRET, OWNER2_SECRET,
};

fn tagged(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag).to_byte_array();
    let mut engine = sha256::Hash::engine();
    engine.input(&t);
    engine.input(&t);
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn pk1() -> [u8; 33] {
    hex_arr("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
}

fn pk2() -> [u8; 33] {
    hex_arr("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766")
}

fn pk3() -> [u8; 33] {
    hex_arr("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337")
}

fn record(chain_code: [u8; 32], key: [u8; 33]) -> Vec<u8> {
    [&chain_code[..], &key[..]].concat()
}

#[test]
fn policy_id_hashes_descriptor_bytes() {
    let c = RustBitcoin::new();

    assert_eq!(
        policy_id(&c, b"descriptor"),
        sha256::Hash::hash(b"descriptor").to_byte_array()
    );
    assert_eq!(
        policy_id(&c, b"descriptor"),
        hex_arr::<32>("194b520dc30384b3fc233e123778835e2adc362d91c6e33015ed3db2379d7ea1")
    );

    let wallet = wallet();
    assert_eq!(
        policy_id(&c, &c.descriptor_policy(&wallet.descriptor)),
        hex_arr::<32>("b670524275bc74629dd9210f7088a95c2b1119be1bcb53448f32237f9594cd47")
    );
}

#[test]
fn keys_digest_sorts_raw_bytes_and_dedups() {
    let c = RustBitcoin::new();

    let a = Xpub {
        key: pk2(),
        chain_code: [0x02; 32],
        branches: [vec![0], vec![1]],
    };
    let b = Xpub {
        key: pk1(),
        chain_code: [0x01; 32],
        branches: [vec![0], vec![1]],
    };

    let raw_sorted = [record(b.chain_code, b.key), record(a.chain_code, a.key)].concat();
    let mut engine = c.sha256();
    engine.update(&raw_sorted);
    let expected = engine.finalize();
    assert_eq!(
        expected,
        hex_arr::<32>("600eb31ff22c4d751d781acd82d59f655e0fae9f88ec319c0e424fce48614ce3")
    );

    let dup_digest = keys_digest(&c, &[a.clone(), b.clone(), a.clone()]);
    assert_eq!(dup_digest, expected);

    let key_ordered = [record(a.chain_code, a.key), record(b.chain_code, b.key)].concat();
    let mut engine = c.sha256();
    engine.update(&key_ordered);
    let key_ordered_digest = engine.finalize();
    assert_eq!(
        key_ordered_digest,
        hex_arr::<32>("21886da13af0e5de9806bcec877308317b9dde7e3aa7a7260e8258f4dfec9c83")
    );
    assert_ne!(dup_digest, key_ordered_digest);

    let wallet = wallet();
    assert_eq!(
        keys_digest(&c, &c.descriptor_xpubs(&wallet.descriptor).unwrap()),
        hex_arr::<32>("428d6ec9132ea4622391506e24b341c7a1c83be7be092668a7293b1ec9e93949")
    );
}

#[test]
fn leaf_nonce_chain_matches_hmac_sha512() {
    let c = RustBitcoin::new();

    let pid = [0x42; 32];
    let kd = [0x24; 32];
    let keychain = 1u32;
    let tree_start = 300u32;

    let mut chaincode = policy_hash(&c, &pid, keychain, tree_start);
    let expected_cc0 = tagged(
        POLICY_TAG,
        &[&pid[..], &keychain.to_be_bytes(), &tree_start.to_be_bytes()].concat(),
    );
    assert_eq!(chaincode, expected_cc0);

    let mut nonces = Vec::new();
    for index in [300u32, 301, 302] {
        let (next_chaincode, nonce) = leaf_nonce(&c, &chaincode, &kd, keychain, index);

        let mut engine = HmacEngine::<sha512::Hash>::new(&chaincode);
        engine.input(NONCE_TAG);
        engine.input(&kd);
        engine.input(&keychain.to_be_bytes());
        engine.input(&index.to_be_bytes());
        let out = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();

        assert_eq!(next_chaincode, out[..32]);
        assert_eq!(nonce, out[32..]);

        chaincode = next_chaincode;
        nonces.push(nonce);
    }

    assert_ne!(nonces[0], nonces[1]);
    assert_ne!(nonces[1], nonces[2]);
    assert_ne!(nonces[0], nonces[2]);
}

#[test]
fn leaf_hash_is_tagged_bundle_and_nonce() {
    let c = RustBitcoin::new();

    let bundle = Bundle::new(vec![
        Entry {
            key: pk3(),
            tweak: [0x33; 32],
        },
        Entry {
            key: pk1(),
            tweak: [0x11; 32],
        },
        Entry {
            key: pk2(),
            tweak: [0x22; 32],
        },
    ])
    .unwrap();
    let nonce = [0x5a; 32];

    let ser = bundle.to_bytes();
    assert_eq!(ser.len(), 195);
    assert!(ser.starts_with(&pk2()));

    let expected = tagged(LEAF_TAG, &[&ser[..], &nonce[..]].concat());
    assert_eq!(leaf_hash(&c, &bundle, &nonce), expected);

    let changed = Bundle::new(vec![
        Entry {
            key: pk3(),
            tweak: [0x33; 32],
        },
        Entry {
            key: pk1(),
            tweak: [0x12; 32],
        },
        Entry {
            key: pk2(),
            tweak: [0x22; 32],
        },
    ])
    .unwrap();
    assert_ne!(
        leaf_hash(&c, &changed, &nonce),
        leaf_hash(&c, &bundle, &nonce)
    );
}

#[test]
fn branch_hash_keeps_child_order_and_root_is_tagged() {
    let c = RustBitcoin::new();

    let l = [0x01; 32];
    let r = [0x02; 32];

    assert_eq!(
        branch_hash(&c, &l, &r),
        tagged(BRANCH_TAG, &[&l[..], &r[..]].concat())
    );
    assert_ne!(branch_hash(&c, &l, &r), branch_hash(&c, &r, &l));

    assert_eq!(root_hash(&c, &l), tagged(ROOT_TAG, &l));
}

#[test]
fn shuffle_is_deterministic() {
    let c = RustBitcoin::new();
    let key = [0x42; 32];

    assert_eq!(shuffle_order(&c, &key), shuffle_order(&c, &key));
}

#[test]
fn shuffle_is_a_permutation() {
    let c = RustBitcoin::new();
    let order = shuffle_order(&c, &[0x42; 32]);

    let mut sorted = order;
    sorted.sort_unstable();
    let identity: Vec<u8> = (0..=255).collect();
    assert_eq!(sorted.to_vec(), identity);
    assert_ne!(order.to_vec(), identity);
}

#[test]
fn invert_roundtrips() {
    let c = RustBitcoin::new();
    let order = shuffle_order(&c, &[0x42; 32]);
    let inv = invert(&order);

    for pos in 0..order.len() {
        assert_eq!(inv[order[pos] as usize] as usize, pos);
    }
    assert_eq!(invert(&inv), order);
}

#[test]
fn shuffle_is_key_dependent() {
    let c = RustBitcoin::new();

    let a = shuffle_order(&c, &[0x01; 32]);
    let b = shuffle_order(&c, &[0x02; 32]);
    assert_ne!(a, b);
}

#[test]
fn shuffle_is_tree_bound() {
    let c = RustBitcoin::new();
    let pid = [0x42; 32];

    let a = shuffle_order(&c, &shuffle_key(&c, &pid, 0, 0));
    let b = shuffle_order(&c, &shuffle_key(&c, &pid, 0, 1));
    assert_ne!(a, b);

    assert_eq!(
        shuffle_key(&c, &pid, 1, 300),
        tagged(
            SHUFFLE_TAG,
            &[&pid[..], &1u32.to_be_bytes(), &300u32.to_be_bytes()].concat()
        )
    );
}

#[test]
fn shuffle_is_keychain_bound() {
    let c = RustBitcoin::new();
    let pid = [0x42; 32];

    let a = shuffle_order(&c, &shuffle_key(&c, &pid, 0, 0));
    let b = shuffle_order(&c, &shuffle_key(&c, &pid, 1, 0));
    assert_ne!(a, b);
}

#[test]
fn shuffle_matches_reference_order() {
    let c = RustBitcoin::new();
    let order = shuffle_order(&c, &[7u8; 32]);

    // values pinned from the original blinded address accumulator crate
    assert_eq!(
        order[..16],
        [103, 85, 131, 248, 116, 51, 109, 89, 223, 24, 242, 186, 200, 151, 60, 72]
    );
}

fn hash(level: usize, pos: usize) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = level as u8;
    hash[1] = pos as u8;
    hash
}

/// Builds a real 256-leaf tree over bundles that each tweak `pk1()` by their
/// offset, so `committed_tree` produces a root a `verify_proof` call can
/// actually check.
fn committed_tree(c: &RustBitcoin) -> (Tree, Vec<Bundle>) {
    let mut builder = ProofTreeBuilder::new(1, 512);
    let mut bundles = Vec::new();
    let mut level = vec![[0u8; 32]; 256];
    for offset in 0..256usize {
        let mut tweak = [0u8; 32];
        tweak[31] = offset as u8;
        let bundle = Bundle::new(vec![Entry { key: pk1(), tweak }]).unwrap();
        let nonce = [offset as u8; 32];
        let position = 255 - offset;
        level[position] = leaf_hash(c, &bundle, &nonce);
        builder.leaf(
            position as u8,
            512 + offset as u32,
            &level[position],
            &nonce,
        );
        bundles.push(bundle);
    }
    for l in 1..=8u8 {
        level = level
            .chunks(2)
            .map(|p| branch_hash(c, &p[0], &p[1]))
            .collect();
        for (position, hash) in level.iter().enumerate() {
            builder.node(l, position as u8, hash);
        }
    }
    let root = root_hash(c, &level[0]);
    (builder.finish(root), bundles)
}

#[test]
fn proof_tree_returns_proof_for_absolute_index() {
    let mut builder = ProofTreeBuilder::new(1, 512);
    for local_pos in 0..256usize {
        let offset = 255 - local_pos;
        builder.leaf(
            local_pos as u8,
            512 + offset as u32,
            &hash(0, local_pos),
            &[offset as u8; 32],
        );
    }
    for level in 1..=8u8 {
        for pos in 0..(256usize >> level) {
            builder.node(level, pos as u8, &hash(level as usize, pos));
        }
    }
    let tree = builder.finish([9u8; 32]);

    assert_eq!(tree.root, [9u8; 32]);
    assert_eq!(tree.keychain, 1);
    assert_eq!(tree.tree_start, 512);

    let proof = tree.proof(1, 623).unwrap();
    assert_eq!(proof.nonce, [111u8; 32]);
    assert_eq!(proof.position, 144);
    let expected_positions = [145u8, 73, 37, 19, 8, 5, 3, 0];
    for (level, &pos) in expected_positions.iter().enumerate() {
        assert_eq!(proof.siblings[level], hash(level, pos as usize));
    }
}

#[test]
fn proof_tree_returns_none_outside_tree() {
    let mut builder = ProofTreeBuilder::new(1, 512);
    for offset in 0..256usize {
        builder.leaf(
            offset as u8,
            512 + offset as u32,
            &hash(0, offset),
            &[offset as u8; 32],
        );
    }
    let tree = builder.finish([9u8; 32]);

    assert_eq!(tree.proof(1, 511), None);
    assert_eq!(tree.proof(1, 768), None);
    assert_eq!(tree.proof(1, u32::MAX), None);
    assert_eq!(tree.proof(0, 512), None);

    let proof = tree.proof(1, 767).unwrap();
    assert_eq!(proof.position, 255);
    assert_eq!(proof.nonce, [255u8; 32]);
}

#[test]
fn proof_codec_roundtrip_and_lengths() {
    let mut siblings = [[0u8; 32]; HEIGHT];
    for (level, sibling) in siblings.iter_mut().enumerate() {
        *sibling = [0x20 + level as u8; 32];
    }
    let proof = Proof {
        nonce: [0x11; 32],
        position: 0x90,
        siblings,
    };

    let bytes = proof.to_bytes();
    assert_eq!(bytes[0], 0x11);
    assert_eq!(bytes[31], 0x11);
    assert_eq!(bytes[32], 0x90);
    assert_eq!(bytes[33], 0x20);
    assert_eq!(bytes[64], 0x20);
    assert_eq!(bytes[65], 0x21);
    assert_eq!(bytes[288], 0x27);
    assert_eq!(Proof::from_bytes(&bytes), Ok(proof));

    assert_eq!(Proof::from_bytes(&bytes[..288]), Err(Error::ProofLength));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert_eq!(Proof::from_bytes(&too_long), Err(Error::ProofLength));
    assert_eq!(Proof::from_bytes(&[]), Err(Error::ProofLength));
}

#[test]
fn sibling_position_literals() {
    assert_eq!(sibling_position(0, 0), 1);
    assert_eq!(sibling_position(1, 0), 0);
    assert_eq!(sibling_position(144, 0), 145);
    assert_eq!(sibling_position(144, 4), 8);
    assert_eq!(sibling_position(254, 0), 255);
    assert_eq!(sibling_position(0, 7), 1);
    assert_eq!(sibling_position(255, 7), 0);
}

#[test]
fn valid_proof_verifies() {
    let c = RustBitcoin::new();
    let (tree, bundles) = committed_tree(&c);
    let proof = tree.proof(1, 623).unwrap();

    assert!(verify_proof(&c, &bundles[111], &proof, &tree.root));
    assert!(!verify_proof(&c, &bundles[112], &proof, &tree.root));
    assert!(!verify_proof(&c, &bundles[111], &proof, &[0u8; 32]));
}

#[test]
fn tampered_sibling_fails() {
    let c = RustBitcoin::new();
    let (tree, bundles) = committed_tree(&c);
    let proof = tree.proof(1, 623).unwrap();

    for level in 0..HEIGHT {
        let mut tampered = proof;
        tampered.siblings[level][0] ^= 1;
        assert!(!verify_proof(&c, &bundles[111], &tampered, &tree.root));
    }
}

#[test]
fn tampered_position_fails() {
    let c = RustBitcoin::new();
    let (tree, bundles) = committed_tree(&c);
    let proof = tree.proof(1, 623).unwrap();

    for position in 0u16..=255 {
        let position = position as u8;
        if position == proof.position {
            continue;
        }
        let mut tampered = proof;
        tampered.position = position;
        assert!(!verify_proof(&c, &bundles[111], &tampered, &tree.root));
    }
}

#[test]
fn tampered_nonce_fails() {
    let c = RustBitcoin::new();
    let (tree, bundles) = committed_tree(&c);
    let mut proof = tree.proof(1, 623).unwrap();
    proof.nonce[31] ^= 1;

    assert!(!verify_proof(&c, &bundles[111], &proof, &tree.root));
}

#[test]
fn generate_tree_verifies_all_proofs() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let mut trees = HashMap::new();
    for tree_start in [0u32, 1, 300, 512] {
        for keychain in [0u32, 1] {
            let tree = generate_tree(
                &c,
                d,
                keychain,
                tree_start,
                ProofTreeBuilder::new(keychain, tree_start),
            )
            .unwrap();
            assert_eq!(tree.keychain, keychain);
            assert_eq!(tree.tree_start, tree_start);

            for offset in 0..256u32 {
                let index = tree_start + offset;
                let proof = tree
                    .proof(keychain, index)
                    .unwrap_or_else(|| panic!("missing proof start {tree_start} offset {offset}"));
                let bundle = derive_bundle(&c, d, keychain, index).unwrap();
                assert!(
                    verify_proof(&c, &bundle, &proof, &tree.root),
                    "start {tree_start} offset {offset}"
                );
            }
            trees.insert((keychain, tree_start), tree);
        }
    }

    assert_eq!(trees[&(1, 300)].proof(1, 305).unwrap().position, 99);
    assert_eq!(trees[&(0, 0)].proof(0, 9).unwrap().position, 37);
    assert_eq!(trees[&(1, 0)].proof(1, 3).unwrap().position, 85);
}

#[test]
fn null_and_proof_builders_agree() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let cases: [(u32, u32, [u8; 32]); 3] = [
        (
            0,
            0,
            hex_arr("5cac3809f3f1f1453bec2970a05f06898ecc5e20d43b800f6ce2528d9059b504"),
        ),
        (
            1,
            300,
            hex_arr("73b82914c358291941f25af7409534aa4ecfa91b40a30da5617fc62612d48570"),
        ),
        (
            1,
            0,
            hex_arr("6692aa17194acaf0924373a301d4b18bc5f6b85791dc6504ba8f3dfc98591be9"),
        ),
    ];

    for (keychain, tree_start, expected) in cases {
        let null_root = generate_tree(&c, d, keychain, tree_start, NullTreeBuilder).unwrap();
        let proof_root = generate_tree(
            &c,
            d,
            keychain,
            tree_start,
            ProofTreeBuilder::new(keychain, tree_start),
        )
        .unwrap()
        .root;
        assert_eq!(null_root, expected);
        assert_eq!(proof_root, expected);
    }
}

struct Recorder {
    leaves: Vec<(u8, u32, [u8; 32], [u8; 32])>,
    nodes: usize,
}

impl TreeBuilder for Recorder {
    type Tree = Recorder;

    fn leaf(&mut self, position: u8, index: u32, hash: &[u8; 32], nonce: &[u8; 32]) {
        self.leaves.push((position, index, *hash, *nonce));
    }

    fn node(&mut self, _level: u8, _position: u8, _hash: &[u8; 32]) {
        self.nodes += 1;
    }

    fn finish(self, _root: [u8; 32]) -> Recorder {
        self
    }
}

#[test]
fn derived_leaf_matches_bundle_leaf() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let rec = generate_tree(
        &c,
        d,
        1,
        300,
        Recorder {
            leaves: Vec::new(),
            nodes: 0,
        },
    )
    .unwrap();

    assert_eq!(rec.leaves.len(), 256);
    assert_eq!(rec.nodes, 255);

    let indexes: Vec<u32> = rec.leaves.iter().map(|(_, index, _, _)| *index).collect();
    assert_eq!(indexes, (300..556).collect::<Vec<u32>>());

    let mut positions: Vec<u8> = rec.leaves.iter().map(|(position, ..)| *position).collect();
    positions.sort_unstable();
    assert_eq!(positions, (0..=255).collect::<Vec<u8>>());

    for (_, index, hash, nonce) in &rec.leaves {
        let bundle = derive_bundle(&c, d, 1, *index).unwrap();
        assert_eq!(*hash, leaf_hash(&c, &bundle, nonce));
    }

    let expected_nonce = leaf_nonce(
        &c,
        &policy_hash(&c, &policy_id(&c, &c.descriptor_policy(d)), 1, 300),
        &keys_digest(&c, &c.descriptor_xpubs(d).unwrap()),
        1,
        300,
    )
    .1;
    assert_eq!(rec.leaves[0].3, expected_nonce);

    let v = VectorBackend::default();
    let s = SliceDescriptor(c.descriptor_xpubs(d).unwrap().into_iter().rev().collect());
    let rec = generate_tree(
        &v,
        &s,
        0,
        0,
        Recorder {
            leaves: Vec::new(),
            nodes: 0,
        },
    )
    .unwrap();
    for (_, index, hash, nonce) in &rec.leaves {
        let bundle = derive_bundle(&v, &s, 0, *index).unwrap();
        assert_eq!(*hash, leaf_hash(&c, &bundle, nonce));
    }

    let mut dup_xpubs = c.descriptor_xpubs(d).unwrap();
    dup_xpubs.push(dup_xpubs[0].clone());
    let dup = SliceDescriptor(dup_xpubs);
    assert_eq!(
        generate_tree(&v, &dup, 0, 0, NullTreeBuilder),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn other_index_bundle_fails() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let tree = generate_tree(&c, d, 0, 0, ProofTreeBuilder::new(0, 0)).unwrap();
    let proof = tree.proof(0, 5).unwrap();

    let other_index = derive_bundle(&c, d, 0, 6).unwrap();
    assert!(!verify_proof(&c, &other_index, &proof, &tree.root));

    let other_keychain = derive_bundle(&c, d, 1, 5).unwrap();
    assert!(!verify_proof(&c, &other_keychain, &proof, &tree.root));

    let same = derive_bundle(&c, d, 0, 5).unwrap();
    assert!(verify_proof(&c, &same, &proof, &tree.root));
}

#[test]
fn tree_start_range_rejected() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    assert_eq!(
        generate_tree(&c, d, 0, 0x8000_0000 - 255, NullTreeBuilder),
        Err(Error::IndexRange)
    );
    assert_eq!(
        generate_tree(&c, d, 0, u32::MAX, NullTreeBuilder),
        Err(Error::IndexRange)
    );
    assert!(generate_tree(&c, d, 0, 0x8000_0000 - 256, NullTreeBuilder).is_ok());
}

#[test]
fn invalid_keychain_rejected() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    assert_eq!(
        generate_tree(&c, d, 2, 0, NullTreeBuilder),
        Err(Error::InvalidKeychain)
    );
    assert_eq!(
        generate_tree(&c, d, 2, u32::MAX, NullTreeBuilder),
        Err(Error::InvalidKeychain)
    );
}

const TEMPLATE_ID: &str = "c00957a72d065006ddac8c072160c1a7779fe1ca3ad88e73643e11bef6cb1da7";
const OTHER_TEMPLATE_ID: &str = "d8c7c371909c9b68a8e101fcc38154183f6d544d3ba48cdfbbc18cbf6222ca8d";
const ROOT_0_0: &str = "5cac3809f3f1f1453bec2970a05f06898ecc5e20d43b800f6ce2528d9059b504";
const ROOT_1_0: &str = "6692aa17194acaf0924373a301d4b18bc5f6b85791dc6504ba8f3dfc98591be9";
const ROOT_MESSAGE_0_0: &str = "738ac879beb5c14d5ace163c31674ae4edc859bef585943f714c95f24030180b";
const OTHER_SECRET: [u8; 32] = [0x05; 32];

#[test]
fn template_id_and_root_message_literals() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let tid = template_id(&c, &c.descriptor_template(d).unwrap());
    assert_eq!(tid, hex_arr::<32>(TEMPLATE_ID));

    let other_tid = template_id(&c, b"tr(other)");
    assert_eq!(other_tid, hex_arr::<32>(OTHER_TEMPLATE_ID));

    let root_0_0: [u8; 32] = hex_arr(ROOT_0_0);
    let message = root_message(&c, &tid, &root_0_0);
    assert_eq!(message, hex_arr::<32>(ROOT_MESSAGE_0_0));
    assert_ne!(message, root_message(&c, &other_tid, &root_0_0));
}

#[test]
fn root_signature_roundtrip() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let record = sign_tree_root(&c, d, &OWNER1_SECRET, 0, 0).unwrap();
    assert_eq!(record.keychain, 0);
    assert_eq!(record.tree_start, 0);
    assert_eq!(record.root, hex_arr::<32>(ROOT_0_0));
    let signed = root_signature(&record);
    assert_eq!(signed.key, hex_arr::<33>(OWNER1_KEY));

    let owner1 = tpub(
        PublicKey::from_slice(&signed.key).unwrap(),
        OWNER1_CHAIN_CODE,
    );
    let receive_branch = owner1
        .derive_pub(&w.secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap();
    assert_eq!(
        tweak_key(&c, &signed.key, &signed.branch_tweak),
        Ok(receive_branch.public_key.serialize())
    );

    assert_eq!(verify_root(&c, &w.template, &record), Ok(()));

    let mut flipped = record;
    // the first byte of the Schnorr signature, after the item count and its length
    flipped.signature.as_mut().unwrap().signature[2] ^= 1;
    assert_eq!(
        verify_root(&c, &w.template, &flipped),
        Err(Error::RootSignature)
    );
}

#[test]
fn root_signature_wrong_key_fails() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let record = sign_tree_root(&c, d, &OWNER1_SECRET, 0, 0).unwrap();
    let other = sign_tree_root(&c, d, &OWNER2_SECRET, 0, 0).unwrap();
    assert_eq!(verify_root(&c, &w.template, &other), Ok(()));

    let signed = root_signature(&record);
    let other_signed = root_signature(&other);
    let other_key = RootRecord {
        signature: Some(RootSignature {
            key: other_signed.key,
            branch_tweak: other_signed.branch_tweak,
            ..signed.clone()
        }),
        ..record.clone()
    };
    assert_eq!(
        verify_root(&c, &w.template, &other_key),
        Err(Error::RootSignature)
    );

    let other_signature = RootRecord {
        signature: Some(RootSignature {
            signature: other_signed.signature,
            ..signed
        }),
        ..record
    };
    assert_eq!(
        verify_root(&c, &w.template, &other_signature),
        Err(Error::RootSignature)
    );
}

#[test]
fn root_signature_non_participant_key_fails() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    assert_eq!(
        sign_tree_root(&c, d, &OTHER_SECRET, 0, 0),
        Err(Error::NotParticipant)
    );

    let tid = template_id(&c, &c.template_bytes(&w.template));
    let root: [u8; 32] = hex_arr(ROOT_0_0);
    let outsider = RootRecord {
        keychain: 0,
        tree_start: 0,
        root,
        signature: Some(RootSignature {
            key: c.base_mul(&OTHER_SECRET).unwrap(),
            branch_tweak: [0u8; 32],
            signature: c
                .bip322_sign(&OTHER_SECRET, &root_message(&c, &tid, &root))
                .unwrap(),
        }),
    };
    assert_eq!(
        verify_root(&c, &w.template, &outsider),
        Err(Error::NotParticipant)
    );
}

#[test]
fn root_signature_other_template_fails() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;
    let other = other_template();
    assert_eq!(
        c.template_base_keys(&other),
        c.template_base_keys(&w.template)
    );

    let signed = sign_tree_root(&c, d, &OWNER1_SECRET, 0, 0).unwrap();

    assert_eq!(verify_root(&c, &other, &signed), Err(Error::RootSignature));
}

#[test]
fn root_signature_forged_branch_tweak_fails() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let receive = sign_tree_root(&c, d, &OWNER1_SECRET, 0, 0).unwrap();
    let change = sign_tree_root(&c, d, &OWNER1_SECRET, 1, 0).unwrap();
    let signed = root_signature(&receive);
    assert_ne!(signed.branch_tweak, root_signature(&change).branch_tweak);

    let change_tweak = RootRecord {
        signature: Some(RootSignature {
            branch_tweak: root_signature(&change).branch_tweak,
            ..signed.clone()
        }),
        ..receive.clone()
    };
    assert_eq!(
        verify_root(&c, &w.template, &change_tweak),
        Err(Error::RootSignature)
    );

    // without the owner1 secret, a forger only holds the secret of its tweak
    let forged_tweak = [0x41; 32];
    let tid = template_id(&c, &c.template_bytes(&w.template));
    let forged = RootRecord {
        signature: Some(RootSignature {
            branch_tweak: forged_tweak,
            signature: c
                .bip322_sign(&forged_tweak, &root_message(&c, &tid, &receive.root))
                .unwrap(),
            ..signed
        }),
        ..receive
    };
    assert_eq!(
        verify_root(&c, &w.template, &forged),
        Err(Error::RootSignature)
    );
}

#[test]
fn sign_tree_root_root_equals_build_tree_root() {
    let c = RustBitcoin::new();
    let w = wallet();
    let d = &w.descriptor;

    let root_0_0: [u8; 32] = hex_arr(ROOT_0_0);
    assert_eq!(build_tree(&c, d, 0, 0).unwrap().root, root_0_0);
    assert_eq!(
        sign_tree_root(&c, d, &OWNER1_SECRET, 0, 0).unwrap().root,
        root_0_0
    );

    let root_1_0: [u8; 32] = hex_arr(ROOT_1_0);
    let tree = build_tree(&c, d, 1, 0).unwrap();
    assert_eq!(tree.root, root_1_0);
    assert_eq!(tree.keychain, 1);
    assert_eq!(
        sign_tree_root(&c, d, &OWNER1_SECRET, 1, 0).unwrap().root,
        root_1_0
    );

    assert_eq!(
        sign_tree_root(&c, d, &OWNER1_SECRET, 2, 0),
        Err(Error::InvalidKeychain)
    );
    assert_eq!(
        sign_tree_root(&c, d, &[0u8; 32], 0, 0),
        Err(Error::SecretKey)
    );
}
