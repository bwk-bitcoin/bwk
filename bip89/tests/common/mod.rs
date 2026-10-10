#![allow(dead_code)]

use std::str::FromStr;

use bwk_bip89::{
    accumulator::record::{sign_tree_root, tree_root, RootRecord, RootSignature},
    coordinator::Owned,
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                self,
                absolute::LockTime,
                bip32::{self, ChainCode, ChildNumber, Fingerprint},
                psbt::raw::ProprietaryKey,
                secp256k1::{self, All, PublicKey, Secp256k1, SecretKey},
                transaction::Version,
                Amount, NetworkKind, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
                Txid, Witness,
            },
            Descriptor as MsDescriptor, DescriptorPublicKey,
        },
        RustBitcoin, PREFIX,
    },
    BitcoinBackend, Error, Rng, Xpub,
};

pub fn hex_vec(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

pub fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    hex_vec(s).try_into().unwrap()
}

/// The proprietary key of a BIP89 field of `subtype` with `key` as keydata.
pub fn field_key(subtype: u8, key: Vec<u8>) -> ProprietaryKey {
    ProprietaryKey {
        prefix: PREFIX.to_vec(),
        subtype,
        key,
    }
}

/// Implements the hashing, curve, BIP322 and PSBT methods of `BitcoinBackend`
/// for a test backend wrapping `RustBitcoin` in its first field.
macro_rules! delegate_to_rust_bitcoin {
    () => {
        type Sha256 = <bwk_bip89::rust_bitcoin::RustBitcoin as bwk_bip89::BitcoinBackend>::Sha256;
        type Sha512 = <bwk_bip89::rust_bitcoin::RustBitcoin as bwk_bip89::BitcoinBackend>::Sha512;
        type Psbt = <bwk_bip89::rust_bitcoin::RustBitcoin as bwk_bip89::BitcoinBackend>::Psbt;

        fn sha256(&self) -> Self::Sha256 {
            self.0.sha256()
        }

        fn sha512(&self) -> Self::Sha512 {
            self.0.sha512()
        }

        fn point_is_valid(&self, p: &[u8; 33]) -> bool {
            self.0.point_is_valid(p)
        }

        fn point_add(&self, a: &[u8; 33], b: &[u8; 33]) -> Option<[u8; 33]> {
            self.0.point_add(a, b)
        }

        fn point_mul(&self, p: &[u8; 33], k: &[u8; 32]) -> Option<[u8; 33]> {
            self.0.point_mul(p, k)
        }

        fn base_mul(&self, k: &[u8; 32]) -> Option<[u8; 33]> {
            self.0.base_mul(k)
        }

        fn scalar_add(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            self.0.scalar_add(a, b)
        }

        fn scalar_mul(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            self.0.scalar_mul(a, b)
        }

        fn bip322_sign(
            &self,
            secret: &[u8; 32],
            message: &[u8; 32],
        ) -> Result<Vec<u8>, bwk_bip89::Error> {
            self.0.bip322_sign(secret, message)
        }

        fn bip322_verify(&self, key: &[u8; 33], message: &[u8; 32], signature: &[u8]) -> bool {
            self.0.bip322_verify(key, message, signature)
        }

        fn input_count(&self, p: &Self::Psbt) -> usize {
            self.0.input_count(p)
        }

        fn output_count(&self, p: &Self::Psbt) -> usize {
            self.0.output_count(p)
        }

        fn spent_output(
            &self,
            p: &Self::Psbt,
            input: usize,
        ) -> Result<bwk_bip89::Output, bwk_bip89::Error> {
            self.0.spent_output(p, input)
        }

        fn output(
            &self,
            p: &Self::Psbt,
            output: usize,
        ) -> Result<bwk_bip89::Output, bwk_bip89::Error> {
            self.0.output(p, output)
        }

        fn input_bundle(
            &self,
            p: &Self::Psbt,
            input: usize,
        ) -> Result<Option<bwk_bip89::Bundle>, bwk_bip89::Error> {
            self.0.input_bundle(p, input)
        }

        fn set_input_bundle(
            &self,
            p: &mut Self::Psbt,
            input: usize,
            bundle: &bwk_bip89::Bundle,
        ) -> Result<(), bwk_bip89::Error> {
            self.0.set_input_bundle(p, input, bundle)
        }

        fn output_bundle(
            &self,
            p: &Self::Psbt,
            output: usize,
        ) -> Result<Option<bwk_bip89::Bundle>, bwk_bip89::Error> {
            self.0.output_bundle(p, output)
        }

        fn set_output_bundle(
            &self,
            p: &mut Self::Psbt,
            output: usize,
            bundle: &bwk_bip89::Bundle,
        ) -> Result<(), bwk_bip89::Error> {
            self.0.set_output_bundle(p, output, bundle)
        }

        fn output_proof(
            &self,
            p: &Self::Psbt,
            output: usize,
        ) -> Result<Option<bwk_bip89::accumulator::tree::Proof>, bwk_bip89::Error> {
            self.0.output_proof(p, output)
        }

        fn set_output_proof(
            &self,
            p: &mut Self::Psbt,
            output: usize,
            proof: &bwk_bip89::accumulator::tree::Proof,
        ) -> Result<(), bwk_bip89::Error> {
            self.0.set_output_proof(p, output, proof)
        }

        fn tap_leaf_sighash(
            &self,
            p: &Self::Psbt,
            input: usize,
            leaf_hash: &[u8; 32],
        ) -> Result<[u8; 32], bwk_bip89::Error> {
            self.0.tap_leaf_sighash(p, input, leaf_hash)
        }

        fn add_tap_script_sig(
            &self,
            p: &mut Self::Psbt,
            input: usize,
            xonly: &[u8; 32],
            leaf_hash: &[u8; 32],
            sig: &[u8; 64],
        ) -> Result<(), bwk_bip89::Error> {
            self.0.add_tap_script_sig(p, input, xonly, leaf_hash, sig)
        }
    };
}

pub(crate) use delegate_to_rust_bitcoin;

/// A descriptor given directly as its xpubs, unvalidated and in the given order.
pub struct SliceDescriptor(pub Vec<Xpub>);

/// A test-only `wsh(sortedmulti(threshold, keys))` witness script template,
/// used to run the BIP89 verification vectors. Not shipped support: the
/// crates ship taproot templates only.
pub struct SortedMulti {
    pub threshold: u8,
    pub keys: Vec<[u8; 33]>,
}

/// `RustBitcoin` with `SliceDescriptor` descriptors and `SortedMulti`
/// templates, for the vectors that use neither a `tr()` descriptor nor its
/// template.
#[derive(Default)]
pub struct VectorBackend(pub RustBitcoin);

impl BitcoinBackend for VectorBackend {
    delegate_to_rust_bitcoin!();

    type Descriptor = SliceDescriptor;
    type Template = SortedMulti;

    fn descriptor_policy(&self, _d: &SliceDescriptor) -> Vec<u8> {
        Vec::new()
    }

    fn descriptor_template(&self, _d: &SliceDescriptor) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }

    fn descriptor_xpubs(&self, d: &SliceDescriptor) -> Result<Vec<Xpub>, Error> {
        Ok(d.0.clone())
    }

    fn template_bytes(&self, _t: &SortedMulti) -> Vec<u8> {
        Vec::new()
    }

    fn template_base_keys(&self, t: &SortedMulti) -> Vec<[u8; 33]> {
        let mut keys = t.keys.clone();
        keys.sort();
        keys.dedup();
        keys
    }

    fn template_script_pubkey(
        &self,
        t: &SortedMulti,
        tweaked: &[([u8; 33], [u8; 33])],
    ) -> Result<Vec<u8>, Error> {
        let mut tweaked_keys = Vec::with_capacity(t.keys.len());
        for key in &self.template_base_keys(t) {
            let pos = tweaked
                .binary_search_by(|(base, _)| base.cmp(key))
                .map_err(|_| Error::MissingTweak)?;
            tweaked_keys.push(tweaked[pos].1);
        }
        tweaked_keys.sort();

        let mut script = Vec::with_capacity(2 + tweaked_keys.len() * 34);
        script.push(0x50 + t.threshold);
        for key in &tweaked_keys {
            script.push(0x21);
            script.extend_from_slice(key);
        }
        script.push(0x50 + tweaked_keys.len() as u8);
        script.push(0xae);
        Ok(script)
    }

    fn template_leaf_hashes(
        &self,
        _t: &SortedMulti,
        _tweaked: &[([u8; 33], [u8; 33])],
        _key: &[u8; 33],
    ) -> Result<Vec<[u8; 32]>, Error> {
        Ok(Vec::new())
    }
}

/// A deterministic test `Rng` that serves bytes from a fixed buffer, so
/// vector-driven tests can supply the exact randomness a test case expects.
pub struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl Rng for FixedRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let end = self.pos + buf.len();
        assert!(end <= self.bytes.len(), "fixed rng exhausted");
        buf.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
    }
}

pub const OWNER1_SECRET: [u8; 32] = [0x01; 32];
pub const OWNER2_SECRET: [u8; 32] = [0x02; 32];
pub const DELEGATOR_SECRET: [u8; 32] = [0x03; 32];
pub const NUMS_CHAIN_CODE: [u8; 32] = [0x0e; 32];
pub const OWNER1_CHAIN_CODE: [u8; 32] = [0x0b; 32];
pub const OWNER2_CHAIN_CODE: [u8; 32] = [0x0c; 32];
pub const DELEGATOR_CHAIN_CODE: [u8; 32] = [0x0d; 32];
pub const NUMS_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
pub const OWNER1_KEY: &str = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
pub const OWNER2_KEY: &str = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766";
pub const DELEGATOR_KEY: &str =
    "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337";
/// Public key of the `[0x77; 32]` secret, outside the test wallet.
pub const EXTERNAL_KEY: &str = "037962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da";
pub const POLICY: &str = "tr(tpubD6NzVbkrYhZ4WUjicNhwiY99hU5HrkSGgpGAoBkVTAK8u9SvizRqERT9Ppf1U4htEmVZc5rLYFQnQ4yMK4R5RFoaU9WwM1LsP7GZnvwEtPN/<0;1>/*,multi_a(2,tpubD6NzVbkrYhZ4WSzr8iXBzE2xoeUnqZbFWcycoXrmVMfy6Lzr1pP7VrqBJywDtPFUMDbbUqwxcnn6MAtSTuD1wJ81Vsodoyin7gnWDoc14p4/<0;1>/*,tpubD6NzVbkrYhZ4WTaUHwFSZfQMmb1dBHsbEgjoU5pg9HtMhH9YFYQ25P3Afunnh6dkCzFYgm4eJfrz37EJVoTQ6Ec9m9917Q4HYcAdDWMVu58/<0;1>/*,tpubD6NzVbkrYhZ4WUA6T9yh96mkjXYTX29vxkVz8dnaoE6kJDJEVGQveuFA2sFk8byGjhyKAxqna8tqoR8hhWLA4YWD6RsK3S3zorpZ29gTp4Z/<0;1>/*))#rumuj3h3";
pub const TEMPLATE: &str = "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,multi_a(2,031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f,024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766,02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337))#0gcs0xjw";

pub struct Wallet {
    pub secp: Secp256k1<All>,
    pub descriptor: MsDescriptor<DescriptorPublicKey>,
    pub template: MsDescriptor<bitcoin::PublicKey>,
}

pub fn tpub(public_key: secp256k1::PublicKey, chain_code: [u8; 32]) -> bip32::Xpub {
    bip32::Xpub {
        network: NetworkKind::Test,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key,
        chain_code: ChainCode::from(chain_code),
    }
}

pub fn wallet() -> Wallet {
    let secp = Secp256k1::new();

    let nums = tpub(
        PublicKey::from_slice(&hex_vec(NUMS_KEY)).unwrap(),
        NUMS_CHAIN_CODE,
    );
    let owner1 = tpub(
        SecretKey::from_slice(&OWNER1_SECRET)
            .unwrap()
            .public_key(&secp),
        OWNER1_CHAIN_CODE,
    );
    let owner2 = tpub(
        SecretKey::from_slice(&OWNER2_SECRET)
            .unwrap()
            .public_key(&secp),
        OWNER2_CHAIN_CODE,
    );
    let delegator = tpub(
        SecretKey::from_slice(&DELEGATOR_SECRET)
            .unwrap()
            .public_key(&secp),
        DELEGATOR_CHAIN_CODE,
    );

    let descriptor = MsDescriptor::from_str(&format!(
        "tr({nums}/<0;1>/*,multi_a(2,{owner1}/<0;1>/*,{owner2}/<0;1>/*,{delegator}/<0;1>/*))"
    ))
    .unwrap();
    let template = template_of(&RustBitcoin::new(), &descriptor);

    Wallet {
        secp,
        descriptor,
        template,
    }
}

/// The wallet template with a threshold of 1: the same base keys under another
/// template id.
pub fn other_template() -> MsDescriptor<bitcoin::PublicKey> {
    MsDescriptor::from_str(&format!(
        "tr({NUMS_KEY},multi_a(1,{OWNER1_KEY},{OWNER2_KEY},{DELEGATOR_KEY}))"
    ))
    .unwrap()
}

/// The template of `d`, parsed back from its canonical bytes.
pub fn template_of(
    c: &RustBitcoin,
    d: &MsDescriptor<DescriptorPublicKey>,
) -> MsDescriptor<bitcoin::PublicKey> {
    let bytes = c.descriptor_template(d).unwrap();
    MsDescriptor::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

impl Wallet {
    pub fn script_pubkey(&self, keychain: usize, index: u32) -> ScriptBuf {
        self.descriptor.clone().into_single_descriptors().unwrap()[keychain]
            .at_derivation_index(index)
            .unwrap()
            .script_pubkey()
    }
}

pub const INPUT_VALUE: u64 = 100_000;
pub const EXTERNAL_VALUE: u64 = 30_000;
pub const CHANGE_VALUE: u64 = 50_000;
pub const SELF_SEND_VALUE: u64 = 19_000;
pub const FEE: u64 = 1_000;
pub const EXTERNAL_SECRET: [u8; 32] = [0x77; 32];
pub const FUNDING_TXID: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// A test-only p2tr script external to the wallet, spent to by `spend_psbt`'s
/// first output.
pub fn external_script(w: &Wallet) -> ScriptBuf {
    ScriptBuf::new_p2tr(
        &w.secp,
        SecretKey::from_slice(&EXTERNAL_SECRET)
            .unwrap()
            .x_only_public_key(&w.secp)
            .0,
        None,
    )
}

/// A one-input, three-output taproot PSBT over the wallet fixture: an
/// external output, a change output at (1, 3) and a self-send at (0, 9). Only
/// the witness UTXO of the input is set; no derivation or taproot origin
/// field is written.
pub fn spend_psbt(w: &Wallet) -> Psbt {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(FUNDING_TXID).unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(EXTERNAL_VALUE),
                script_pubkey: external_script(w),
            },
            TxOut {
                value: Amount::from_sat(CHANGE_VALUE),
                script_pubkey: w.script_pubkey(1, 3),
            },
            TxOut {
                value: Amount::from_sat(SELF_SEND_VALUE),
                script_pubkey: w.script_pubkey(0, 9),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(INPUT_VALUE),
        script_pubkey: w.script_pubkey(0, 5),
    });
    psbt
}

/// The receive and change roots at tree start 0, signed by owner1.
pub fn signed_roots(c: &RustBitcoin, w: &Wallet) -> [RootRecord; 2] {
    [
        sign_tree_root(c, &w.descriptor, &OWNER1_SECRET, 0, 0).unwrap(),
        sign_tree_root(c, &w.descriptor, &OWNER1_SECRET, 1, 0).unwrap(),
    ]
}

/// The receive and change roots at tree start 0, with no signature.
pub fn unsigned_roots(c: &RustBitcoin, w: &Wallet) -> [RootRecord; 2] {
    [
        tree_root(c, &w.descriptor, 0, 0).unwrap(),
        tree_root(c, &w.descriptor, 1, 0).unwrap(),
    ]
}

/// The signature of a record that carries one.
pub fn root_signature(record: &RootRecord) -> RootSignature {
    record.signature.clone().unwrap()
}

pub fn standard_lists() -> ([Owned; 1], [Owned; 2]) {
    (
        [Owned {
            psbt_index: 0,
            keychain: 0,
            index: 5,
        }],
        [
            Owned {
                psbt_index: 1,
                keychain: 1,
                index: 3,
            },
            Owned {
                psbt_index: 2,
                keychain: 0,
                index: 9,
            },
        ],
    )
}
