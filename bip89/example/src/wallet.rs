//! The user's device: the BIP89 delegatee, the coordinator and the root signing
//! key holder in one type. It builds everything the server needs and never
//! gives the server a chain code.

use std::str::{self, FromStr};

use bwk_bip89::{
    accumulator::{
        record::{build_tree, sign_tree_root, RootRecord},
        tree::Tree,
    },
    bundle::derive_bundle,
    coordinator::{prepare, Owned},
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                self,
                absolute::LockTime,
                bip32::{self, ChainCode, ChildNumber, Fingerprint},
                hashes::Hash,
                secp256k1::{All, Keypair, Message, PublicKey, Secp256k1, SecretKey},
                taproot,
                transaction::Version,
                Amount, NetworkKind, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType,
                Transaction, TxIn, TxOut, Witness,
            },
            psbt::PsbtExt,
            DefiniteDescriptorKey, Descriptor, DescriptorPublicKey,
        },
        RustBitcoin,
    },
    BitcoinBackend, Error,
};

use crate::{Entropy, ExampleError};

pub const RECEIVE: u32 = 0;
pub const CHANGE: u32 = 1;
/// Position of the change output in a spend, after the payment.
pub const CHANGE_OUTPUT: usize = 1;
/// BIP341's NUMS point H, the internal key no one can sign for.
const NUMS_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub struct Utxo {
    outpoint: OutPoint,
    keychain: u32,
    index: u32,
    value: u64,
}

pub struct Wallet {
    backend: RustBitcoin,
    secp: Secp256k1<All>,
    keypair: Keypair,
    descriptor: Descriptor<DescriptorPublicKey>,
    trees: Vec<Tree>,
    next_change: u32,
    utxos: Vec<Utxo>,
}

fn tpub(public_key: PublicKey, chain_code: [u8; 32]) -> bip32::Xpub {
    bip32::Xpub {
        network: NetworkKind::Test,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key,
        chain_code: ChainCode::from(chain_code),
    }
}

impl Wallet {
    /// Builds `tr(NUMS/<0;1>/*,multi_a(2,wallet/<0;1>/*,server/<0;1>/*))`. The
    /// wallet picks every chain code, the server key's included: the server
    /// only gives its bare public key.
    pub fn new(rng: &mut Entropy, server_key: [u8; 33]) -> Result<Self, ExampleError> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &rng.secret_key());
        let nums = tpub(PublicKey::from_str(NUMS_KEY)?, rng.chain_code());
        let wallet = tpub(keypair.public_key(), rng.chain_code());
        let server = tpub(PublicKey::from_slice(&server_key)?, rng.chain_code());
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "tr({nums}/<0;1>/*,multi_a(2,{wallet}/<0;1>/*,{server}/<0;1>/*))"
        ))?;
        Ok(Self {
            backend: RustBitcoin::new(),
            secp,
            keypair,
            descriptor,
            trees: Vec::new(),
            next_change: 0,
            utxos: Vec::new(),
        })
    }

    /// The template, and the receive and change roots at tree start 0, for the
    /// server to register. Builds both proof trees.
    pub fn registration(
        &mut self,
    ) -> Result<(Descriptor<bitcoin::PublicKey>, RootRecord, RootRecord), ExampleError> {
        // the backend gives the template as its canonical string only
        let bytes = self.backend.descriptor_template(&self.descriptor)?;
        let template = Descriptor::<bitcoin::PublicKey>::from_str(str::from_utf8(&bytes)?)?;
        let receive = self.add_tree(RECEIVE, 0)?;
        let change = self.add_tree(CHANGE, 0)?;
        Ok((template, receive, change))
    }

    /// Builds and keeps the proof tree of `keychain` at `tree_start`, and
    /// returns its root signed with the wallet key.
    pub fn add_tree(&mut self, keychain: u32, tree_start: u32) -> Result<RootRecord, ExampleError> {
        let secret = self.keypair.secret_key().secret_bytes();
        let signed = sign_tree_root(
            &self.backend,
            &self.descriptor,
            &secret,
            keychain,
            tree_start,
        )?;
        self.trees.push(build_tree(
            &self.backend,
            &self.descriptor,
            keychain,
            tree_start,
        )?);
        Ok(signed)
    }

    pub fn receive_script(&self, index: u32) -> Result<ScriptBuf, ExampleError> {
        self.script(RECEIVE, index)
    }

    /// Records a funding output as if seen on chain: the example has no chain
    /// backend.
    pub fn receive(&mut self, outpoint: OutPoint, index: u32, value: u64) {
        self.utxos.push(Utxo {
            outpoint,
            keychain: RECEIVE,
            index,
            value,
        });
    }

    /// Builds a taproot PSBT spending the largest UTXO: `amount` to `to`, the
    /// rest minus `fee` to the next change index. `prepare` then writes the
    /// bundles and the change proof. Returns the serialized PSBT.
    pub fn spend(&self, to: ScriptBuf, amount: u64, fee: u64) -> Result<Vec<u8>, ExampleError> {
        let utxo = self
            .utxos
            .iter()
            .max_by_key(|utxo| utxo.value)
            .ok_or(ExampleError::Funds)?;
        let change = utxo
            .value
            .checked_sub(amount + fee)
            .ok_or(ExampleError::Funds)?;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            // the change sits at CHANGE_OUTPUT
            output: vec![
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: to,
                },
                TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: self.script(CHANGE, self.next_change)?,
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx)?;
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(utxo.value),
            script_pubkey: self.script(utxo.keychain, utxo.index)?,
        });

        let inputs = [Owned {
            psbt_index: 0,
            keychain: utxo.keychain,
            index: utxo.index,
        }];
        let outputs = [Owned {
            psbt_index: CHANGE_OUTPUT,
            keychain: CHANGE,
            index: self.next_change,
        }];
        prepare(
            &self.backend,
            &self.descriptor,
            &self.trees,
            &inputs,
            &outputs,
            &mut psbt,
        )?;
        Ok(psbt.serialize())
    }

    /// Adds the wallet's signature to every input of the PSBT the server
    /// signed, finalizes it and extracts the transaction, then records the
    /// spend. The example trusts the returned transaction; a real wallet checks
    /// it is the one it built.
    pub fn finalize(&mut self, signed_psbt: &[u8]) -> Result<Transaction, ExampleError> {
        let mut psbt = Psbt::deserialize(signed_psbt)?;
        for input in 0..psbt.inputs.len() {
            self.sign_input(&mut psbt, input)?;
        }
        psbt.finalize_mut(&self.secp)?;
        let tx = psbt.extract_tx()?;
        self.record(&tx)?;
        Ok(tx)
    }

    /// Signs every tapleaf of `input` holding the wallet key, derived with the
    /// input's bundle tweak.
    fn sign_input(&self, psbt: &mut Psbt, input: usize) -> Result<(), ExampleError> {
        let outpoint = psbt.unsigned_tx.input[input].previous_output;
        let utxo = self
            .utxos
            .iter()
            .find(|utxo| utxo.outpoint == outpoint)
            .ok_or(ExampleError::UnknownInput(outpoint))?;
        psbt.update_input_with_descriptor(input, &self.definite(utxo.keychain, utxo.index)?)?;

        let key = self.keypair.public_key().serialize();
        let tweak = derive_bundle(&self.backend, &self.descriptor, utxo.keychain, utxo.index)?
            .tweak(&key)
            .ok_or(Error::MissingTweak)?;
        let secret = SecretKey::from_slice(
            &self
                .backend
                .scalar_add(&self.keypair.secret_key().secret_bytes(), &tweak),
        )?;
        let keypair = Keypair::from_secret_key(&self.secp, &secret);
        let xonly = keypair.x_only_public_key().0;

        let leaves = psbt.inputs[input]
            .tap_key_origins
            .get(&xonly)
            .map(|(leaves, _)| leaves.clone())
            .ok_or(Error::NothingToSign(input))?;
        for leaf in leaves {
            let sighash = self
                .backend
                .tap_leaf_sighash(psbt, input, &leaf.to_byte_array())?;
            let signature = self
                .secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &keypair);
            psbt.inputs[input].tap_script_sigs.insert(
                (xonly, leaf),
                taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                },
            );
        }
        Ok(())
    }

    /// Drops the UTXOs `tx` spends and keeps its change output.
    fn record(&mut self, tx: &Transaction) -> Result<(), ExampleError> {
        self.utxos.retain(|utxo| {
            !tx.input
                .iter()
                .any(|txin| txin.previous_output == utxo.outpoint)
        });
        let change = self.script(CHANGE, self.next_change)?;
        if let Some(vout) = tx
            .output
            .iter()
            .position(|output| output.script_pubkey == change)
        {
            self.utxos.push(Utxo {
                outpoint: OutPoint {
                    txid: tx.compute_txid(),
                    vout: vout as u32,
                },
                keychain: CHANGE,
                index: self.next_change,
                value: tx.output[vout].value.to_sat(),
            });
            self.next_change += 1;
        }
        Ok(())
    }

    fn definite(
        &self,
        keychain: u32,
        index: u32,
    ) -> Result<Descriptor<DefiniteDescriptorKey>, ExampleError> {
        let single = self
            .descriptor
            .clone()
            .into_single_descriptors()?
            .into_iter()
            .nth(keychain as usize)
            .ok_or(Error::InvalidKeychain)?;
        Ok(single.at_derivation_index(index)?)
    }

    fn script(&self, keychain: u32, index: u32) -> Result<ScriptBuf, ExampleError> {
        Ok(self.definite(keychain, index)?.script_pubkey())
    }
}
