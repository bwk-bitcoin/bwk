//! A signing server and a wallet running BIP89 with the tweak accumulator end
//! to end. The two sides only exchange serialized PSBTs.

use std::str::{FromStr, Utf8Error};

use bwk_bip89::{
    accumulator::record::RootPolicy,
    rust_bitcoin::{
        miniscript::{
            self,
            bitcoin::{
                self,
                hashes::Hash,
                hex::DisplayHex,
                psbt::{self, ExtractTxError},
                secp256k1::{self, Secp256k1, SecretKey, XOnlyPublicKey},
                OutPoint, Psbt, ScriptBuf, Txid,
            },
            descriptor::ConversionError,
            psbt::UtxoUpdateError,
            Descriptor,
        },
        RustBitcoin, PREFIX, SUBTYPE_PROOF,
    },
    verify::{change_output_verification, tweaked_keys},
    BitcoinBackend, Bundle, Entry, Error, Rng,
};
use rand::{rngs::ThreadRng, RngCore};

use crate::{
    server::{ServerError, SigningServer},
    wallet::{Wallet, CHANGE, CHANGE_OUTPUT, RECEIVE},
};

mod server;
mod wallet;

const ACCOUNT: u64 = 1;
/// The account registered with roots that carry no signature.
const UNSIGNED_ACCOUNT: u64 = 2;
/// Largest outflow, fee included, the server signs for the account.
const LIMIT: u64 = 50_000;
const FUNDING: u64 = 100_000;
const FUNDING_INDEX: u32 = 0;
const UNSIGNED_FUNDING_INDEX: u32 = 1;
const AMOUNT: u64 = 30_000;
const OVER_LIMIT_AMOUNT: u64 = 60_000;
const FEE: u64 = 1_000;
/// The receive tree after the first one, which covers indexes 0 to 255.
const NEXT_TREE_START: u32 = 256;
const NEXT_TREE_INDEX: u32 = 300;
/// X-only public key of the `[0x77; 32]` secret, outside the wallet.
const EXTERNAL_KEY: &str = "7962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da";

#[derive(Debug, thiserror::Error)]
enum ExampleError {
    #[error("protocol: {0:?}")]
    Protocol(Error),
    #[error("server: {0}")]
    Server(#[from] ServerError),
    #[error("descriptor: {0}")]
    Descriptor(#[from] miniscript::Error),
    #[error("derivation: {0}")]
    Derivation(#[from] ConversionError),
    #[error("key: {0}")]
    Key(#[from] secp256k1::Error),
    #[error("template: {0}")]
    Template(#[from] Utf8Error),
    #[error("psbt: {0}")]
    Psbt(#[from] psbt::Error),
    #[error("psbt update: {0}")]
    Update(#[from] UtxoUpdateError),
    #[error("finalize: {0:?}")]
    Finalize(Vec<miniscript::psbt::Error>),
    // boxed: the error carries the whole transaction
    #[error("extract: {0}")]
    Extract(Box<ExtractTxError>),
    #[error("no UTXO covers the amount and the fee")]
    Funds,
    #[error("input {0} is not a wallet UTXO")]
    UnknownInput(OutPoint),
    #[error("the server signed a spend it must refuse")]
    Accepted,
}

impl From<Error> for ExampleError {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}

impl From<ExtractTxError> for ExampleError {
    fn from(e: ExtractTxError) -> Self {
        Self::Extract(Box::new(e))
    }
}

impl From<Vec<miniscript::psbt::Error>> for ExampleError {
    fn from(e: Vec<miniscript::psbt::Error>) -> Self {
        Self::Finalize(e)
    }
}

/// `bwk_bip89::Rng` over rand's thread generator.
struct Entropy(ThreadRng);

impl Entropy {
    /// A uniform secret key: bytes that are zero or not below the curve order,
    /// which almost never happens, are drawn again.
    fn secret_key(&mut self) -> SecretKey {
        let mut bytes = [0u8; 32];
        loop {
            self.0.fill_bytes(&mut bytes);
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return secret;
            }
        }
    }

    fn chain_code(&mut self) -> [u8; 32] {
        let mut chain_code = [0u8; 32];
        self.0.fill_bytes(&mut chain_code);
        chain_code
    }
}

impl Rng for Entropy {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.0.fill_bytes(buf);
    }
}

/// The error of a spend the server must refuse.
fn refusal(result: Result<(Vec<u8>, u64), ServerError>) -> Result<ServerError, ExampleError> {
    match result {
        Ok(_) => Err(ExampleError::Accepted),
        Err(e) => Ok(e),
    }
}

/// The change bundle a compromised coordinator makes up: every tweak is an
/// arbitrary scalar, never the output of ComputeBIP32Tweak for any index.
/// Returned with the script it builds, so plain ChangeOutputVerification
/// passes.
fn forged_change(
    b: &RustBitcoin,
    template: &Descriptor<bitcoin::PublicKey>,
) -> Result<(Bundle, Vec<u8>), Error> {
    let base = b.template_base_keys(template);
    let mut entries = Vec::with_capacity(base.len());
    for (i, key) in base.iter().enumerate() {
        entries.push(Entry {
            key: *key,
            tweak: [0x41 + i as u8; 32],
        });
    }
    let forged = Bundle::new(entries)?;
    let script = b.template_script_pubkey(template, &tweaked_keys(b, &base, &forged)?)?;
    Ok((forged, script))
}

fn main() -> Result<(), ExampleError> {
    let mut rng = Entropy(rand::rng());
    let backend = RustBitcoin::new();
    let external = ScriptBuf::new_p2tr(
        &Secp256k1::verification_only(),
        XOnlyPublicKey::from_str(EXTERNAL_KEY)?,
        None,
    );

    let mut server = SigningServer::new(&mut rng);
    let server_key = server.public_key();
    let mut wallet = Wallet::new(&mut rng, server_key)?;
    println!(
        "1. server key {}, wallet descriptor built on it",
        server_key.as_hex()
    );

    let (template, receive, change) = wallet.registration()?;
    server.register(
        ACCOUNT,
        template.clone(),
        RootPolicy::RequireSignature,
        &receive,
        &change,
        LIMIT,
    )?;
    println!("2. account {ACCOUNT} registered, template {template}, limit {LIMIT} sats");

    let funding = OutPoint {
        txid: Txid::from_byte_array([0x01; 32]),
        vout: 0,
    };
    wallet.receive(funding, FUNDING_INDEX, FUNDING);
    println!(
        "3. wallet received {FUNDING} sats on {:x} (receive index {FUNDING_INDEX})",
        wallet.receive_script(FUNDING_INDEX)?
    );

    let honest = wallet.spend(external.clone(), AMOUNT, FEE)?;
    let (signed, outflow) = server.sign(ACCOUNT, &honest, &mut rng)?;
    let tx = wallet.finalize(&signed)?;
    println!(
        "4. honest spend signed: outflow {outflow} sats, txid {}, vsize {}",
        tx.compute_txid(),
        tx.vsize()
    );

    let over_limit = wallet.spend(external.clone(), OVER_LIMIT_AMOUNT, FEE)?;
    println!(
        "5. over-limit spend refused: {:?}",
        refusal(server.sign(ACCOUNT, &over_limit, &mut rng))?
    );

    let (bundle, script) = forged_change(&backend, &template)?;
    let passes = change_output_verification(&backend, &template, &script, &bundle)?;
    let mut forged = Psbt::deserialize(&honest)?;
    forged.unsigned_tx.output[CHANGE_OUTPUT].script_pubkey = ScriptBuf::from_bytes(script);
    // bundle entries are keyed by base key, so the genuine ones are overwritten
    backend.set_output_bundle(&mut forged, CHANGE_OUTPUT, &bundle)?;
    let old_proof = refusal(server.sign(ACCOUNT, &forged.serialize(), &mut rng))?;
    forged.outputs[CHANGE_OUTPUT]
        .proprietary
        .retain(|key, _| !(key.prefix == PREFIX && key.subtype == SUBTYPE_PROOF));
    let no_proof = refusal(server.sign(ACCOUNT, &forged.serialize(), &mut rng))?;
    println!(
        "6. forged change passes ChangeOutputVerification: {passes}, refused with the old \
         proof: {old_proof:?}, without a proof: {no_proof:?}"
    );

    let next = wallet.add_tree(RECEIVE, NEXT_TREE_START)?;
    server.record_root(ACCOUNT, &next)?;
    let funding = OutPoint {
        txid: Txid::from_byte_array([0x02; 32]),
        vout: 0,
    };
    wallet.receive(funding, NEXT_TREE_INDEX, FUNDING);
    let psbt = wallet.spend(external.clone(), AMOUNT, FEE)?;
    let (signed, outflow) = server.sign(ACCOUNT, &psbt, &mut rng)?;
    let tx = wallet.finalize(&signed)?;
    println!(
        "7. receive tree at {NEXT_TREE_START} recorded, receive index {NEXT_TREE_INDEX} \
         spent: outflow {outflow} sats, txid {}",
        tx.compute_txid()
    );

    server.register(
        UNSIGNED_ACCOUNT,
        template,
        RootPolicy::AllowUnsigned,
        &wallet.unsigned_root(RECEIVE, 0)?,
        &wallet.unsigned_root(CHANGE, 0)?,
        LIMIT,
    )?;
    let funding = OutPoint {
        txid: Txid::from_byte_array([0x03; 32]),
        vout: 0,
    };
    wallet.receive(funding, UNSIGNED_FUNDING_INDEX, FUNDING);
    let psbt = wallet.spend(external, AMOUNT, FEE)?;
    let (signed, outflow) = server.sign(UNSIGNED_ACCOUNT, &psbt, &mut rng)?;
    let tx = wallet.finalize(&signed)?;
    println!(
        "8. account {UNSIGNED_ACCOUNT} registered with unsigned roots, receive index \
         {UNSIGNED_FUNDING_INDEX} spent: outflow {outflow} sats, txid {}",
        tx.compute_txid()
    );

    Ok(())
}
