//! The cosigning service, the BIP89 delegator. It keeps one registration per
//! account and signs a spend only when its verified outflow is within the
//! account's limit.

use std::collections::BTreeMap;

use bwk_bip89::{
    accumulator::record::{RootPolicy, RootRecord},
    delegator::{register, sign_spend, verify_spend, Registration},
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                self,
                psbt::{self, Psbt},
                secp256k1::{Keypair, Secp256k1},
            },
            Descriptor,
        },
        RustBitcoin,
    },
    Error,
};

use crate::Entropy;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("protocol: {0:?}")]
    Protocol(Error),
    #[error("psbt: {0}")]
    Psbt(#[from] psbt::Error),
    #[error("unknown account {0}")]
    UnknownAccount(u64),
    #[error("outflow {outflow} above the limit {limit}")]
    OverLimit { outflow: u64, limit: u64 },
}

impl From<Error> for ServerError {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}

struct Account {
    registration: Registration<RustBitcoin>,
    /// Largest outflow, fee included, the server signs for.
    max_outflow: u64,
}

pub struct SigningServer {
    backend: RustBitcoin,
    keypair: Keypair,
    accounts: BTreeMap<u64, Account>,
}

impl SigningServer {
    pub fn new(rng: &mut Entropy) -> Self {
        Self {
            backend: RustBitcoin::new(),
            keypair: Keypair::from_secret_key(&Secp256k1::signing_only(), &rng.secret_key()),
            accounts: BTreeMap::new(),
        }
    }

    /// The bare key the wallet builds its descriptor with. The server never
    /// learns the chain code the wallet pairs it with.
    pub fn public_key(&self) -> [u8; 33] {
        self.keypair.public_key().serialize()
    }

    /// Records the template and the receive and change roots of `account`,
    /// once `register` has checked both records under `policy`. Any base key of
    /// the template is accepted as root signer, as `register` does: which keys a
    /// real service requires is its contract with its users.
    pub fn register(
        &mut self,
        account: u64,
        template: Descriptor<bitcoin::PublicKey>,
        policy: RootPolicy,
        receive: &RootRecord,
        change: &RootRecord,
        max_outflow: u64,
    ) -> Result<(), Error> {
        let registration = register(&self.backend, template, policy, receive, change)?;
        self.accounts.insert(
            account,
            Account {
                registration,
                max_outflow,
            },
        );
        Ok(())
    }

    /// Records the root of the next tree of a keychain of `account`.
    pub fn record_root(&mut self, account: u64, record: &RootRecord) -> Result<(), ServerError> {
        let registered = self
            .accounts
            .get_mut(&account)
            .ok_or(ServerError::UnknownAccount(account))?;
        registered.registration.record_root(&self.backend, record)?;
        Ok(())
    }

    /// Verifies the spend of `account` and refuses an outflow above its limit,
    /// then signs. Returns the PSBT with the server signatures and the outflow.
    pub fn sign(
        &self,
        account: u64,
        psbt: &[u8],
        rng: &mut Entropy,
    ) -> Result<(Vec<u8>, u64), ServerError> {
        let registered = self
            .accounts
            .get(&account)
            .ok_or(ServerError::UnknownAccount(account))?;
        let mut psbt = Psbt::deserialize(psbt)?;
        let outflow = verify_spend(&self.backend, &registered.registration, &psbt)?;
        if outflow > registered.max_outflow {
            return Err(ServerError::OverLimit {
                outflow,
                limit: registered.max_outflow,
            });
        }
        // sign_spend has no policy hook, so it verifies the spend a second time
        sign_spend(
            &self.backend,
            rng,
            &registered.registration,
            &self.keypair.secret_key().secret_bytes(),
            &mut psbt,
        )?;
        Ok((psbt.serialize(), outflow))
    }
}
