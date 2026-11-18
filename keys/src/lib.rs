pub mod derivator;
pub mod keys;
#[cfg(feature = "musig")]
pub mod musig;
pub mod nums;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Fail to create Xpriv from seed.")]
    XPrivFromSeed,
    #[error("Mnemonics words are invalid.")]
    InvalidMnemonicWords,
}
