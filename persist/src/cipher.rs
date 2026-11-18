//! Encryption at rest, supplied by the consumer.
//!
//! bwk does not pick a scheme or hold a key: a consumer that wants the wallet
//! state encrypted installs a [`Cipher`] once it holds its key, and every
//! backend seals what it writes and opens what it reads through it. With no
//! cipher installed the files are written as they always were.
//!
//! The cipher is process wide, like the key it wraps: one wallet application,
//! one key. A file written in clear does not open once a cipher is installed
//! (the cipher refuses it), and the reverse: a consumer switching to encryption
//! starts from an empty state rather than migrating silently.

use std::sync::{Arc, RwLock};

use crate::PersistError;

/// Seals and opens the bytes a backend persists. `open(seal(x)) == x`; `open`
/// refuses bytes it did not seal.
pub trait Cipher: Send + Sync + std::fmt::Debug {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, PersistError>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, PersistError>;
    /// The file extension of what it seals, in place of the clear format's (`json`,
    /// `bin`): a sealed store is no longer JSON.
    fn extension(&self) -> &str;
}

static CIPHER: RwLock<Option<Arc<dyn Cipher>>> = RwLock::new(None);

/// Installs the cipher every backend uses from now on, or removes it (`None`).
/// Install it before opening an account: an open backend reads through
/// whatever cipher is current at each read and write.
pub fn set_cipher(cipher: Option<Arc<dyn Cipher>>) {
    *CIPHER.write().unwrap_or_else(|e| e.into_inner()) = cipher;
}

/// The cipher installed, `None` when the state is written in clear.
pub fn cipher() -> Option<Arc<dyn Cipher>> {
    CIPHER.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `path` with the installed cipher's extension, unchanged without one.
pub fn sealed_path(path: &std::path::Path) -> std::path::PathBuf {
    match cipher() {
        Some(cipher) => path.with_extension(cipher.extension()),
        None => path.to_path_buf(),
    }
}

/// `plain` sealed with the cipher installed, unchanged without one.
pub(crate) fn seal(plain: &[u8]) -> Result<Vec<u8>, PersistError> {
    match cipher() {
        Some(cipher) => cipher.seal(plain),
        None => Ok(plain.to_vec()),
    }
}

/// `bytes` opened with the cipher installed, unchanged without one.
pub(crate) fn open(bytes: &[u8]) -> Result<Vec<u8>, PersistError> {
    match cipher() {
        Some(cipher) => cipher.open(bytes),
        None => Ok(bytes.to_vec()),
    }
}
