pub mod error;
pub mod hot_signer;
#[cfg(all(feature = "hwi", not(target_os = "android")))]
pub mod hwi;
#[cfg(all(feature = "hwi", not(target_os = "android")))]
pub mod hwi_manager;
pub mod identity;
pub mod manager;
pub mod protocol;
pub mod remote_manager;
pub mod signer;
pub mod signing_manager;

// re-export
pub use bip39;
pub use bwk_descriptor;
#[cfg(all(feature = "hwi", not(target_os = "android")))]
pub use bwk_hwi;
pub use bwk_keys;
pub use bwk_utils;
pub use crossbeam;
pub use miniscript;
pub use serde;
pub use serde_json;
