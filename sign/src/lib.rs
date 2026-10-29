pub mod error;
#[cfg(feature = "musig")]
pub mod hot_musig;
pub mod hot_signer;
#[cfg(all(feature = "hwi", not(target_os = "android")))]
pub mod hwi;
#[cfg(all(feature = "hwi", not(target_os = "android")))]
pub mod hwi_manager;
pub mod identity;
pub mod manager;
#[cfg(feature = "musig")]
pub mod musig;
pub mod protocol;
#[cfg(feature = "musig")]
pub mod qr_musig;
#[cfg(feature = "musig")]
pub mod qr_musig_host;
pub mod remote_manager;
pub mod signer;
pub mod signing_manager;

// re-export
pub use bip39;
pub use bwk_descriptor;
#[cfg(all(feature = "hwi", not(target_os = "android")))]
pub use bwk_hwi;
pub use bwk_keys;
#[cfg(feature = "musig")]
pub use bwk_musig;
pub use crossbeam;
pub use miniscript;
pub use serde;
pub use serde_json;
