//! Bitcoin user policy: a descriptor-agnostic policy model on top of `rust-miniscript`.
//!
//! Policies are modelled as a set of [`Path`]s, each carrying a key shape ([`Semantic`])
//! and an optional locktime gate ([`Locktime`]). A [`Policy`] compiles into a Taproot
//! multipath [`miniscript::Descriptor`] and round-trips back via [`Policy::from_descriptor`].

pub mod compile;
pub mod key_role;
pub mod multipath;
#[cfg(feature = "musig")]
pub mod musig;
pub mod nums;
pub mod parse;
pub mod path;
pub mod policy;
#[cfg(all(test, feature = "musig"))]
mod test_keys;
pub mod tree_builder;

pub use key_role::{Bip87Account, KeyRoleError, KeyType};
pub use multipath::{get_multipath_index, MultipathError};
pub use nums::{bip341_nums, unspendable_internal_key};
pub use path::{
    cltv_align, is_cltv_aligned, Leaf, Locktime, OXpub, OXpubError, Path, Semantic, TapPosition,
    CLTV_ALIGNMENT, MULTIPATH_SEMANTIC_FACTOR,
};
pub use policy::{Policy, PolicyError, PolicyType};
pub use tree_builder::TreeBuilderError;
