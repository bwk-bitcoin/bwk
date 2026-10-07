//! A block the consumer vouches for, which the header chain must contain.
//!
//! `bwk` ships no checkpoint data: the consumer supplies one, the way an
//! Electrum client ships a `(height, hash)` it trusts. The header chain is
//! anchored at the checkpoint: every header above it is proven by full
//! validation, and one below it by linkage up to it.

use miniscript::bitcoin::{params::Params, BlockHash};
use serde::{Deserialize, Serialize};

use crate::header_validator;

/// The block at `height` is `hash`. `height` sits on a retarget boundary, so a
/// chain anchored at it has the window every retarget above it is checked
/// against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    height: u32,
    hash: BlockHash,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "checkpoint height {height} is not a multiple of the {interval} block retarget interval"
    )]
    NotRetargetBoundary { height: u32, interval: u32 },
}

impl Checkpoint {
    /// Fails when `height` is not a retarget boundary. The interval is the
    /// same on every network.
    pub fn new(height: u32, hash: BlockHash) -> Result<Self, Error> {
        let interval = header_validator::retarget_interval(&Params::MAINNET) as u32;
        if height % interval != 0 {
            return Err(Error::NotRetargetBoundary { height, interval });
        }
        Ok(Self { height, hash })
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn hash(&self) -> BlockHash {
        self.hash
    }
}
