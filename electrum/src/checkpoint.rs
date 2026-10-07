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

#[cfg(test)]
mod tests {
    use miniscript::bitcoin::{hashes::Hash, BlockHash};

    use crate::checkpoint::{Checkpoint, Error};

    #[test]
    fn a_retarget_boundary_is_accepted() {
        let hash = BlockHash::all_zeros();
        let checkpoint = Checkpoint::new(707_616, hash).unwrap();
        assert_eq!(checkpoint.height(), 707_616);
        assert_eq!(checkpoint.hash(), hash);
    }

    #[test]
    fn a_height_off_the_retarget_boundary_is_refused() {
        let err = Checkpoint::new(707_617, BlockHash::all_zeros()).unwrap_err();
        assert!(matches!(
            err,
            Error::NotRetargetBoundary {
                height: 707_617,
                interval: 2016
            }
        ));
    }

    #[test]
    fn a_checkpoint_round_trips_through_serde() {
        let checkpoint = Checkpoint::new(4032, BlockHash::all_zeros()).unwrap();
        let json = serde_json::to_string(&checkpoint).unwrap();
        assert_eq!(
            serde_json::from_str::<Checkpoint>(&json).unwrap(),
            checkpoint
        );
    }
}
