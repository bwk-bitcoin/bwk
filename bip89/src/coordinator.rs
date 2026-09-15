//! The coordinator is the BIP89 delegatee that holds the proof trees whose
//! roots are recorded with the delegator. `prepare` writes the bundle of every
//! owned input and output, and the accumulator proof of every owned output,
//! into the PSBT, next to the script they describe, so the delegator can find
//! them without any derivation happening on its side.

use alloc::vec::Vec;

use crate::{accumulator::tree::Tree, backend::BitcoinBackend, bundle::derive_bundle, Error};

/// A bundle the coordinator owns, identified by its PSBT index and its
/// derivation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owned {
    pub psbt_index: usize,
    pub keychain: u32,
    pub index: u32,
}

/// Writes the BIP89 bundle of every owned input and output, plus the
/// accumulator proof of every owned output from the first of `trees` that
/// covers it (`NoTree` otherwise), into `psbt`. Everything is computed first,
/// so an error leaves the PSBT untouched. Outputs not listed in `outputs` get
/// nothing.
pub fn prepare<B: BitcoinBackend>(
    b: &B,
    d: &B::Descriptor,
    trees: &[Tree],
    inputs: &[Owned],
    outputs: &[Owned],
    psbt: &mut B::Psbt,
) -> Result<(), Error> {
    let mut input_bundles = Vec::with_capacity(inputs.len());
    for owned in inputs {
        if owned.psbt_index >= b.input_count(psbt) {
            return Err(Error::Psbt);
        }
        let bundle = derive_bundle(b, d, owned.keychain, owned.index)?;
        input_bundles.push((owned.psbt_index, bundle));
    }

    let mut output_bundles = Vec::with_capacity(outputs.len());
    for owned in outputs {
        if owned.psbt_index >= b.output_count(psbt) {
            return Err(Error::Psbt);
        }
        let bundle = derive_bundle(b, d, owned.keychain, owned.index)?;
        let proof = trees
            .iter()
            .find_map(|tree| tree.proof(owned.keychain, owned.index))
            .ok_or(Error::NoTree(owned.psbt_index))?;
        output_bundles.push((owned.psbt_index, bundle, proof));
    }

    for (psbt_index, bundle) in &input_bundles {
        b.set_input_bundle(psbt, *psbt_index, bundle)?;
    }
    for (psbt_index, bundle, proof) in &output_bundles {
        b.set_output_bundle(psbt, *psbt_index, bundle)?;
        b.set_output_proof(psbt, *psbt_index, proof)?;
    }

    Ok(())
}
