//! Taproot input helpers.

use std::collections::BTreeSet;

use bitcoin::{
    psbt::Input,
    taproot::{TapLeafHash, TapNodeHash},
};

/// True when `input.tap_scripts` lists only part of its tap tree, as in a PSBT
/// restricted to one leaf: a merkle branch node of a listed leaf is neither a listed
/// leaf nor a node computed from them. Every node of a complete tree is computed from
/// its leaves. False without `tap_scripts`. A single-leaf tree restricted to its leaf
/// is the whole tree.
pub fn is_partial_tap_tree(input: &Input) -> bool {
    let mut computed = BTreeSet::new();
    let mut siblings = Vec::new();
    for (control_block, (script, version)) in &input.tap_scripts {
        let mut node = TapNodeHash::from(TapLeafHash::from_script(script, *version));
        computed.insert(node);
        for sibling in control_block.merkle_branch.iter() {
            siblings.push(*sibling);
            node = TapNodeHash::from_node_hashes(node, *sibling);
            computed.insert(node);
        }
    }
    siblings.iter().any(|sibling| !computed.contains(sibling))
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        key::{Secp256k1, XOnlyPublicKey},
        psbt::Input,
        secp256k1::SecretKey,
        taproot::{LeafVersion, TaprootBuilder},
        ScriptBuf,
    };

    use crate::taproot::is_partial_tap_tree;

    fn leaf_script(byte: u8) -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51, byte])
    }

    /// An input listing the leaves `listed` of a tree of `depths.len()` leaves.
    fn input(depths: &[u8], listed: &[usize]) -> Input {
        let secp = Secp256k1::new();
        let internal: XOnlyPublicKey = SecretKey::from_slice(&[1; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        let mut builder = TaprootBuilder::new();
        for (i, depth) in depths.iter().enumerate() {
            builder = builder.add_leaf(*depth, leaf_script(i as u8)).unwrap();
        }
        let info = builder.finalize(&secp, internal).unwrap();
        let mut input = Input {
            tap_internal_key: Some(internal),
            ..Default::default()
        };
        for i in listed {
            let leaf = (leaf_script(*i as u8), LeafVersion::TapScript);
            let control_block = info.control_block(&leaf).unwrap();
            input.tap_scripts.insert(control_block, leaf);
        }
        input
    }

    #[test]
    fn whole_trees_are_not_partial() {
        assert!(!is_partial_tap_tree(&input(&[0], &[])));
        assert!(!is_partial_tap_tree(&input(&[0], &[0])));
        assert!(!is_partial_tap_tree(&input(&[1, 1], &[0, 1])));
        assert!(!is_partial_tap_tree(&input(&[1, 2, 2], &[0, 1, 2])));
        assert!(!is_partial_tap_tree(&input(&[2, 2, 2, 2], &[0, 1, 2, 3])));
    }

    #[test]
    fn a_missing_leaf_is_partial() {
        assert!(is_partial_tap_tree(&input(&[1, 1], &[0])));
        assert!(is_partial_tap_tree(&input(&[1, 2, 2], &[0])));
        assert!(is_partial_tap_tree(&input(&[1, 2, 2], &[1, 2])));
        assert!(is_partial_tap_tree(&input(&[1, 2, 2], &[0, 2])));
        assert!(is_partial_tap_tree(&input(&[2, 2, 2, 2], &[0, 1, 2])));
    }
}
