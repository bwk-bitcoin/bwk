//! MuSig2 helpers the compiler and the reader call.

use bwk_keys::musig::{Error, MusigAggregate, MusigDerivation, MusigKey};
use miniscript::{
    bitcoin::bip32::DerivationPath,
    descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
    policy::Concrete as ConcretePolicy,
    Miniscript, Tap,
};

use crate::{
    multipath::{deriv_paths_starting_at, multipath_start, MultipathError},
    OXpub, PolicyError,
};

/// A musig() participant: the R-level xpub with its origin and no derivation.
pub(crate) fn participant_key(key: &OXpub) -> DescriptorPublicKey {
    DescriptorPublicKey::XPub(DescriptorXKey {
        origin: key.origin.clone(),
        xkey: key.xkey,
        derivation_path: DerivationPath::master(),
        wildcard: Wildcard::None,
    })
}

/// The aggregate behind `musig(keys...)/<start;start+1>/*`, participants in the given
/// order.
pub(crate) fn musig_aggregate(keys: &[OXpub], start: u32) -> Result<MusigAggregate, PolicyError> {
    let first = keys
        .first()
        .ok_or(PolicyError::Musig(Error::InvalidShape("musig() of no key")))?;
    let derivation = MusigDerivation {
        paths: deriv_paths_starting_at(start),
        wildcard: Wildcard::Unhardened,
    };
    Ok(MusigAggregate::new(
        keys.iter().map(participant_key).collect(),
        Some(derivation),
        first.xkey.network,
    )?)
}

/// `musig(keys...)/<start;start+1>/*`, participants in the given order.
pub fn musig_key(keys: &[OXpub], start: u32) -> Result<MusigKey, PolicyError> {
    Ok(MusigKey::Musig(musig_aggregate(keys, start)?))
}

/// `pk(musig(keys...)/<start;start+1>/*)`.
pub fn musig_leaf(keys: &[OXpub], start: u32) -> Result<Miniscript<MusigKey, Tap>, PolicyError> {
    ConcretePolicy::Key(musig_key(keys, start)?)
        .compile::<Tap>()
        .map_err(|e| PolicyError::Miniscript(e.into()))
}

/// The participants of an aggregate-then-derive musig() and its zone index.
pub fn musig_participants(aggregate: &MusigAggregate) -> Result<(Vec<OXpub>, u32), PolicyError> {
    if aggregate.derives_cosigners() {
        return Err(PolicyError::MusigDerivation);
    }
    let mut participants = Vec::with_capacity(aggregate.cosigners().len());
    for cosigner in aggregate.cosigners() {
        let DescriptorPublicKey::XPub(x) = cosigner else {
            return Err(PolicyError::Multipath(MultipathError::NotMultiXPub));
        };
        if !x.derivation_path.is_empty() || x.wildcard != Wildcard::None {
            return Err(PolicyError::MusigDerivation);
        }
        participants.push(OXpub::new(x.origin.clone(), x.xkey));
    }
    let derivation = aggregate
        .derivation()
        .ok_or(PolicyError::Multipath(MultipathError::NotMultiXPub))?;
    let index = multipath_start(derivation.paths.paths())?;
    Ok((participants, index))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bwk_keys::musig::{MusigAggregate, MusigKey};
    use miniscript::{
        bitcoin::{bip32::DerivationPath, NetworkKind},
        descriptor::{DerivPaths, DescriptorMultiXKey, DescriptorPublicKey, Wildcard},
    };

    use crate::{
        musig::{musig_key, musig_participants, participant_key},
        test_keys::test_key,
        PolicyError,
    };

    #[test]
    fn musig_participants_reads_back_musig_key() {
        let keys = vec![test_key(1), test_key(2), test_key(3)];
        let MusigKey::Musig(aggregate) = musig_key(&keys, 1024).unwrap() else {
            panic!("expected a musig() key");
        };
        assert_eq!(musig_participants(&aggregate).unwrap(), (keys, 1024));
    }

    #[test]
    fn musig_participants_refuses_derive_then_aggregate() {
        let ranged = |seed: u8| {
            let key = test_key(seed);
            DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
                origin: key.origin,
                xkey: key.xkey,
                derivation_paths: DerivPaths::new(vec![
                    DerivationPath::from_str("m/0").unwrap(),
                    DerivationPath::from_str("m/1").unwrap(),
                ])
                .unwrap(),
                wildcard: Wildcard::Unhardened,
            })
        };
        let aggregate =
            MusigAggregate::new(vec![ranged(1), ranged(2)], None, NetworkKind::Main).unwrap();
        assert!(matches!(
            musig_participants(&aggregate),
            Err(PolicyError::MusigDerivation)
        ));
    }

    #[test]
    fn musig_key_keeps_written_order() {
        let (a, b, c) = (test_key(1), test_key(2), test_key(3));
        let MusigKey::Musig(aggregate) =
            musig_key(&[c.clone(), a.clone(), b.clone()], 512).unwrap()
        else {
            panic!("expected a musig() key");
        };
        assert_eq!(
            aggregate.cosigners(),
            &[
                participant_key(&c),
                participant_key(&a),
                participant_key(&b)
            ]
        );
    }
}
