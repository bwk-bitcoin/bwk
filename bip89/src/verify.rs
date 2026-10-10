//! BIP89 verification of a script against a template and a delegated tweak
//! bundle. `Ok(false)` means the script does not match the template once the
//! bundle's tweaks are substituted in; `Err` means the bundle itself is
//! malformed for the template. A passing check proves the script is built
//! from the template with these tweaks, not that the tweaks belong to the
//! wallet checking them.

use alloc::vec::Vec;

use crate::{backend::BitcoinBackend, bundle::Bundle, tweak::tweak_key, Error};

/// Substitutes each base key of `base_keys` with its tweaked key from
/// `bundle`. A base key with no entry in `bundle` is `MissingTweak`; a bundle
/// entry whose key is not in `base_keys` is `ExtraTweak`. The result is
/// sorted by base key, following `base_keys`.
#[allow(clippy::type_complexity)]
pub fn tweaked_keys<B: BitcoinBackend>(
    c: &B,
    base_keys: &[[u8; 33]],
    bundle: &Bundle,
) -> Result<Vec<([u8; 33], [u8; 33])>, Error> {
    let mut out = Vec::with_capacity(base_keys.len());
    for key in base_keys {
        let tweak = bundle.tweak(key).ok_or(Error::MissingTweak)?;
        out.push((*key, tweak_key(c, key, &tweak)?));
    }
    if bundle.entries().len() != base_keys.len() {
        return Err(Error::ExtraTweak);
    }
    Ok(out)
}

fn verify<B: BitcoinBackend>(
    c: &B,
    template: &B::Template,
    script: &[u8],
    bundle: &Bundle,
) -> Result<bool, Error> {
    let tweaked = tweaked_keys(c, &c.template_base_keys(template), bundle)?;
    Ok(c.template_script_pubkey(template, &tweaked)? == script)
}

/// BIP89 InputVerification: rebuilds the script from `template` with the
/// tweaked keys of `bundle`, and compares it to `script`.
pub fn input_verification<B: BitcoinBackend>(
    c: &B,
    template: &B::Template,
    script: &[u8],
    bundle: &Bundle,
) -> Result<bool, Error> {
    verify(c, template, script, bundle)
}

/// BIP89 ChangeOutputVerification: the same check as `input_verification`,
/// applied to a change output's script.
pub fn change_output_verification<B: BitcoinBackend>(
    c: &B,
    template: &B::Template,
    script: &[u8],
    bundle: &Bundle,
) -> Result<bool, Error> {
    verify(c, template, script, bundle)
}
