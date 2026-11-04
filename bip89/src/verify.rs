//! BIP89 verification of a script against a template and a delegated tweak
//! bundle. `Ok(false)` means the script does not match the template once the
//! bundle's tweaks are substituted in; `Err` means the bundle itself is
//! malformed for the template. A passing check proves the script is built
//! from the template with these tweaks, not that the tweaks belong to the
//! wallet checking them.

use alloc::vec::Vec;

use crate::{backend::BitcoinBackend, bundle::Bundle, slot::Slot, tweak::tweak_key, Error};

/// Substitutes each slot of `slots` with its base key tweaked by the slot's
/// tweak from `bundle`. A slot with no entry in `bundle` is `MissingTweak`; a
/// bundle entry whose slot is not in `slots` is `ExtraTweak`. The result is
/// sorted by slot, following `slots`.
pub fn tweaked_keys<B: BitcoinBackend>(
    c: &B,
    slots: &[Slot],
    bundle: &Bundle,
) -> Result<Vec<(Slot, [u8; 33])>, Error> {
    let mut out = Vec::with_capacity(slots.len());
    for slot in slots {
        let tweak = bundle.tweak(slot).ok_or(Error::MissingTweak)?;
        out.push((*slot, tweak_key(c, &slot.key, &tweak)?));
    }
    if bundle.entries().len() != slots.len() {
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
    let tweaked = tweaked_keys(c, &c.template_slots(template), bundle)?;
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
