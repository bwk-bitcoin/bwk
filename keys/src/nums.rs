//! The BIP-341 NUMS point H, a key whose secret no one knows: the internal key of
//! a tr() with no key path spender.

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};

/// H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
/// (BIP-341), compressed: lift_x gives the even y.
pub const BIP341_NUMS: [u8; 33] = [
    0x02, 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
    0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a,
    0xc0,
];

/// H as a public key.
pub fn bip341_nums() -> PublicKey {
    PublicKey::from_slice(&BIP341_NUMS).expect("BIP-341 NUMS is a valid point")
}

/// Whether `key` is H or its odd-y negation: taproot keys are x-only, so `02||H.x`
/// and `03||H.x` are equally unspendable.
pub fn is_nums(key: &PublicKey) -> bool {
    is_nums_x_only(&key.x_only_public_key().0)
}

/// Whether the x-only `key` is H.
pub fn is_nums_x_only(key: &XOnlyPublicKey) -> bool {
    key.serialize() == BIP341_NUMS[1..]
}

#[cfg(test)]
mod tests {
    use bitcoin::{key::Parity, secp256k1::PublicKey};

    use crate::nums::{bip341_nums, is_nums, is_nums_x_only};

    #[test]
    fn nums_is_the_x_coordinate() {
        let nums = bip341_nums();
        let (x_only, parity) = nums.x_only_public_key();
        assert_eq!(parity, Parity::Even);
        assert!(is_nums(&nums));
        assert!(is_nums_x_only(&x_only));

        let negated = PublicKey::from_x_only_public_key(x_only, Parity::Odd);
        assert_eq!(negated.serialize()[0], 0x03);
        assert!(is_nums(&negated));
        assert!(is_nums_x_only(&negated.x_only_public_key().0));
    }
}
