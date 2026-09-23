//! Pins the size, alignment, and field offsets of every `#[repr(C)]` type the C
//! binding exposes, so a change on the Rust side fails here until
//! `include/bip89.h` is updated to match. The numbers are for a 64-bit target
//! (8-byte pointers and `size_t`), the same layout a C compiler produces over
//! the header.

use core::mem::{align_of, offset_of, size_of};

use bwk_bip89_ll::{
    CryptoVtable, DescriptorVtable, FfiOwned, FfiRootRecord, FfiXpub, PsbtVtable, TemplateVtable,
    U32List,
};

#[test]
fn crypto_vtable_layout() {
    assert_eq!(size_of::<CryptoVtable>(), 128);
    assert_eq!(align_of::<CryptoVtable>(), 8);
    assert_eq!(offset_of!(CryptoVtable, ctx), 0);
    assert_eq!(offset_of!(CryptoVtable, sha256_init), 8);
    assert_eq!(offset_of!(CryptoVtable, sha256_update), 16);
    assert_eq!(offset_of!(CryptoVtable, sha256_final), 24);
    assert_eq!(offset_of!(CryptoVtable, sha512_init), 32);
    assert_eq!(offset_of!(CryptoVtable, sha512_update), 40);
    assert_eq!(offset_of!(CryptoVtable, sha512_final), 48);
    assert_eq!(offset_of!(CryptoVtable, point_is_valid), 56);
    assert_eq!(offset_of!(CryptoVtable, point_add), 64);
    assert_eq!(offset_of!(CryptoVtable, point_mul), 72);
    assert_eq!(offset_of!(CryptoVtable, base_mul), 80);
    assert_eq!(offset_of!(CryptoVtable, scalar_add), 88);
    assert_eq!(offset_of!(CryptoVtable, scalar_mul), 96);
    assert_eq!(offset_of!(CryptoVtable, bip322_sign), 104);
    assert_eq!(offset_of!(CryptoVtable, bip322_verify), 112);
    assert_eq!(offset_of!(CryptoVtable, fill_random), 120);
}

#[test]
fn u32_list_layout() {
    assert_eq!(size_of::<U32List>(), 16);
    assert_eq!(align_of::<U32List>(), 8);
    assert_eq!(offset_of!(U32List, ptr), 0);
    assert_eq!(offset_of!(U32List, len), 8);
}

#[test]
fn xpub_layout() {
    assert_eq!(size_of::<FfiXpub>(), 104);
    assert_eq!(align_of::<FfiXpub>(), 8);
    assert_eq!(offset_of!(FfiXpub, key), 0);
    assert_eq!(offset_of!(FfiXpub, chain_code), 33);
    assert_eq!(offset_of!(FfiXpub, branch0), 72);
    assert_eq!(offset_of!(FfiXpub, branch1), 88);
}

#[test]
fn descriptor_vtable_layout() {
    assert_eq!(size_of::<DescriptorVtable>(), 32);
    assert_eq!(align_of::<DescriptorVtable>(), 8);
    assert_eq!(offset_of!(DescriptorVtable, ctx), 0);
    assert_eq!(offset_of!(DescriptorVtable, policy_bytes), 8);
    assert_eq!(offset_of!(DescriptorVtable, template_bytes), 16);
    assert_eq!(offset_of!(DescriptorVtable, xpubs), 24);
}

#[test]
fn template_vtable_layout() {
    assert_eq!(size_of::<TemplateVtable>(), 40);
    assert_eq!(align_of::<TemplateVtable>(), 8);
    assert_eq!(offset_of!(TemplateVtable, ctx), 0);
    assert_eq!(offset_of!(TemplateVtable, bytes), 8);
    assert_eq!(offset_of!(TemplateVtable, base_keys), 16);
    assert_eq!(offset_of!(TemplateVtable, script_pubkey), 24);
    assert_eq!(offset_of!(TemplateVtable, leaf_hashes), 32);
}

#[test]
fn psbt_vtable_layout() {
    assert_eq!(size_of::<PsbtVtable>(), 104);
    assert_eq!(align_of::<PsbtVtable>(), 8);
    assert_eq!(offset_of!(PsbtVtable, ctx), 0);
    assert_eq!(offset_of!(PsbtVtable, input_count), 8);
    assert_eq!(offset_of!(PsbtVtable, output_count), 16);
    assert_eq!(offset_of!(PsbtVtable, spent_output), 24);
    assert_eq!(offset_of!(PsbtVtable, output), 32);
    assert_eq!(offset_of!(PsbtVtable, input_bundle), 40);
    assert_eq!(offset_of!(PsbtVtable, set_input_bundle), 48);
    assert_eq!(offset_of!(PsbtVtable, output_bundle), 56);
    assert_eq!(offset_of!(PsbtVtable, set_output_bundle), 64);
    assert_eq!(offset_of!(PsbtVtable, output_proof), 72);
    assert_eq!(offset_of!(PsbtVtable, set_output_proof), 80);
    assert_eq!(offset_of!(PsbtVtable, tap_leaf_sighash), 88);
    assert_eq!(offset_of!(PsbtVtable, add_tap_script_sig), 96);
}

#[test]
fn owned_layout() {
    assert_eq!(size_of::<FfiOwned>(), 16);
    assert_eq!(align_of::<FfiOwned>(), 8);
    assert_eq!(offset_of!(FfiOwned, psbt_index), 0);
    assert_eq!(offset_of!(FfiOwned, keychain), 8);
    assert_eq!(offset_of!(FfiOwned, index), 12);
}

#[test]
fn root_record_layout() {
    assert_eq!(size_of::<FfiRootRecord>(), 128);
    assert_eq!(align_of::<FfiRootRecord>(), 8);
    assert_eq!(offset_of!(FfiRootRecord, keychain), 0);
    assert_eq!(offset_of!(FfiRootRecord, tree_start), 4);
    assert_eq!(offset_of!(FfiRootRecord, root), 8);
    assert_eq!(offset_of!(FfiRootRecord, key), 40);
    assert_eq!(offset_of!(FfiRootRecord, branch_tweak), 73);
    // 105 is padded to the next 8-byte boundary for the pointer
    assert_eq!(offset_of!(FfiRootRecord, signature), 112);
    assert_eq!(offset_of!(FfiRootRecord, signature_len), 120);
}
