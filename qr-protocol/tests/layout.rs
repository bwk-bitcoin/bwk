//! Pins the layout of the C mirror types. The header in `include/` is written by
//! hand, so a change here means the header has to change with it. These are the
//! expected sizes and alignments on a 64-bit target.
#![cfg(all(feature = "ffi", target_pointer_width = "64"))]

use core::{
    ffi::c_char,
    mem::{align_of, offset_of, size_of},
};

use bwk_qr_protocol::ffi::types::{
    AddressUri, Bip388, Buf, Bytes, Descriptor, DescriptorBody, DescriptorValue, Ecdsa, ErrorBody,
    FirmwareVersion, GetKeys, Info, KeyRequest, Keys, List, MusigDerivation, MusigNonce,
    MusigPartialSig, MusigPrepared, MusigPubNonce, MusigSigned, NoncesPrepared, Path, PrepareMusig,
    PrepareNonces, RegisterDescriptor, Registration, Request, RequestBody, Response, ResponseBody,
    ScanValue, Sign, SignMusig, Signature, SignatureValue, Signed, SignedValue, SpDleqProof,
    SpEcdhShare, SpKeys, TapKey, TapScript, VerifyAddress,
};

macro_rules! check {
    ($($ty:ty => $size:expr, $align:expr;)*) => {
        $(
            assert_eq!(size_of::<$ty>(), $size, "size of {}", stringify!($ty));
            assert_eq!(align_of::<$ty>(), $align, "align of {}", stringify!($ty));
        )*
    };
}

#[test]
fn the_c_mirror_matches_the_header() {
    check! {
        Bytes => 16, 8;
        Path => 16, 8;
        KeyRequest => 24, 8;
        List<KeyRequest> => 16, 8;
        List<*const c_char> => 16, 8;
        List<[u8; 78]> => 16, 8;
        Bip388 => 24, 8;
        ScanValue => 32, 8;
        SpKeys => 64, 8;
        DescriptorValue => 64, 8;
        DescriptorBody => 72, 8;
        Descriptor => 32, 8;
        List<Descriptor> => 16, 8;
        GetKeys => 16, 8;
        RegisterDescriptor => 16, 8;
        VerifyAddress => 56, 8;
        Sign => 40, 8;
        MusigDerivation => 8, 4;
        List<MusigDerivation> => 16, 8;
        PrepareMusig => 88, 8;
        SignMusig => 80, 8;
        PrepareNonces => 40, 8;
        RequestBody => 88, 8;
        Request => 96, 8;
        FirmwareVersion => 12, 4;
        Keys => 56, 8;
        Info => 56, 8;
        Registration => 32, 8;
        AddressUri => 8, 8;
        Ecdsa => 56, 8;
        TapKey => 16, 8;
        TapScript => 80, 8;
        MusigPubNonce => 165, 1;
        MusigPartialSig => 131, 1;
        SpEcdhShare => 67, 1;
        SpDleqProof => 98, 1;
        MusigNonce => 184, 4;
        List<MusigNonce> => 16, 8;
        MusigPrepared => 56, 8;
        MusigSigned => 80, 8;
        List<[u8; 66]> => 16, 8;
        NoncesPrepared => 40, 8;
        SignatureValue => 168, 8;
        Signature => 176, 8;
        List<Signature> => 16, 8;
        SignedValue => 16, 8;
        Signed => 24, 8;
        ErrorBody => 16, 8;
        ResponseBody => 80, 8;
        Response => 88, 8;
        Buf => 16, 8;
    }
    assert_eq!(offset_of!(Request, body), 8);
    assert_eq!(offset_of!(Response, body), 8);
    assert_eq!(offset_of!(PrepareMusig, derivations), 72);
    assert_eq!(offset_of!(MusigPrepared, nonces), 40);
    assert_eq!(offset_of!(MusigNonce, nonce), 115);
    assert_eq!(offset_of!(PrepareNonces, has_session_ref), 4);
    assert_eq!(offset_of!(PrepareNonces, session_ref), 5);
    assert_eq!(offset_of!(PrepareNonces, max_inputs), 9);
    assert_eq!(offset_of!(PrepareNonces, derivation_path), 16);
    assert_eq!(offset_of!(PrepareNonces, start), 32);
    assert_eq!(offset_of!(PrepareNonces, end), 36);
    assert_eq!(offset_of!(NoncesPrepared, session_ref), 4);
    assert_eq!(offset_of!(NoncesPrepared, max_inputs), 8);
    assert_eq!(offset_of!(NoncesPrepared, start), 12);
    assert_eq!(offset_of!(NoncesPrepared, end), 16);
    assert_eq!(offset_of!(NoncesPrepared, nonces), 24);
    assert_eq!(offset_of!(SpKeys, spend_path), 8);
    assert_eq!(offset_of!(SpKeys, scan_kind), 24);
    assert_eq!(offset_of!(SpKeys, scan), 32);
    assert_eq!(offset_of!(Info, version), 16);
    assert_eq!(offset_of!(Info, max_message), 36);
    assert_eq!(offset_of!(Info, slots), 42);
    assert_eq!(offset_of!(Info, fingerprint), 45);
}
