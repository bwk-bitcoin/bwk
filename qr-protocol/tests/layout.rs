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
    FirmwareVersion, GetKeys, KeyRequest, Keys, List, MusigDerivation, MusigNonce, MusigPartialSig,
    MusigPrepared, MusigPubNonce, MusigSigned, Path, PrepareMusig, RegisterDescriptor,
    Registration, Request, RequestBody, Response, ResponseBody, Sign, SignMusig, Signature,
    SignatureValue, Signed, SignedValue, TapKey, TapScript, VerifyAddress,
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
        DescriptorValue => 24, 8;
        DescriptorBody => 32, 8;
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
        RequestBody => 88, 8;
        Request => 96, 8;
        FirmwareVersion => 12, 4;
        Keys => 72, 8;
        Registration => 32, 8;
        AddressUri => 8, 8;
        Ecdsa => 56, 8;
        TapKey => 16, 8;
        TapScript => 80, 8;
        MusigPubNonce => 165, 1;
        MusigPartialSig => 131, 1;
        MusigNonce => 184, 4;
        List<MusigNonce> => 16, 8;
        MusigPrepared => 56, 8;
        MusigSigned => 80, 8;
        SignatureValue => 168, 8;
        Signature => 176, 8;
        List<Signature> => 16, 8;
        SignedValue => 16, 8;
        Signed => 24, 8;
        ErrorBody => 34, 1;
        ResponseBody => 80, 8;
        Response => 88, 8;
        Buf => 16, 8;
    }
    assert_eq!(offset_of!(Request, body), 8);
    assert_eq!(offset_of!(Response, body), 8);
    assert_eq!(offset_of!(PrepareMusig, derivations), 72);
    assert_eq!(offset_of!(MusigPrepared, nonces), 40);
    assert_eq!(offset_of!(MusigNonce, nonce), 115);
}
