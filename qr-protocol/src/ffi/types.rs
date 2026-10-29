//! The C view of a message. Every field is either inline or a pointer into memory
//! the owning handle keeps alive, so C reads the tree without any accessor calls.

use core::{ffi::c_char, ptr};

use crate::{
    types::{
        EXTENDED_KEY_LEN, FINGERPRINT_LEN, MUSIG_PARTIAL_SIG_LEN, MUSIG_PUB_NONCE_LEN,
        PUBLIC_KEY_LEN, TAP_LEAF_HASH_LEN,
    },
    ERROR_MESSAGE_LEN, MODEL_LEN, REQUEST_ID_LEN, VENDOR_LEN,
};

/// A borrowed run of `len` items. A null `ptr` means the field is absent, which is
/// distinct from a present but empty run.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct List<T> {
    pub ptr: *const T,
    pub len: usize,
}

pub type Bytes = List<u8>;

impl<T> List<T> {
    pub fn absent() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
        }
    }

    pub fn is_absent(&self) -> bool {
        self.ptr.is_null()
    }

    /// # Safety
    /// `ptr` must be valid for `len` items for as long as the slice is used.
    pub unsafe fn as_slice(&self) -> &[T] {
        if self.len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(self.ptr, self.len)
        }
    }
}

/// BIP-32 child numbers with the hardened bit set. The wire caps the count at 255.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Path {
    pub ptr: *const u32,
    pub len: u8,
}

impl Path {
    /// # Safety
    /// `ptr` must be valid for `len` children for as long as the slice is used.
    pub unsafe fn as_slice(&self) -> &[u32] {
        if self.len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(self.ptr, self.len as usize)
        }
    }
}

/// Absent for an `int8_t` tri-state field.
pub const ABSENT_BOOL: i8 = -1;
/// Absent for the `int16_t` signing response kind.
pub const ABSENT_KIND: i16 = -1;

#[repr(C)]
pub struct Request {
    pub id: [u8; REQUEST_ID_LEN],
    /// The `MessageType` wire code, which selects the `body` arm.
    pub message_type: u8,
    pub body: RequestBody,
}

#[repr(C)]
pub union RequestBody {
    pub get_keys: GetKeys,
    pub register_descriptor: RegisterDescriptor,
    pub verify_address: VerifyAddress,
    pub sign: Sign,
    pub prepare_musig: PrepareMusig,
    pub sign_musig: SignMusig,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetKeys {
    pub keys: List<KeyRequest>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyRequest {
    pub derivation_path: Path,
    /// A `KeyKind` wire code.
    pub kind: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegisterDescriptor {
    pub descriptor_alias: *const c_char,
    pub descriptor: *const DescriptorBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VerifyAddress {
    pub descriptor_alias: *const c_char,
    pub derivation_path: Path,
    pub address: *const c_char,
    pub descriptor: *const DescriptorBody,
    pub proof: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sign {
    pub descriptors: List<Descriptor>,
    pub psbt: Bytes,
    /// A `SignResponseKind` wire code, or `ABSENT_KIND`.
    pub want_kind: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descriptor {
    pub alias: *const c_char,
    pub body: *const DescriptorBody,
    pub proof: Bytes,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MusigDerivation {
    pub keychain: u32,
    pub index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrepareMusig {
    pub descriptor: Descriptor,
    pub session_id: [u8; 32],
    pub max_inputs: u8,
    pub derivations: List<MusigDerivation>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignMusig {
    pub session_id: [u8; 32],
    pub attempt_id: [u8; 32],
    pub psbt: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DescriptorBody {
    /// `DESCRIPTOR_BIP380`, `DESCRIPTOR_BIP388` or `DESCRIPTOR_SP_KEYS`, which selects
    /// the `value` arm.
    pub tag: u8,
    pub value: DescriptorValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union DescriptorValue {
    pub bip380: *const c_char,
    pub bip388: Bip388,
    pub sp_keys: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bip388 {
    pub keys: List<*const c_char>,
    pub policy: *const c_char,
}

#[repr(C)]
pub struct Response {
    pub id: [u8; REQUEST_ID_LEN],
    /// The `MessageType` wire code, which selects the `body` arm unless `is_error`.
    pub message_type: u8,
    pub is_error: bool,
    pub body: ResponseBody,
}

#[repr(C)]
pub union ResponseBody {
    pub keys: Keys,
    pub registration: Registration,
    pub address_uri: AddressUri,
    pub signed: Signed,
    pub musig_prepared: MusigPrepared,
    pub musig_signed: MusigSigned,
    pub error: ErrorBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Keys {
    pub keys: List<[u8; EXTENDED_KEY_LEN]>,
    pub fingerprint: [u8; FINGERPRINT_LEN],
    pub vendor: [c_char; VENDOR_LEN + 1],
    pub model: [c_char; MODEL_LEN + 1],
    pub version: FirmwareVersion,
    pub capabilities: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FirmwareVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u32,
    /// A `ReleaseFlag` wire code.
    pub flag: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Registration {
    pub descriptor_alias: *const c_char,
    /// `0`, `1`, or `ABSENT_BOOL`.
    pub registered: i8,
    /// `0`, `1`, or `ABSENT_BOOL`.
    pub stored: i8,
    pub proof: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddressUri {
    pub uri: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Signed {
    /// A `SignResponseKind` wire code, which selects the `value` arm.
    pub kind: u8,
    pub value: SignedValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SignedValue {
    pub psbt: Bytes,
    pub signatures: List<Signature>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Signature {
    pub input_index: u32,
    /// `SIGNATURE_ECDSA`, `SIGNATURE_TAP_KEY`, `SIGNATURE_TAP_SCRIPT`,
    /// `SIGNATURE_MUSIG_PUB_NONCE` or `SIGNATURE_MUSIG_PARTIAL_SIG`.
    pub kind: u8,
    pub value: SignatureValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SignatureValue {
    pub ecdsa: Ecdsa,
    pub tap_key: TapKey,
    pub tap_script: TapScript,
    pub musig_pub_nonce: MusigPubNonce,
    pub musig_partial_sig: MusigPartialSig,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ecdsa {
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub signature: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TapKey {
    pub signature: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TapScript {
    pub xonly_public_key: [u8; 32],
    pub tap_leaf_hash: [u8; 32],
    pub signature: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MusigPubNonce {
    pub participant: [u8; PUBLIC_KEY_LEN],
    pub aggregate: [u8; PUBLIC_KEY_LEN],
    /// 0 or 1.
    pub has_leaf_hash: u8,
    pub leaf_hash: [u8; TAP_LEAF_HASH_LEN],
    pub nonce: [u8; MUSIG_PUB_NONCE_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MusigPartialSig {
    pub participant: [u8; PUBLIC_KEY_LEN],
    pub aggregate: [u8; PUBLIC_KEY_LEN],
    /// 0 or 1.
    pub has_leaf_hash: u8,
    pub leaf_hash: [u8; TAP_LEAF_HASH_LEN],
    pub signature: [u8; MUSIG_PARTIAL_SIG_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MusigPrepared {
    pub session_id: [u8; 32],
    pub max_inputs: u8,
    pub nonces: List<MusigNonce>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MusigNonce {
    pub derivation: MusigDerivation,
    pub input_index: u32,
    pub expression_index: u32,
    pub participant: [u8; PUBLIC_KEY_LEN],
    pub aggregate: [u8; PUBLIC_KEY_LEN],
    /// 0 or 1.
    pub has_leaf_hash: u8,
    pub leaf_hash: [u8; TAP_LEAF_HASH_LEN],
    pub nonce: [u8; MUSIG_PUB_NONCE_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MusigSigned {
    pub session_id: [u8; 32],
    pub attempt_id: [u8; 32],
    pub psbt: Bytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErrorBody {
    /// A `response::Error` wire code.
    pub error: u8,
    pub message: [c_char; ERROR_MESSAGE_LEN + 1],
}

/// A byte buffer the codec allocated. Release it with `bwk_qr_buf_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Buf {
    pub ptr: *mut u8,
    pub len: usize,
}
