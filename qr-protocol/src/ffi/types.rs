//! The C view of a message. Every field is either inline or a pointer into memory
//! the owning handle keeps alive, so C reads the tree without any accessor calls.

use core::{ffi::c_char, ptr};

use crate::{
    types::{FINGERPRINT_LEN, PUBLIC_KEY_LEN, XPUB_LEN},
    ERROR_MESSAGE_LEN, MODEL_LEN, REQUEST_ID_LEN,
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
    pub get_xpubs: GetXpubs,
    pub register_descriptor: RegisterDescriptor,
    pub verify_address: VerifyAddress,
    pub sign: Sign,
    pub get_sp_descriptor: GetSpDescriptor,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetXpubs {
    pub derivation_paths: List<Path>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GetSpDescriptor {
    pub _unused: u8,
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
#[derive(Clone, Copy)]
pub struct DescriptorBody {
    /// `DESCRIPTOR_BIP380` or `DESCRIPTOR_BIP388`, which selects the `value` arm.
    pub tag: u8,
    pub value: DescriptorValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union DescriptorValue {
    pub bip380: *const c_char,
    pub bip388: Bip388,
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
    pub xpubs: Xpubs,
    pub registration: Registration,
    pub address_uri: AddressUri,
    pub signed: Signed,
    pub sp_descriptor: SpDescriptor,
    pub error: ErrorBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Xpubs {
    pub xpubs: List<[u8; XPUB_LEN]>,
    pub fingerprint: [u8; FINGERPRINT_LEN],
    pub model: [c_char; MODEL_LEN + 1],
    pub version: FirmwareVersion,
    pub capabilities: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SpDescriptor {
    pub descriptor: *const c_char,
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
    /// `SIGNATURE_ECDSA`, `SIGNATURE_TAP_KEY` or `SIGNATURE_TAP_SCRIPT`.
    pub kind: u8,
    pub value: SignatureValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SignatureValue {
    pub ecdsa: Ecdsa,
    pub tap_key: TapKey,
    pub tap_script: TapScript,
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
