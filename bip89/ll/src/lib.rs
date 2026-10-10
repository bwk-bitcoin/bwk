//! C ABI for bwk-bip89: `VtableBackend` implements `BitcoinBackend` over
//! vtables of function pointers, and every entry point runs the generic
//! protocol code on it.
//!
//! The C consumer supplies hashing, curve arithmetic, BIP322 signing,
//! randomness, and descriptor, template and PSBT access through the vtables. The crate pulls
//! no dependency besides bwk-bip89 without its default features.
//!
//! Ownership: Rust never frees C memory. C frees Rust memory only through
//! `bip89_tree_free` and `bip89_registration_free`.
//!
//! No entry point may panic. `no_std` has no unwinding, so a panic would
//! reach the consumer's handler instead of returning a code.

// Every entry point here is one `unsafe extern "C"` body operating on raw C
// pointers, so treat the whole body as the unsafe context rather than
// wrapping each pointer read. The adapter's unsafe methods below follow the
// same convention.
#![allow(unsafe_op_in_unsafe_fn)]
#![no_std]

extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    ffi::{c_char, c_void},
    ptr,
};

use bwk_bip89::{
    accumulator::{
        record::{RootPolicy, RootRecord, RootSignature},
        tree::{Proof, Tree},
    },
    blind::SessionContext,
    bundle::{Bundle, ENTRY_LEN},
    coordinator::Owned,
    delegator::Registration,
    BitcoinBackend, Error, Output, Rng, Sha256Engine, Sha512Engine, Xpub,
};

pub const BIP89_OK: i32 = 0;
pub const BIP89_HASH_STATE_LEN: usize = 256;
pub const BIP89_ROOT_POLICY_REQUIRE_SIGNATURE: u32 = 0;
pub const BIP89_ROOT_POLICY_ALLOW_UNSIGNED: u32 = 1;

pub type HashInitFn = unsafe extern "C" fn(ctx: *mut c_void, state: *mut u8);
pub type HashUpdateFn =
    unsafe extern "C" fn(ctx: *mut c_void, state: *mut u8, data: *const u8, len: usize);
pub type HashFinalFn = unsafe extern "C" fn(ctx: *mut c_void, state: *mut u8, out: *mut u8);
pub type PointIsValidFn = unsafe extern "C" fn(ctx: *mut c_void, point: *const u8) -> i32;
pub type PointAddFn =
    unsafe extern "C" fn(ctx: *mut c_void, a: *const u8, b: *const u8, out: *mut u8) -> i32;
pub type PointMulFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    point: *const u8,
    scalar: *const u8,
    out: *mut u8,
) -> i32;
pub type BaseMulFn = unsafe extern "C" fn(ctx: *mut c_void, scalar: *const u8, out: *mut u8) -> i32;
pub type ScalarOpFn =
    unsafe extern "C" fn(ctx: *mut c_void, a: *const u8, b: *const u8, out: *mut u8);
pub type Bip322SignFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    secret: *const u8,
    msg: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32;
pub type Bip322VerifyFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    key: *const u8,
    msg: *const u8,
    sig: *const u8,
    sig_len: usize,
) -> i32;
pub type FillRandomFn = unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize);
pub type BytesFn =
    unsafe extern "C" fn(ctx: *mut c_void, out: *mut u8, cap: usize, out_len: *mut usize) -> i32;
pub type CountFn = unsafe extern "C" fn(ctx: *mut c_void) -> usize;
pub type XpubsFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    out: *mut FfiXpub,
    cap: usize,
    out_count: *mut usize,
) -> i32;
pub type BaseKeysFn =
    unsafe extern "C" fn(ctx: *mut c_void, out: *mut u8, cap: usize, out_count: *mut usize) -> i32;
pub type ScriptPubkeyFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    tweaked: *const u8,
    n: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32;
pub type LeafHashesFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    tweaked: *const u8,
    n: usize,
    key: *const u8,
    out: *mut u8,
    cap: usize,
    out_count: *mut usize,
) -> i32;

/// Hashing, curve arithmetic, BIP322 signing and randomness supplied by the C
/// consumer.
#[repr(C)]
pub struct CryptoVtable {
    pub ctx: *mut c_void,
    pub sha256_init: Option<HashInitFn>,
    pub sha256_update: Option<HashUpdateFn>,
    pub sha256_final: Option<HashFinalFn>,
    pub sha512_init: Option<HashInitFn>,
    pub sha512_update: Option<HashUpdateFn>,
    pub sha512_final: Option<HashFinalFn>,
    pub point_is_valid: Option<PointIsValidFn>,
    pub point_add: Option<PointAddFn>,
    pub point_mul: Option<PointMulFn>,
    pub base_mul: Option<BaseMulFn>,
    pub scalar_add: Option<ScalarOpFn>,
    pub scalar_mul: Option<ScalarOpFn>,
    pub bip322_sign: Option<Bip322SignFn>,
    pub bip322_verify: Option<Bip322VerifyFn>,
    pub fill_random: Option<FillRandomFn>,
}

/// A borrowed list of child numbers. A null `ptr` with a nonzero `len` is rejected.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct U32List {
    pub ptr: *const u32,
    pub len: usize,
}

/// One extended public key of the descriptor: fixed steps plus multipath element per keychain.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiXpub {
    pub key: [u8; 33],
    pub chain_code: [u8; 32],
    pub branch0: U32List,
    pub branch1: U32List,
}

/// Wallet descriptor access supplied by the C consumer, one callback per
/// descriptor method of `BitcoinBackend`.
#[repr(C)]
pub struct DescriptorVtable {
    pub ctx: *mut c_void,
    pub policy_bytes: Option<BytesFn>,
    pub template_bytes: Option<BytesFn>,
    pub xpubs: Option<XpubsFn>,
}

/// The BIP89 template over base keys supplied by the C consumer, one callback
/// per template method of `BitcoinBackend`.
#[repr(C)]
pub struct TemplateVtable {
    pub ctx: *mut c_void,
    pub bytes: Option<BytesFn>,
    pub base_keys: Option<BaseKeysFn>,
    pub script_pubkey: Option<ScriptPubkeyFn>,
    pub leaf_hashes: Option<LeafHashesFn>,
}

pub type OutputFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    index: usize,
    script: *mut u8,
    cap: usize,
    script_len: *mut usize,
    value: *mut u64,
) -> i32;
pub type BundleFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    index: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    present: *mut u8,
) -> i32;
pub type SetBundleFn =
    unsafe extern "C" fn(ctx: *mut c_void, index: usize, bundle: *const u8, len: usize) -> i32;
pub type ProofFn =
    unsafe extern "C" fn(ctx: *mut c_void, index: usize, out: *mut u8, present: *mut u8) -> i32;
pub type SetProofFn = unsafe extern "C" fn(ctx: *mut c_void, index: usize, proof: *const u8) -> i32;
pub type SighashFn =
    unsafe extern "C" fn(ctx: *mut c_void, input: usize, leaf_hash: *const u8, out: *mut u8) -> i32;
pub type AddSigFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    input: usize,
    xonly: *const u8,
    leaf_hash: *const u8,
    sig: *const u8,
) -> i32;

/// PSBT access supplied by the C consumer, one callback per PSBT method of
/// `BitcoinBackend`.
#[repr(C)]
pub struct PsbtVtable {
    pub ctx: *mut c_void,
    pub input_count: Option<CountFn>,
    pub output_count: Option<CountFn>,
    pub spent_output: Option<OutputFn>,
    pub output: Option<OutputFn>,
    pub input_bundle: Option<BundleFn>,
    pub set_input_bundle: Option<SetBundleFn>,
    pub output_bundle: Option<BundleFn>,
    pub set_output_bundle: Option<SetBundleFn>,
    pub output_proof: Option<ProofFn>,
    pub set_output_proof: Option<SetProofFn>,
    pub tap_leaf_sighash: Option<SighashFn>,
    pub add_tap_script_sig: Option<AddSigFn>,
}

/// An owned input or output: its PSBT index and derivation.
#[repr(C)]
pub struct FfiOwned {
    pub psbt_index: usize,
    pub keychain: u32,
    pub index: u32,
}

/// The accumulator root of one tree. `signature` points at `signature_len`
/// bytes, borrowed for the duration of the call. A `signature_len` of 0 means
/// the root carries no signature, and `key` and `branch_tweak` are ignored.
#[repr(C)]
pub struct FfiRootRecord {
    pub keychain: u32,
    pub tree_start: u32,
    pub root: [u8; 32],
    pub key: [u8; 33],
    pub branch_tweak: [u8; 32],
    pub signature: *const u8,
    pub signature_len: usize,
}

impl FfiRootRecord {
    /// # Safety
    /// `signature` must be readable for `signature_len` bytes, or null when
    /// `signature_len` is 0.
    unsafe fn root_record(&self) -> Result<RootRecord, FfiError> {
        let signature = match slice(self.signature, self.signature_len)? {
            [] => None,
            bytes => Some(RootSignature {
                key: self.key,
                branch_tweak: self.branch_tweak,
                signature: bytes.to_vec(),
            }),
        };
        Ok(RootRecord {
            keychain: self.keychain,
            tree_start: self.tree_start,
            root: self.root,
            signature,
        })
    }
}

// A hash engine is a Rust value that can move between calls, so C must only
// store relocatable data here (plain hash state or a pointer to C-owned
// memory), never a pointer into this buffer itself.
#[repr(C, align(8))]
struct HashState([u8; BIP89_HASH_STATE_LEN]);

const _: () = assert!(
    core::mem::size_of::<HashState>() == BIP89_HASH_STATE_LEN
        && core::mem::align_of::<HashState>() == 8
);

/// Failures the C boundary itself can raise, on top of the protocol [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiError {
    NullPointer,
    BadVtable,
    BufferTooSmall,
    IndexOutOfBounds,
    InvalidRootPolicy,
    Ll(Error),
}

impl FfiError {
    /// The C code and static NUL-terminated message of this error.
    pub fn info(&self) -> (i32, &'static str) {
        match self {
            FfiError::NullPointer => (500, "null pointer\0"),
            FfiError::BadVtable => (501, "vtable has a null callback\0"),
            FfiError::BufferTooSmall => (502, "output buffer too small\0"),
            FfiError::IndexOutOfBounds => (503, "index out of bounds\0"),
            FfiError::InvalidRootPolicy => (504, "invalid root policy\0"),
            FfiError::Ll(error) => ll_error_info(*error),
        }
    }
}

fn ll_error_info(error: Error) -> (i32, &'static str) {
    match error {
        Error::InvalidPoint => (100, "invalid point\0"),
        Error::Infinity => (101, "point at infinity\0"),
        Error::ScalarRange => (102, "scalar out of range\0"),
        Error::SecretKey => (103, "invalid secret key\0"),
        Error::ZeroNonce => (104, "zero nonce\0"),
        Error::HardenedIndex => (105, "hardened index not supported\0"),
        Error::InvalidChild => (106, "invalid child key\0"),
        Error::TweakCount => (107, "tweak count mismatch\0"),
        Error::NonceReuse => (108, "secret nonce already used\0"),
        Error::SecNonceLength => (109, "invalid secret nonce length\0"),
        Error::BlindSignature => (110, "blind signature failed self verification\0"),
        Error::DuplicateKey => (111, "duplicate key in bundle\0"),
        Error::UnsortedBundle => (112, "bundle entries not sorted\0"),
        Error::EntryLength => (113, "invalid bundle entry length\0"),
        Error::MissingTweak => (114, "template key has no tweak\0"),
        Error::ExtraTweak => (115, "bundle key not in template\0"),
        Error::Template => (116, "template rejected or callback failed\0"),
        Error::InvalidKeychain => (117, "invalid keychain\0"),
        Error::IndexRange => (118, "tree index range out of bounds\0"),
        Error::ProofLength => (119, "invalid proof length\0"),
        // 120 and 123 are retired, never reused
        Error::RootSignature => (121, "invalid root signature\0"),
        Error::NotCommitted => (122, "bundle not committed in tree\0"),
        Error::NoTree(_) => (124, "no tree for output\0"),
        Error::MissingUtxo(_) => (125, "input utxo missing\0"),
        Error::MissingBundle(_) => (126, "input bundle missing\0"),
        Error::InputMismatch(_) => (127, "input script mismatch\0"),
        Error::OutputMismatch(_) => (128, "output script mismatch\0"),
        Error::MissingProof(_) => (129, "output proof missing\0"),
        Error::Amount => (130, "amount out of range\0"),
        Error::NotParticipant => (131, "secret key not in template\0"),
        Error::NothingToSign(_) => (132, "nothing to sign for input\0"),
        Error::Psbt => (133, "psbt rejected or callback failed\0"),
        Error::ExtraInLength => (134, "extra input too long\0"),
        Error::NotTaproot => (135, "descriptor is not taproot\0"),
        Error::KeyType => (136, "key is not a multipath extended public key\0"),
        Error::Multipath => (137, "key does not have two multipath elements\0"),
        Error::Wildcard => (138, "key does not end with an unhardened wildcard\0"),
        Error::HardenedStep => (139, "key has a hardened derivation step\0"),
        Error::ConflictingKey => (140, "base key repeated with another chain code or path\0"),
        Error::NoKeys => (141, "descriptor has no key\0"),
        Error::MissingRootSignature => (142, "root signature missing\0"),
    }
}

/// `BitcoinBackend` over a C crypto vtable and the descriptor, template and
/// PSBT adapters. Every crypto callback is checked non-null once, at
/// construction.
#[derive(Clone, Copy)]
pub struct VtableBackend<'a> {
    vtable: &'a CryptoVtable,
    sha256_init: HashInitFn,
    sha256_update: HashUpdateFn,
    sha256_final: HashFinalFn,
    sha512_init: HashInitFn,
    sha512_update: HashUpdateFn,
    sha512_final: HashFinalFn,
    point_is_valid: PointIsValidFn,
    point_add: PointAddFn,
    point_mul: PointMulFn,
    base_mul: BaseMulFn,
    scalar_add: ScalarOpFn,
    scalar_mul: ScalarOpFn,
    bip322_sign: Bip322SignFn,
    bip322_verify: Bip322VerifyFn,
    fill_random: FillRandomFn,
}

impl VtableBackend<'_> {
    /// # Safety
    /// `vtable` must be null or point to a live `CryptoVtable` whose callbacks
    /// are sound and whose `ctx` outlives every use of the backend.
    pub unsafe fn new(vtable: *const CryptoVtable) -> Result<Self, FfiError> {
        if vtable.is_null() {
            return Err(FfiError::NullPointer);
        }
        let v = unsafe { &*vtable };
        macro_rules! required {
            ($field:expr) => {
                match $field {
                    Some(callback) => callback,
                    None => return Err(FfiError::BadVtable),
                }
            };
        }
        let sha256_init = required!(v.sha256_init);
        let sha256_update = required!(v.sha256_update);
        let sha256_final = required!(v.sha256_final);
        let sha512_init = required!(v.sha512_init);
        let sha512_update = required!(v.sha512_update);
        let sha512_final = required!(v.sha512_final);
        let point_is_valid = required!(v.point_is_valid);
        let point_add = required!(v.point_add);
        let point_mul = required!(v.point_mul);
        let base_mul = required!(v.base_mul);
        let scalar_add = required!(v.scalar_add);
        let scalar_mul = required!(v.scalar_mul);
        let bip322_sign = required!(v.bip322_sign);
        let bip322_verify = required!(v.bip322_verify);
        let fill_random = required!(v.fill_random);
        Ok(Self {
            vtable: v,
            sha256_init,
            sha256_update,
            sha256_final,
            sha512_init,
            sha512_update,
            sha512_final,
            point_is_valid,
            point_add,
            point_mul,
            base_mul,
            scalar_add,
            scalar_mul,
            bip322_sign,
            bip322_verify,
            fill_random,
        })
    }
}

pub struct VtableSha256<'a> {
    backend: VtableBackend<'a>,
    state: HashState,
}

impl Sha256Engine for VtableSha256<'_> {
    fn update(&mut self, data: &[u8]) {
        unsafe {
            (self.backend.sha256_update)(
                self.backend.vtable.ctx,
                self.state.0.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
            )
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            (self.backend.sha256_final)(
                self.backend.vtable.ctx,
                self.state.0.as_mut_ptr(),
                out.as_mut_ptr(),
            )
        };
        out
    }
}

pub struct VtableSha512<'a> {
    backend: VtableBackend<'a>,
    state: HashState,
}

impl Sha512Engine for VtableSha512<'_> {
    fn update(&mut self, data: &[u8]) {
        unsafe {
            (self.backend.sha512_update)(
                self.backend.vtable.ctx,
                self.state.0.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
            )
        }
    }

    fn finalize(mut self) -> [u8; 64] {
        let mut out = [0u8; 64];
        unsafe {
            (self.backend.sha512_final)(
                self.backend.vtable.ctx,
                self.state.0.as_mut_ptr(),
                out.as_mut_ptr(),
            )
        };
        out
    }
}

impl Rng for VtableBackend<'_> {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        unsafe { (self.fill_random)(self.vtable.ctx, buf.as_mut_ptr(), buf.len()) };
    }
}

const CALLBACK_CAP: usize = 256;

/// Reads a callback buffer following the retry rule: try once with
/// `CALLBACK_CAP` bytes; if the reported length is larger, retry exactly once
/// with a buffer of that exact size, and the second report must match.
fn read_bytes(
    fail: Error,
    mut call: impl FnMut(*mut u8, usize, *mut usize) -> i32,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; CALLBACK_CAP];
    let mut len = 0usize;
    if call(out.as_mut_ptr(), out.len(), &mut len) != 0 {
        return Err(fail);
    }
    if len <= out.len() {
        out.truncate(len);
        return Ok(out);
    }
    let needed = len;
    out = vec![0u8; needed];
    if call(out.as_mut_ptr(), needed, &mut len) != 0 || len != needed {
        return Err(fail);
    }
    Ok(out)
}

const CALLBACK_RECORDS: usize = 16;

/// Reads a callback array of fixed-size records following the retry rule of
/// `read_bytes`, with `cap` and the reported count in records rather than
/// bytes. `empty` fills the buffer before the callback writes it.
fn read_records<T: Copy>(
    fail: Error,
    empty: T,
    mut call: impl FnMut(*mut T, usize, *mut usize) -> i32,
) -> Result<Vec<T>, Error> {
    let mut out = vec![empty; CALLBACK_RECORDS];
    let mut count = 0usize;
    if call(out.as_mut_ptr(), CALLBACK_RECORDS, &mut count) != 0 {
        return Err(fail);
    }
    if count <= CALLBACK_RECORDS {
        out.truncate(count);
        return Ok(out);
    }
    let needed = count;
    out = Vec::new();
    out.try_reserve_exact(needed).map_err(|_| fail)?;
    out.resize(needed, empty);
    if call(out.as_mut_ptr(), needed, &mut count) != 0 || count != needed {
        return Err(fail);
    }
    Ok(out)
}

/// Reads a presence flag written by a PSBT getter: 0 is absent, 1 present.
fn present(flag: u8) -> Result<bool, Error> {
    match flag {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Psbt),
    }
}

/// The payload index of a protocol error naming an input or output, if any.
fn error_index(error: Error) -> Option<usize> {
    match error {
        Error::NoTree(i)
        | Error::MissingUtxo(i)
        | Error::MissingBundle(i)
        | Error::InputMismatch(i)
        | Error::OutputMismatch(i)
        | Error::MissingProof(i)
        | Error::NothingToSign(i) => Some(i),
        _ => None,
    }
}

/// Writes the payload index of `error` to `index_out`, when `error` carries
/// one and `index_out` is non-null. Otherwise leaves `index_out` untouched.
unsafe fn report_index(error: FfiError, index_out: *mut usize) {
    let FfiError::Ll(e) = error else {
        return;
    };
    let Some(i) = error_index(e) else {
        return;
    };
    if !index_out.is_null() {
        unsafe { *index_out = i };
    }
}

/// The descriptor adapter over a C descriptor vtable. Every callback is
/// preloaded at construction, so the backend methods never call back into C.
pub struct VtableDescriptor {
    policy: Vec<u8>,
    template: Vec<u8>,
    xpubs: Vec<Xpub>,
}

impl VtableDescriptor {
    /// # Safety
    /// `vtable` must be null or point to a live `DescriptorVtable` whose
    /// callbacks are sound; `ctx` must stay valid for the duration of this call.
    pub unsafe fn new(vtable: *const DescriptorVtable) -> Result<Self, FfiError> {
        if vtable.is_null() {
            return Err(FfiError::NullPointer);
        }
        let v = unsafe { &*vtable };
        let policy_bytes = v.policy_bytes.ok_or(FfiError::BadVtable)?;
        let template_bytes = v.template_bytes.ok_or(FfiError::BadVtable)?;
        let xpubs_fn = v.xpubs.ok_or(FfiError::BadVtable)?;

        let policy = read_bytes(Error::Template, |out, cap, out_len| unsafe {
            policy_bytes(v.ctx, out, cap, out_len)
        })?;
        let template = read_bytes(Error::Template, |out, cap, out_len| unsafe {
            template_bytes(v.ctx, out, cap, out_len)
        })?;

        let empty = FfiXpub {
            key: [0u8; 33],
            chain_code: [0u8; 32],
            branch0: U32List {
                ptr: ptr::null(),
                len: 0,
            },
            branch1: U32List {
                ptr: ptr::null(),
                len: 0,
            },
        };
        let raw = read_records(Error::Template, empty, |out, cap, out_count| unsafe {
            xpubs_fn(v.ctx, out, cap, out_count)
        })?;
        let mut xpubs = Vec::with_capacity(raw.len());
        for x in &raw {
            let branch0 = slice(x.branch0.ptr, x.branch0.len)?.to_vec();
            let branch1 = slice(x.branch1.ptr, x.branch1.len)?.to_vec();
            xpubs.push(Xpub {
                key: x.key,
                chain_code: x.chain_code,
                branches: [branch0, branch1],
            });
        }

        Ok(Self {
            policy,
            template,
            xpubs,
        })
    }
}

const TWEAKED_PAIR_LEN: usize = 66;

/// Flattens tweaked pairs into `TWEAKED_PAIR_LEN`-byte `base || tweaked` records.
fn flatten_tweaked(tweaked: &[([u8; 33], [u8; 33])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tweaked.len() * TWEAKED_PAIR_LEN);
    for (base, tw) in tweaked {
        out.extend_from_slice(base);
        out.extend_from_slice(tw);
    }
    out
}

/// The template adapter over a C template vtable. The template bytes and base
/// keys are preloaded at construction, so only `script_pubkey` and
/// `leaf_hashes` call back into C.
pub struct VtableTemplate {
    ctx: *mut c_void,
    script_pubkey: ScriptPubkeyFn,
    leaf_hashes: LeafHashesFn,
    bytes: Vec<u8>,
    base_keys: Vec<[u8; 33]>,
}

impl VtableTemplate {
    /// # Safety
    /// `vtable` must be null or point to a live `TemplateVtable` whose
    /// callbacks are sound; `ctx` must stay valid for as long as the adapter
    /// is used.
    pub unsafe fn new(vtable: *const TemplateVtable) -> Result<Self, FfiError> {
        if vtable.is_null() {
            return Err(FfiError::NullPointer);
        }
        let v = unsafe { &*vtable };
        let bytes_fn = v.bytes.ok_or(FfiError::BadVtable)?;
        let base_keys_fn = v.base_keys.ok_or(FfiError::BadVtable)?;
        let script_pubkey = v.script_pubkey.ok_or(FfiError::BadVtable)?;
        let leaf_hashes = v.leaf_hashes.ok_or(FfiError::BadVtable)?;

        let bytes = read_bytes(Error::Template, |out, cap, out_len| unsafe {
            bytes_fn(v.ctx, out, cap, out_len)
        })?;

        let base_keys = read_records(Error::Template, [0u8; 33], |out, cap, out_count| unsafe {
            base_keys_fn(v.ctx, out.cast(), cap, out_count)
        })?;
        if base_keys.windows(2).any(|pair| pair[1] <= pair[0]) {
            return Err(FfiError::Ll(Error::Template));
        }

        Ok(Self {
            ctx: v.ctx,
            script_pubkey,
            leaf_hashes,
            bytes,
            base_keys,
        })
    }
}

/// The PSBT adapter over a C PSBT vtable. Every callback calls through to C
/// on every use.
pub struct VtablePsbt {
    ctx: *mut c_void,
    input_count: CountFn,
    output_count: CountFn,
    spent_output: OutputFn,
    output: OutputFn,
    input_bundle: BundleFn,
    set_input_bundle: SetBundleFn,
    output_bundle: BundleFn,
    set_output_bundle: SetBundleFn,
    output_proof: ProofFn,
    set_output_proof: SetProofFn,
    tap_leaf_sighash: SighashFn,
    add_tap_script_sig: AddSigFn,
}

impl VtablePsbt {
    /// # Safety
    /// `vtable` must be null or point to a live `PsbtVtable` whose callbacks
    /// are sound and whose `ctx` outlives every use of the adapter.
    pub unsafe fn new(vtable: *const PsbtVtable) -> Result<Self, FfiError> {
        if vtable.is_null() {
            return Err(FfiError::NullPointer);
        }
        let v = unsafe { &*vtable };
        macro_rules! required {
            ($field:expr) => {
                match $field {
                    Some(callback) => callback,
                    None => return Err(FfiError::BadVtable),
                }
            };
        }
        let input_count = required!(v.input_count);
        let output_count = required!(v.output_count);
        let spent_output = required!(v.spent_output);
        let output = required!(v.output);
        let input_bundle = required!(v.input_bundle);
        let set_input_bundle = required!(v.set_input_bundle);
        let output_bundle = required!(v.output_bundle);
        let set_output_bundle = required!(v.set_output_bundle);
        let output_proof = required!(v.output_proof);
        let set_output_proof = required!(v.set_output_proof);
        let tap_leaf_sighash = required!(v.tap_leaf_sighash);
        let add_tap_script_sig = required!(v.add_tap_script_sig);
        Ok(Self {
            ctx: v.ctx,
            input_count,
            output_count,
            spent_output,
            output,
            input_bundle,
            set_input_bundle,
            output_bundle,
            set_output_bundle,
            output_proof,
            set_output_proof,
            tap_leaf_sighash,
            add_tap_script_sig,
        })
    }

    /// Reads the output `get` reports at `index`.
    fn read_output(&self, get: OutputFn, index: usize) -> Result<Output, Error> {
        let mut value = 0u64;
        let script_pubkey = read_bytes(Error::Psbt, |out, cap, out_len| unsafe {
            get(self.ctx, index, out, cap, out_len, &mut value)
        })?;
        Ok(Output {
            script_pubkey,
            value,
        })
    }

    /// Reads and decodes the bundle `get` reports at `index`, if present.
    fn read_bundle(&self, get: BundleFn, index: usize) -> Result<Option<Bundle>, Error> {
        let mut flag = 0u8;
        let bytes = read_bytes(Error::Psbt, |out, cap, out_len| unsafe {
            get(self.ctx, index, out, cap, out_len, &mut flag)
        })?;
        if !present(flag)? {
            return Ok(None);
        }
        Bundle::from_bytes(&bytes).map(Some)
    }

    /// Writes the serialized `bundle` at `index` through `set`.
    fn write_bundle(&self, set: SetBundleFn, index: usize, bundle: &Bundle) -> Result<(), Error> {
        let bytes = bundle.to_bytes();
        if unsafe { set(self.ctx, index, bytes.as_ptr(), bytes.len()) } != 0 {
            return Err(Error::Psbt);
        }
        Ok(())
    }
}

impl<'a> BitcoinBackend for VtableBackend<'a> {
    type Sha256 = VtableSha256<'a>;
    type Sha512 = VtableSha512<'a>;
    type Descriptor = VtableDescriptor;
    type Template = VtableTemplate;
    type Psbt = VtablePsbt;

    fn sha256(&self) -> Self::Sha256 {
        let mut state = HashState([0u8; BIP89_HASH_STATE_LEN]);
        unsafe { (self.sha256_init)(self.vtable.ctx, state.0.as_mut_ptr()) };
        VtableSha256 {
            backend: *self,
            state,
        }
    }

    fn sha512(&self) -> Self::Sha512 {
        let mut state = HashState([0u8; BIP89_HASH_STATE_LEN]);
        unsafe { (self.sha512_init)(self.vtable.ctx, state.0.as_mut_ptr()) };
        VtableSha512 {
            backend: *self,
            state,
        }
    }

    fn point_is_valid(&self, p: &[u8; 33]) -> bool {
        unsafe { (self.point_is_valid)(self.vtable.ctx, p.as_ptr()) == 1 }
    }

    fn point_add(&self, a: &[u8; 33], b: &[u8; 33]) -> Option<[u8; 33]> {
        let mut out = [0u8; 33];
        let rc =
            unsafe { (self.point_add)(self.vtable.ctx, a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
        if rc == 0 {
            Some(out)
        } else {
            None
        }
    }

    fn point_mul(&self, p: &[u8; 33], k: &[u8; 32]) -> Option<[u8; 33]> {
        let mut out = [0u8; 33];
        let rc =
            unsafe { (self.point_mul)(self.vtable.ctx, p.as_ptr(), k.as_ptr(), out.as_mut_ptr()) };
        if rc == 0 {
            Some(out)
        } else {
            None
        }
    }

    fn base_mul(&self, k: &[u8; 32]) -> Option<[u8; 33]> {
        let mut out = [0u8; 33];
        let rc = unsafe { (self.base_mul)(self.vtable.ctx, k.as_ptr(), out.as_mut_ptr()) };
        if rc == 0 {
            Some(out)
        } else {
            None
        }
    }

    fn scalar_add(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe { (self.scalar_add)(self.vtable.ctx, a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
        out
    }

    fn scalar_mul(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe { (self.scalar_mul)(self.vtable.ctx, a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
        out
    }

    fn bip322_sign(&self, secret: &[u8; 32], message: &[u8; 32]) -> Result<Vec<u8>, Error> {
        read_bytes(Error::SecretKey, |out, cap, out_len| unsafe {
            (self.bip322_sign)(
                self.vtable.ctx,
                secret.as_ptr(),
                message.as_ptr(),
                out,
                cap,
                out_len,
            )
        })
    }

    fn bip322_verify(&self, key: &[u8; 33], message: &[u8; 32], signature: &[u8]) -> bool {
        unsafe {
            (self.bip322_verify)(
                self.vtable.ctx,
                key.as_ptr(),
                message.as_ptr(),
                signature.as_ptr(),
                signature.len(),
            ) == 1
        }
    }

    fn descriptor_policy(&self, d: &VtableDescriptor) -> Vec<u8> {
        d.policy.clone()
    }

    fn descriptor_template(&self, d: &VtableDescriptor) -> Result<Vec<u8>, Error> {
        Ok(d.template.clone())
    }

    fn descriptor_xpubs(&self, d: &VtableDescriptor) -> Result<Vec<Xpub>, Error> {
        Ok(d.xpubs.clone())
    }

    fn template_bytes(&self, t: &VtableTemplate) -> Vec<u8> {
        t.bytes.clone()
    }

    fn template_base_keys(&self, t: &VtableTemplate) -> Vec<[u8; 33]> {
        t.base_keys.clone()
    }

    fn template_script_pubkey(
        &self,
        t: &VtableTemplate,
        tweaked: &[([u8; 33], [u8; 33])],
    ) -> Result<Vec<u8>, Error> {
        let flat = flatten_tweaked(tweaked);
        read_bytes(Error::Template, |out, cap, out_len| unsafe {
            (t.script_pubkey)(t.ctx, flat.as_ptr(), tweaked.len(), out, cap, out_len)
        })
    }

    fn template_leaf_hashes(
        &self,
        t: &VtableTemplate,
        tweaked: &[([u8; 33], [u8; 33])],
        key: &[u8; 33],
    ) -> Result<Vec<[u8; 32]>, Error> {
        let flat = flatten_tweaked(tweaked);
        read_records(Error::Template, [0u8; 32], |out, cap, out_count| unsafe {
            (t.leaf_hashes)(
                t.ctx,
                flat.as_ptr(),
                tweaked.len(),
                key.as_ptr(),
                out.cast(),
                cap,
                out_count,
            )
        })
    }

    fn input_count(&self, p: &VtablePsbt) -> usize {
        unsafe { (p.input_count)(p.ctx) }
    }

    fn output_count(&self, p: &VtablePsbt) -> usize {
        unsafe { (p.output_count)(p.ctx) }
    }

    fn spent_output(&self, p: &VtablePsbt, input: usize) -> Result<Output, Error> {
        p.read_output(p.spent_output, input)
    }

    fn output(&self, p: &VtablePsbt, output: usize) -> Result<Output, Error> {
        p.read_output(p.output, output)
    }

    fn input_bundle(&self, p: &VtablePsbt, input: usize) -> Result<Option<Bundle>, Error> {
        p.read_bundle(p.input_bundle, input)
    }

    fn set_input_bundle(
        &self,
        p: &mut VtablePsbt,
        input: usize,
        bundle: &Bundle,
    ) -> Result<(), Error> {
        p.write_bundle(p.set_input_bundle, input, bundle)
    }

    fn output_bundle(&self, p: &VtablePsbt, output: usize) -> Result<Option<Bundle>, Error> {
        p.read_bundle(p.output_bundle, output)
    }

    fn set_output_bundle(
        &self,
        p: &mut VtablePsbt,
        output: usize,
        bundle: &Bundle,
    ) -> Result<(), Error> {
        p.write_bundle(p.set_output_bundle, output, bundle)
    }

    fn output_proof(&self, p: &VtablePsbt, output: usize) -> Result<Option<Proof>, Error> {
        let mut bytes = [0u8; Proof::LEN];
        let mut flag = 0u8;
        if unsafe { (p.output_proof)(p.ctx, output, bytes.as_mut_ptr(), &mut flag) } != 0 {
            return Err(Error::Psbt);
        }
        if !present(flag)? {
            return Ok(None);
        }
        Proof::from_bytes(&bytes).map(Some)
    }

    fn set_output_proof(
        &self,
        p: &mut VtablePsbt,
        output: usize,
        proof: &Proof,
    ) -> Result<(), Error> {
        let bytes = proof.to_bytes();
        if unsafe { (p.set_output_proof)(p.ctx, output, bytes.as_ptr()) } != 0 {
            return Err(Error::Psbt);
        }
        Ok(())
    }

    fn tap_leaf_sighash(
        &self,
        p: &VtablePsbt,
        input: usize,
        leaf_hash: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        let rc =
            unsafe { (p.tap_leaf_sighash)(p.ctx, input, leaf_hash.as_ptr(), out.as_mut_ptr()) };
        if rc != 0 {
            return Err(Error::Psbt);
        }
        Ok(out)
    }

    fn add_tap_script_sig(
        &self,
        p: &mut VtablePsbt,
        input: usize,
        xonly: &[u8; 32],
        leaf_hash: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<(), Error> {
        let rc = unsafe {
            (p.add_tap_script_sig)(
                p.ctx,
                input,
                xonly.as_ptr(),
                leaf_hash.as_ptr(),
                sig.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Psbt);
        }
        Ok(())
    }
}

/// Registration built from a C-supplied template; the template vtable is
/// copied into `VtableTemplate`, so its `ctx` must outlive the handle.
pub type RegistrationHandle = Registration<VtableBackend<'static>>;

impl From<Error> for FfiError {
    fn from(error: Error) -> Self {
        FfiError::Ll(error)
    }
}

unsafe fn fail(error: FfiError, err: *mut *const c_char) -> i32 {
    let (code, message) = error.info();
    if !err.is_null() {
        *err = message.as_ptr().cast();
    }
    code
}

/// Reads `len` elements at `ptr`. A null `ptr` with `len == 0` is the empty
/// slice; a null `ptr` with `len > 0` is `NullPointer`.
unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], FfiError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FfiError::NullPointer);
    }
    Ok(core::slice::from_raw_parts(ptr, len))
}

/// Copies a fixed-size input out of a raw pointer, rejecting a null pointer.
unsafe fn array<const N: usize>(ptr: *const u8) -> Result<[u8; N], FfiError> {
    if ptr.is_null() {
        return Err(FfiError::NullPointer);
    }
    let mut out = [0u8; N];
    ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N);
    Ok(out)
}

/// Writes a fixed-size output to a raw pointer. Callers null-check `out` first.
unsafe fn write<const N: usize>(out: *mut u8, value: &[u8; N]) {
    ptr::copy_nonoverlapping(value.as_ptr(), out, N);
}

/// Aggregate the BIP32 tweak of `path_len` unhardened child numbers at `path`
/// (may be null when `path_len` is 0) from the 33-byte `key` and 32-byte
/// `chain_code`.
///
/// # Safety
/// `crypto` must point to a sound vtable; `key` and `chain_code` must be
/// readable for 33 and 32 bytes; `path` must be readable for `path_len` `u32`
/// values, or null when `path_len` is 0. `tweak_out` must be writable for 32
/// bytes, `key_out` for 33 bytes, `chain_code_out` for 32 bytes. `err` may be
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_compute_tweak(
    crypto: *const CryptoVtable,
    key: *const u8,
    chain_code: *const u8,
    path: *const u32,
    path_len: usize,
    tweak_out: *mut u8,
    key_out: *mut u8,
    chain_code_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match compute_tweak_inner(
        crypto,
        key,
        chain_code,
        path,
        path_len,
        tweak_out,
        key_out,
        chain_code_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn compute_tweak_inner(
    crypto: *const CryptoVtable,
    key: *const u8,
    chain_code: *const u8,
    path: *const u32,
    path_len: usize,
    tweak_out: *mut u8,
    key_out: *mut u8,
    chain_code_out: *mut u8,
) -> Result<(), FfiError> {
    if tweak_out.is_null() || key_out.is_null() || chain_code_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let key = array::<33>(key)?;
    let chain_code = array::<32>(chain_code)?;
    let path = slice(path, path_len)?;
    let b = VtableBackend::new(crypto)?;
    let derived = bwk_bip89::tweak::compute_bip32_tweak(&b, &key, &chain_code, path)?;
    write(tweak_out, &derived.tweak);
    write(key_out, &derived.key);
    write(chain_code_out, &derived.chain_code);
    Ok(())
}

/// Tweak a compressed base key by a 32-byte scalar.
///
/// # Safety
/// `crypto` must point to a sound vtable; `base` and `tweak` must be readable for
/// 33 and 32 bytes, `out` writable for 33 bytes. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_tweak_key(
    crypto: *const CryptoVtable,
    base: *const u8,
    tweak: *const u8,
    out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match tweak_key_inner(crypto, base, tweak, out) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn tweak_key_inner(
    crypto: *const CryptoVtable,
    base: *const u8,
    tweak: *const u8,
    out: *mut u8,
) -> Result<(), FfiError> {
    if out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let base = array::<33>(base)?;
    let tweak = array::<32>(tweak)?;
    let b = VtableBackend::new(crypto)?;
    write(out, &bwk_bip89::tweak::tweak_key(&b, &base, &tweak)?);
    Ok(())
}

/// BIP89 DelegatorSign: BIP340 signature of the 32-byte `msg` under `secret`
/// plus `tweak`, with the 32-byte `aux`.
///
/// # Safety
/// `crypto` must point to a sound vtable; `tweak`, `secret`, `msg` and `aux`
/// must each be readable for 32 bytes; `sig_out` must be writable for 64
/// bytes. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_delegator_sign(
    crypto: *const CryptoVtable,
    tweak: *const u8,
    secret: *const u8,
    msg: *const u8,
    aux: *const u8,
    sig_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match delegator_sign_inner(crypto, tweak, secret, msg, aux, sig_out) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn delegator_sign_inner(
    crypto: *const CryptoVtable,
    tweak: *const u8,
    secret: *const u8,
    msg: *const u8,
    aux: *const u8,
    sig_out: *mut u8,
) -> Result<(), FfiError> {
    if sig_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let tweak = array::<32>(tweak)?;
    let secret = array::<32>(secret)?;
    let msg = array::<32>(msg)?;
    let aux = array::<32>(aux)?;
    let b = VtableBackend::new(crypto)?;
    write(
        sig_out,
        &bwk_bip89::sign::delegator_sign(&b, &tweak, &secret, &msg, &aux)?,
    );
    Ok(())
}

const SECNONCE_LEN: usize = 65;
const SESSION_BASE_LEN: usize = 130;
const SESSION_TWEAK_LEN: usize = 33;

/// Encodes a `SessionContext` as `pk || blindfactor || challenge || pubnonce`
/// followed by `tweak || is_xonly` (one flag byte, 0 or 1) per tweak.
fn session_to_bytes(session: &SessionContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(SESSION_BASE_LEN + SESSION_TWEAK_LEN * session.tweaks.len());
    out.extend_from_slice(&session.pk);
    out.extend_from_slice(&session.blindfactor);
    out.extend_from_slice(&session.challenge);
    out.extend_from_slice(&session.pubnonce);
    for (tweak, xonly) in session.tweaks.iter().zip(&session.is_xonly) {
        out.extend_from_slice(tweak);
        out.push(u8::from(*xonly));
    }
    out
}

/// Parses the bytes `session_to_bytes` writes. A length below
/// `SESSION_BASE_LEN`, a remainder not a multiple of `SESSION_TWEAK_LEN`, or a
/// flag byte other than 0 or 1 is `Error::TweakCount`.
fn session_from_bytes(bytes: &[u8]) -> Result<SessionContext, FfiError> {
    if bytes.len() < SESSION_BASE_LEN {
        return Err(FfiError::Ll(Error::TweakCount));
    }
    let (base, tweaks_bytes) = bytes.split_at(SESSION_BASE_LEN);
    if tweaks_bytes.len() % SESSION_TWEAK_LEN != 0 {
        return Err(FfiError::Ll(Error::TweakCount));
    }

    let (pk, base) = base.split_at(33);
    let (blindfactor, base) = base.split_at(32);
    let (challenge, base) = base.split_at(32);
    let (pubnonce, _) = base.split_at(33);
    let bad = || FfiError::Ll(Error::TweakCount);
    let pk: [u8; 33] = pk.try_into().map_err(|_| bad())?;
    let blindfactor: [u8; 32] = blindfactor.try_into().map_err(|_| bad())?;
    let challenge: [u8; 32] = challenge.try_into().map_err(|_| bad())?;
    let pubnonce: [u8; 33] = pubnonce.try_into().map_err(|_| bad())?;

    let count = tweaks_bytes.len() / SESSION_TWEAK_LEN;
    let mut tweaks = Vec::with_capacity(count);
    let mut is_xonly = Vec::with_capacity(count);
    for record in tweaks_bytes.chunks_exact(SESSION_TWEAK_LEN) {
        let (tweak, flag) = record.split_at(32);
        let tweak: [u8; 32] = tweak.try_into().map_err(|_| bad())?;
        let xonly = match flag[0] {
            0 => false,
            1 => true,
            _ => return Err(bad()),
        };
        tweaks.push(tweak);
        is_xonly.push(xonly);
    }

    Ok(SessionContext {
        pk,
        blindfactor,
        challenge,
        pubnonce,
        tweaks,
        is_xonly,
    })
}

/// Generates a blind secret nonce and its public counterpart. `sk` (32 bytes)
/// and `pk` (33 bytes) may be null, meaning no secret key or public key is
/// mixed in. `extra_in` may be null when `extra_in_len` is 0. An `extra_in`
/// too long for its 4-byte length prefix fails with `ExtraInLength`.
///
/// # Safety
/// `crypto` must point to a sound vtable. `sk` and `pk`, when non-null, must
/// be readable for 32 and 33 bytes. `extra_in` must be readable for
/// `extra_in_len` bytes, or null when `extra_in_len` is 0. `secnonce_out`
/// must be writable for `SECNONCE_LEN` bytes, `secnonce_len` writable for one
/// `usize`, `pubnonce_out` writable for 33 bytes. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_blind_nonce_gen(
    crypto: *const CryptoVtable,
    sk: *const u8,
    pk: *const u8,
    extra_in: *const u8,
    extra_in_len: usize,
    secnonce_out: *mut u8,
    secnonce_len: *mut usize,
    pubnonce_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match blind_nonce_gen_inner(
        crypto,
        sk,
        pk,
        extra_in,
        extra_in_len,
        secnonce_out,
        secnonce_len,
        pubnonce_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn blind_nonce_gen_inner(
    crypto: *const CryptoVtable,
    sk: *const u8,
    pk: *const u8,
    extra_in: *const u8,
    extra_in_len: usize,
    secnonce_out: *mut u8,
    secnonce_len: *mut usize,
    pubnonce_out: *mut u8,
) -> Result<(), FfiError> {
    if secnonce_out.is_null() || secnonce_len.is_null() || pubnonce_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let sk = if sk.is_null() {
        None
    } else {
        Some(array::<32>(sk)?)
    };
    let pk = if pk.is_null() {
        None
    } else {
        Some(array::<33>(pk)?)
    };
    let extra_in = if extra_in.is_null() {
        if extra_in_len != 0 {
            return Err(FfiError::NullPointer);
        }
        None
    } else {
        Some(slice(extra_in, extra_in_len)?)
    };

    let b = VtableBackend::new(crypto)?;
    let mut rng = b;
    let (secnonce, pubnonce) =
        bwk_bip89::blind::blind_nonce_gen(&b, &mut rng, sk.as_ref(), pk.as_ref(), extra_in)?;

    let bytes = secnonce.as_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), secnonce_out, bytes.len());
    if bytes.len() < SECNONCE_LEN {
        ptr::write_bytes(secnonce_out.add(bytes.len()), 0, SECNONCE_LEN - bytes.len());
    }
    *secnonce_len = bytes.len();
    write(pubnonce_out, &pubnonce);
    Ok(())
}

/// Generates a blind challenge for `msg` under `pk` tweaked by `tweaks` and
/// `is_xonly`, given the signer's public nonce `blindpubnonce`. Writes the
/// session to `session_out`; when `session_cap` is too small, writes the
/// needed length to `session_len` and returns `BufferTooSmall` without
/// drawing randomness. An `extra_in` too long for its 4-byte length prefix
/// fails with `ExtraInLength`.
///
/// # Safety
/// `crypto` must point to a sound vtable. `msg` must be readable for
/// `msg_len` bytes, or null when `msg_len` is 0. `blindpubnonce` and `pk`
/// must be readable for 33 bytes. `tweaks` must be readable as `n_tweaks`
/// 32-byte records, `is_xonly` as `n_is_xonly` bytes. `extra_in` must be
/// readable for `extra_in_len` bytes, or null when `extra_in_len` is 0.
/// `session_out` must be writable for `session_cap` bytes, or null when
/// `session_cap` is 0. `session_len`, `blindchallenge_out`, `pk_parity_out`
/// and `nonce_parity_out` must be writable. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_blind_challenge_gen(
    crypto: *const CryptoVtable,
    msg: *const u8,
    msg_len: usize,
    blindpubnonce: *const u8,
    pk: *const u8,
    tweaks: *const u8,
    n_tweaks: usize,
    is_xonly: *const u8,
    n_is_xonly: usize,
    extra_in: *const u8,
    extra_in_len: usize,
    session_out: *mut u8,
    session_cap: usize,
    session_len: *mut usize,
    blindchallenge_out: *mut u8,
    pk_parity_out: *mut u8,
    nonce_parity_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match blind_challenge_gen_inner(
        crypto,
        msg,
        msg_len,
        blindpubnonce,
        pk,
        tweaks,
        n_tweaks,
        is_xonly,
        n_is_xonly,
        extra_in,
        extra_in_len,
        session_out,
        session_cap,
        session_len,
        blindchallenge_out,
        pk_parity_out,
        nonce_parity_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn blind_challenge_gen_inner(
    crypto: *const CryptoVtable,
    msg: *const u8,
    msg_len: usize,
    blindpubnonce: *const u8,
    pk: *const u8,
    tweaks: *const u8,
    n_tweaks: usize,
    is_xonly: *const u8,
    n_is_xonly: usize,
    extra_in: *const u8,
    extra_in_len: usize,
    session_out: *mut u8,
    session_cap: usize,
    session_len: *mut usize,
    blindchallenge_out: *mut u8,
    pk_parity_out: *mut u8,
    nonce_parity_out: *mut u8,
) -> Result<(), FfiError> {
    if session_len.is_null()
        || blindchallenge_out.is_null()
        || pk_parity_out.is_null()
        || nonce_parity_out.is_null()
    {
        return Err(FfiError::NullPointer);
    }
    let blindpubnonce = array::<33>(blindpubnonce)?;
    let pk = array::<33>(pk)?;
    let msg = slice(msg, msg_len)?;
    let tweaks = slice::<[u8; 32]>(tweaks.cast(), n_tweaks)?;
    let is_xonly_bytes = slice(is_xonly, n_is_xonly)?;
    let is_xonly: Vec<bool> = is_xonly_bytes.iter().map(|&b| b != 0).collect();
    let extra_in = if extra_in.is_null() {
        if extra_in_len != 0 {
            return Err(FfiError::NullPointer);
        }
        None
    } else {
        Some(slice(extra_in, extra_in_len)?)
    };
    let b = VtableBackend::new(crypto)?;

    let needed = SESSION_TWEAK_LEN
        .checked_mul(n_tweaks)
        .and_then(|scaled| scaled.checked_add(SESSION_BASE_LEN))
        .ok_or(FfiError::BufferTooSmall)?;
    if needed > session_cap {
        *session_len = needed;
        return Err(FfiError::BufferTooSmall);
    }
    if session_out.is_null() {
        return Err(FfiError::NullPointer);
    }

    let mut rng = b;
    let out = bwk_bip89::blind::blind_challenge_gen(
        &b,
        &mut rng,
        msg,
        &blindpubnonce,
        &pk,
        tweaks,
        &is_xonly,
        extra_in,
    )?;

    let bytes = session_to_bytes(&out.session);
    ptr::copy_nonoverlapping(bytes.as_ptr(), session_out, bytes.len());
    *session_len = bytes.len();
    write(blindchallenge_out, &out.blindchallenge);
    *pk_parity_out = u8::from(out.pk_parity);
    *nonce_parity_out = u8::from(out.nonce_parity);
    Ok(())
}

/// Signs under a blinded challenge with the secret nonce from
/// `bip89_blind_nonce_gen`. The `secnonce` bytes the protocol zeroes are copied
/// back into the caller buffer whether the call succeeds or fails, so a
/// second call on the same buffer fails with nonce reuse.
///
/// # Safety
/// `crypto` must point to a sound vtable. `sk` and `blindchallenge` must be
/// readable for 32 bytes. `secnonce` must be readable and writable for
/// `secnonce_len` bytes (32 or 65). `sig_out` must be writable for 32 bytes.
/// `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_blind_sign(
    crypto: *const CryptoVtable,
    sk: *const u8,
    blindchallenge: *const u8,
    secnonce: *mut u8,
    secnonce_len: usize,
    pk_parity: u8,
    nonce_parity: u8,
    sig_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match blind_sign_inner(
        crypto,
        sk,
        blindchallenge,
        secnonce,
        secnonce_len,
        pk_parity,
        nonce_parity,
        sig_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn blind_sign_inner(
    crypto: *const CryptoVtable,
    sk: *const u8,
    blindchallenge: *const u8,
    secnonce: *mut u8,
    secnonce_len: usize,
    pk_parity: u8,
    nonce_parity: u8,
    sig_out: *mut u8,
) -> Result<(), FfiError> {
    if secnonce.is_null() || sig_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let sk = array::<32>(sk)?;
    let blindchallenge = array::<32>(blindchallenge)?;

    let secnonce_bytes = slice(secnonce as *const u8, secnonce_len)?;
    let mut secnonce_obj = bwk_bip89::blind::BlindSecNonce::from_bytes(secnonce_bytes)?;

    let b = VtableBackend::new(crypto)?;

    let result = bwk_bip89::blind::blind_sign(
        &b,
        &sk,
        &blindchallenge,
        &mut secnonce_obj,
        pk_parity != 0,
        nonce_parity != 0,
    );

    let bytes_back = secnonce_obj.as_bytes();
    ptr::copy_nonoverlapping(bytes_back.as_ptr(), secnonce, bytes_back.len());

    let sig = result?;
    write(sig_out, &sig);
    Ok(())
}

/// Checks a blind signature against the signer's public nonce, before
/// unblinding. A malformed input is an error; a mismatch is `*valid_out = 0`.
///
/// # Safety
/// `crypto` must point to a sound vtable. `pk` and `blindpubnonce` must be
/// readable for 33 bytes; `blindchallenge` and `blindsignature` for 32 bytes.
/// `valid_out` must be writable for one byte. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_verify_blind_signature(
    crypto: *const CryptoVtable,
    pk: *const u8,
    blindpubnonce: *const u8,
    blindchallenge: *const u8,
    blindsignature: *const u8,
    pk_parity: u8,
    nonce_parity: u8,
    valid_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match verify_blind_signature_inner(
        crypto,
        pk,
        blindpubnonce,
        blindchallenge,
        blindsignature,
        pk_parity,
        nonce_parity,
        valid_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn verify_blind_signature_inner(
    crypto: *const CryptoVtable,
    pk: *const u8,
    blindpubnonce: *const u8,
    blindchallenge: *const u8,
    blindsignature: *const u8,
    pk_parity: u8,
    nonce_parity: u8,
    valid_out: *mut u8,
) -> Result<(), FfiError> {
    if valid_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let pk = array::<33>(pk)?;
    let blindpubnonce = array::<33>(blindpubnonce)?;
    let blindchallenge = array::<32>(blindchallenge)?;
    let blindsignature = array::<32>(blindsignature)?;
    let b = VtableBackend::new(crypto)?;

    let valid = bwk_bip89::blind::verify_blind_signature(
        &b,
        &pk,
        &blindpubnonce,
        &blindchallenge,
        &blindsignature,
        pk_parity != 0,
        nonce_parity != 0,
    )?;
    *valid_out = u8::from(valid);
    Ok(())
}

/// Unblinds a blind signature using a session from `bip89_blind_challenge_gen`.
///
/// # Safety
/// `crypto` must point to a sound vtable. `session` must be readable for
/// `session_len` bytes. `blindsignature` must be readable for 32 bytes.
/// `sig_out` must be writable for 64 bytes. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_unblind_signature(
    crypto: *const CryptoVtable,
    session: *const u8,
    session_len: usize,
    blindsignature: *const u8,
    sig_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match unblind_signature_inner(crypto, session, session_len, blindsignature, sig_out) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn unblind_signature_inner(
    crypto: *const CryptoVtable,
    session: *const u8,
    session_len: usize,
    blindsignature: *const u8,
    sig_out: *mut u8,
) -> Result<(), FfiError> {
    if sig_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let blindsignature = array::<32>(blindsignature)?;
    let b = VtableBackend::new(crypto)?;

    let session_bytes = slice(session, session_len)?;
    let session = session_from_bytes(session_bytes)?;

    let sig = bwk_bip89::blind::unblind_signature(&b, &session, &blindsignature)?;
    write(sig_out, &sig);
    Ok(())
}

/// Serializes the BIP89 delegation bundle of the descriptor for `keychain`
/// and `index`: one tweak entry per distinct base key.
///
/// # Safety
/// `crypto` and `descriptor` must point to sound vtables. `out` must be
/// writable for `out_cap` bytes, or null when `out_cap` is 0. `out_len` must
/// be writable. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_derive_bundle(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    keychain: u32,
    index: u32,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    err: *mut *const c_char,
) -> i32 {
    match derive_bundle_inner(crypto, descriptor, keychain, index, out, out_cap, out_len) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn derive_bundle_inner(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    keychain: u32,
    index: u32,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> Result<(), FfiError> {
    if out_len.is_null() {
        return Err(FfiError::NullPointer);
    }
    let b = VtableBackend::new(crypto)?;
    let descriptor = VtableDescriptor::new(descriptor)?;

    let needed = descriptor
        .xpubs
        .len()
        .checked_mul(ENTRY_LEN)
        .ok_or(FfiError::BufferTooSmall)?;
    if needed > out_cap {
        *out_len = needed;
        return Err(FfiError::BufferTooSmall);
    }
    if out.is_null() {
        return Err(FfiError::NullPointer);
    }

    let bundle = bwk_bip89::bundle::derive_bundle(&b, &descriptor, keychain, index)?;
    let bytes = bundle.to_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    *out_len = bytes.len();
    Ok(())
}

/// Builds the tree of the descriptor for `keychain` and `tree_start`, then
/// signs its root with BIP322 under the branch key of the 32-byte `secret`.
/// Writes the 32-byte root, the 33-byte base key of `secret`, its 32-byte
/// branch tweak, and the signature to `signature_out` with its length in
/// `*signature_len`. When `signature_cap` is too small, writes only the needed
/// length and returns `BufferTooSmall`.
///
/// # Safety
/// `crypto` and `descriptor` must point to sound vtables. `secret` must be
/// readable for 32 bytes. `root_out` must be writable for 32 bytes, `key_out`
/// for 33 bytes, `branch_tweak_out` for 32 bytes. `signature_out` must be
/// writable for `signature_cap` bytes, or null when `signature_cap` is 0.
/// `signature_len` must be writable. `err` may be null.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_sign_tree_root(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    secret: *const u8,
    keychain: u32,
    tree_start: u32,
    root_out: *mut u8,
    key_out: *mut u8,
    branch_tweak_out: *mut u8,
    signature_out: *mut u8,
    signature_cap: usize,
    signature_len: *mut usize,
    err: *mut *const c_char,
) -> i32 {
    match sign_tree_root_inner(
        crypto,
        descriptor,
        secret,
        keychain,
        tree_start,
        root_out,
        key_out,
        branch_tweak_out,
        signature_out,
        signature_cap,
        signature_len,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn sign_tree_root_inner(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    secret: *const u8,
    keychain: u32,
    tree_start: u32,
    root_out: *mut u8,
    key_out: *mut u8,
    branch_tweak_out: *mut u8,
    signature_out: *mut u8,
    signature_cap: usize,
    signature_len: *mut usize,
) -> Result<(), FfiError> {
    if root_out.is_null()
        || key_out.is_null()
        || branch_tweak_out.is_null()
        || signature_len.is_null()
    {
        return Err(FfiError::NullPointer);
    }
    let secret = array::<32>(secret)?;
    let b = VtableBackend::new(crypto)?;
    let descriptor = VtableDescriptor::new(descriptor)?;

    let record = bwk_bip89::accumulator::record::sign_tree_root(
        &b,
        &descriptor,
        &secret,
        keychain,
        tree_start,
    )?;
    // sign_tree_root always signs the root it builds
    let Some(signed) = record.signature else {
        return Err(FfiError::Ll(Error::MissingRootSignature));
    };
    if signed.signature.len() > signature_cap {
        *signature_len = signed.signature.len();
        return Err(FfiError::BufferTooSmall);
    }
    if signature_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    write(root_out, &record.root);
    write(key_out, &signed.key);
    write(branch_tweak_out, &signed.branch_tweak);
    ptr::copy_nonoverlapping(
        signed.signature.as_ptr(),
        signature_out,
        signed.signature.len(),
    );
    *signature_len = signed.signature.len();
    Ok(())
}

/// Builds a proof tree of the descriptor for `keychain` and `tree_start`.
/// Writes the 32-byte root and, on success only, an owning handle to `*out`.
///
/// # Safety
/// `crypto` and `descriptor` must point to sound vtables. `root_out` must be
/// writable for 32 bytes, `out` writable for one pointer. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_build_tree(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    keychain: u32,
    tree_start: u32,
    root_out: *mut u8,
    out: *mut *mut Tree,
    err: *mut *const c_char,
) -> i32 {
    match build_tree_inner(crypto, descriptor, keychain, tree_start, root_out, out) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn build_tree_inner(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    keychain: u32,
    tree_start: u32,
    root_out: *mut u8,
    out: *mut *mut Tree,
) -> Result<(), FfiError> {
    if root_out.is_null() || out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let b = VtableBackend::new(crypto)?;
    let descriptor = VtableDescriptor::new(descriptor)?;
    let tree = bwk_bip89::accumulator::record::build_tree(&b, &descriptor, keychain, tree_start)?;
    write(root_out, &tree.root);
    *out = Box::into_raw(Box::new(tree));
    Ok(())
}

/// Writes the `BIP89_PROOF_LEN`-byte membership proof of `keychain`/`index`
/// in `tree`.
///
/// # Safety
/// `tree` must come from `bip89_build_tree` and be live. `proof_out` must be
/// writable for `BIP89_PROOF_LEN` bytes. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_tree_proof(
    tree: *const Tree,
    keychain: u32,
    index: u32,
    proof_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match tree_proof_inner(tree, keychain, index, proof_out) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn tree_proof_inner(
    tree: *const Tree,
    keychain: u32,
    index: u32,
    proof_out: *mut u8,
) -> Result<(), FfiError> {
    if tree.is_null() || proof_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let tree = unsafe { &*tree };
    let proof = tree
        .proof(keychain, index)
        .ok_or(FfiError::IndexOutOfBounds)?;
    write(proof_out, &proof.to_bytes());
    Ok(())
}

/// Release a tree returned by `bip89_build_tree`. A null pointer is a no-op.
///
/// # Safety
/// `tree` must come from `bip89_build_tree` and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_tree_free(tree: *mut Tree) {
    if tree.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(tree) });
}

/// BIP89 InputVerification of `script` (the spent output scriptPubKey)
/// against a serialized bundle. Writes 1 or 0 to `valid_out`.
///
/// # Safety
/// `crypto` and `tmpl` must point to sound vtables. `script` must be readable
/// for `script_len` bytes, or null when `script_len` is 0. `bundle` must be
/// readable for `bundle_len` bytes. `valid_out` must be writable. `err` may
/// be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_input_verification(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    script: *const u8,
    script_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    valid_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match input_verification_inner(
        crypto, tmpl, script, script_len, bundle, bundle_len, valid_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn input_verification_inner(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    script: *const u8,
    script_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    valid_out: *mut u8,
) -> Result<(), FfiError> {
    verify_inner(
        crypto,
        tmpl,
        script,
        script_len,
        bundle,
        bundle_len,
        valid_out,
        bwk_bip89::verify::input_verification,
    )
}

/// BIP89 ChangeOutputVerification: the same check as `bip89_input_verification`.
///
/// # Safety
/// Same as `bip89_input_verification`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_change_output_verification(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    script: *const u8,
    script_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    valid_out: *mut u8,
    err: *mut *const c_char,
) -> i32 {
    match change_output_verification_inner(
        crypto, tmpl, script, script_len, bundle, bundle_len, valid_out,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn change_output_verification_inner(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    script: *const u8,
    script_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    valid_out: *mut u8,
) -> Result<(), FfiError> {
    verify_inner(
        crypto,
        tmpl,
        script,
        script_len,
        bundle,
        bundle_len,
        valid_out,
        bwk_bip89::verify::change_output_verification,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn verify_inner<'a>(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    script: *const u8,
    script_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    valid_out: *mut u8,
    core: fn(&VtableBackend<'a>, &VtableTemplate, &[u8], &Bundle) -> Result<bool, Error>,
) -> Result<(), FfiError> {
    if valid_out.is_null() {
        return Err(FfiError::NullPointer);
    }
    let b = VtableBackend::new(crypto)?;
    let tmpl = VtableTemplate::new(tmpl)?;
    let script = slice(script, script_len)?;
    let bundle_bytes = slice(bundle, bundle_len)?;
    let bundle = Bundle::from_bytes(bundle_bytes)?;

    let valid = core(&b, &tmpl, script, &bundle)?;
    *valid_out = u8::from(valid);
    Ok(())
}

/// The `RootPolicy` of a `BIP89_ROOT_POLICY_*` value.
fn root_policy(policy: u32) -> Result<RootPolicy, FfiError> {
    match policy {
        BIP89_ROOT_POLICY_REQUIRE_SIGNATURE => Ok(RootPolicy::RequireSignature),
        BIP89_ROOT_POLICY_ALLOW_UNSIGNED => Ok(RootPolicy::AllowUnsigned),
        _ => Err(FfiError::InvalidRootPolicy),
    }
}

/// Pins `tmpl` and `policy` with the `receive` (keychain 0) and `change`
/// (keychain 1) roots, each checked against a base key of `tmpl` first. Writes
/// an owning handle to `*out` on success only. The handle keeps a copy of the
/// template vtable, so its `ctx` must stay valid until
/// `bip89_registration_free`.
///
/// # Safety
/// `crypto` and `tmpl` must point to sound vtables. `policy` must be a
/// `BIP89_ROOT_POLICY_*` value. `receive` and `change` must point to readable
/// records whose signatures follow the rule of `FfiRootRecord`. `out` must be
/// writable for one pointer. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_register(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    policy: u32,
    receive: *const FfiRootRecord,
    change: *const FfiRootRecord,
    out: *mut *mut RegistrationHandle,
    err: *mut *const c_char,
) -> i32 {
    match register_inner(crypto, tmpl, policy, receive, change, out) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn register_inner(
    crypto: *const CryptoVtable,
    tmpl: *const TemplateVtable,
    policy: u32,
    receive: *const FfiRootRecord,
    change: *const FfiRootRecord,
    out: *mut *mut RegistrationHandle,
) -> Result<(), FfiError> {
    if out.is_null() || receive.is_null() || change.is_null() {
        return Err(FfiError::NullPointer);
    }
    let policy = root_policy(policy)?;
    let receive = (*receive).root_record()?;
    let change = (*change).root_record()?;
    let b = VtableBackend::new(crypto)?;
    let tmpl = VtableTemplate::new(tmpl)?;

    let registration = bwk_bip89::delegator::register(&b, tmpl, policy, &receive, &change)?;
    *out = Box::into_raw(Box::new(registration));
    Ok(())
}

/// Records the root of the next tree of a keychain in `registration`, once
/// checked against a base key of its template, under the policy pinned at
/// `bip89_register`.
///
/// # Safety
/// `crypto` must point to a sound vtable. `registration` must come from
/// `bip89_register` and be live. `record` must point to a readable record
/// whose signature follows the rule of `FfiRootRecord`. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_registration_record_root(
    crypto: *const CryptoVtable,
    registration: *mut RegistrationHandle,
    record: *const FfiRootRecord,
    err: *mut *const c_char,
) -> i32 {
    match registration_record_root_inner(crypto, registration, record) {
        Ok(()) => BIP89_OK,
        Err(error) => fail(error, err),
    }
}

unsafe fn registration_record_root_inner(
    crypto: *const CryptoVtable,
    registration: *mut RegistrationHandle,
    record: *const FfiRootRecord,
) -> Result<(), FfiError> {
    if registration.is_null() || record.is_null() {
        return Err(FfiError::NullPointer);
    }
    let record = (*record).root_record()?;
    let b = VtableBackend::new(crypto)?;
    let registration = unsafe { &mut *registration };

    registration.record_root(&b, &record)?;
    Ok(())
}

/// Release a registration returned by `bip89_register`. A null pointer is a no-op.
///
/// # Safety
/// `registration` must come from `bip89_register` and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_registration_free(registration: *mut RegistrationHandle) {
    if registration.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(registration) });
}

/// Writes bundles for `inputs` and bundles plus accumulator proofs for
/// `outputs`. `trees` are borrowed handles, cloned internally. On an error
/// naming an output, its index goes to `*index_out`.
///
/// # Safety
/// `crypto`, `descriptor` and `psbt` must point to sound vtables. `trees` must
/// be readable for `n_trees` pointers, each non-null and live from
/// `bip89_build_tree`, or `n_trees` may be 0 with `trees` null. `inputs` must
/// be readable for `n_inputs` records, `outputs` for `n_outputs` records,
/// under the same rule. `index_out` may be null. `err` may be null.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_coordinator_prepare(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    trees: *const *const Tree,
    n_trees: usize,
    inputs: *const FfiOwned,
    n_inputs: usize,
    outputs: *const FfiOwned,
    n_outputs: usize,
    psbt: *const PsbtVtable,
    index_out: *mut usize,
    err: *mut *const c_char,
) -> i32 {
    match coordinator_prepare_inner(
        crypto, descriptor, trees, n_trees, inputs, n_inputs, outputs, n_outputs, psbt,
    ) {
        Ok(()) => BIP89_OK,
        Err(error) => {
            unsafe { report_index(error, index_out) };
            fail(error, err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn coordinator_prepare_inner(
    crypto: *const CryptoVtable,
    descriptor: *const DescriptorVtable,
    trees: *const *const Tree,
    n_trees: usize,
    inputs: *const FfiOwned,
    n_inputs: usize,
    outputs: *const FfiOwned,
    n_outputs: usize,
    psbt: *const PsbtVtable,
) -> Result<(), FfiError> {
    if (n_trees > 0 && trees.is_null())
        || (n_inputs > 0 && inputs.is_null())
        || (n_outputs > 0 && outputs.is_null())
    {
        return Err(FfiError::NullPointer);
    }
    let tree_ptrs = slice(trees, n_trees)?;
    if tree_ptrs.iter().any(|p| p.is_null()) {
        return Err(FfiError::NullPointer);
    }
    let inputs_raw = slice(inputs, n_inputs)?;
    let outputs_raw = slice(outputs, n_outputs)?;

    let b = VtableBackend::new(crypto)?;
    let descriptor = VtableDescriptor::new(descriptor)?;
    let mut psbt = VtablePsbt::new(psbt)?;

    let owned_trees: Vec<Tree> = tree_ptrs
        .iter()
        .map(|tree_ptr| unsafe { (**tree_ptr).clone() })
        .collect();

    let owned_inputs: Vec<Owned> = inputs_raw
        .iter()
        .map(|o| Owned {
            psbt_index: o.psbt_index,
            keychain: o.keychain,
            index: o.index,
        })
        .collect();
    let owned_outputs: Vec<Owned> = outputs_raw
        .iter()
        .map(|o| Owned {
            psbt_index: o.psbt_index,
            keychain: o.keychain,
            index: o.index,
        })
        .collect();

    bwk_bip89::coordinator::prepare(
        &b,
        &descriptor,
        &owned_trees,
        &owned_inputs,
        &owned_outputs,
        &mut psbt,
    )?;
    Ok(())
}

/// Verifies every input bundle and every output that carries a bundle.
/// Writes the outflow (inputs minus owned outputs, fee included) to
/// `*outflow_out` on success. On an error naming an input or output, its
/// index goes to `*index_out`.
///
/// # Safety
/// `crypto` and `psbt` must point to sound vtables. `registration` must come
/// from `bip89_register` and be live. `outflow_out` must be writable.
/// `index_out` may be null. `err` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_delegator_verify_spend(
    crypto: *const CryptoVtable,
    registration: *const RegistrationHandle,
    psbt: *const PsbtVtable,
    outflow_out: *mut u64,
    index_out: *mut usize,
    err: *mut *const c_char,
) -> i32 {
    match delegator_verify_spend_inner(crypto, registration, psbt, outflow_out) {
        Ok(()) => BIP89_OK,
        Err(error) => {
            unsafe { report_index(error, index_out) };
            fail(error, err)
        }
    }
}

unsafe fn delegator_verify_spend_inner(
    crypto: *const CryptoVtable,
    registration: *const RegistrationHandle,
    psbt: *const PsbtVtable,
    outflow_out: *mut u64,
) -> Result<(), FfiError> {
    if outflow_out.is_null() || registration.is_null() {
        return Err(FfiError::NullPointer);
    }
    let b = VtableBackend::new(crypto)?;
    let registration = unsafe { &*registration };
    let psbt = VtablePsbt::new(psbt)?;

    let outflow = bwk_bip89::delegator::verify_spend(&b, registration, &psbt)?;
    unsafe { *outflow_out = outflow };
    Ok(())
}

/// Verifies as `bip89_delegator_verify_spend`, then adds BIP340 script path
/// signatures with the 32-byte delegator `secret` (aux from `fill_random`).
/// No signature is added when verification fails.
///
/// # Safety
/// `crypto` and `psbt` must point to sound vtables. `registration` must come
/// from `bip89_register` and be live. `secret` must be readable for 32 bytes.
/// `outflow_out` must be writable. `index_out` may be null. `err` may be null.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip89_delegator_sign_spend(
    crypto: *const CryptoVtable,
    registration: *const RegistrationHandle,
    psbt: *const PsbtVtable,
    secret: *const u8,
    outflow_out: *mut u64,
    index_out: *mut usize,
    err: *mut *const c_char,
) -> i32 {
    match delegator_sign_spend_inner(crypto, registration, psbt, secret, outflow_out) {
        Ok(()) => BIP89_OK,
        Err(error) => {
            unsafe { report_index(error, index_out) };
            fail(error, err)
        }
    }
}

unsafe fn delegator_sign_spend_inner(
    crypto: *const CryptoVtable,
    registration: *const RegistrationHandle,
    psbt: *const PsbtVtable,
    secret: *const u8,
    outflow_out: *mut u64,
) -> Result<(), FfiError> {
    if outflow_out.is_null() || registration.is_null() {
        return Err(FfiError::NullPointer);
    }
    let secret = array::<32>(secret)?;
    let b = VtableBackend::new(crypto)?;
    let registration = unsafe { &*registration };
    let mut psbt = VtablePsbt::new(psbt)?;
    let mut rng = b;

    let outflow = bwk_bip89::delegator::sign_spend(&b, &mut rng, registration, &secret, &mut psbt)?;
    unsafe { *outflow_out = outflow };
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use bwk_bip89::Error;

    use crate::FfiError;

    const LL_ROWS: [(Error, i32, &str); 41] = [
        (Error::InvalidPoint, 100, "invalid point\0"),
        (Error::Infinity, 101, "point at infinity\0"),
        (Error::ScalarRange, 102, "scalar out of range\0"),
        (Error::SecretKey, 103, "invalid secret key\0"),
        (Error::ZeroNonce, 104, "zero nonce\0"),
        (Error::HardenedIndex, 105, "hardened index not supported\0"),
        (Error::InvalidChild, 106, "invalid child key\0"),
        (Error::TweakCount, 107, "tweak count mismatch\0"),
        (Error::NonceReuse, 108, "secret nonce already used\0"),
        (Error::SecNonceLength, 109, "invalid secret nonce length\0"),
        (
            Error::BlindSignature,
            110,
            "blind signature failed self verification\0",
        ),
        (Error::DuplicateKey, 111, "duplicate key in bundle\0"),
        (Error::UnsortedBundle, 112, "bundle entries not sorted\0"),
        (Error::EntryLength, 113, "invalid bundle entry length\0"),
        (Error::MissingTweak, 114, "template key has no tweak\0"),
        (Error::ExtraTweak, 115, "bundle key not in template\0"),
        (
            Error::Template,
            116,
            "template rejected or callback failed\0",
        ),
        (Error::InvalidKeychain, 117, "invalid keychain\0"),
        (Error::IndexRange, 118, "tree index range out of bounds\0"),
        (Error::ProofLength, 119, "invalid proof length\0"),
        (Error::RootSignature, 121, "invalid root signature\0"),
        (Error::NotCommitted, 122, "bundle not committed in tree\0"),
        (Error::NoTree(7), 124, "no tree for output\0"),
        (Error::MissingUtxo(7), 125, "input utxo missing\0"),
        (Error::MissingBundle(7), 126, "input bundle missing\0"),
        (Error::InputMismatch(7), 127, "input script mismatch\0"),
        (Error::OutputMismatch(7), 128, "output script mismatch\0"),
        (Error::MissingProof(7), 129, "output proof missing\0"),
        (Error::Amount, 130, "amount out of range\0"),
        (Error::NotParticipant, 131, "secret key not in template\0"),
        (Error::NothingToSign(7), 132, "nothing to sign for input\0"),
        (Error::Psbt, 133, "psbt rejected or callback failed\0"),
        (Error::ExtraInLength, 134, "extra input too long\0"),
        (Error::NotTaproot, 135, "descriptor is not taproot\0"),
        (
            Error::KeyType,
            136,
            "key is not a multipath extended public key\0",
        ),
        (
            Error::Multipath,
            137,
            "key does not have two multipath elements\0",
        ),
        (
            Error::Wildcard,
            138,
            "key does not end with an unhardened wildcard\0",
        ),
        (
            Error::HardenedStep,
            139,
            "key has a hardened derivation step\0",
        ),
        (
            Error::ConflictingKey,
            140,
            "base key repeated with another chain code or path\0",
        ),
        (Error::NoKeys, 141, "descriptor has no key\0"),
        (Error::MissingRootSignature, 142, "root signature missing\0"),
    ];

    const BOUNDARY_ROWS: [(FfiError, i32, &str); 5] = [
        (FfiError::NullPointer, 500, "null pointer\0"),
        (FfiError::BadVtable, 501, "vtable has a null callback\0"),
        (FfiError::BufferTooSmall, 502, "output buffer too small\0"),
        (FfiError::IndexOutOfBounds, 503, "index out of bounds\0"),
        (FfiError::InvalidRootPolicy, 504, "invalid root policy\0"),
    ];

    fn all_infos() -> [(i32, &'static str); 46] {
        let mut out = [(0, ""); 46];
        for (i, (error, code, message)) in LL_ROWS.into_iter().enumerate() {
            let info = FfiError::Ll(error).info();
            assert_eq!(info, (code, message));
            out[i] = info;
        }
        for (i, (error, code, message)) in BOUNDARY_ROWS.into_iter().enumerate() {
            let info = error.info();
            assert_eq!(info, (code, message));
            out[LL_ROWS.len() + i] = info;
        }
        out
    }

    #[test]
    fn error_codes_are_fixed() {
        let infos = all_infos();
        for i in 0..infos.len() {
            for j in (i + 1)..infos.len() {
                assert_ne!(infos[i].0, infos[j].0, "duplicate code between {i} and {j}");
            }
        }
    }

    #[test]
    fn messages_are_nul_terminated() {
        let infos = all_infos();
        for (_, message) in infos {
            let bytes = message.as_bytes();
            assert_eq!(bytes.iter().filter(|&&b| b == 0).count(), 1);
            assert_eq!(*bytes.last().unwrap(), 0);
            assert!(CStr::from_bytes_with_nul(bytes).is_ok());
        }
    }
}
