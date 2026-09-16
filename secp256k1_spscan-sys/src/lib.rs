// SPDX-License-Identifier: CC0-1.0

//! secp256k1_spscan-sys: byte-only FFI for the SP-scan libsecp fork.
//!
//! The fork is built with `USE_EXTERNAL_DEFAULT_CALLBACKS`, so the context
//! allocator wrappers and the default illegal/error callbacks are provided here
//! in Rust, exactly as upstream secp256k1-sys does.
//!
//! No async, no pre-validation: the safe API hands raw tweak/spend bytes
//! straight to the C kernel (which validates each point via `ec_pubkey_parse`)
//! and surfaces a malformed point as a [`MalformedPubkey`] `Err` rather than
//! panicking, so a bad oracle tweak fails gracefully on a worker thread.

use std::alloc;
use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use std::fmt;
use std::ptr::NonNull;

/// A tweak or spend point handed to the scan kernel was not a valid compressed
/// secp256k1 point (the C `ec_pubkey_parse` rejected it).
#[derive(Debug)]
pub struct MalformedPubkey;

impl fmt::Display for MalformedPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("malformed secp256k1 pubkey reached the SP-scan kernel")
    }
}

impl std::error::Error for MalformedPubkey {}

// Flags value matching SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY (the
// fork's START_SIGN | START_VERIFY). Sufficient for all functionality.
const SECP256K1_START_SIGN: c_uint = 1 | (1 << 9);
const SECP256K1_START_VERIFY: c_uint = 1 | (1 << 8);
const CONTEXT_FLAGS: c_uint = SECP256K1_START_SIGN | SECP256K1_START_VERIFY;

/// Opaque secp256k1 context. We only ever hold it behind a pointer.
#[repr(C)]
pub struct Context(c_int);

// A type as aligned as C's max_align_t (16 on every arch rustc supports), used to
// size the over-allocation that lets context_destroy recover the block length.
#[repr(align(16))]
struct AlignedType;

const ALIGN_TO: usize = core::mem::align_of::<AlignedType>();

extern "C" {
    #[link_name = "secp256k1_context_preallocated_size"]
    fn context_preallocated_size(flags: c_uint) -> usize;

    #[link_name = "secp256k1_context_preallocated_create"]
    fn context_preallocated_create(prealloc: NonNull<c_void>, flags: c_uint) -> NonNull<Context>;

    #[link_name = "secp256k1_context_preallocated_destroy"]
    fn context_preallocated_destroy(cx: NonNull<Context>);

    // Byte-FFI shim entries (spscan_ffi.c).
    fn secp256k1_spscan_scan_spend_points(
        ctx: *const Context,
        out_xonly32: *mut c_uchar,
        n_out: *mut usize,
        tweak33: *const c_uchar,
        scan_key32: *const c_uchar,
        spend_points33: *const c_uchar,
        n_spend_points: usize,
    ) -> c_int;

    fn secp256k1_spscan_scan_spend_points_batch(
        ctx: *const Context,
        out_xonly32: *mut c_uchar,
        n_out: *mut usize,
        tweaks33: *const c_uchar,
        n_tweaks: usize,
        scan_key32: *const c_uchar,
        spend_points33: *const c_uchar,
        n_spend_points: usize,
    ) -> c_int;
}

// --- Context allocator wrappers ---
//
// The C library is compiled without its own context_create/destroy (the fork
// removed them); only context_preallocated_* exist in C. We reimplement
// create/destroy here, over-allocating ALIGN_TO bytes to stash the block size so
// destroy can free it. This mirrors secp256k1-sys exactly.

/// # Safety
/// The returned context must be freed with [`context_destroy`].
unsafe fn context_create(flags: c_uint) -> NonNull<Context> {
    assert!(ALIGN_TO >= core::mem::align_of::<usize>());
    assert!(ALIGN_TO >= core::mem::size_of::<usize>());

    let bytes = context_preallocated_size(flags) + ALIGN_TO;
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    let ptr = alloc::alloc(layout);
    if ptr.is_null() {
        alloc::handle_alloc_error(layout);
    }
    // Stash the allocation size at the head so destroy can rebuild the layout.
    (ptr as *mut usize).write(bytes);
    let ptr = ptr.add(ALIGN_TO);
    let ptr = NonNull::new_unchecked(ptr as *mut c_void);
    context_preallocated_create(ptr, flags)
}

/// # Safety
/// `ctx` must come from [`context_create`] and must not be used afterwards.
unsafe fn context_destroy(ctx: NonNull<Context>) {
    context_preallocated_destroy(ctx);
    let ptr = (ctx.as_ptr() as *mut u8).sub(ALIGN_TO);
    let bytes = (ptr as *mut usize).read();
    let layout = alloc::Layout::from_size_align(bytes, ALIGN_TO).unwrap();
    alloc::dealloc(ptr, layout);
}

// --- External default callbacks ---
//
// Required by USE_EXTERNAL_DEFAULT_CALLBACKS. Both panic: these only fire on a
// library bug or genuinely illegal API usage, never on normal data.

unsafe fn strlen(mut s: *const c_char) -> usize {
    let mut n = 0;
    while *s != 0 {
        n += 1;
        s = s.offset(1);
    }
    n
}

#[no_mangle]
unsafe extern "C" fn secp256k1_default_illegal_callback_fn(
    message: *const c_char,
    _data: *mut c_void,
) {
    let slice = core::slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = core::str::from_utf8_unchecked(slice);
    panic!("[libsecp256k1] illegal argument. {msg}");
}

#[no_mangle]
unsafe extern "C" fn secp256k1_default_error_callback_fn(
    message: *const c_char,
    _data: *mut c_void,
) {
    let slice = core::slice::from_raw_parts(message as *const u8, strlen(message));
    let msg = core::str::from_utf8_unchecked(slice);
    panic!("[libsecp256k1] internal consistency check failed {msg}");
}

// --- Safe Rust API ---

/// Owns a SIGN|VERIFY secp context for the lifetime of one call set.
struct Ctx(NonNull<Context>);

impl Ctx {
    fn new() -> Self {
        // SAFETY: paired with the Drop below; flags are a valid context flag set.
        Ctx(unsafe { context_create(CONTEXT_FLAGS) })
    }

    fn as_ptr(&self) -> *const Context {
        self.0.as_ptr()
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: self.0 came from context_create and is dropped exactly once.
        unsafe { context_destroy(self.0) }
    }
}

/// Per-tweak light-client scan: returns one x-only candidate (32 bytes) per spend
/// point, in spend-point order, for the single `tweak`.
///
/// Returns `Err` on a malformed pubkey: `tweak`/`spend_points` are handed raw to
/// the C kernel, which rejects a non-curve-point.
pub fn scan_spend_points(
    scan_key: &[u8; 32],
    tweak: &[u8; 33],
    spend_points: &[[u8; 33]],
) -> Result<Vec<[u8; 32]>, MalformedPubkey> {
    if spend_points.is_empty() {
        return Ok(Vec::new());
    }
    let ctx = Ctx::new();
    let n_spend = spend_points.len();
    let out_len = n_spend.checked_mul(32).ok_or(MalformedPubkey)?;
    let mut out = vec![0u8; out_len];
    let mut n_out: usize = n_spend;

    // SAFETY: out holds n_spend*32 bytes; spend_points is n_spend contiguous
    // 33-byte blobs; tweak/scan_key are fixed-size; ctx is live.
    let ret = unsafe {
        secp256k1_spscan_scan_spend_points(
            ctx.as_ptr(),
            out.as_mut_ptr(),
            &mut n_out,
            tweak.as_ptr(),
            scan_key.as_ptr(),
            spend_points.as_ptr() as *const c_uchar,
            n_spend,
        )
    };
    if ret != 1 {
        return Err(MalformedPubkey);
    }
    if n_out != n_spend {
        return Err(MalformedPubkey);
    }

    Ok(pack_xonly(&out, n_out))
}

/// Batched light-client scan: returns the x-only candidates for every
/// (tweak, spend point) pair as one flat buffer, row-major by tweak (candidate
/// for tweak `t`, spend point `s` of `n_spend` is at index `t * n_spend + s`;
/// tweaks in `tweaks` order, spend points in `spend_points` order).
///
/// Byte-identical to calling [`scan_spend_points`] once per tweak and
/// concatenating. Returns `Err` on a malformed pubkey.
pub fn scan_spend_points_batch(
    scan_key: &[u8; 32],
    tweaks: &[[u8; 33]],
    spend_points: &[[u8; 33]],
) -> Result<Vec<[u8; 32]>, MalformedPubkey> {
    if tweaks.is_empty() || spend_points.is_empty() {
        return Ok(Vec::new());
    }
    let ctx = Ctx::new();
    let n_tweaks = tweaks.len();
    let n_spend = spend_points.len();
    let total = n_tweaks.checked_mul(n_spend).ok_or(MalformedPubkey)?;
    let out_len = total.checked_mul(32).ok_or(MalformedPubkey)?;
    let mut out = vec![0u8; out_len];
    let mut n_out: usize = total;

    // SAFETY: out holds total*32 bytes; tweaks/spend_points are contiguous
    // 33-byte blobs of the given counts; scan_key is fixed-size; ctx is live.
    let ret = unsafe {
        secp256k1_spscan_scan_spend_points_batch(
            ctx.as_ptr(),
            out.as_mut_ptr(),
            &mut n_out,
            tweaks.as_ptr() as *const c_uchar,
            n_tweaks,
            scan_key.as_ptr(),
            spend_points.as_ptr() as *const c_uchar,
            n_spend,
        )
    };
    if ret != 1 {
        return Err(MalformedPubkey);
    }
    if n_out != total {
        return Err(MalformedPubkey);
    }

    Ok(pack_xonly(&out, n_out))
}

/// Slice the flat byte buffer into `n` 32-byte x-only candidates.
fn pack_xonly(out: &[u8], n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut x = [0u8; 32];
            x.copy_from_slice(&out[i * 32..i * 32 + 32]);
            x
        })
        .collect()
}
