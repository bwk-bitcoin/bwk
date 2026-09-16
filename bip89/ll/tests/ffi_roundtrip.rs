//! Drives every C ABI entry point through `extern "C"` callbacks backed by
//! `RustBitcoin` and compares each with the Rust API.

#[path = "../../tests/common/mod.rs"]
mod common;

use core::ffi::{c_char, c_void, CStr};

use bwk_bip89::{
    accumulator::{
        record::{self, RootPolicy},
        tree::{Proof, Tree},
    },
    bip340, blind,
    bundle::{self, Bundle, Entry},
    coordinator::prepare,
    delegator,
    rust_bitcoin::{
        miniscript::{
            bitcoin::{self, Psbt, ScriptBuf},
            Descriptor as MsDescriptor, DescriptorPublicKey,
        },
        RustBitcoin, SUBTYPE_PROOF,
    },
    scalar::{scalar_neg, xbytes, N},
    sign, tweak, verify, BitcoinBackend, Error, Rng, Sha256Engine, Sha512Engine, Xpub,
};
use bwk_bip89_ll::{
    bip89_blind_challenge_gen, bip89_blind_nonce_gen, bip89_blind_sign, bip89_build_tree,
    bip89_change_output_verification, bip89_compute_tweak, bip89_coordinator_prepare,
    bip89_delegator_sign, bip89_delegator_sign_spend, bip89_delegator_verify_spend,
    bip89_derive_bundle, bip89_input_verification, bip89_register, bip89_registration_free,
    bip89_registration_record_root, bip89_sign_tree_root, bip89_tree_free, bip89_tree_proof,
    bip89_tweak_key, bip89_unblind_signature, bip89_verify_blind_signature, CryptoVtable,
    DescriptorVtable, FfiError, FfiOwned, FfiRootRecord, FfiXpub, PsbtVtable, RegistrationHandle,
    TemplateVtable, U32List, VtableBackend, VtableTemplate, BIP89_OK,
    BIP89_ROOT_POLICY_ALLOW_UNSIGNED, BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
};
use common::{
    hex_arr, hex_vec, root_signature, signed_roots, spend_psbt, standard_lists, unsigned_roots,
    wallet, FixedRng, DELEGATOR_SECRET, OWNER1_SECRET,
};

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct TestCtx {
    crypto: RustBitcoin,
    rng: FixedRng,
}

type Sha256Of = <RustBitcoin as BitcoinBackend>::Sha256;
type Sha512Of = <RustBitcoin as BitcoinBackend>::Sha512;

unsafe extern "C" fn sha256_init(ctx: *mut c_void, state: *mut u8) {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let engine = Box::into_raw(Box::new(test.crypto.sha256()));
    unsafe { state.cast::<*mut Sha256Of>().write_unaligned(engine) };
}

unsafe extern "C" fn sha256_update(_ctx: *mut c_void, state: *mut u8, data: *const u8, len: usize) {
    let engine = unsafe { &mut *state.cast::<*mut Sha256Of>().read_unaligned() };
    engine.update(unsafe { core::slice::from_raw_parts(data, len) });
}

unsafe extern "C" fn sha256_final(_ctx: *mut c_void, state: *mut u8, out: *mut u8) {
    let engine = unsafe { Box::from_raw(state.cast::<*mut Sha256Of>().read_unaligned()) };
    let digest = engine.finalize();
    unsafe { out.copy_from_nonoverlapping(digest.as_ptr(), 32) };
}

unsafe extern "C" fn sha512_init(ctx: *mut c_void, state: *mut u8) {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let engine = Box::into_raw(Box::new(test.crypto.sha512()));
    unsafe { state.cast::<*mut Sha512Of>().write_unaligned(engine) };
}

unsafe extern "C" fn sha512_update(_ctx: *mut c_void, state: *mut u8, data: *const u8, len: usize) {
    let engine = unsafe { &mut *state.cast::<*mut Sha512Of>().read_unaligned() };
    engine.update(unsafe { core::slice::from_raw_parts(data, len) });
}

unsafe extern "C" fn sha512_final(_ctx: *mut c_void, state: *mut u8, out: *mut u8) {
    let engine = unsafe { Box::from_raw(state.cast::<*mut Sha512Of>().read_unaligned()) };
    let digest = engine.finalize();
    unsafe { out.copy_from_nonoverlapping(digest.as_ptr(), 64) };
}

unsafe extern "C" fn point_is_valid(ctx: *mut c_void, point: *const u8) -> i32 {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let point = unsafe { &*point.cast::<[u8; 33]>() };
    i32::from(test.crypto.point_is_valid(point))
}

unsafe extern "C" fn point_add(ctx: *mut c_void, a: *const u8, b: *const u8, out: *mut u8) -> i32 {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let (a, b) = unsafe { (&*a.cast::<[u8; 33]>(), &*b.cast::<[u8; 33]>()) };
    match test.crypto.point_add(a, b) {
        Some(p) => {
            unsafe { out.copy_from_nonoverlapping(p.as_ptr(), 33) };
            0
        }
        None => 1,
    }
}

unsafe extern "C" fn point_mul(
    ctx: *mut c_void,
    point: *const u8,
    scalar: *const u8,
    out: *mut u8,
) -> i32 {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let (point, scalar) = unsafe { (&*point.cast::<[u8; 33]>(), &*scalar.cast::<[u8; 32]>()) };
    match test.crypto.point_mul(point, scalar) {
        Some(p) => {
            unsafe { out.copy_from_nonoverlapping(p.as_ptr(), 33) };
            0
        }
        None => 1,
    }
}

unsafe extern "C" fn base_mul(ctx: *mut c_void, scalar: *const u8, out: *mut u8) -> i32 {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let scalar = unsafe { &*scalar.cast::<[u8; 32]>() };
    match test.crypto.base_mul(scalar) {
        Some(p) => {
            unsafe { out.copy_from_nonoverlapping(p.as_ptr(), 33) };
            0
        }
        None => 1,
    }
}

unsafe extern "C" fn scalar_add(ctx: *mut c_void, a: *const u8, b: *const u8, out: *mut u8) {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let (a, b) = unsafe { (&*a.cast::<[u8; 32]>(), &*b.cast::<[u8; 32]>()) };
    let sum = test.crypto.scalar_add(a, b);
    unsafe { out.copy_from_nonoverlapping(sum.as_ptr(), 32) };
}

unsafe extern "C" fn scalar_mul(ctx: *mut c_void, a: *const u8, b: *const u8, out: *mut u8) {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let (a, b) = unsafe { (&*a.cast::<[u8; 32]>(), &*b.cast::<[u8; 32]>()) };
    let product = test.crypto.scalar_mul(a, b);
    unsafe { out.copy_from_nonoverlapping(product.as_ptr(), 32) };
}

unsafe extern "C" fn bip322_sign(
    ctx: *mut c_void,
    secret: *const u8,
    msg: *const u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let (secret, msg) = unsafe { (&*secret.cast::<[u8; 32]>(), &*msg.cast::<[u8; 32]>()) };
    match test.crypto.bip322_sign(secret, msg) {
        Ok(signature) => unsafe { write_buf(&signature, out, cap, out_len) },
        Err(_) => 1,
    }
}

unsafe extern "C" fn bip322_verify(
    ctx: *mut c_void,
    key: *const u8,
    msg: *const u8,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    let test = unsafe { &*ctx.cast::<TestCtx>() };
    let (key, msg) = unsafe { (&*key.cast::<[u8; 33]>(), &*msg.cast::<[u8; 32]>()) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    i32::from(test.crypto.bip322_verify(key, msg, sig))
}

unsafe extern "C" fn fill_random(ctx: *mut c_void, buf: *mut u8, len: usize) {
    let test = unsafe { &mut *ctx.cast::<TestCtx>() };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    test.rng.fill_bytes(buf);
}

fn vtable(ctx: &mut TestCtx) -> CryptoVtable {
    CryptoVtable {
        ctx: (ctx as *mut TestCtx).cast::<c_void>(),
        sha256_init: Some(sha256_init),
        sha256_update: Some(sha256_update),
        sha256_final: Some(sha256_final),
        sha512_init: Some(sha512_init),
        sha512_update: Some(sha512_update),
        sha512_final: Some(sha512_final),
        point_is_valid: Some(point_is_valid),
        point_add: Some(point_add),
        point_mul: Some(point_mul),
        base_mul: Some(base_mul),
        scalar_add: Some(scalar_add),
        scalar_mul: Some(scalar_mul),
        bip322_sign: Some(bip322_sign),
        bip322_verify: Some(bip322_verify),
        fill_random: Some(fill_random),
    }
}

fn message(err: *const c_char) -> &'static str {
    unsafe { CStr::from_ptr(err) }.to_str().unwrap()
}

unsafe fn write_buf(bytes: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    unsafe { *out_len = bytes.len() };
    if bytes.len() <= cap && !out.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    }
    0
}

/// Writes `records` to `out` when they fit in `cap` records, reporting their count.
unsafe fn write_records<T: Copy>(
    records: &[T],
    out: *mut T,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    unsafe { *out_count = records.len() };
    if records.len() <= cap && !out.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(records.as_ptr(), out, records.len()) };
    }
    0
}

struct DescCtx {
    b: RustBitcoin,
    desc: MsDescriptor<DescriptorPublicKey>,
    xpubs: Vec<Xpub>,
}

impl DescCtx {
    fn new(desc: &MsDescriptor<DescriptorPublicKey>) -> Self {
        let b = RustBitcoin::new();
        let xpubs = b.descriptor_xpubs(desc).unwrap();
        Self {
            b,
            desc: desc.clone(),
            xpubs,
        }
    }
}

unsafe extern "C" fn policy_bytes(
    ctx: *mut c_void,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let desc = unsafe { &*ctx.cast::<DescCtx>() };
    let bytes = desc.b.descriptor_policy(&desc.desc);
    unsafe { write_buf(&bytes, out, cap, out_len) }
}

unsafe extern "C" fn template_bytes(
    ctx: *mut c_void,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let desc = unsafe { &*ctx.cast::<DescCtx>() };
    let Ok(bytes) = desc.b.descriptor_template(&desc.desc) else {
        return 1;
    };
    unsafe { write_buf(&bytes, out, cap, out_len) }
}

unsafe extern "C" fn xpubs(
    ctx: *mut c_void,
    out: *mut FfiXpub,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    let desc = unsafe { &*ctx.cast::<DescCtx>() };
    let records: Vec<FfiXpub> = desc
        .xpubs
        .iter()
        .map(|x| FfiXpub {
            key: x.key,
            chain_code: x.chain_code,
            branch0: U32List {
                ptr: x.branches[0].as_ptr(),
                len: x.branches[0].len(),
            },
            branch1: U32List {
                ptr: x.branches[1].as_ptr(),
                len: x.branches[1].len(),
            },
        })
        .collect();
    unsafe { write_records(&records, out, cap, out_count) }
}

fn descriptor_vtable(ctx: &mut DescCtx) -> DescriptorVtable {
    DescriptorVtable {
        ctx: (ctx as *mut DescCtx).cast::<c_void>(),
        policy_bytes: Some(policy_bytes),
        template_bytes: Some(template_bytes),
        xpubs: Some(xpubs),
    }
}

unsafe extern "C" fn failing_policy_bytes(
    _ctx: *mut c_void,
    _out: *mut u8,
    _cap: usize,
    _out_len: *mut usize,
) -> i32 {
    1
}

static MISMATCHED_POLICY_CALLS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn mismatched_policy_bytes(
    _ctx: *mut c_void,
    _out: *mut u8,
    _cap: usize,
    out_len: *mut usize,
) -> i32 {
    let n = MISMATCHED_POLICY_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    unsafe { *out_len = if n == 0 { 300 } else { 301 } };
    0
}

unsafe extern "C" fn bad_branch_xpubs(
    _ctx: *mut c_void,
    out: *mut FfiXpub,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    let record = FfiXpub {
        key: [0u8; 33],
        chain_code: [0u8; 32],
        branch0: U32List {
            ptr: core::ptr::null(),
            len: 1,
        },
        branch1: U32List {
            ptr: core::ptr::null(),
            len: 0,
        },
    };
    unsafe { write_records(&[record], out, cap, out_count) }
}

struct TplCtx {
    b: RustBitcoin,
    tpl: MsDescriptor<bitcoin::PublicKey>,
}

impl TplCtx {
    fn new(tpl: &MsDescriptor<bitcoin::PublicKey>) -> Self {
        Self {
            b: RustBitcoin::new(),
            tpl: tpl.clone(),
        }
    }
}

unsafe fn pairs_from_raw(tweaked: *const u8, n: usize) -> Vec<([u8; 33], [u8; 33])> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let base = unsafe { *tweaked.add(i * 66).cast::<[u8; 33]>() };
        let tw = unsafe { *tweaked.add(i * 66 + 33).cast::<[u8; 33]>() };
        out.push((base, tw));
    }
    out
}

unsafe extern "C" fn template_bytes_cb(
    ctx: *mut c_void,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<TplCtx>() };
    let bytes = ctx.b.template_bytes(&ctx.tpl);
    unsafe { write_buf(&bytes, out, cap, out_len) }
}

unsafe extern "C" fn base_keys(
    ctx: *mut c_void,
    out: *mut u8,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<TplCtx>() };
    let keys = ctx.b.template_base_keys(&ctx.tpl);
    unsafe { write_records(&keys, out.cast(), cap, out_count) }
}

unsafe extern "C" fn script_pubkey(
    ctx: *mut c_void,
    tweaked: *const u8,
    n: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<TplCtx>() };
    let pairs = unsafe { pairs_from_raw(tweaked, n) };
    let Ok(bytes) = ctx.b.template_script_pubkey(&ctx.tpl, &pairs) else {
        return 1;
    };
    unsafe { write_buf(&bytes, out, cap, out_len) }
}

unsafe extern "C" fn leaf_hashes(
    ctx: *mut c_void,
    tweaked: *const u8,
    n: usize,
    key: *const u8,
    out: *mut u8,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<TplCtx>() };
    let pairs = unsafe { pairs_from_raw(tweaked, n) };
    let key = unsafe { &*key.cast::<[u8; 33]>() };
    let Ok(hashes) = ctx.b.template_leaf_hashes(&ctx.tpl, &pairs, key) else {
        return 1;
    };
    unsafe { write_records(&hashes, out.cast(), cap, out_count) }
}

fn template_vtable(ctx: &mut TplCtx) -> TemplateVtable {
    TemplateVtable {
        ctx: (ctx as *mut TplCtx).cast::<c_void>(),
        bytes: Some(template_bytes_cb),
        base_keys: Some(base_keys),
        script_pubkey: Some(script_pubkey),
        leaf_hashes: Some(leaf_hashes),
    }
}

unsafe extern "C" fn failing_script_pubkey(
    _ctx: *mut c_void,
    _tweaked: *const u8,
    _n: usize,
    _out: *mut u8,
    _cap: usize,
    _out_len: *mut usize,
) -> i32 {
    1
}

unsafe extern "C" fn twenty_leaf_hashes(
    _ctx: *mut c_void,
    _tweaked: *const u8,
    _n: usize,
    _key: *const u8,
    out: *mut u8,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    let hashes: Vec<[u8; 32]> = (0u8..20).map(|i| [i; 32]).collect();
    unsafe { write_records(&hashes, out.cast(), cap, out_count) }
}

static MISMATCHED_LEAF_HASHES_CALLS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn mismatched_leaf_hashes(
    _ctx: *mut c_void,
    _tweaked: *const u8,
    _n: usize,
    _key: *const u8,
    _out: *mut u8,
    _cap: usize,
    out_count: *mut usize,
) -> i32 {
    let n = MISMATCHED_LEAF_HASHES_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    unsafe { *out_count = if n == 0 { 20 } else { 21 } };
    0
}

unsafe extern "C" fn descending_base_keys(
    ctx: *mut c_void,
    out: *mut u8,
    cap: usize,
    out_count: *mut usize,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<TplCtx>() };
    let mut keys = ctx.b.template_base_keys(&ctx.tpl);
    keys.sort_by(|a, b| b.cmp(a));
    unsafe { write_records(&keys, out.cast(), cap, out_count) }
}

unsafe extern "C" fn zero_base_keys(
    _ctx: *mut c_void,
    _out: *mut u8,
    _cap: usize,
    out_count: *mut usize,
) -> i32 {
    unsafe { *out_count = 0 };
    0
}

struct PsbtCtx {
    b: RustBitcoin,
    psbt: Psbt,
}

impl PsbtCtx {
    fn new(psbt: Psbt) -> Self {
        Self {
            b: RustBitcoin::new(),
            psbt,
        }
    }
}

unsafe extern "C" fn psbt_input_count(ctx: *mut c_void) -> usize {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    ctx.b.input_count(&ctx.psbt)
}

unsafe extern "C" fn psbt_output_count(ctx: *mut c_void) -> usize {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    ctx.b.output_count(&ctx.psbt)
}

unsafe extern "C" fn psbt_spent_output(
    ctx: *mut c_void,
    index: usize,
    script: *mut u8,
    cap: usize,
    script_len: *mut usize,
    value: *mut u64,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    let Ok(output) = ctx.b.spent_output(&ctx.psbt, index) else {
        return 1;
    };
    unsafe {
        *value = output.value;
        write_buf(&output.script_pubkey, script, cap, script_len)
    }
}

unsafe extern "C" fn psbt_output(
    ctx: *mut c_void,
    index: usize,
    script: *mut u8,
    cap: usize,
    script_len: *mut usize,
    value: *mut u64,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    let Ok(output) = ctx.b.output(&ctx.psbt, index) else {
        return 1;
    };
    unsafe {
        *value = output.value;
        write_buf(&output.script_pubkey, script, cap, script_len)
    }
}

/// Writes a bundle getter's result: the serialized bundle and a present flag.
unsafe fn write_bundle(
    bundle: Result<Option<Bundle>, Error>,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    present: *mut u8,
) -> i32 {
    match bundle {
        Ok(Some(bundle)) => unsafe {
            *present = 1;
            write_buf(&bundle.to_bytes(), out, cap, out_len)
        },
        Ok(None) => unsafe {
            *present = 0;
            write_buf(&[], out, cap, out_len)
        },
        Err(_) => 1,
    }
}

unsafe extern "C" fn psbt_input_bundle(
    ctx: *mut c_void,
    index: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    present: *mut u8,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    let bundle = ctx.b.input_bundle(&ctx.psbt, index);
    unsafe { write_bundle(bundle, out, cap, out_len, present) }
}

unsafe extern "C" fn psbt_output_bundle(
    ctx: *mut c_void,
    index: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
    present: *mut u8,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    let bundle = ctx.b.output_bundle(&ctx.psbt, index);
    unsafe { write_bundle(bundle, out, cap, out_len, present) }
}

unsafe extern "C" fn psbt_set_input_bundle(
    ctx: *mut c_void,
    index: usize,
    bundle: *const u8,
    len: usize,
) -> i32 {
    let ctx = unsafe { &mut *ctx.cast::<PsbtCtx>() };
    let bytes = unsafe { core::slice::from_raw_parts(bundle, len) };
    let Ok(bundle) = Bundle::from_bytes(bytes) else {
        return 1;
    };
    match ctx.b.set_input_bundle(&mut ctx.psbt, index, &bundle) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

unsafe extern "C" fn psbt_set_output_bundle(
    ctx: *mut c_void,
    index: usize,
    bundle: *const u8,
    len: usize,
) -> i32 {
    let ctx = unsafe { &mut *ctx.cast::<PsbtCtx>() };
    let bytes = unsafe { core::slice::from_raw_parts(bundle, len) };
    let Ok(bundle) = Bundle::from_bytes(bytes) else {
        return 1;
    };
    match ctx.b.set_output_bundle(&mut ctx.psbt, index, &bundle) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

unsafe extern "C" fn psbt_output_proof(
    ctx: *mut c_void,
    index: usize,
    out: *mut u8,
    present: *mut u8,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    match ctx.b.output_proof(&ctx.psbt, index) {
        Ok(Some(proof)) => {
            let bytes = proof.to_bytes();
            unsafe {
                out.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
                *present = 1;
            }
            0
        }
        Ok(None) => {
            unsafe { *present = 0 };
            0
        }
        Err(_) => 1,
    }
}

unsafe extern "C" fn psbt_set_output_proof(
    ctx: *mut c_void,
    index: usize,
    proof: *const u8,
) -> i32 {
    let ctx = unsafe { &mut *ctx.cast::<PsbtCtx>() };
    let bytes = unsafe { core::slice::from_raw_parts(proof, Proof::LEN) };
    let Ok(proof) = Proof::from_bytes(bytes) else {
        return 1;
    };
    match ctx.b.set_output_proof(&mut ctx.psbt, index, &proof) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

unsafe extern "C" fn psbt_tap_leaf_sighash(
    ctx: *mut c_void,
    input: usize,
    leaf_hash: *const u8,
    out: *mut u8,
) -> i32 {
    let ctx = unsafe { &*ctx.cast::<PsbtCtx>() };
    let leaf_hash = unsafe { &*leaf_hash.cast::<[u8; 32]>() };
    match ctx.b.tap_leaf_sighash(&ctx.psbt, input, leaf_hash) {
        Ok(hash) => {
            unsafe { out.copy_from_nonoverlapping(hash.as_ptr(), 32) };
            0
        }
        Err(_) => 1,
    }
}

unsafe extern "C" fn psbt_add_tap_script_sig(
    ctx: *mut c_void,
    input: usize,
    xonly: *const u8,
    leaf_hash: *const u8,
    sig: *const u8,
) -> i32 {
    let ctx = unsafe { &mut *ctx.cast::<PsbtCtx>() };
    let xonly = unsafe { &*xonly.cast::<[u8; 32]>() };
    let leaf_hash = unsafe { &*leaf_hash.cast::<[u8; 32]>() };
    let sig = unsafe { &*sig.cast::<[u8; 64]>() };
    match ctx
        .b
        .add_tap_script_sig(&mut ctx.psbt, input, xonly, leaf_hash, sig)
    {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn psbt_vtable(ctx: &mut PsbtCtx) -> PsbtVtable {
    PsbtVtable {
        ctx: (ctx as *mut PsbtCtx).cast::<c_void>(),
        input_count: Some(psbt_input_count),
        output_count: Some(psbt_output_count),
        spent_output: Some(psbt_spent_output),
        output: Some(psbt_output),
        input_bundle: Some(psbt_input_bundle),
        set_input_bundle: Some(psbt_set_input_bundle),
        output_bundle: Some(psbt_output_bundle),
        set_output_bundle: Some(psbt_set_output_bundle),
        output_proof: Some(psbt_output_proof),
        set_output_proof: Some(psbt_set_output_proof),
        tap_leaf_sighash: Some(psbt_tap_leaf_sighash),
        add_tap_script_sig: Some(psbt_add_tap_script_sig),
    }
}

unsafe extern "C" fn failing_psbt_output(
    _ctx: *mut c_void,
    _index: usize,
    _script: *mut u8,
    _cap: usize,
    _script_len: *mut usize,
    _value: *mut u64,
) -> i32 {
    1
}

unsafe extern "C" fn failing_psbt_output_bundle(
    _ctx: *mut c_void,
    _index: usize,
    _out: *mut u8,
    _cap: usize,
    _out_len: *mut usize,
    _present: *mut u8,
) -> i32 {
    1
}

unsafe extern "C" fn failing_psbt_add_tap_script_sig(
    _ctx: *mut c_void,
    _input: usize,
    _xonly: *const u8,
    _leaf_hash: *const u8,
    _sig: *const u8,
) -> i32 {
    1
}

unsafe extern "C" fn failing_psbt_set_output_bundle(
    _ctx: *mut c_void,
    _index: usize,
    _bundle: *const u8,
    _len: usize,
) -> i32 {
    1
}

fn test_ctx() -> TestCtx {
    TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(Vec::new()),
    }
}

/// Signs the root of the `keychain` tree at tree start 0 with `secret` through
/// `bip89_sign_tree_root`.
fn sign_root_through_c(
    v: &CryptoVtable,
    dv: &DescriptorVtable,
    secret: &[u8; 32],
    keychain: u32,
) -> record::RootRecord {
    let mut root = [0u8; 32];
    let mut key = [0u8; 33];
    let mut branch_tweak = [0u8; 32];
    let mut signature = [0u8; 256];
    let mut signature_len = 0usize;
    let mut err: *const c_char = core::ptr::null();
    let rc = unsafe {
        bip89_sign_tree_root(
            v,
            dv,
            secret.as_ptr(),
            keychain,
            0,
            root.as_mut_ptr(),
            key.as_mut_ptr(),
            branch_tweak.as_mut_ptr(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    record::RootRecord {
        keychain,
        tree_start: 0,
        root,
        signature: Some(record::RootSignature {
            key,
            branch_tweak,
            signature: signature[..signature_len].to_vec(),
        }),
    }
}

/// The C record of `record`, borrowing its signature. A record with no
/// signature crosses with a null signature of length 0.
fn ffi_root_record(record: &record::RootRecord) -> FfiRootRecord {
    let (key, branch_tweak, signature, signature_len) = match &record.signature {
        Some(signed) => (
            signed.key,
            signed.branch_tweak,
            signed.signature.as_ptr(),
            signed.signature.len(),
        ),
        None => ([0u8; 33], [0u8; 32], core::ptr::null(), 0),
    };
    FfiRootRecord {
        keychain: record.keychain,
        tree_start: record.tree_start,
        root: record.root,
        key,
        branch_tweak,
        signature,
        signature_len,
    }
}

fn xpub_key() -> [u8; 33] {
    hex_arr("0296928602758150d2b4a8a253451b887625b94ab0a91f801f1408cb33b9cf0f83")
}

fn xpub_cc() -> [u8; 32] {
    hex_arr("433cf1154e61c4eb9793488880f8a795a3a72052ad14a7367852542425609640")
}

fn tweak_vector() -> [u8; 32] {
    hex_arr("d81d8e239630639ac24f3976257d9e4d905272b3da3a6507841c1ec80b04b91b")
}

fn child_key() -> [u8; 33] {
    hex_arr("03636eb334a6ffdfc4b975a61dae12f49e7f94461690fa4688632db8eed5601b03")
}

fn child_cc() -> [u8; 32] {
    hex_arr("299bc0ad44ab883a5be9601918badd2720c86c48a6d8b9d17e1ae1c3b0ad975d")
}

fn secret() -> [u8; 32] {
    hex_arr("9303c68c414a6208dbc0329181dd640b135e669647ad7dcb2f09870c54b26ed9")
}

fn msg() -> [u8; 32] {
    hex_arr("ed952b43f26247e9b79c9170ee6c69eb911e59c4e78fd2e44c270bbd262ec80e")
}

fn sig() -> [u8; 64] {
    hex_arr(
        "2f558d1519106f6cffdcfce09954c6ae328b98308718a0903e3efed103b457cd563c315fe6\
         c6b5ffe6f71f413ce68ba22ee793238ab73fd2cef9d5881ae80017",
    )
}

fn blind_sign_sk() -> [u8; 32] {
    hex_arr("E4E64DB308215A81F1F41969624B9A6265D50F479BA6789E40190027AC6C72A8")
}

fn blind_sign_pk() -> [u8; 33] {
    hex_arr("03E812BE6ED9A2B180FA21B682D5FB35158A9542399D389B736AEDC930CAED04AA")
}

fn blind_sign_secnonce() -> [u8; 65] {
    hex_arr(
        "D05EC853CBCFC49EAEB5DF5AED030C880C1FB59414AD4ECC3D0E5C50CD7B906803E812BE6ED9A2B180F\
         A21B682D5FB35158A9542399D389B736AEDC930CAED04AA",
    )
}

fn blind_sign_blindpubnonce() -> [u8; 33] {
    hex_arr("03E97BD8C531CB0B40AC13857BCDCA6E9FF33889148BA5C9C02E0BE93D79560186")
}

fn blind_sign_challenge() -> [u8; 32] {
    hex_arr("64FD1082FA5E7C5BF1267A5AB5BC3F4BD41167427E4D4A4166876709857E92EB")
}

fn blind_sign_signature() -> [u8; 32] {
    hex_arr("8632B771A6A923FF1561B3513C4841F2D88795B05D99BC581ABCA201EED86EC5")
}

#[test]
fn compute_tweak_matches_rust() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let key = xpub_key();
    let chain_code = xpub_cc();
    let path = [0u32, 1u32];

    let mut tweak_out = [0u8; 32];
    let mut key_out = [0u8; 33];
    let mut chain_code_out = [0u8; 32];
    let sentinel = c"sentinel".as_ptr();
    let mut err: *const c_char = sentinel;

    let rc = unsafe {
        bip89_compute_tweak(
            &v,
            key.as_ptr(),
            chain_code.as_ptr(),
            path.as_ptr(),
            path.len(),
            tweak_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
            chain_code_out.as_mut_ptr(),
            &mut err,
        )
    };

    assert_eq!(rc, BIP89_OK);
    assert_eq!(tweak_out, tweak_vector());
    assert_eq!(key_out, child_key());
    assert_eq!(chain_code_out, child_cc());
    assert!(core::ptr::eq(err, sentinel));

    let rust_c = RustBitcoin::new();
    let derived = tweak::compute_bip32_tweak(&rust_c, &key, &chain_code, &path).unwrap();
    assert_eq!(tweak_out, derived.tweak);
    assert_eq!(key_out, derived.key);
    assert_eq!(chain_code_out, derived.chain_code);

    let mut tweak_out2 = [0u8; 32];
    let mut key_out2 = [0u8; 33];
    let mut chain_code_out2 = [0u8; 32];
    let rc2 = unsafe {
        bip89_compute_tweak(
            &v,
            key.as_ptr(),
            chain_code.as_ptr(),
            core::ptr::null(),
            0,
            tweak_out2.as_mut_ptr(),
            key_out2.as_mut_ptr(),
            chain_code_out2.as_mut_ptr(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert_eq!(tweak_out2, [0u8; 32]);
    assert_eq!(key_out2, key);
    assert_eq!(chain_code_out2, chain_code);
}

#[test]
fn compute_tweak_hardened_index_code() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let key = xpub_key();
    let chain_code = xpub_cc();
    let path = [0u32, 0x8000_0000u32];

    let mut tweak_out = [0u8; 32];
    let mut key_out = [0u8; 33];
    let mut chain_code_out = [0u8; 32];
    let mut err: *const c_char = core::ptr::null();

    let rc = unsafe {
        bip89_compute_tweak(
            &v,
            key.as_ptr(),
            chain_code.as_ptr(),
            path.as_ptr(),
            path.len(),
            tweak_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
            chain_code_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, 105);
    assert_eq!(message(err), "hardened index not supported");

    let rust_c = RustBitcoin::new();
    assert_eq!(
        tweak::compute_bip32_tweak(&rust_c, &key, &chain_code, &path),
        Err(Error::HardenedIndex)
    );

    let rc_no_err = unsafe {
        bip89_compute_tweak(
            &v,
            key.as_ptr(),
            chain_code.as_ptr(),
            path.as_ptr(),
            path.len(),
            tweak_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
            chain_code_out.as_mut_ptr(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc_no_err, 105);
}

#[test]
fn tweak_key_matches_rust() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let base = xpub_key();
    let t = tweak_vector();
    let mut out = [0u8; 33];
    let mut err: *const c_char = core::ptr::null();
    let rc = unsafe { bip89_tweak_key(&v, base.as_ptr(), t.as_ptr(), out.as_mut_ptr(), &mut err) };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(out, child_key());

    let rust_c = RustBitcoin::new();
    assert_eq!(tweak::tweak_key(&rust_c, &base, &t).unwrap(), out);

    let mut out2 = [0u8; 33];
    let rc2 =
        unsafe { bip89_tweak_key(&v, base.as_ptr(), N.as_ptr(), out2.as_mut_ptr(), &mut err) };
    assert_eq!(rc2, 102);
    assert_eq!(message(err), "scalar out of range");

    let mut bad_key = [0u8; 33];
    bad_key[0] = 0x04;
    bad_key[1..].copy_from_slice(&base[1..]);
    let mut out3 = [0u8; 33];
    let rc3 = unsafe {
        bip89_tweak_key(
            &v,
            bad_key.as_ptr(),
            t.as_ptr(),
            out3.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc3, 100);
    assert_eq!(message(err), "invalid point");
}

#[test]
fn delegator_sign_matches_rust() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let t = tweak_vector();
    let s = secret();
    let m = msg();
    let aux = [0u8; 32];
    let mut sig_out = [0u8; 64];
    let mut err: *const c_char = core::ptr::null();
    let rc = unsafe {
        bip89_delegator_sign(
            &v,
            t.as_ptr(),
            s.as_ptr(),
            m.as_ptr(),
            aux.as_ptr(),
            sig_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(sig_out, sig());

    let rust_c = RustBitcoin::new();
    assert_eq!(
        sign::delegator_sign(&rust_c, &t, &s, &m, &aux).unwrap(),
        sig_out
    );

    let base_key = rust_c.base_mul(&s).unwrap();
    let tweaked_key = tweak::tweak_key(&rust_c, &base_key, &t).unwrap();
    assert!(bip340::verify(&rust_c, &xbytes(&tweaked_key), &m, &sig_out));

    let bad_tweak = scalar_neg(&s);
    let mut sig_out2 = [0u8; 64];
    let rc2 = unsafe {
        bip89_delegator_sign(
            &v,
            bad_tweak.as_ptr(),
            s.as_ptr(),
            m.as_ptr(),
            aux.as_ptr(),
            sig_out2.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc2, 103);
    assert_eq!(message(err), "invalid secret key");
}

#[test]
fn null_pointer_code() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let key = xpub_key();
    let chain_code = xpub_cc();
    let path = [0u32, 1u32];
    let t = tweak_vector();
    let s = secret();
    let m = msg();
    let aux = [0u8; 32];
    let mut err: *const c_char = core::ptr::null();

    let mut tweak_out = [0xaau8; 32];
    let mut key_out = [0xaau8; 33];
    let mut chain_code_out = [0xaau8; 32];
    let rc = unsafe {
        bip89_compute_tweak(
            core::ptr::null(),
            key.as_ptr(),
            chain_code.as_ptr(),
            path.as_ptr(),
            path.len(),
            tweak_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
            chain_code_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);
    assert_eq!(message(err), "null pointer");
    assert_eq!(tweak_out, [0xaau8; 32]);
    assert_eq!(key_out, [0xaau8; 33]);
    assert_eq!(chain_code_out, [0xaau8; 32]);

    let mut out = [0xaau8; 33];
    let rc = unsafe {
        bip89_tweak_key(
            core::ptr::null(),
            key.as_ptr(),
            t.as_ptr(),
            out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);
    assert_eq!(message(err), "null pointer");
    assert_eq!(out, [0xaau8; 33]);

    let mut sig_out = [0xaau8; 64];
    let rc = unsafe {
        bip89_delegator_sign(
            core::ptr::null(),
            t.as_ptr(),
            s.as_ptr(),
            m.as_ptr(),
            aux.as_ptr(),
            sig_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);
    assert_eq!(message(err), "null pointer");
    assert_eq!(sig_out, [0xaau8; 64]);

    let rc = unsafe {
        bip89_tweak_key(
            &v,
            key.as_ptr(),
            t.as_ptr(),
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);

    let rc = unsafe {
        bip89_delegator_sign(
            &v,
            t.as_ptr(),
            s.as_ptr(),
            m.as_ptr(),
            aux.as_ptr(),
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);

    let mut tweak_out2 = [0xaau8; 32];
    let mut chain_code_out2 = [0xaau8; 32];
    let rc = unsafe {
        bip89_compute_tweak(
            &v,
            key.as_ptr(),
            chain_code.as_ptr(),
            path.as_ptr(),
            path.len(),
            tweak_out2.as_mut_ptr(),
            core::ptr::null_mut(),
            chain_code_out2.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);
    assert_eq!(tweak_out2, [0xaau8; 32]);
    assert_eq!(chain_code_out2, [0xaau8; 32]);

    let mut tweak_out3 = [0xaau8; 32];
    let mut key_out3 = [0xaau8; 33];
    let mut chain_code_out3 = [0xaau8; 32];
    let rc = unsafe {
        bip89_compute_tweak(
            &v,
            key.as_ptr(),
            chain_code.as_ptr(),
            core::ptr::null(),
            2,
            tweak_out3.as_mut_ptr(),
            key_out3.as_mut_ptr(),
            chain_code_out3.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, 500);
    assert_eq!(tweak_out3, [0xaau8; 32]);
    assert_eq!(key_out3, [0xaau8; 33]);
    assert_eq!(chain_code_out3, [0xaau8; 32]);
}

#[test]
fn null_callback_code() {
    let key = xpub_key();
    let chain_code = xpub_cc();
    let path = [0u32, 1u32];
    let t = tweak_vector();
    let s = secret();
    let m = msg();
    let aux = [0u8; 32];
    let mut err: *const c_char = core::ptr::null();

    let checks: [fn(&mut CryptoVtable); 4] = [
        |v| v.point_add = None,
        |v| v.sha512_final = None,
        |v| v.bip322_sign = None,
        |v| v.fill_random = None,
    ];

    for set_null in checks {
        let mut ctx = test_ctx();
        let mut v = vtable(&mut ctx);
        set_null(&mut v);

        let mut tweak_out = [0u8; 32];
        let mut key_out = [0u8; 33];
        let mut chain_code_out = [0u8; 32];
        let rc = unsafe {
            bip89_compute_tweak(
                &v,
                key.as_ptr(),
                chain_code.as_ptr(),
                path.as_ptr(),
                path.len(),
                tweak_out.as_mut_ptr(),
                key_out.as_mut_ptr(),
                chain_code_out.as_mut_ptr(),
                &mut err,
            )
        };
        assert_eq!(rc, 501);
        assert_eq!(message(err), "vtable has a null callback");

        let mut out = [0u8; 33];
        let rc =
            unsafe { bip89_tweak_key(&v, key.as_ptr(), t.as_ptr(), out.as_mut_ptr(), &mut err) };
        assert_eq!(rc, 501);
        assert_eq!(message(err), "vtable has a null callback");

        let mut sig_out = [0u8; 64];
        let rc = unsafe {
            bip89_delegator_sign(
                &v,
                t.as_ptr(),
                s.as_ptr(),
                m.as_ptr(),
                aux.as_ptr(),
                sig_out.as_mut_ptr(),
                &mut err,
            )
        };
        assert_eq!(rc, 501);
        assert_eq!(message(err), "vtable has a null callback");
    }
}

#[test]
fn blind_nonce_gen_matches_rust() {
    let rand_ = hex_vec("0F6166D1645791EAD551572348A43CA9293E02CF0ED32B17EA5E1AEC6BC41931");
    let sk = hex_arr::<32>("F22F1B584D8B5CE15ED8F561DAD077B3FB743E6AABB97DBA758AFD88852DB490");
    let pk = hex_arr::<33>("0204B445C4EF4E822DA5842965BC03CBDC865EF846774FD27ACDE063F40CD7812C");
    let extra_in = hex_vec("887BEFE686260D09F471715719B7CB2D48E4116BD346319D9C002A4FC9D82857");
    let expected_secnonce = hex_vec(
        "A4B954BBCB05059CF0ACE8BC2C82BEA5ABD0D2C39B03D7A7205DB41E9BE9CA610204B445C4EF4E822DA5\
         842965BC03CBDC865EF846774FD27ACDE063F40CD7812C",
    );
    let expected_pubnonce =
        hex_arr::<33>("0355A32C1B472EE1874924CD9A1BF2536D6A2B214413684FBDFC5B84870EFDCEF8");

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(rand_.clone()),
    };
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let mut secnonce_out = [0xaau8; 65];
    let mut secnonce_len: usize = 0;
    let mut pubnonce_out = [0u8; 33];
    let rc = unsafe {
        bip89_blind_nonce_gen(
            &v,
            sk.as_ptr(),
            pk.as_ptr(),
            extra_in.as_ptr(),
            extra_in.len(),
            secnonce_out.as_mut_ptr(),
            &mut secnonce_len,
            pubnonce_out.as_mut_ptr(),
            &mut err,
        )
    };

    assert_eq!(rc, BIP89_OK);
    assert_eq!(secnonce_len, 65);
    assert_eq!(secnonce_out.as_slice(), expected_secnonce.as_slice());
    assert_eq!(pubnonce_out, expected_pubnonce);

    let rust_c = RustBitcoin::new();
    let mut rust_rng = FixedRng::new(rand_);
    let (rust_sec, rust_pub) = blind::blind_nonce_gen(
        &rust_c,
        &mut rust_rng,
        Some(&sk),
        Some(&pk),
        Some(&extra_in),
    )
    .unwrap();
    assert_eq!(rust_sec.as_bytes(), secnonce_out.as_slice());
    assert_eq!(rust_pub, pubnonce_out);

    let rand2 = hex_vec("D4B20323E12CEC7E21B41A4FD2395844F93D4B3E9F3FED13CF3234C32702A242");
    let expected_secnonce2 =
        hex_arr::<32>("78ACDD864846BB5C18017A421E792CC771D63EDA6B63A6CDC3825F298CAC7788");
    let expected_pubnonce2 =
        hex_arr::<33>("025CA329F7676AECEAC10C29566D9C7883A661DB2574454AE491476EADEE3CD430");

    let mut ctx2 = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(rand2),
    };
    let v2 = vtable(&mut ctx2);

    let mut secnonce_out2 = [0xaau8; 65];
    let mut secnonce_len2: usize = 0;
    let mut pubnonce_out2 = [0u8; 33];
    let rc2 = unsafe {
        bip89_blind_nonce_gen(
            &v2,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            secnonce_out2.as_mut_ptr(),
            &mut secnonce_len2,
            pubnonce_out2.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert_eq!(secnonce_len2, 32);
    assert_eq!(secnonce_out2[..32], expected_secnonce2);
    assert_eq!(secnonce_out2[32..], [0u8; 33]);
    assert_eq!(pubnonce_out2, expected_pubnonce2);

    let mut secnonce_out3 = [0u8; 65];
    let mut secnonce_len3: usize = 0;
    let mut pubnonce_out3 = [0u8; 33];
    let rc3 = unsafe {
        bip89_blind_nonce_gen(
            &v2,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            4,
            secnonce_out3.as_mut_ptr(),
            &mut secnonce_len3,
            pubnonce_out3.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc3, 500);
    assert_eq!(message(err), "null pointer");
}

#[test]
fn blind_challenge_gen_matches_rust() {
    let rand = hex_vec("92950940B9C21B956D2950EA4C2CBD966D5DCF32517D2419636C3B434E7E7243");
    let msg = hex_vec("33DF4B220B36836C25198D4AFCFD25D1EE2E7B237C3021D7A0EDBA137E70958C");
    let blindpubnonce =
        hex_arr::<33>("02866A953BB982D4755FC9DCF0E09CC8EA56E2F75040DCAFE0C17A2A6FB5D4AC6E");
    let pk = hex_arr::<33>("0232D9E2657C0AA02A6E5AFF67175757832D1B3260A915970EA1CD95E2C9838B52");
    let tweaks = [
        hex_arr::<32>("7F91E8EA5D4FD39AAEB0FCDE90ABAAA8681D2610AF0FDDF132DEFBD5E1183580"),
        hex_arr::<32>("8F4ECAB71A22CDB15945BD2898DF005A8623B8DC50013F12700E678E92837406"),
        hex_arr::<32>("FD890EE6226ECA9EFB889DC1EC77B5D59FE0AF1D876C35F2CBE9F25F6B8FB760"),
    ];
    let is_xonly = [1u8, 1, 0];
    let extra_in = hex_vec("FD8AA0C64B66C38EA627FABB0CFCCE5BB905D130470101ED88771E0A62331AC9");
    let session_cap = 229usize;

    let expected_blindchallenge =
        hex_arr::<32>("B5B3A3D63771818E930E55D3F91EBF11ED16BCDB11E0F1B5DF06F636F870DFB5");
    let mut expected_session = Vec::new();
    expected_session.extend_from_slice(&pk);
    expected_session.extend_from_slice(&hex_arr::<32>(
        "545AB2AAB17406BE3270D0DFB7B13568F9ED5FAD5ABC5E9ACBAFC8D17131CC37",
    ));
    expected_session.extend_from_slice(&hex_arr::<32>(
        "AC03DF1F1DA05BFD6E01E11BD7B95E3A6A0752BBB0E31EA26251675CECCE3A15",
    ));
    expected_session.extend_from_slice(&hex_arr::<33>(
        "0367E34DAB4F1377CD8F3E7C5CD3E1E4A4D3B27BEAB9C0C0DC6717C9C52275D03B",
    ));
    for (tweak, flag) in tweaks.iter().zip([1u8, 1, 0]) {
        expected_session.extend_from_slice(tweak);
        expected_session.push(flag);
    }
    assert_eq!(expected_session.len(), session_cap);

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(rand.clone()),
    };
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let mut session_out = [0u8; 229];
    let mut session_len: usize = 0;
    let mut blindchallenge_out = [0u8; 32];
    let mut pk_parity_out = 0xaau8;
    let mut nonce_parity_out = 0xaau8;

    let rc = unsafe {
        bip89_blind_challenge_gen(
            &v,
            msg.as_ptr(),
            msg.len(),
            blindpubnonce.as_ptr(),
            pk.as_ptr(),
            tweaks.as_ptr().cast::<u8>(),
            tweaks.len(),
            is_xonly.as_ptr(),
            is_xonly.len(),
            extra_in.as_ptr(),
            extra_in.len(),
            session_out.as_mut_ptr(),
            session_out.len(),
            &mut session_len,
            blindchallenge_out.as_mut_ptr(),
            &mut pk_parity_out,
            &mut nonce_parity_out,
            &mut err,
        )
    };

    assert_eq!(rc, BIP89_OK);
    assert_eq!(session_len, session_cap);
    assert_eq!(session_out.as_slice(), expected_session.as_slice());
    assert_eq!(blindchallenge_out, expected_blindchallenge);
    assert_eq!(pk_parity_out, 1);
    assert_eq!(nonce_parity_out, 0);

    let rust_c = RustBitcoin::new();
    let mut rust_rng = FixedRng::new(rand);
    let rust_out = blind::blind_challenge_gen(
        &rust_c,
        &mut rust_rng,
        &msg,
        &blindpubnonce,
        &pk,
        &tweaks,
        &[true, true, false],
        Some(&extra_in),
    )
    .unwrap();
    assert_eq!(rust_out.blindchallenge, blindchallenge_out);
    assert!(rust_out.pk_parity);
    assert!(!rust_out.nonce_parity);

    let mut small_out = [0xaau8; 228];
    let mut small_len: usize = 0;
    let rc2 = unsafe {
        bip89_blind_challenge_gen(
            &v,
            msg.as_ptr(),
            msg.len(),
            blindpubnonce.as_ptr(),
            pk.as_ptr(),
            tweaks.as_ptr().cast::<u8>(),
            tweaks.len(),
            is_xonly.as_ptr(),
            is_xonly.len(),
            extra_in.as_ptr(),
            extra_in.len(),
            small_out.as_mut_ptr(),
            228,
            &mut small_len,
            blindchallenge_out.as_mut_ptr(),
            &mut pk_parity_out,
            &mut nonce_parity_out,
            &mut err,
        )
    };
    assert_eq!(rc2, 502);
    assert_eq!(small_len, session_cap);
    assert_eq!(small_out, [0xaau8; 228]);

    let mut null_len: usize = 0;
    let rc3 = unsafe {
        bip89_blind_challenge_gen(
            &v,
            msg.as_ptr(),
            msg.len(),
            blindpubnonce.as_ptr(),
            pk.as_ptr(),
            tweaks.as_ptr().cast::<u8>(),
            tweaks.len(),
            is_xonly.as_ptr(),
            is_xonly.len(),
            extra_in.as_ptr(),
            extra_in.len(),
            core::ptr::null_mut(),
            0,
            &mut null_len,
            blindchallenge_out.as_mut_ptr(),
            &mut pk_parity_out,
            &mut nonce_parity_out,
            &mut err,
        )
    };
    assert_eq!(rc3, 502);
    assert_eq!(null_len, session_cap);

    let mut mismatch_out = [0u8; 229];
    let mut mismatch_len: usize = 0;
    let rc4 = unsafe {
        bip89_blind_challenge_gen(
            &v,
            msg.as_ptr(),
            msg.len(),
            blindpubnonce.as_ptr(),
            pk.as_ptr(),
            tweaks.as_ptr().cast::<u8>(),
            1,
            is_xonly.as_ptr(),
            2,
            extra_in.as_ptr(),
            extra_in.len(),
            mismatch_out.as_mut_ptr(),
            mismatch_out.len(),
            &mut mismatch_len,
            blindchallenge_out.as_mut_ptr(),
            &mut pk_parity_out,
            &mut nonce_parity_out,
            &mut err,
        )
    };
    assert_eq!(rc4, 107);
    assert_eq!(message(err), "tweak count mismatch");
}

#[test]
fn blind_sign_matches_rust_and_zeroes_nonce() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let sk = blind_sign_sk();
    let mut secnonce = blind_sign_secnonce();
    let e = blind_sign_challenge();
    let mut err: *const c_char = core::ptr::null();

    let mut sig_out = [0u8; 32];
    let rc = unsafe {
        bip89_blind_sign(
            &v,
            sk.as_ptr(),
            e.as_ptr(),
            secnonce.as_mut_ptr(),
            secnonce.len(),
            1,
            0,
            sig_out.as_mut_ptr(),
            &mut err,
        )
    };

    assert_eq!(rc, BIP89_OK);
    assert_eq!(sig_out, blind_sign_signature());

    let rust_c = RustBitcoin::new();
    let mut rust_secnonce = blind::BlindSecNonce::from_bytes(&blind_sign_secnonce()).unwrap();
    let rust_sig = blind::blind_sign(&rust_c, &sk, &e, &mut rust_secnonce, true, false).unwrap();
    assert_eq!(rust_sig, sig_out);

    assert_eq!(&secnonce[..64], [0u8; 64].as_slice());
    assert_eq!(secnonce[64], 0xAA);
}

#[test]
fn blind_sign_reused_nonce_code() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let sk = blind_sign_sk();
    let mut secnonce = blind_sign_secnonce();
    let e = blind_sign_challenge();
    let mut err: *const c_char = core::ptr::null();

    let mut sig_out = [0u8; 32];
    let rc = unsafe {
        bip89_blind_sign(
            &v,
            sk.as_ptr(),
            e.as_ptr(),
            secnonce.as_mut_ptr(),
            secnonce.len(),
            1,
            0,
            sig_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut sig_out2 = [0xaau8; 32];
    let rc2 = unsafe {
        bip89_blind_sign(
            &v,
            sk.as_ptr(),
            e.as_ptr(),
            secnonce.as_mut_ptr(),
            secnonce.len(),
            1,
            0,
            sig_out2.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc2, 108);
    assert_eq!(message(err), "secret nonce already used");
    assert_eq!(sig_out2, [0xaau8; 32]);

    let mut short_secnonce = blind_sign_secnonce();
    let mut sig_out3 = [0xaau8; 32];
    let rc3 = unsafe {
        bip89_blind_sign(
            &v,
            sk.as_ptr(),
            e.as_ptr(),
            short_secnonce.as_mut_ptr(),
            64,
            1,
            0,
            sig_out3.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc3, 109);
    assert_eq!(message(err), "invalid secret nonce length");
}

#[test]
fn verify_blind_signature_matches_rust() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let pk = blind_sign_pk();
    let blindpubnonce = blind_sign_blindpubnonce();
    let e = blind_sign_challenge();
    let sig = blind_sign_signature();
    let mut err: *const c_char = core::ptr::null();

    let mut valid_out = 0xaau8;
    let rc = unsafe {
        bip89_verify_blind_signature(
            &v,
            pk.as_ptr(),
            blindpubnonce.as_ptr(),
            e.as_ptr(),
            sig.as_ptr(),
            1,
            0,
            &mut valid_out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(valid_out, 1);

    let rust_c = RustBitcoin::new();
    assert_eq!(
        blind::verify_blind_signature(&rust_c, &pk, &blindpubnonce, &e, &sig, true, false),
        Ok(true)
    );

    let bad_sig = hex_arr::<32>("9632B771A6A923FF1561B3513C4841F2D88795B05D99BC581ABCA201EED86EC5");
    let mut valid_out2 = 0xaau8;
    let rc2 = unsafe {
        bip89_verify_blind_signature(
            &v,
            pk.as_ptr(),
            blindpubnonce.as_ptr(),
            e.as_ptr(),
            bad_sig.as_ptr(),
            1,
            0,
            &mut valid_out2,
            &mut err,
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert_eq!(valid_out2, 0);
    assert_eq!(
        blind::verify_blind_signature(&rust_c, &pk, &blindpubnonce, &e, &bad_sig, true, false),
        Ok(false)
    );
}

#[test]
fn unblind_signature_matches_rust() {
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);

    let pk = hex_arr::<33>("03A1B69A6C047657AA6A0DF9ED43E5B0CA75097260F065048606D0946B2B89A6AD");
    let blindfactor =
        hex_arr::<32>("D08134A1CA8F716EE99EE69179BD939CF2DCD29D3EB1827124BAEB1364088AA9");
    let challenge =
        hex_arr::<32>("0AB1D307369FB4D994A8DEDE3D503FDC7B8AF459AECE3C69B5C22F5BFA293618");
    let pubnonce =
        hex_arr::<33>("02ED7E7EB4E886F9A9DF4E375F5F9321DCF5AA909B85A028B7EBB14F2ED80AE3BD");
    let tweak1 = hex_arr::<32>("1956DF466B657FFA287B6BFC63219BB6BF3D5A72ECE44E43E14091CBF15100BB");
    let tweak2 = hex_arr::<32>("2CB93A737A3B9A86D678DD8060ECA5443978B87BA54CFC21AE1341B47C2640B9");
    let blindsignature =
        hex_arr::<32>("6180428458B0EDA605A2D897A45784C399D310060FD0BE701DA4AE5B2EEB7A40");
    let expected_sig = hex_arr::<64>(
        "ED7E7EB4E886F9A9DF4E375F5F9321DCF5AA909B85A028B7EBB14F2ED80AE3BD1A606D2DE092BD1A05B\
         82532BDEA7F11493D00EB1109CF1EF30A8D8E2FF2721C",
    );

    let mut session = Vec::new();
    session.extend_from_slice(&pk);
    session.extend_from_slice(&blindfactor);
    session.extend_from_slice(&challenge);
    session.extend_from_slice(&pubnonce);
    session.extend_from_slice(&tweak1);
    session.push(0);
    session.extend_from_slice(&tweak2);
    session.push(1);
    assert_eq!(session.len(), 196);

    let mut err: *const c_char = core::ptr::null();
    let mut sig_out = [0u8; 64];
    let rc = unsafe {
        bip89_unblind_signature(
            &v,
            session.as_ptr(),
            session.len(),
            blindsignature.as_ptr(),
            sig_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(sig_out, expected_sig);

    let rust_c = RustBitcoin::new();
    let rust_session = blind::SessionContext {
        pk,
        blindfactor,
        challenge,
        pubnonce,
        tweaks: vec![tweak1, tweak2],
        is_xonly: vec![false, true],
    };
    assert_eq!(
        blind::unblind_signature(&rust_c, &rust_session, &blindsignature),
        Ok(sig_out)
    );

    let mut bad_pubnonce_session = session.clone();
    bad_pubnonce_session[97] = 0x04;
    let mut bad_sig_out = [0xaau8; 64];
    let rc2 = unsafe {
        bip89_unblind_signature(
            &v,
            bad_pubnonce_session.as_ptr(),
            bad_pubnonce_session.len(),
            blindsignature.as_ptr(),
            bad_sig_out.as_mut_ptr(),
            &mut err,
        )
    };
    let mut bad_rust_session = rust_session.clone();
    bad_rust_session.pubnonce[0] = 0x04;
    let rust_err =
        blind::unblind_signature(&rust_c, &bad_rust_session, &blindsignature).unwrap_err();
    assert_eq!(rc2, FfiError::Ll(rust_err).info().0);

    for len in [195usize, 129] {
        let short = &session[..len];
        let mut out = [0u8; 64];
        let rc3 = unsafe {
            bip89_unblind_signature(
                &v,
                short.as_ptr(),
                short.len(),
                blindsignature.as_ptr(),
                out.as_mut_ptr(),
                &mut err,
            )
        };
        assert_eq!(rc3, 107);
    }

    let mut bad_flag_session = session.clone();
    *bad_flag_session.last_mut().unwrap() = 2;
    let mut out = [0u8; 64];
    let rc4 = unsafe {
        bip89_unblind_signature(
            &v,
            bad_flag_session.as_ptr(),
            bad_flag_session.len(),
            blindsignature.as_ptr(),
            out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc4, 107);
    assert_eq!(message(err), "tweak count mismatch");
}

#[test]
fn blind_roundtrip_through_c() {
    let sk = blind_sign_sk();
    let pk = blind_sign_pk();
    let msg = [0x5au8; 32];

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x33; 64]),
    };
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let mut secnonce_out = [0u8; 65];
    let mut secnonce_len: usize = 0;
    let mut pubnonce_out = [0u8; 33];
    let rc = unsafe {
        bip89_blind_nonce_gen(
            &v,
            sk.as_ptr(),
            pk.as_ptr(),
            core::ptr::null(),
            0,
            secnonce_out.as_mut_ptr(),
            &mut secnonce_len,
            pubnonce_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut session_out = [0u8; 130];
    let mut session_len: usize = 0;
    let mut blindchallenge_out = [0u8; 32];
    let mut pk_parity_out = 0u8;
    let mut nonce_parity_out = 0u8;
    let rc2 = unsafe {
        bip89_blind_challenge_gen(
            &v,
            msg.as_ptr(),
            msg.len(),
            pubnonce_out.as_ptr(),
            pk.as_ptr(),
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            session_out.as_mut_ptr(),
            session_out.len(),
            &mut session_len,
            blindchallenge_out.as_mut_ptr(),
            &mut pk_parity_out,
            &mut nonce_parity_out,
            &mut err,
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert_eq!(session_len, 130);

    let mut sig_out = [0u8; 32];
    let rc3 = unsafe {
        bip89_blind_sign(
            &v,
            sk.as_ptr(),
            blindchallenge_out.as_ptr(),
            secnonce_out.as_mut_ptr(),
            secnonce_len,
            pk_parity_out,
            nonce_parity_out,
            sig_out.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc3, BIP89_OK);

    let mut valid_out = 0u8;
    let rc4 = unsafe {
        bip89_verify_blind_signature(
            &v,
            pk.as_ptr(),
            pubnonce_out.as_ptr(),
            blindchallenge_out.as_ptr(),
            sig_out.as_ptr(),
            pk_parity_out,
            nonce_parity_out,
            &mut valid_out,
            &mut err,
        )
    };
    assert_eq!(rc4, BIP89_OK);
    assert_eq!(valid_out, 1);

    let mut final_sig = [0u8; 64];
    let rc5 = unsafe {
        bip89_unblind_signature(
            &v,
            session_out.as_ptr(),
            session_len,
            sig_out.as_ptr(),
            final_sig.as_mut_ptr(),
            &mut err,
        )
    };
    assert_eq!(rc5, BIP89_OK);

    let rust_c = RustBitcoin::new();
    assert!(bip340::verify(&rust_c, &xbytes(&pk), &msg, &final_sig));
}

#[test]
fn derive_bundle_matches_rust() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    assert!(rust_c.descriptor_policy(&w.descriptor).len() > 256);

    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    for (keychain, index) in [(0u32, 5u32), (1u32, 3u32)] {
        let mut out = [0xaau8; 260];
        let mut out_len: usize = 0;
        let rc = unsafe {
            bip89_derive_bundle(
                &v,
                &dv,
                keychain,
                index,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut err,
            )
        };
        assert_eq!(rc, BIP89_OK);
        assert_eq!(out_len, 260);
        let expected = bundle::derive_bundle(&rust_c, &w.descriptor, keychain, index)
            .unwrap()
            .to_bytes();
        assert_eq!(&out[..out_len], expected.as_slice());
    }

    let mut out = [0u8; 260];
    let mut out_len: usize = 0;
    let rc = unsafe {
        bip89_derive_bundle(
            &v,
            &dv,
            2,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, 117);
    assert_eq!(message(err), "invalid keychain");

    let mut out2 = [0u8; 260];
    let mut out_len2: usize = 0;
    let rc2 = unsafe {
        bip89_derive_bundle(
            &v,
            &dv,
            0,
            2147483648u32,
            out2.as_mut_ptr(),
            out2.len(),
            &mut out_len2,
            &mut err,
        )
    };
    assert_eq!(rc2, 105);
}

#[test]
fn derive_bundle_buffer_too_small() {
    let w = wallet();
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let mut small = [0xaau8; 259];
    let mut small_len: usize = 0;
    let rc = unsafe {
        bip89_derive_bundle(
            &v,
            &dv,
            1,
            3,
            small.as_mut_ptr(),
            small.len(),
            &mut small_len,
            &mut err,
        )
    };
    assert_eq!(rc, 502);
    assert_eq!(message(err), "output buffer too small");
    assert_eq!(small_len, 260);
    assert_eq!(small, [0xaau8; 259]);

    let mut null_len: usize = 0;
    let rc2 = unsafe {
        bip89_derive_bundle(
            &v,
            &dv,
            1,
            3,
            core::ptr::null_mut(),
            0,
            &mut null_len,
            &mut err,
        )
    };
    assert_eq!(rc2, 502);
    assert_eq!(null_len, 260);
}

#[test]
fn sign_tree_root_matches_rust() {
    let w = wallet();
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let signed = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 1);

    let rust_c = RustBitcoin::new();
    let expected = record::sign_tree_root(&rust_c, &w.descriptor, &OWNER1_SECRET, 1, 0).unwrap();
    assert_eq!(signed, expected);
    assert_eq!(
        record::verify_root(&rust_c, &w.template, &signed, RootPolicy::RequireSignature),
        Ok(())
    );

    let mut root_out = [0xaau8; 32];
    let mut key_out = [0xaau8; 33];
    let mut branch_tweak_out = [0xaau8; 32];
    let mut signature_len = 0usize;
    let rc = unsafe {
        bip89_sign_tree_root(
            &v,
            &dv,
            OWNER1_SECRET.as_ptr(),
            1,
            0,
            root_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
            branch_tweak_out.as_mut_ptr(),
            core::ptr::null_mut(),
            0,
            &mut signature_len,
            &mut err,
        )
    };
    assert_eq!(rc, 502);
    assert_eq!(message(err), "output buffer too small");
    assert_eq!(signature_len, root_signature(&expected).signature.len());
    assert_eq!(root_out, [0xaau8; 32]);
    assert_eq!(key_out, [0xaau8; 33]);
    assert_eq!(branch_tweak_out, [0xaau8; 32]);

    let outsider_secret = [0x05u8; 32];
    let mut signature_out = [0u8; 256];
    let rc2 = unsafe {
        bip89_sign_tree_root(
            &v,
            &dv,
            outsider_secret.as_ptr(),
            1,
            0,
            root_out.as_mut_ptr(),
            key_out.as_mut_ptr(),
            branch_tweak_out.as_mut_ptr(),
            signature_out.as_mut_ptr(),
            signature_out.len(),
            &mut signature_len,
            &mut err,
        )
    };
    assert_eq!(rc2, 131);
    assert_eq!(message(err), "secret key not in template");
    assert_eq!(
        record::sign_tree_root(&rust_c, &w.descriptor, &outsider_secret, 1, 0),
        Err(Error::NotParticipant)
    );
}

#[test]
fn build_tree_and_proof_match_rust() {
    let w = wallet();
    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x5a; 32]),
    };
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let signed = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 1);

    let mut root_out = [0u8; 32];
    let mut tree: *mut Tree = core::ptr::null_mut();
    let rc = unsafe { bip89_build_tree(&v, &dv, 1, 0, root_out.as_mut_ptr(), &mut tree, &mut err) };
    assert_eq!(rc, BIP89_OK);
    assert!(!tree.is_null());

    let rust_c = RustBitcoin::new();
    let expected_tree = record::build_tree(&rust_c, &w.descriptor, 1, 0).unwrap();
    assert_eq!(root_out, expected_tree.root);
    assert_eq!(root_out, signed.root);

    let mut proof_out = [0u8; 289];
    let rc2 = unsafe { bip89_tree_proof(tree, 1, 3, proof_out.as_mut_ptr(), &mut err) };
    assert_eq!(rc2, BIP89_OK);
    let expected_proof = expected_tree.proof(1, 3).unwrap().to_bytes();
    assert_eq!(proof_out, expected_proof);

    let mut proof_out2 = [0u8; 289];
    let rc3 = unsafe { bip89_tree_proof(tree, 1, 256, proof_out2.as_mut_ptr(), &mut err) };
    assert_eq!(rc3, 503);
    assert_eq!(message(err), "index out of bounds");

    let rc4 = unsafe { bip89_tree_proof(tree, 0, 3, proof_out2.as_mut_ptr(), &mut err) };
    assert_eq!(rc4, 503);
    assert_eq!(message(err), "index out of bounds");

    let rc5 =
        unsafe { bip89_tree_proof(core::ptr::null(), 1, 3, proof_out2.as_mut_ptr(), &mut err) };
    assert_eq!(rc5, 500);

    unsafe { bip89_tree_free(tree) };
    unsafe { bip89_tree_free(core::ptr::null_mut()) };

    let mut root_out3 = [0xaau8; 32];
    let mut out_tree: *mut Tree = core::ptr::null_mut();
    let rc6 = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            1,
            2147483393,
            root_out3.as_mut_ptr(),
            &mut out_tree,
            &mut err,
        )
    };
    assert_eq!(rc6, 118);
    assert!(out_tree.is_null());

    let mut root_out4 = [0u8; 32];
    let mut out_tree2: *mut Tree = core::ptr::null_mut();
    let rc7 = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            2,
            0,
            root_out4.as_mut_ptr(),
            &mut out_tree2,
            &mut err,
        )
    };
    assert_eq!(rc7, 117);
}

#[test]
fn descriptor_vtable_failures() {
    let w = wallet();
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let mut out = [0u8; 260];
    let mut out_len: usize = 0;
    let rc = unsafe {
        bip89_derive_bundle(
            &v,
            core::ptr::null(),
            0,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, 500);

    let mut desc_ctx = DescCtx::new(&w.descriptor);

    let mut dv_no_xpub = descriptor_vtable(&mut desc_ctx);
    dv_no_xpub.xpubs = None;
    let rc2 = unsafe {
        bip89_derive_bundle(
            &v,
            &dv_no_xpub,
            0,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc2, 501);
    assert_eq!(message(err), "vtable has a null callback");

    let mut dv_failing_policy = descriptor_vtable(&mut desc_ctx);
    dv_failing_policy.policy_bytes = Some(failing_policy_bytes);
    let rc3 = unsafe {
        bip89_derive_bundle(
            &v,
            &dv_failing_policy,
            0,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc3, 116);
    assert_eq!(message(err), "template rejected or callback failed");

    let mut dv_mismatched_policy = descriptor_vtable(&mut desc_ctx);
    dv_mismatched_policy.policy_bytes = Some(mismatched_policy_bytes);
    let rc4 = unsafe {
        bip89_derive_bundle(
            &v,
            &dv_mismatched_policy,
            0,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc4, 116);
    assert_eq!(message(err), "template rejected or callback failed");

    let mut dv_bad_branch = descriptor_vtable(&mut desc_ctx);
    dv_bad_branch.xpubs = Some(bad_branch_xpubs);
    let rc5 = unsafe {
        bip89_derive_bundle(
            &v,
            &dv_bad_branch,
            0,
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc5, 500);
    assert_eq!(message(err), "null pointer");
}

#[test]
fn input_verification_matches_rust() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let tpl = w.template.clone();
    let mut tpl_ctx = TplCtx::new(&tpl);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let bundle05 = bundle::derive_bundle(&rust_c, &w.descriptor, 0, 5).unwrap();
    let pairs05 =
        verify::tweaked_keys(&rust_c, &rust_c.template_base_keys(&tpl), &bundle05).unwrap();
    let script05 = rust_c.template_script_pubkey(&tpl, &pairs05).unwrap();
    let bundle_bytes05 = bundle05.to_bytes();

    let mut valid_out = 0xaau8;
    let rc = unsafe {
        bip89_input_verification(
            &v,
            &tv,
            script05.as_ptr(),
            script05.len(),
            bundle_bytes05.as_ptr(),
            bundle_bytes05.len(),
            &mut valid_out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(valid_out, 1);
    assert_eq!(
        verify::input_verification(&rust_c, &tpl, &script05, &bundle05),
        Ok(true)
    );

    let bundle06 = bundle::derive_bundle(&rust_c, &w.descriptor, 0, 6).unwrap();
    let pairs06 =
        verify::tweaked_keys(&rust_c, &rust_c.template_base_keys(&tpl), &bundle06).unwrap();
    let script06 = rust_c.template_script_pubkey(&tpl, &pairs06).unwrap();

    let mut valid_out2 = 0xaau8;
    let rc2 = unsafe {
        bip89_input_verification(
            &v,
            &tv,
            script06.as_ptr(),
            script06.len(),
            bundle_bytes05.as_ptr(),
            bundle_bytes05.len(),
            &mut valid_out2,
            &mut err,
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert_eq!(valid_out2, 0);
    assert_eq!(
        verify::input_verification(&rust_c, &tpl, &script06, &bundle05),
        Ok(false)
    );
}

#[test]
fn change_output_verification_matches_rust() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let tpl = w.template.clone();
    let mut tpl_ctx = TplCtx::new(&tpl);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let bundle13 = bundle::derive_bundle(&rust_c, &w.descriptor, 1, 3).unwrap();
    let pairs13 =
        verify::tweaked_keys(&rust_c, &rust_c.template_base_keys(&tpl), &bundle13).unwrap();
    let script13 = rust_c.template_script_pubkey(&tpl, &pairs13).unwrap();
    let bundle_bytes13 = bundle13.to_bytes();

    let mut valid_out = 0xaau8;
    let rc = unsafe {
        bip89_change_output_verification(
            &v,
            &tv,
            script13.as_ptr(),
            script13.len(),
            bundle_bytes13.as_ptr(),
            bundle_bytes13.len(),
            &mut valid_out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(valid_out, 1);

    let mut bad_script = script13.clone();
    let last = bad_script.len() - 1;
    bad_script[last] ^= 0x01;

    let mut valid_out2 = 0xaau8;
    let rc2 = unsafe {
        bip89_change_output_verification(
            &v,
            &tv,
            bad_script.as_ptr(),
            bad_script.len(),
            bundle_bytes13.as_ptr(),
            bundle_bytes13.len(),
            &mut valid_out2,
            &mut err,
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert_eq!(valid_out2, 0);
    assert_eq!(
        verify::change_output_verification(&rust_c, &tpl, &bad_script, &bundle13),
        Ok(false)
    );
}

#[test]
fn verification_bundle_errors() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let tpl = w.template.clone();
    let mut tpl_ctx = TplCtx::new(&tpl);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let bundle13 = bundle::derive_bundle(&rust_c, &w.descriptor, 1, 3).unwrap();
    let pairs13 =
        verify::tweaked_keys(&rust_c, &rust_c.template_base_keys(&tpl), &bundle13).unwrap();
    let script13 = rust_c.template_script_pubkey(&tpl, &pairs13).unwrap();
    let bundle_bytes13 = bundle13.to_bytes();

    let short_bundle = &bundle_bytes13[65..];
    let mut valid_out = 0xaau8;
    let rc = unsafe {
        bip89_input_verification(
            &v,
            &tv,
            script13.as_ptr(),
            script13.len(),
            short_bundle.as_ptr(),
            short_bundle.len(),
            &mut valid_out,
            &mut err,
        )
    };
    assert_eq!(rc, 114);
    assert_eq!(message(err), "template key has no tweak");
    let short_rust = Bundle::from_bytes(short_bundle).unwrap();
    assert_eq!(
        verify::input_verification(&rust_c, &tpl, &script13, &short_rust),
        Err(Error::MissingTweak)
    );

    let g = hex_arr::<33>(G);
    let mut extra_entries = bundle13.entries().to_vec();
    extra_entries.push(Entry {
        key: g,
        tweak: [0x01; 32],
    });
    let extra_bundle = Bundle::new(extra_entries).unwrap();
    let extra_bytes = extra_bundle.to_bytes();

    let rc2 = unsafe {
        bip89_input_verification(
            &v,
            &tv,
            script13.as_ptr(),
            script13.len(),
            extra_bytes.as_ptr(),
            extra_bytes.len(),
            &mut valid_out,
            &mut err,
        )
    };
    assert_eq!(rc2, 115);
    assert_eq!(message(err), "bundle key not in template");
    assert_eq!(
        verify::input_verification(&rust_c, &tpl, &script13, &extra_bundle),
        Err(Error::ExtraTweak)
    );

    let short_len = &bundle_bytes13[..64];
    let mut valid_out3 = 0xaau8;
    let rc3 = unsafe {
        bip89_input_verification(
            &v,
            &tv,
            script13.as_ptr(),
            script13.len(),
            short_len.as_ptr(),
            short_len.len(),
            &mut valid_out3,
            &mut err,
        )
    };
    assert_eq!(rc3, 113);
    assert_eq!(message(err), "invalid bundle entry length");

    let mut tv_failing = template_vtable(&mut tpl_ctx);
    tv_failing.script_pubkey = Some(failing_script_pubkey);
    let mut valid_out4 = 0xaau8;
    let rc4 = unsafe {
        bip89_input_verification(
            &v,
            &tv_failing,
            script13.as_ptr(),
            script13.len(),
            bundle_bytes13.as_ptr(),
            bundle_bytes13.len(),
            &mut valid_out4,
            &mut err,
        )
    };
    assert_eq!(rc4, 116);
    assert_eq!(message(err), "template rejected or callback failed");

    let rc5 = unsafe {
        bip89_input_verification(
            &v,
            &tv,
            script13.as_ptr(),
            script13.len(),
            bundle_bytes13.as_ptr(),
            bundle_bytes13.len(),
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc5, 500);
    assert_eq!(message(err), "null pointer");

    let mut valid_out6 = 0xaau8;
    let rc6 = unsafe {
        bip89_input_verification(
            &v,
            core::ptr::null(),
            script13.as_ptr(),
            script13.len(),
            bundle_bytes13.as_ptr(),
            bundle_bytes13.len(),
            &mut valid_out6,
            &mut err,
        )
    };
    assert_eq!(rc6, 500);
    assert_eq!(message(err), "null pointer");

    let mut tv_no_leaf = template_vtable(&mut tpl_ctx);
    tv_no_leaf.leaf_hashes = None;
    let mut valid_out7 = 0xaau8;
    let rc7 = unsafe {
        bip89_input_verification(
            &v,
            &tv_no_leaf,
            script13.as_ptr(),
            script13.len(),
            bundle_bytes13.as_ptr(),
            bundle_bytes13.len(),
            &mut valid_out7,
            &mut err,
        )
    };
    assert_eq!(rc7, 501);
    assert_eq!(message(err), "vtable has a null callback");
}

#[test]
fn template_adapter_matches_tr_template() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let tpl = w.template.clone();
    let mut tpl_ctx = TplCtx::new(&tpl);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let b = unsafe { VtableBackend::new(&v) }.unwrap();

    let adapter = unsafe { VtableTemplate::new(&tv) }.unwrap();
    assert_eq!(
        b.template_base_keys(&adapter),
        rust_c.template_base_keys(&tpl)
    );
    assert_eq!(b.template_base_keys(&adapter).len(), 4);
    assert_eq!(b.template_bytes(&adapter), rust_c.template_bytes(&tpl));

    let bundle05 = bundle::derive_bundle(&rust_c, &w.descriptor, 0, 5).unwrap();
    let pairs = verify::tweaked_keys(&rust_c, &rust_c.template_base_keys(&tpl), &bundle05).unwrap();
    let delegator_base = rust_c.base_mul(&DELEGATOR_SECRET).unwrap();
    let d = pairs
        .iter()
        .find(|(base, _)| *base == delegator_base)
        .unwrap()
        .1;

    let expected = rust_c.template_leaf_hashes(&tpl, &pairs, &d).unwrap();
    assert!(!expected.is_empty());
    assert_eq!(
        b.template_leaf_hashes(&adapter, &pairs, &d).unwrap(),
        expected
    );

    let g = hex_arr::<33>(G);
    assert_eq!(
        b.template_leaf_hashes(&adapter, &pairs, &g).unwrap(),
        Vec::<[u8; 32]>::new()
    );

    let mut tv20 = template_vtable(&mut tpl_ctx);
    tv20.leaf_hashes = Some(twenty_leaf_hashes);
    let adapter20 = unsafe { VtableTemplate::new(&tv20) }.unwrap();
    let expected20: Vec<[u8; 32]> = (0u8..20).map(|i| [i; 32]).collect();
    assert_eq!(
        b.template_leaf_hashes(&adapter20, &pairs, &d).unwrap(),
        expected20
    );

    let mut tv_mismatch = template_vtable(&mut tpl_ctx);
    tv_mismatch.leaf_hashes = Some(mismatched_leaf_hashes);
    let adapter_mismatch = unsafe { VtableTemplate::new(&tv_mismatch) }.unwrap();
    assert_eq!(
        b.template_leaf_hashes(&adapter_mismatch, &pairs, &d),
        Err(Error::Template)
    );

    let mut tv_desc = template_vtable(&mut tpl_ctx);
    tv_desc.base_keys = Some(descending_base_keys);
    assert!(matches!(
        unsafe { VtableTemplate::new(&tv_desc) },
        Err(FfiError::Ll(Error::Template))
    ));
}

#[test]
fn register_through_c() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let tpl = w.template.clone();
    let mut tpl_ctx = TplCtx::new(&tpl);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let [receive, change] = signed_roots(&rust_c, &w);
    let c_receive = ffi_root_record(&receive);
    let c_change = ffi_root_record(&change);
    let mut out: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_receive,
            &c_change,
            &mut out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert!(!out.is_null());
    unsafe { bip89_registration_free(out) };
    unsafe { bip89_registration_free(core::ptr::null_mut()) };

    let mut out2: *mut RegistrationHandle = core::ptr::null_mut();
    let rc2 = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_change,
            &c_receive,
            &mut out2,
            &mut err,
        )
    };
    assert_eq!(rc2, 117);
    assert_eq!(message(err), "invalid keychain");
    assert!(out2.is_null());
    assert!(matches!(
        delegator::register(
            &rust_c,
            tpl.clone(),
            RootPolicy::RequireSignature,
            &change,
            &receive
        ),
        Err(Error::InvalidKeychain)
    ));

    let mut forged_signature = root_signature(&change).signature;
    // the first byte of the Schnorr signature, after the item count and its length
    forged_signature[2] ^= 0x01;
    let forged_change = FfiRootRecord {
        signature: forged_signature.as_ptr(),
        signature_len: forged_signature.len(),
        ..ffi_root_record(&change)
    };
    let mut out3: *mut RegistrationHandle = core::ptr::null_mut();
    let rc3 = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_receive,
            &forged_change,
            &mut out3,
            &mut err,
        )
    };
    assert_eq!(rc3, 121);
    assert_eq!(message(err), "invalid root signature");
    assert!(out3.is_null());

    let mut tv_zero = template_vtable(&mut tpl_ctx);
    tv_zero.base_keys = Some(zero_base_keys);
    let mut out4: *mut RegistrationHandle = core::ptr::null_mut();
    let rc4 = unsafe {
        bip89_register(
            &v,
            &tv_zero,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_receive,
            &c_change,
            &mut out4,
            &mut err,
        )
    };
    assert_eq!(rc4, 116);
    assert_eq!(message(err), "template rejected or callback failed");

    let mut tv_desc = template_vtable(&mut tpl_ctx);
    tv_desc.base_keys = Some(descending_base_keys);
    let mut out5: *mut RegistrationHandle = core::ptr::null_mut();
    let rc5 = unsafe {
        bip89_register(
            &v,
            &tv_desc,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_receive,
            &c_change,
            &mut out5,
            &mut err,
        )
    };
    assert_eq!(rc5, 116);
    assert_eq!(message(err), "template rejected or callback failed");

    let rc6 = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_receive,
            &c_change,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc6, 500);
    assert_eq!(message(err), "null pointer");

    let mut out7: *mut RegistrationHandle = core::ptr::null_mut();
    let rc7 = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            core::ptr::null(),
            &c_change,
            &mut out7,
            &mut err,
        )
    };
    assert_eq!(rc7, 500);
    assert!(out7.is_null());

    let mut out8: *mut RegistrationHandle = core::ptr::null_mut();
    let rc8 = unsafe { bip89_register(&v, &tv, 2, &c_receive, &c_change, &mut out8, &mut err) };
    assert_eq!(rc8, 504);
    assert_eq!(message(err), "invalid root policy");
    assert!(out8.is_null());
}

#[test]
fn register_unsigned_roots_through_c() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let mut tpl_ctx = TplCtx::new(&w.template);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let [receive, change] = unsigned_roots(&rust_c, &w);
    let c_receive = ffi_root_record(&receive);
    let c_change = ffi_root_record(&change);
    assert!(c_receive.signature.is_null());
    assert_eq!(c_receive.signature_len, 0);

    let mut out: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &c_receive,
            &c_change,
            &mut out,
            &mut err,
        )
    };
    assert_eq!(rc, 142);
    assert_eq!(message(err), "root signature missing");
    assert!(out.is_null());

    let rc2 = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_ALLOW_UNSIGNED,
            &c_receive,
            &c_change,
            &mut out,
            &mut err,
        )
    };
    assert_eq!(rc2, BIP89_OK);
    assert!(!out.is_null());

    let next = record::tree_root(&rust_c, &w.descriptor, 0, 256).unwrap();
    let rc3 = unsafe { bip89_registration_record_root(&v, out, &ffi_root_record(&next), &mut err) };
    assert_eq!(rc3, BIP89_OK);

    unsafe { bip89_registration_free(out) };
}

#[test]
fn registration_record_root_through_c() {
    let w = wallet();
    let rust_c = RustBitcoin::new();
    let mut tpl_ctx = TplCtx::new(&w.template);
    let tv = template_vtable(&mut tpl_ctx);
    let mut ctx = test_ctx();
    let v = vtable(&mut ctx);
    let mut err: *const c_char = core::ptr::null();

    let [receive, change] = signed_roots(&rust_c, &w);
    let mut reg: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &ffi_root_record(&receive),
            &ffi_root_record(&change),
            &mut reg,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let next = record::sign_tree_root(&rust_c, &w.descriptor, &OWNER1_SECRET, 0, 256).unwrap();
    let rc1 = unsafe { bip89_registration_record_root(&v, reg, &ffi_root_record(&next), &mut err) };
    assert_eq!(rc1, BIP89_OK);

    let outsider = record::RootRecord {
        signature: Some(record::RootSignature {
            key: rust_c.base_mul(&[0x05u8; 32]).unwrap(),
            ..root_signature(&next)
        }),
        ..next.clone()
    };
    let rc2 =
        unsafe { bip89_registration_record_root(&v, reg, &ffi_root_record(&outsider), &mut err) };
    assert_eq!(rc2, 131);
    assert_eq!(message(err), "secret key not in template");

    let other_signature = record::RootRecord {
        signature: Some(record::RootSignature {
            signature: root_signature(&change).signature,
            ..root_signature(&next)
        }),
        ..next.clone()
    };
    let rc3 = unsafe {
        bip89_registration_record_root(&v, reg, &ffi_root_record(&other_signature), &mut err)
    };
    assert_eq!(rc3, 121);
    assert_eq!(message(err), "invalid root signature");

    let rc4 = unsafe {
        bip89_registration_record_root(&v, core::ptr::null_mut(), &ffi_root_record(&next), &mut err)
    };
    assert_eq!(rc4, 500);
    let rc5 = unsafe { bip89_registration_record_root(&v, reg, core::ptr::null(), &mut err) };
    assert_eq!(rc5, 500);
    assert_eq!(message(err), "null pointer");

    unsafe { bip89_registration_free(reg) };
}

#[test]
fn spend_flow_matches_rust() {
    let w = wallet();
    let rust_c = RustBitcoin::new();

    let mut rust_rng = FixedRng::new(vec![0x5a; 96]);
    let trees_rust = [
        record::build_tree(&rust_c, &w.descriptor, 0, 0).unwrap(),
        record::build_tree(&rust_c, &w.descriptor, 1, 0).unwrap(),
    ];
    let (rust_inputs, rust_outputs) = standard_lists();
    let mut psbt_rust = spend_psbt(&w);
    prepare(
        &rust_c,
        &w.descriptor,
        &trees_rust,
        &rust_inputs,
        &rust_outputs,
        &mut psbt_rust,
    )
    .unwrap();
    let [receive_rust, change_rust] = signed_roots(&rust_c, &w);
    let reg_rust = delegator::register(
        &rust_c,
        w.template.clone(),
        RootPolicy::RequireSignature,
        &receive_rust,
        &change_rust,
    )
    .unwrap();
    assert_eq!(
        delegator::verify_spend(&rust_c, &reg_rust, &psbt_rust),
        Ok(31_000)
    );
    assert_eq!(
        delegator::sign_spend(
            &rust_c,
            &mut rust_rng,
            &reg_rust,
            &DELEGATOR_SECRET,
            &mut psbt_rust
        ),
        Ok(31_000)
    );

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x5a; 96]),
    };
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let receive = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 0);
    let change = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 1);
    assert_eq!(receive, receive_rust);
    assert_eq!(change, change_rust);

    let mut tree0_root = [0u8; 32];
    let mut tree0_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            0,
            0,
            tree0_root.as_mut_ptr(),
            &mut tree0_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    let mut tree1_root = [0u8; 32];
    let mut tree1_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            1,
            0,
            tree1_root.as_mut_ptr(),
            &mut tree1_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let trees: [*const Tree; 2] = [tree0_c, tree1_c];
    let c_inputs = [FfiOwned {
        psbt_index: 0,
        keychain: 0,
        index: 5,
    }];
    let c_outputs = [
        FfiOwned {
            psbt_index: 1,
            keychain: 1,
            index: 3,
        },
        FfiOwned {
            psbt_index: 2,
            keychain: 0,
            index: 9,
        },
    ];

    let mut psbt_ctx = PsbtCtx::new(spend_psbt(&w));
    let pv = psbt_vtable(&mut psbt_ctx);
    let mut index_out = usize::MAX;
    let rc = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            trees.as_ptr(),
            trees.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv,
            &mut index_out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut tv_ctx = TplCtx::new(&w.template);
    let tv = template_vtable(&mut tv_ctx);
    let mut reg: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &ffi_root_record(&receive),
            &ffi_root_record(&change),
            &mut reg,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut outflow = 0u64;
    let rc = unsafe {
        bip89_delegator_verify_spend(&v, reg, &pv, &mut outflow, &mut index_out, &mut err)
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(outflow, 31_000);

    let mut outflow2 = 0u64;
    let rc = unsafe {
        bip89_delegator_sign_spend(
            &v,
            reg,
            &pv,
            DELEGATOR_SECRET.as_ptr(),
            &mut outflow2,
            &mut index_out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    assert_eq!(outflow2, 31_000);

    assert_eq!(psbt_ctx.psbt, psbt_rust);
    assert!(!psbt_ctx.psbt.inputs[0].tap_script_sigs.is_empty());

    unsafe { bip89_tree_free(tree0_c) };
    unsafe { bip89_tree_free(tree1_c) };
    unsafe { bip89_registration_free(reg) };
}

#[test]
fn forged_change_refused_through_c() {
    let w = wallet();
    let rust_c = RustBitcoin::new();

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x5a; 96]),
    };
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let receive = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 0);
    let change = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 1);

    let mut tree0_root = [0u8; 32];
    let mut tree0_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            0,
            0,
            tree0_root.as_mut_ptr(),
            &mut tree0_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    let mut tree1_root = [0u8; 32];
    let mut tree1_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            1,
            0,
            tree1_root.as_mut_ptr(),
            &mut tree1_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let trees: [*const Tree; 2] = [tree0_c, tree1_c];
    let c_inputs = [FfiOwned {
        psbt_index: 0,
        keychain: 0,
        index: 5,
    }];
    let c_outputs = [
        FfiOwned {
            psbt_index: 1,
            keychain: 1,
            index: 3,
        },
        FfiOwned {
            psbt_index: 2,
            keychain: 0,
            index: 9,
        },
    ];

    let mut psbt_ctx = PsbtCtx::new(spend_psbt(&w));
    let pv = psbt_vtable(&mut psbt_ctx);
    let mut idx = usize::MAX;
    let rc = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            trees.as_ptr(),
            trees.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv,
            &mut idx,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut tv_ctx = TplCtx::new(&w.template);
    let tv = template_vtable(&mut tv_ctx);
    let mut reg: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &ffi_root_record(&receive),
            &ffi_root_record(&change),
            &mut reg,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let template = &w.template;
    let base = rust_c.template_base_keys(template);
    let genuine = bundle::derive_bundle(&rust_c, &w.descriptor, 1, 3).unwrap();
    let entries = vec![
        Entry {
            key: base[0],
            tweak: [0x41; 32],
        },
        Entry {
            key: base[1],
            tweak: [0x42; 32],
        },
        Entry {
            key: base[2],
            tweak: [0x43; 32],
        },
        Entry {
            key: base[3],
            tweak: genuine.tweak(&base[3]).unwrap(),
        },
    ];
    let forged = Bundle::new(entries).unwrap();
    let forged_script = rust_c
        .template_script_pubkey(
            template,
            &verify::tweaked_keys(&rust_c, &base, &forged).unwrap(),
        )
        .unwrap();

    psbt_ctx.psbt.unsigned_tx.output[1].script_pubkey = ScriptBuf::from_bytes(forged_script);
    rust_c
        .set_output_bundle(&mut psbt_ctx.psbt, 1, &forged)
        .unwrap();

    let tree1_check = record::build_tree(&rust_c, &w.descriptor, 1, 0).unwrap();
    rust_c
        .set_output_proof(&mut psbt_ctx.psbt, 1, &tree1_check.proof(1, 4).unwrap())
        .unwrap();

    let mut outflow = u64::MAX;
    let mut verify_idx = usize::MAX;
    let rc = unsafe {
        bip89_delegator_verify_spend(&v, reg, &pv, &mut outflow, &mut verify_idx, &mut err)
    };
    assert_eq!(rc, 122);
    assert_eq!(message(err), "bundle not committed in tree");
    assert_eq!(outflow, u64::MAX);
    assert_eq!(verify_idx, usize::MAX);

    let mut outflow2 = u64::MAX;
    let mut sign_idx = usize::MAX;
    let rc2 = unsafe {
        bip89_delegator_sign_spend(
            &v,
            reg,
            &pv,
            DELEGATOR_SECRET.as_ptr(),
            &mut outflow2,
            &mut sign_idx,
            &mut err,
        )
    };
    assert_eq!(rc2, 122);
    assert!(psbt_ctx.psbt.inputs[0].tap_script_sigs.is_empty());

    unsafe { bip89_tree_free(tree0_c) };
    unsafe { bip89_tree_free(tree1_c) };
    unsafe { bip89_registration_free(reg) };
}

#[test]
fn missing_proof_index_through_c() {
    let w = wallet();

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x5a; 96]),
    };
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let receive = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 0);
    let change = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 1);

    let mut tree0_root = [0u8; 32];
    let mut tree0_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            0,
            0,
            tree0_root.as_mut_ptr(),
            &mut tree0_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    let mut tree1_root = [0u8; 32];
    let mut tree1_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            1,
            0,
            tree1_root.as_mut_ptr(),
            &mut tree1_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let trees: [*const Tree; 2] = [tree0_c, tree1_c];
    let c_inputs = [FfiOwned {
        psbt_index: 0,
        keychain: 0,
        index: 5,
    }];
    let c_outputs = [
        FfiOwned {
            psbt_index: 1,
            keychain: 1,
            index: 3,
        },
        FfiOwned {
            psbt_index: 2,
            keychain: 0,
            index: 9,
        },
    ];

    let mut psbt_ctx = PsbtCtx::new(spend_psbt(&w));
    let pv = psbt_vtable(&mut psbt_ctx);
    let mut idx = usize::MAX;
    let rc = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            trees.as_ptr(),
            trees.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv,
            &mut idx,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut tv_ctx = TplCtx::new(&w.template);
    let tv = template_vtable(&mut tv_ctx);
    let mut reg: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &ffi_root_record(&receive),
            &ffi_root_record(&change),
            &mut reg,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    psbt_ctx.psbt.outputs[1]
        .proprietary
        .retain(|key, _| key.subtype != SUBTYPE_PROOF);

    let mut outflow = 0u64;
    let mut verify_idx = usize::MAX;
    let rc = unsafe {
        bip89_delegator_verify_spend(&v, reg, &pv, &mut outflow, &mut verify_idx, &mut err)
    };
    assert_eq!(rc, 129);
    assert_eq!(message(err), "output proof missing");
    assert_eq!(verify_idx, 1);

    let mut outflow2 = 0u64;
    let rc2 = unsafe {
        bip89_delegator_verify_spend(&v, reg, &pv, &mut outflow2, core::ptr::null_mut(), &mut err)
    };
    assert_eq!(rc2, 129);

    unsafe { bip89_tree_free(tree0_c) };
    unsafe { bip89_tree_free(tree1_c) };
    unsafe { bip89_registration_free(reg) };
}

#[test]
fn prepare_errors_through_c() {
    let w = wallet();
    let rust_c = RustBitcoin::new();

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x5a; 96]),
    };
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let mut tree0_root = [0u8; 32];
    let mut tree0_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            0,
            0,
            tree0_root.as_mut_ptr(),
            &mut tree0_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let c_inputs = [FfiOwned {
        psbt_index: 0,
        keychain: 0,
        index: 5,
    }];
    let c_outputs = [
        FfiOwned {
            psbt_index: 1,
            keychain: 1,
            index: 3,
        },
        FfiOwned {
            psbt_index: 2,
            keychain: 0,
            index: 9,
        },
    ];

    let tree0_only: [*const Tree; 1] = [tree0_c];
    let mut psbt_ctx1 = PsbtCtx::new(spend_psbt(&w));
    let pv1 = psbt_vtable(&mut psbt_ctx1);
    let mut idx = usize::MAX;
    let rc = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            tree0_only.as_ptr(),
            tree0_only.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv1,
            &mut idx,
            &mut err,
        )
    };
    assert_eq!(rc, 124);
    assert_eq!(message(err), "no tree for output");

    let (rust_inputs, rust_outputs) = standard_lists();
    let mut rust_psbt = spend_psbt(&w);
    let rust_err = prepare(
        &rust_c,
        &w.descriptor,
        &[record::build_tree(&rust_c, &w.descriptor, 0, 0).unwrap()],
        &rust_inputs,
        &rust_outputs,
        &mut rust_psbt,
    )
    .unwrap_err();
    let Error::NoTree(rust_idx) = rust_err else {
        panic!("expected NoTree, got {rust_err:?}");
    };
    assert_eq!(idx, rust_idx);

    let bad_trees: [*const Tree; 2] = [tree0_c, core::ptr::null()];
    let mut psbt_ctx3 = PsbtCtx::new(spend_psbt(&w));
    let pv3 = psbt_vtable(&mut psbt_ctx3);
    let rc3 = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            bad_trees.as_ptr(),
            bad_trees.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv3,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc3, 500);

    unsafe { bip89_tree_free(tree0_c) };
}

#[test]
fn psbt_callback_failures_through_c() {
    let w = wallet();

    let mut ctx = TestCtx {
        crypto: RustBitcoin::new(),
        rng: FixedRng::new(vec![0x5a; 96]),
    };
    let v = vtable(&mut ctx);
    let mut desc_ctx = DescCtx::new(&w.descriptor);
    let dv = descriptor_vtable(&mut desc_ctx);
    let mut err: *const c_char = core::ptr::null();

    let receive = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 0);
    let change = sign_root_through_c(&v, &dv, &OWNER1_SECRET, 1);

    let mut tree0_root = [0u8; 32];
    let mut tree0_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            0,
            0,
            tree0_root.as_mut_ptr(),
            &mut tree0_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);
    let mut tree1_root = [0u8; 32];
    let mut tree1_c: *mut Tree = core::ptr::null_mut();
    let rc = unsafe {
        bip89_build_tree(
            &v,
            &dv,
            1,
            0,
            tree1_root.as_mut_ptr(),
            &mut tree1_c,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let trees: [*const Tree; 2] = [tree0_c, tree1_c];
    let c_inputs = [FfiOwned {
        psbt_index: 0,
        keychain: 0,
        index: 5,
    }];
    let c_outputs = [
        FfiOwned {
            psbt_index: 1,
            keychain: 1,
            index: 3,
        },
        FfiOwned {
            psbt_index: 2,
            keychain: 0,
            index: 9,
        },
    ];

    let mut psbt_ctx = PsbtCtx::new(spend_psbt(&w));
    let pv = psbt_vtable(&mut psbt_ctx);
    let mut idx = usize::MAX;
    let rc = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            trees.as_ptr(),
            trees.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv,
            &mut idx,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut tv_ctx = TplCtx::new(&w.template);
    let tv = template_vtable(&mut tv_ctx);
    let mut reg: *mut RegistrationHandle = core::ptr::null_mut();
    let rc = unsafe {
        bip89_register(
            &v,
            &tv,
            BIP89_ROOT_POLICY_REQUIRE_SIGNATURE,
            &ffi_root_record(&receive),
            &ffi_root_record(&change),
            &mut reg,
            &mut err,
        )
    };
    assert_eq!(rc, BIP89_OK);

    let mut pv_out_fail = psbt_vtable(&mut psbt_ctx);
    pv_out_fail.output = Some(failing_psbt_output);
    let mut outflow1 = 0u64;
    let rc1 = unsafe {
        bip89_delegator_verify_spend(
            &v,
            reg,
            &pv_out_fail,
            &mut outflow1,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc1, 133);
    assert_eq!(message(err), "psbt rejected or callback failed");

    let mut pv_prop_fail = psbt_vtable(&mut psbt_ctx);
    pv_prop_fail.output_bundle = Some(failing_psbt_output_bundle);
    let mut outflow2 = 0u64;
    let rc2 = unsafe {
        bip89_delegator_verify_spend(
            &v,
            reg,
            &pv_prop_fail,
            &mut outflow2,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc2, 133);

    let mut outflow3 = 0u64;
    let rc3 = unsafe {
        bip89_delegator_sign_spend(
            &v,
            reg,
            &pv_prop_fail,
            DELEGATOR_SECRET.as_ptr(),
            &mut outflow3,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc3, 133);
    assert!(psbt_ctx.psbt.inputs[0].tap_script_sigs.is_empty());

    let mut pv_sig_fail = psbt_vtable(&mut psbt_ctx);
    pv_sig_fail.add_tap_script_sig = Some(failing_psbt_add_tap_script_sig);
    let mut outflow4 = 0u64;
    let rc4 = unsafe {
        bip89_delegator_sign_spend(
            &v,
            reg,
            &pv_sig_fail,
            DELEGATOR_SECRET.as_ptr(),
            &mut outflow4,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc4, 133);

    let mut fresh_psbt_ctx = PsbtCtx::new(spend_psbt(&w));
    let mut pv_set_fail = psbt_vtable(&mut fresh_psbt_ctx);
    pv_set_fail.set_output_bundle = Some(failing_psbt_set_output_bundle);
    let rc5 = unsafe {
        bip89_coordinator_prepare(
            &v,
            &dv,
            trees.as_ptr(),
            trees.len(),
            c_inputs.as_ptr(),
            c_inputs.len(),
            c_outputs.as_ptr(),
            c_outputs.len(),
            &pv_set_fail,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc5, 133);

    let mut pv_no_sighash = psbt_vtable(&mut psbt_ctx);
    pv_no_sighash.tap_leaf_sighash = None;
    let mut outflow6 = 0u64;
    let rc6 = unsafe {
        bip89_delegator_verify_spend(
            &v,
            reg,
            &pv_no_sighash,
            &mut outflow6,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc6, 501);
    assert_eq!(message(err), "vtable has a null callback");

    let mut outflow7 = 0u64;
    let rc7 = unsafe {
        bip89_delegator_verify_spend(
            &v,
            core::ptr::null(),
            &pv,
            &mut outflow7,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc7, 500);
    assert_eq!(message(err), "null pointer");

    let mut outflow8 = 0u64;
    let rc8 = unsafe {
        bip89_delegator_sign_spend(
            &v,
            reg,
            &pv,
            core::ptr::null(),
            &mut outflow8,
            core::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc8, 500);
    assert_eq!(message(err), "null pointer");

    unsafe { bip89_tree_free(tree0_c) };
    unsafe { bip89_tree_free(tree1_c) };
    unsafe { bip89_registration_free(reg) };
}
