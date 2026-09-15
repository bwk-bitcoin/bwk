/*
 * C binding for bwk-bip89-ll: the crypto, descriptor, template and PSBT vtables,
 * the opaque handles, the error codes and every entry point.
 *
 * Kept in sync by hand with bip89/ll/src/lib.rs. bip89/ll/tests/layout.rs pins
 * the size, alignment, and field offset of every struct below, so a change on
 * the Rust side fails that test until this header follows.
 *
 * Ownership: Rust never frees your memory, and you never free Rust memory
 * except through bip89_tree_free and bip89_registration_free. No entry point
 * returns through a panic; every failure is a return code.
 */
#ifndef BIP89_H
#define BIP89_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Success. Any other returned int32 is an error code; see the ranges below. */
#define BIP89_OK 0

/* Size in bytes of the hash state buffer passed to the hash callbacks. */
#define BIP89_HASH_STATE_LEN 256

/* Writable size in bytes of a blind secret nonce output buffer. */
#define BIP89_SECNONCE_LEN 65

/* Fixed part of the session bytes bip89_blind_challenge_gen writes. */
#define BIP89_SESSION_BASE_LEN 130

/* Bytes added to the session length per tweak. */
#define BIP89_SESSION_TWEAK_LEN 33

/* Byte length of one bundle entry: a compressed key plus a tweak. */
#define BIP89_ENTRY_LEN 65

/* Byte length of a serialized accumulator proof. */
#define BIP89_PROOF_LEN 289

/* Length of one tweaked pair record: base key (33) then tweaked key (33). */
#define BIP89_TWEAKED_PAIR_LEN 66

/*
 * Error code ranges (all negative-free int32; 0 is success):
 *   100 to 199 protocol errors, one to one with bwk_bip89::Error
 *   500 to 599 C boundary errors (null pointer, null vtable callback, ...)
 * Codes 120 and 123 are retired and never reused.
 * The message via the err out-parameter is always a static, NUL-terminated
 * string, never freed by the caller.
 */
#define BIP89_ERR_INVALID_POINT 100
#define BIP89_ERR_INFINITY 101
#define BIP89_ERR_SCALAR_RANGE 102
#define BIP89_ERR_SECRET_KEY 103
#define BIP89_ERR_ZERO_NONCE 104
#define BIP89_ERR_HARDENED_INDEX 105
#define BIP89_ERR_INVALID_CHILD 106
#define BIP89_ERR_TWEAK_COUNT 107
#define BIP89_ERR_NONCE_REUSE 108
#define BIP89_ERR_SEC_NONCE_LENGTH 109
#define BIP89_ERR_BLIND_SIGNATURE 110
#define BIP89_ERR_DUPLICATE_KEY 111
#define BIP89_ERR_UNSORTED_BUNDLE 112
#define BIP89_ERR_ENTRY_LENGTH 113
#define BIP89_ERR_MISSING_TWEAK 114
#define BIP89_ERR_EXTRA_TWEAK 115
#define BIP89_ERR_TEMPLATE 116
#define BIP89_ERR_INVALID_KEYCHAIN 117
#define BIP89_ERR_INDEX_RANGE 118
#define BIP89_ERR_PROOF_LENGTH 119
#define BIP89_ERR_ROOT_SIGNATURE 121
#define BIP89_ERR_NOT_COMMITTED 122
#define BIP89_ERR_NO_TREE 124
#define BIP89_ERR_MISSING_UTXO 125
#define BIP89_ERR_MISSING_BUNDLE 126
#define BIP89_ERR_INPUT_MISMATCH 127
#define BIP89_ERR_OUTPUT_MISMATCH 128
#define BIP89_ERR_MISSING_PROOF 129
#define BIP89_ERR_AMOUNT 130
#define BIP89_ERR_NOT_PARTICIPANT 131
#define BIP89_ERR_NOTHING_TO_SIGN 132
#define BIP89_ERR_PSBT 133
#define BIP89_ERR_EXTRA_IN_LENGTH 134
#define BIP89_ERR_NOT_TAPROOT 135
#define BIP89_ERR_KEY_TYPE 136
#define BIP89_ERR_MULTIPATH 137
#define BIP89_ERR_WILDCARD 138
#define BIP89_ERR_HARDENED_STEP 139
#define BIP89_ERR_CONFLICTING_KEY 140
#define BIP89_ERR_NO_KEYS 141
#define BIP89_ERR_NULL_POINTER 500
#define BIP89_ERR_BAD_VTABLE 501
#define BIP89_ERR_BUFFER_TOO_SMALL 502
#define BIP89_ERR_INDEX_OUT_OF_BOUNDS 503

/*
 * The crypto primitives you supply. `ctx` is passed back to every callback so
 * you can carry state. A null callback makes an operation that needs it fail
 * with BIP89_ERR_BAD_VTABLE.
 */
typedef struct bip89_crypto_vtable {
    void *ctx;
    /*
     * Initialize a hash state in the 256-byte, 8-byte aligned state buffer
     * owned by the library. The buffer's address may change between calls
     * (it lives inside a Rust value that can move), so init/update/final
     * must store only relocatable data in it: plain hash state, or a
     * pointer to memory you own elsewhere. Never store a pointer into the
     * buffer itself.
     */
    void (*sha256_init)(void *ctx, uint8_t *state);
    /* Absorb len bytes at data (may be any pointer when len is 0). */
    void (*sha256_update)(void *ctx, uint8_t *state, const uint8_t *data, size_t len);
    /* Write the 32-byte digest to out. */
    void (*sha256_final)(void *ctx, uint8_t *state, uint8_t *out);
    /* Same relocatable-buffer rule as sha256_init applies here. */
    void (*sha512_init)(void *ctx, uint8_t *state);
    void (*sha512_update)(void *ctx, uint8_t *state, const uint8_t *data, size_t len);
    /* Write the 64-byte digest to out. */
    void (*sha512_final)(void *ctx, uint8_t *state, uint8_t *out);
    /* Return 1 when the 33 bytes at point are a valid compressed point, else 0. */
    int32_t (*point_is_valid)(void *ctx, const uint8_t *point);
    /* Write a plus b (33 bytes each) to out and return 0; nonzero means infinity. */
    int32_t (*point_add)(void *ctx, const uint8_t *a, const uint8_t *b, uint8_t *out);
    /* Write point times the 32-byte scalar to out and return 0; nonzero means infinity. */
    int32_t (*point_mul)(void *ctx, const uint8_t *point, const uint8_t *scalar, uint8_t *out);
    /* Write the generator times the 32-byte scalar to out and return 0; nonzero means infinity. */
    int32_t (*base_mul)(void *ctx, const uint8_t *scalar, uint8_t *out);
    /* Write the canonical 32-byte sum modulo the curve order to out. */
    void (*scalar_add)(void *ctx, const uint8_t *a, const uint8_t *b, uint8_t *out);
    /* Write the canonical 32-byte product modulo the curve order to out. */
    void (*scalar_mul)(void *ctx, const uint8_t *a, const uint8_t *b, uint8_t *out);
    /*
     * Write the BIP322 simple signature of the 32-byte `msg` for the single-key taproot
     * address (no script tree) of the public key of the 32-byte `secret`, as
     * consensus-serialized witness bytes. Follows the buffer callback rule of
     * bip89_descriptor_vtable. Nonzero means failure and gives BIP89_ERR_SECRET_KEY.
     */
    int32_t (*bip322_sign)(void *ctx, const uint8_t *secret, const uint8_t *msg, uint8_t *out,
                           size_t cap, size_t *out_len);
    /*
     * Return 1 when the `sig_len` bytes at sig are a valid BIP322 simple signature of the
     * 32-byte `msg` for the single-key taproot address of the 33-byte `key`, else 0.
     */
    int32_t (*bip322_verify)(void *ctx, const uint8_t *key, const uint8_t *msg,
                             const uint8_t *sig, size_t sig_len);
    /* Fill len bytes at buf with cryptographically secure randomness. */
    void (*fill_random)(void *ctx, uint8_t *buf, size_t len);
} bip89_crypto_vtable;

/*
 * Aggregate the BIP32 tweak of `path_len` unhardened child numbers at `path` (may be
 * NULL when path_len is 0) from the 33-byte `key` and 32-byte `chain_code`. Writes
 * the 32-byte tweak, the 33-byte derived key and the 32-byte derived chain code.
 * A hardened child number gives BIP89_ERR_HARDENED_INDEX. `err` may be NULL.
 */
int32_t bip89_compute_tweak(const bip89_crypto_vtable *crypto, const uint8_t *key,
                            const uint8_t *chain_code, const uint32_t *path, size_t path_len,
                            uint8_t *tweak_out, uint8_t *key_out, uint8_t *chain_code_out,
                            const char **err);

/*
 * Write the 33-byte `base` key plus `tweak` (32 bytes) times the generator to `out`.
 * BIP89_ERR_INVALID_POINT, BIP89_ERR_SCALAR_RANGE, BIP89_ERR_INFINITY. `err` may be NULL.
 */
int32_t bip89_tweak_key(const bip89_crypto_vtable *crypto, const uint8_t *base,
                        const uint8_t *tweak, uint8_t *out, const char **err);

/*
 * BIP89 DelegatorSign: BIP340 signature of the 32-byte `msg` under `secret` plus
 * `tweak` (32 bytes each), with the 32-byte `aux`. Writes 64 bytes to `sig_out`.
 * BIP89_ERR_SECRET_KEY, BIP89_ERR_SCALAR_RANGE, BIP89_ERR_ZERO_NONCE. `err` may be NULL.
 */
int32_t bip89_delegator_sign(const bip89_crypto_vtable *crypto, const uint8_t *tweak,
                             const uint8_t *secret, const uint8_t *msg, const uint8_t *aux,
                             uint8_t *sig_out, const char **err);

/*
 * Session layout written by bip89_blind_challenge_gen and read by
 * bip89_unblind_signature: pk (33) || blindfactor (32) || challenge (32) ||
 * pubnonce (33), then for each tweak: tweak (32) || is_xonly (1 byte, 0 or 1).
 * Its length is BIP89_SESSION_BASE_LEN plus BIP89_SESSION_TWEAK_LEN per tweak.
 */

/*
 * Generate a blind nonce. `sk` (32 bytes) and `pk` (33 bytes) may be NULL; `extra_in`
 * may be NULL when extra_in_len is 0. Draws 32 bytes from fill_random. Writes the
 * secret nonce to `secnonce_out` (BIP89_SECNONCE_LEN writable bytes, unused bytes
 * zeroed) and its length (32 or 65) to `*secnonce_len`, and the 33-byte public
 * nonce to `pubnonce_out`. An `extra_in` too long for its 4-byte length prefix gives
 * BIP89_ERR_EXTRA_IN_LENGTH. `err` may be NULL.
 */
int32_t bip89_blind_nonce_gen(const bip89_crypto_vtable *crypto, const uint8_t *sk,
                              const uint8_t *pk, const uint8_t *extra_in, size_t extra_in_len,
                              uint8_t *secnonce_out, size_t *secnonce_len, uint8_t *pubnonce_out,
                              const char **err);

/*
 * Generate a blind challenge for `msg` (may be NULL when msg_len is 0) under the
 * 33-byte `pk` tweaked by `n_tweaks` 32-byte `tweaks` flagged by `n_is_xonly`
 * `is_xonly` bytes (nonzero is x-only). Writes the session to `session_out` and its
 * length to `*session_len`; when session_cap is too small returns
 * BIP89_ERR_BUFFER_TOO_SMALL with the needed length in `*session_len` (session_out
 * may be NULL when session_cap is 0). Writes the 32-byte blind challenge and the
 * two parities as 0 or 1. Mismatched counts give BIP89_ERR_TWEAK_COUNT; an
 * `extra_in` too long for its 4-byte length prefix gives BIP89_ERR_EXTRA_IN_LENGTH.
 */
int32_t bip89_blind_challenge_gen(const bip89_crypto_vtable *crypto, const uint8_t *msg,
                                  size_t msg_len, const uint8_t *blindpubnonce,
                                  const uint8_t *pk, const uint8_t *tweaks, size_t n_tweaks,
                                  const uint8_t *is_xonly, size_t n_is_xonly,
                                  const uint8_t *extra_in, size_t extra_in_len,
                                  uint8_t *session_out, size_t session_cap, size_t *session_len,
                                  uint8_t *blindchallenge_out, uint8_t *pk_parity_out,
                                  uint8_t *nonce_parity_out, const char **err);

/*
 * Sign the 32-byte `blindchallenge` with the 32-byte `sk` and the caller secret
 * nonce (`secnonce_len` bytes, 32 or 65). The nonce bytes the protocol zeroes are
 * copied back into `secnonce` whether the call succeeds or fails, so a second call
 * with the same buffer gives BIP89_ERR_NONCE_REUSE. Parities: 0 false, nonzero true.
 * Writes the 32-byte blind signature to `sig_out`.
 */
int32_t bip89_blind_sign(const bip89_crypto_vtable *crypto, const uint8_t *sk,
                         const uint8_t *blindchallenge, uint8_t *secnonce, size_t secnonce_len,
                         uint8_t pk_parity, uint8_t nonce_parity, uint8_t *sig_out,
                         const char **err);

/*
 * Check a 32-byte blind signature. Returns BIP89_OK with `*valid_out` 1 or 0; a
 * malformed input is an error code instead.
 */
int32_t bip89_verify_blind_signature(const bip89_crypto_vtable *crypto, const uint8_t *pk,
                                     const uint8_t *blindpubnonce,
                                     const uint8_t *blindchallenge,
                                     const uint8_t *blindsignature, uint8_t pk_parity,
                                     uint8_t nonce_parity, uint8_t *valid_out, const char **err);

/*
 * Unblind a 32-byte blind signature with a session from bip89_blind_challenge_gen.
 * Writes the 64-byte BIP340 signature to `sig_out`. A malformed session gives
 * BIP89_ERR_TWEAK_COUNT.
 */
int32_t bip89_unblind_signature(const bip89_crypto_vtable *crypto, const uint8_t *session,
                                size_t session_len, const uint8_t *blindsignature,
                                uint8_t *sig_out, const char **err);

/* One xpub's borrowed derivation branch: raw BIP32 child numbers. A null `ptr`
 * with a nonzero `len` is rejected.
 */
typedef struct bip89_u32_list {
    const uint32_t *ptr;
    size_t len;
} bip89_u32_list;

typedef struct bip89_xpub {
    uint8_t key[33];
    uint8_t chain_code[32];
    /* Fixed steps then the multipath element of keychain 0, and of keychain 1. */
    bip89_u32_list branch0;
    bip89_u32_list branch1;
} bip89_xpub;

/*
 * Buffer callbacks: write the full length to *out_len; write the bytes to `out`
 * only when they fit in `cap`; return 0 in both cases. The library calls again once
 * with a buffer of exactly the reported length. Array callbacks follow the same rule
 * with `cap` and `*out_count` counted in records. Nonzero means failure and gives
 * BIP89_ERR_TEMPLATE.
 */
typedef struct bip89_descriptor_vtable {
    void *ctx;
    /* The full descriptor string with extended keys, UTF-8, no trailing newline. */
    int32_t (*policy_bytes)(void *ctx, uint8_t *out, size_t cap, size_t *out_len);
    /* The template string over base keys, UTF-8, no trailing newline. */
    int32_t (*template_bytes)(void *ctx, uint8_t *out, size_t cap, size_t *out_len);
    /*
     * The xpubs sorted by key, one record each; branch pointers must stay valid until
     * the entry point returns.
     */
    int32_t (*xpubs)(void *ctx, bip89_xpub *out, size_t cap, size_t *out_count);
} bip89_descriptor_vtable;

/* Opaque proof tree; release with bip89_tree_free. */
typedef struct bip89_tree bip89_tree;

/*
 * Serialize the delegation bundle of `keychain` and `index` (BIP89_ENTRY_LEN bytes
 * per distinct base key) into `out`. When out_cap is too small returns
 * BIP89_ERR_BUFFER_TOO_SMALL with the needed length in *out_len (`out` may be NULL
 * when out_cap is 0).
 */
int32_t bip89_derive_bundle(const bip89_crypto_vtable *crypto,
                            const bip89_descriptor_vtable *descriptor, uint32_t keychain,
                            uint32_t index, uint8_t *out, size_t out_cap, size_t *out_len,
                            const char **err);

/*
 * Build the tree itself and sign its root with BIP322 under the branch key of the 32-byte
 * `secret` for `keychain`. Writes the 32-byte root, the 33-byte base key of `secret`, its
 * 32-byte branch tweak, and the signature to `signature_out` with its length in
 * *signature_len. When signature_cap is too small returns BIP89_ERR_BUFFER_TOO_SMALL
 * with the needed length in *signature_len (`signature_out` may be NULL when
 * signature_cap is 0). A secret that is not a key of the descriptor gives
 * BIP89_ERR_NOT_PARTICIPANT.
 */
int32_t bip89_sign_tree_root(const bip89_crypto_vtable *crypto,
                             const bip89_descriptor_vtable *descriptor, const uint8_t *secret,
                             uint32_t keychain, uint32_t tree_start, uint8_t *root_out,
                             uint8_t *key_out, uint8_t *branch_tweak_out,
                             uint8_t *signature_out, size_t signature_cap,
                             size_t *signature_len, const char **err);

/* Build a proof tree. Writes the 32-byte root and an owning handle to *out (only on success). */
int32_t bip89_build_tree(const bip89_crypto_vtable *crypto,
                         const bip89_descriptor_vtable *descriptor, uint32_t keychain,
                         uint32_t tree_start, uint8_t *root_out, bip89_tree **out,
                         const char **err);

/* Write the BIP89_PROOF_LEN-byte proof of `keychain`/`index`; outside the tree gives BIP89_ERR_INDEX_OUT_OF_BOUNDS. */
int32_t bip89_tree_proof(const bip89_tree *tree, uint32_t keychain, uint32_t index,
                         uint8_t *proof_out, const char **err);

/* Release a tree. A NULL pointer is a no-op. */
void bip89_tree_free(bip89_tree *tree);

/*
 * `tweaked` points at `n` BIP89_TWEAKED_PAIR_LEN records in ascending base key order.
 * Buffer and array callbacks follow the rule of bip89_descriptor_vtable; leaf_hashes
 * counts 32-byte hashes in `cap` and `*out_count`. Nonzero means failure and gives
 * BIP89_ERR_TEMPLATE.
 */
typedef struct bip89_template_vtable {
    void *ctx;
    /* The template string, UTF-8, no trailing newline. */
    int32_t (*bytes)(void *ctx, uint8_t *out, size_t cap, size_t *out_len);
    /* The distinct base keys, 33 bytes each, strictly ascending; counts in keys. */
    int32_t (*base_keys)(void *ctx, uint8_t *out, size_t cap, size_t *out_count);
    /* Write the output scriptPubKey of the template over the tweaked keys. */
    int32_t (*script_pubkey)(void *ctx, const uint8_t *tweaked, size_t n, uint8_t *out,
                             size_t cap, size_t *out_len);
    /* Write the tapleaf hashes whose scripts contain the 33-byte `key`, possibly none. */
    int32_t (*leaf_hashes)(void *ctx, const uint8_t *tweaked, size_t n, const uint8_t *key,
                           uint8_t *out, size_t cap, size_t *out_count);
} bip89_template_vtable;

/* Opaque registration; release with bip89_registration_free. */
typedef struct bip89_registration bip89_registration;

/*
 * BIP89 InputVerification of `script` (the spent output scriptPubKey) against a
 * serialized bundle. Writes 1 or 0 to *valid_out and returns BIP89_OK; malformed or
 * incomplete bundles give an error code.
 */
int32_t bip89_input_verification(const bip89_crypto_vtable *crypto,
                                 const bip89_template_vtable *tmpl, const uint8_t *script,
                                 size_t script_len, const uint8_t *bundle, size_t bundle_len,
                                 uint8_t *valid_out, const char **err);

/* BIP89 ChangeOutputVerification; same contract as bip89_input_verification. */
int32_t bip89_change_output_verification(const bip89_crypto_vtable *crypto,
                                         const bip89_template_vtable *tmpl,
                                         const uint8_t *script, size_t script_len,
                                         const uint8_t *bundle, size_t bundle_len,
                                         uint8_t *valid_out, const char **err);

/*
 * A root signed by one key of the descriptor, as bip89_sign_tree_root writes it: `key` is
 * the signer's base key, `branch_tweak` the tweak from it to its branch key for `keychain`,
 * and `signature` points at `signature_len` bytes, borrowed for the duration of the call
 * (may be NULL when signature_len is 0).
 */
typedef struct bip89_signed_root {
    uint32_t keychain;
    uint32_t tree_start;
    uint8_t root[32];
    uint8_t key[33];
    uint8_t branch_tweak[32];
    const uint8_t *signature;
    size_t signature_len;
} bip89_signed_root;

/*
 * Pin the template with the `receive` (keychain 0) and `change` (keychain 1) roots. Each
 * key must be a base key of `tmpl` (BIP89_ERR_NOT_PARTICIPANT) and each signature must
 * verify (BIP89_ERR_ROOT_SIGNATURE); a root on another keychain gives
 * BIP89_ERR_INVALID_KEYCHAIN. Writes an owning handle to *out on success. The handle keeps
 * a copy of `tmpl`: its ctx must stay valid until bip89_registration_free.
 */
int32_t bip89_register(const bip89_crypto_vtable *crypto, const bip89_template_vtable *tmpl,
                       const bip89_signed_root *receive, const bip89_signed_root *change,
                       bip89_registration **out, const char **err);

/*
 * Record the root of the next tree of a keychain, once the current one is exhausted. The
 * root is checked as in bip89_register before it is recorded.
 */
int32_t bip89_registration_record_root(const bip89_crypto_vtable *crypto,
                                       bip89_registration *registration,
                                       const bip89_signed_root *signed_root, const char **err);

/* Release a registration. A NULL pointer is a no-op. */
void bip89_registration_free(bip89_registration *registration);

/*
 * PSBT access. `index` is an input index for input callbacks and an output index for
 * output callbacks. Buffer callbacks follow the rule of bip89_descriptor_vtable.
 * Getters write 1 to *present when the field is set and 0 when it is absent; an
 * absent field is distinct from an empty one. Bundles cross as their canonical
 * serialization (BIP89_ENTRY_LEN bytes per entry), accumulator proofs as
 * BIP89_PROOF_LEN bytes. How they are stored in the PSBT is up to you. Nonzero
 * means failure and gives BIP89_ERR_PSBT.
 */
typedef struct bip89_psbt_vtable {
    void *ctx;
    size_t (*input_count)(void *ctx);
    size_t (*output_count)(void *ctx);
    /* scriptPubKey and value in satoshis of the output spent by input `index`. */
    int32_t (*spent_output)(void *ctx, size_t index, uint8_t *script, size_t cap,
                            size_t *script_len, uint64_t *value);
    /* scriptPubKey and value in satoshis of transaction output `index`. */
    int32_t (*output)(void *ctx, size_t index, uint8_t *script, size_t cap,
                      size_t *script_len, uint64_t *value);
    /* The serialized bundle of input `index`, if any. */
    int32_t (*input_bundle)(void *ctx, size_t index, uint8_t *out, size_t cap,
                            size_t *out_len, uint8_t *present);
    /* Set the bundle of input `index` to the `len` serialized bytes. */
    int32_t (*set_input_bundle)(void *ctx, size_t index, const uint8_t *bundle, size_t len);
    /* The serialized bundle of output `index`, if any. */
    int32_t (*output_bundle)(void *ctx, size_t index, uint8_t *out, size_t cap,
                             size_t *out_len, uint8_t *present);
    /* Set the bundle of output `index` to the `len` serialized bytes. */
    int32_t (*set_output_bundle)(void *ctx, size_t index, const uint8_t *bundle, size_t len);
    /* Write the accumulator proof of output `index` to `out` when present. */
    int32_t (*output_proof)(void *ctx, size_t index, uint8_t *out, uint8_t *present);
    /* Set the accumulator proof of output `index`. */
    int32_t (*set_output_proof)(void *ctx, size_t index, const uint8_t *proof);
    /* BIP341 script path sighash (default type) of `input` for the 32-byte leaf hash. */
    int32_t (*tap_leaf_sighash)(void *ctx, size_t input, const uint8_t *leaf_hash,
                                uint8_t *out);
    /* Record the 64-byte signature for the 32-byte x-only key and leaf hash. */
    int32_t (*add_tap_script_sig)(void *ctx, size_t input, const uint8_t *xonly,
                                  const uint8_t *leaf_hash, const uint8_t *sig);
} bip89_psbt_vtable;

typedef struct bip89_owned {
    size_t psbt_index;
    uint32_t keychain;
    uint32_t index;
} bip89_owned;

/*
 * Write bundles for `inputs` and bundles plus accumulator proofs for `outputs`.
 * `trees` are borrowed handles (cloned internally). On an error naming an output, its
 * index goes to *index_out (may be NULL).
 */
int32_t bip89_coordinator_prepare(const bip89_crypto_vtable *crypto,
                                  const bip89_descriptor_vtable *descriptor,
                                  const bip89_tree *const *trees, size_t n_trees,
                                  const bip89_owned *inputs, size_t n_inputs,
                                  const bip89_owned *outputs, size_t n_outputs,
                                  const bip89_psbt_vtable *psbt, size_t *index_out,
                                  const char **err);

/*
 * Verify every input bundle and every output that carries a bundle. Writes the
 * outflow (inputs minus owned outputs, fee included) to *outflow_out on success. On
 * an error naming an input or output, its index goes to *index_out (may be NULL).
 */
int32_t bip89_delegator_verify_spend(const bip89_crypto_vtable *crypto,
                                     const bip89_registration *registration,
                                     const bip89_psbt_vtable *psbt, uint64_t *outflow_out,
                                     size_t *index_out, const char **err);

/*
 * Verify as bip89_delegator_verify_spend, then add BIP340 script path signatures with
 * the 32-byte delegator `secret` (aux from fill_random). No signature is added when
 * verification fails.
 */
int32_t bip89_delegator_sign_spend(const bip89_crypto_vtable *crypto,
                                   const bip89_registration *registration,
                                   const bip89_psbt_vtable *psbt, const uint8_t *secret,
                                   uint64_t *outflow_out, size_t *index_out, const char **err);

#ifdef __cplusplus
}
#endif

#endif /* BIP89_H */
