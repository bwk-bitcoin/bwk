/*
 * Example C consumer of bwk-bip89-ll: compute a BIP89 tweak and produce a delegator
 * signature through the C ABI, checking both against the BIP89 test vectors.
 *
 * The crypto vtable is backed by libsecp256k1 for curve arithmetic and by
 * libsodium for SHA-256, SHA-512 and randomness. Any other library works the same way.
 *
 * Build and run from the repository root:
 *   cargo build --release -p bwk-bip89-cabi
 *   cc -Wall -Wextra -I bip89/ll/include bip89/ll/examples/consumer.c \
 *      target/release/libbip89.a -lsecp256k1 -lsodium -lpthread -ldl -lm -o target/consumer
 *   ./target/consumer
 * If the link fails, `cargo rustc --release -p bwk-bip89-cabi --crate-type staticlib --
 * --print native-static-libs` lists the system libraries to add.
 */
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <sodium.h>

#include "bip89.h"

_Static_assert(sizeof(crypto_hash_sha256_state) <= BIP89_HASH_STATE_LEN, "sha256 state too large");
_Static_assert(sizeof(crypto_hash_sha512_state) <= BIP89_HASH_STATE_LEN, "sha512 state too large");

static void sha256_init_cb(void *ctx, uint8_t *state) {
    (void)ctx;
    crypto_hash_sha256_init((crypto_hash_sha256_state *)(void *)state);
}

static void sha256_update_cb(void *ctx, uint8_t *state, const uint8_t *data, size_t len) {
    (void)ctx;
    crypto_hash_sha256_update((crypto_hash_sha256_state *)(void *)state, data, len);
}

static void sha256_final_cb(void *ctx, uint8_t *state, uint8_t *out) {
    (void)ctx;
    crypto_hash_sha256_final((crypto_hash_sha256_state *)(void *)state, out);
}

static void sha512_init_cb(void *ctx, uint8_t *state) {
    (void)ctx;
    crypto_hash_sha512_init((crypto_hash_sha512_state *)(void *)state);
}

static void sha512_update_cb(void *ctx, uint8_t *state, const uint8_t *data, size_t len) {
    (void)ctx;
    crypto_hash_sha512_update((crypto_hash_sha512_state *)(void *)state, data, len);
}

static void sha512_final_cb(void *ctx, uint8_t *state, uint8_t *out) {
    (void)ctx;
    crypto_hash_sha512_final((crypto_hash_sha512_state *)(void *)state, out);
}

static int32_t serialize(const secp256k1_context *secp, const secp256k1_pubkey *pk, uint8_t *out) {
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp, out, &len, pk, SECP256K1_EC_COMPRESSED) || len != 33) {
        return 1;
    }
    return 0;
}

static int32_t point_is_valid_cb(void *ctx, const uint8_t *point) {
    secp256k1_pubkey pk;
    return secp256k1_ec_pubkey_parse(ctx, &pk, point, 33) ? 1 : 0;
}

static int32_t point_add_cb(void *ctx, const uint8_t *a, const uint8_t *b, uint8_t *out) {
    secp256k1_pubkey pa, pb, sum;
    const secp256k1_pubkey *ins[2] = {&pa, &pb};
    if (!secp256k1_ec_pubkey_parse(ctx, &pa, a, 33) || !secp256k1_ec_pubkey_parse(ctx, &pb, b, 33)) {
        return 1;
    }
    /* combine fails when the sum is the point at infinity */
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, ins, 2)) {
        return 1;
    }
    return serialize(ctx, &sum, out);
}

static int32_t point_mul_cb(void *ctx, const uint8_t *point, const uint8_t *scalar, uint8_t *out) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, point, 33)) {
        return 1;
    }
    /* tweak_mul rejects a zero scalar, whose product is infinity */
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, scalar)) {
        return 1;
    }
    return serialize(ctx, &pk, out);
}

static int32_t base_mul_cb(void *ctx, const uint8_t *scalar, uint8_t *out) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, scalar)) {
        return 1;
    }
    return serialize(ctx, &pk, out);
}

static int is_zero(const uint8_t *s) {
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++) {
        acc |= s[i];
    }
    return acc == 0;
}

static void scalar_add_cb(void *ctx, const uint8_t *a, const uint8_t *b, uint8_t *out) {
    if (is_zero(a)) {
        memcpy(out, b, 32);
        return;
    }
    memcpy(out, a, 32);
    /* fails only when the sum is zero */
    if (!secp256k1_ec_seckey_tweak_add(ctx, out, b)) {
        memset(out, 0, 32);
    }
}

static void scalar_mul_cb(void *ctx, const uint8_t *a, const uint8_t *b, uint8_t *out) {
    if (is_zero(a) || is_zero(b)) {
        memset(out, 0, 32);
        return;
    }
    memcpy(out, a, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, out, b)) {
        memset(out, 0, 32);
    }
}

/* This example signs and verifies no accumulator root, so BIP322 always fails. */
static int32_t bip322_sign_cb(void *ctx, const uint8_t *secret, const uint8_t *msg, uint8_t *out,
                              size_t cap, size_t *out_len) {
    (void)ctx;
    (void)secret;
    (void)msg;
    (void)out;
    (void)cap;
    (void)out_len;
    return 1;
}

static int32_t bip322_verify_cb(void *ctx, const uint8_t *key, const uint8_t *msg,
                                const uint8_t *sig, size_t sig_len) {
    (void)ctx;
    (void)key;
    (void)msg;
    (void)sig;
    (void)sig_len;
    return 0;
}

static void fill_random_cb(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    randombytes_buf(buf, len);
}

static int from_hex(const char *hex, uint8_t *out, size_t len) {
    return sodium_hex2bin(out, len, hex, strlen(hex), NULL, NULL, NULL) == 0 ? 0 : 1;
}

static void print_hex(const char *label, const uint8_t *bytes, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (secp == NULL) {
        fprintf(stderr, "libsecp256k1 context failed\n");
        return 1;
    }

    bip89_crypto_vtable vtable = {
        .ctx = secp,
        .sha256_init = sha256_init_cb,
        .sha256_update = sha256_update_cb,
        .sha256_final = sha256_final_cb,
        .sha512_init = sha512_init_cb,
        .sha512_update = sha512_update_cb,
        .sha512_final = sha512_final_cb,
        .point_is_valid = point_is_valid_cb,
        .point_add = point_add_cb,
        .point_mul = point_mul_cb,
        .base_mul = base_mul_cb,
        .scalar_add = scalar_add_cb,
        .scalar_mul = scalar_mul_cb,
        .bip322_sign = bip322_sign_cb,
        .bip322_verify = bip322_verify_cb,
        .fill_random = fill_random_cb,
    };

    uint8_t key[33], chain_code[32], expected_tweak[32], secret[32], expected_sig[64];
    if (from_hex("0296928602758150d2b4a8a253451b887625b94ab0a91f801f1408cb33b9cf0f83", key, 33) ||
        from_hex("433cf1154e61c4eb9793488880f8a795a3a72052ad14a7367852542425609640", chain_code, 32) ||
        from_hex("d81d8e239630639ac24f3976257d9e4d905272b3da3a6507841c1ec80b04b91b", expected_tweak, 32) ||
        from_hex("9303c68c414a6208dbc0329181dd640b135e669647ad7dcb2f09870c54b26ed9", secret, 32) ||
        from_hex("2f558d1519106f6cffdcfce09954c6ae328b98308718a0903e3efed103b457cd"
                 "563c315fe6c6b5ffe6f71f413ce68ba22ee793238ab73fd2cef9d5881ae80017", expected_sig, 64)) {
        fprintf(stderr, "bad hex literal\n");
        secp256k1_context_destroy(secp);
        return 1;
    }

    const uint32_t path[2] = {0, 1};
    uint8_t tweak[32], child_key[33], child_chain_code[32];
    const char *err = NULL;
    int32_t rc = bip89_compute_tweak(&vtable, key, chain_code, path, 2, tweak, child_key,
                                     child_chain_code, &err);
    if (rc != BIP89_OK) {
        fprintf(stderr, "compute tweak failed (%d): %s\n", rc, err ? err : "");
        secp256k1_context_destroy(secp);
        return 1;
    }
    print_hex("tweak", tweak, 32);

    const char *message = "Chain Code Delegation";
    uint8_t msg[32];
    uint8_t aux[32] = {0};
    uint8_t sig[64];
    crypto_hash_sha256(msg, (const unsigned char *)message, strlen(message));
    rc = bip89_delegator_sign(&vtable, tweak, secret, msg, aux, sig, &err);
    if (rc != BIP89_OK) {
        fprintf(stderr, "delegator sign failed (%d): %s\n", rc, err ? err : "");
        secp256k1_context_destroy(secp);
        return 1;
    }
    print_hex("signature", sig, 64);

    secp256k1_context_destroy(secp);
    if (memcmp(tweak, expected_tweak, 32) != 0 || memcmp(sig, expected_sig, 64) != 0) {
        fprintf(stderr, "mismatch against the BIP89 vectors\n");
        return 1;
    }
    printf("ok\n");
    return 0;
}
