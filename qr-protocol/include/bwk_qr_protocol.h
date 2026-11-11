/* C binding for the bwk QR signing-flow codec, signer direction.
 *
 * Kept in sync by hand with qr-protocol/src/ffi/types.rs. The wire format is
 * specified in ENCODING.md.
 *
 * Ownership: this library never frees memory you own, and you never free memory it
 * owns except through bwk_qr_request_free and bwk_qr_buf_free. On encode your struct
 * is borrowed for the duration of the call only.
 */

#ifndef BWK_QR_PROTOCOL_H
#define BWK_QR_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BWK_QR_REQUEST_ID_LEN 2
#define BWK_QR_MAX_DESCRIPTOR_ALIAS 32
#define BWK_QR_EXTENDED_KEY_LEN 78
#define BWK_QR_FINGERPRINT_LEN 4
#define BWK_QR_PUBLIC_KEY_LEN 33
#define BWK_QR_SECRET_KEY_LEN 32
#define BWK_QR_MUSIG_PUB_NONCE_LEN 66
#define BWK_QR_MUSIG_PARTIAL_SIG_LEN 32
#define BWK_QR_TAP_LEAF_HASH_LEN 32
#define BWK_QR_DLEQ_PROOF_LEN 64
#define BWK_QR_SCHNORR_SIGNATURE_LEN 64 /* 65 with a sighash type byte */
#define BWK_QR_MAX_PATH 255
#define BWK_QR_MAX_VEC 4096
#define BWK_QR_MAX_NONCE_EXPRESSIONS 16
#define BWK_QR_MAX_STRING (64 * 1024)
#define BWK_QR_MAX_BYTES (512 * 1024)

/* Sizes and limits stay macros: they are array dimensions and a consumer may want
 * them in an #if. Everything a field can hold is an enum below.
 *
 * No field or return type is declared as one of these enum types. A C enum's size is
 * implementation-defined while the wire fields are one byte, so the structs use
 * uint8_t and the functions return int32_t. The enums name the values, they do not
 * type them. */

/* Closed: the decoder rejects any other value. */
enum bwk_qr_message_type {
    BWK_QR_MESSAGE_GET_INFO = 0x01, /* no request body: the body union is unused */
    BWK_QR_MESSAGE_GET_KEYS = 0x02,
    BWK_QR_MESSAGE_REGISTER_DESCRIPTOR = 0x03,
    BWK_QR_MESSAGE_ADDRESS_VERIFICATION = 0x04,
    BWK_QR_MESSAGE_SIGNING = 0x05,
    BWK_QR_MESSAGE_MUSIG_PREPARATION = 0x06,
    BWK_QR_MESSAGE_MUSIG_SIGNING = 0x07,
    BWK_QR_MESSAGE_NONCE_PREPARATION = 0x08
};

enum bwk_qr_capability {
    BWK_QR_CAPABILITY_MUSIG_CACHE = 1u << 4,
    BWK_QR_CAPABILITY_NONCE_CACHE = 1u << 5
};

/* Open: a value outside this list is a newer state, which counts as not ready. To
 * encode, it must sit above BWK_QR_STATE_UNINITIALIZED. */
enum bwk_qr_state {
    BWK_QR_STATE_READY = 0x00,
    BWK_QR_STATE_LOCKED = 0x01,
    BWK_QR_STATE_UNINITIALIZED = 0x02
};

/* Encoding a response rejects any other bit. */
enum bwk_qr_network {
    BWK_QR_NETWORK_MAINNET = 1u << 1,
    BWK_QR_NETWORK_TESTNET = 1u << 2,
    BWK_QR_NETWORK_SIGNET = 1u << 3,
    BWK_QR_NETWORK_REGTEST = 1u << 4
};

/* Closed: the decoder rejects any other value. */
enum bwk_qr_key_kind {
    BWK_QR_KEY_PUBLIC = 0x00,
    BWK_QR_KEY_PRIVATE = 0x01
};

/* Closed: the decoder rejects any other value. */
enum bwk_qr_descriptor_form {
    BWK_QR_DESCRIPTOR_BIP380 = 0x01,
    BWK_QR_DESCRIPTOR_BIP388 = 0x02,
    BWK_QR_DESCRIPTOR_SP_KEYS = 0x03
};

/* Closed: the decoder rejects any other value. */
enum bwk_qr_sign_response_kind {
    BWK_QR_SIGN_RESPONSE_PSBT = 0x01,
    BWK_QR_SIGN_RESPONSE_SIGNATURES = 0x02
};

/* Closed: encoding a response rejects any other value. */
enum bwk_qr_signature_kind {
    BWK_QR_SIGNATURE_ECDSA = 0x01,
    BWK_QR_SIGNATURE_TAP_KEY = 0x02,
    BWK_QR_SIGNATURE_TAP_SCRIPT = 0x03,
    BWK_QR_SIGNATURE_MUSIG_PUB_NONCE = 0x04,
    BWK_QR_SIGNATURE_MUSIG_PARTIAL_SIG = 0x05,
    BWK_QR_SIGNATURE_SP_ECDH_SHARE = 0x06,
    BWK_QR_SIGNATURE_SP_DLEQ_PROOF = 0x07
};

/* Open: a value outside this list is a newer flag and passes through unchanged. */
enum bwk_qr_release_flag {
    BWK_QR_RELEASE_STABLE = 0x00,
    BWK_QR_RELEASE_ALPHA = 0x01,
    BWK_QR_RELEASE_BETA = 0x02,
    BWK_QR_RELEASE_CANDIDATE = 0x03
};

/* Open: a value outside this list passes through as an unknown code, and must sit in
 * 0x0e..=0xfe to encode. */
enum bwk_qr_response_error {
    BWK_QR_RESPONSE_ERROR_USER_DECLINED = 0x01,
    BWK_QR_RESPONSE_ERROR_UNSUPPORTED_VERSION = 0x02,
    BWK_QR_RESPONSE_ERROR_MALFORMED_REQUEST = 0x03,
    BWK_QR_RESPONSE_ERROR_UNKNOWN_DESCRIPTOR_ALIAS = 0x04,
    BWK_QR_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED = 0x05,
    BWK_QR_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM = 0x06,
    BWK_QR_RESPONSE_ERROR_INVALID_PROOF = 0x07,
    BWK_QR_RESPONSE_ERROR_ADDRESS_MISMATCH = 0x08,
    BWK_QR_RESPONSE_ERROR_NOTHING_TO_SIGN = 0x09,
    BWK_QR_RESPONSE_ERROR_INVALID_PSBT = 0x0a,
    BWK_QR_RESPONSE_ERROR_INTERNAL = 0x0b,
    BWK_QR_RESPONSE_ERROR_PRIVATE_KEY_EXPORT_REFUSED = 0x0c,
    BWK_QR_RESPONSE_ERROR_MUSIG_SESSION = 0x0d,
    BWK_QR_RESPONSE_ERROR_VENDOR = 0xff
};

/* Selects the scan arm of bwk_qr_sp_keys. Not a wire value: the wire carries the
 * scan path and the scan key as two optional fields, exactly one present. */
enum bwk_qr_scan_kind {
    BWK_QR_SCAN_PATH = 0x00, /* the signer's own scan key, at scan.path */
    BWK_QR_SCAN_KEY = 0x01   /* a scan private key the signer does not hold */
};

/* Absent markers for the tri-state fields. */
enum bwk_qr_absent {
    BWK_QR_ABSENT_BOOL = -1,
    BWK_QR_ABSENT_KIND = -1
};

/* What the four functions return. 100..=199 come from the byte reader, 200..=299
 * from the decoder, 300..=399 from the encoder, 400..=499 from this binding,
 * 500..=599 from shared MuSig validation, 600..=699 from shared silent payment
 * validation, 700..=799 from shared Get Info validation, 800..=899 from shared
 * signature validation and 900..=999 from shared nonce cache validation, the last
 * five both on encode and decode. */
enum bwk_qr_status {
    BWK_QR_OK = 0,

    BWK_QR_ERR_TRUNCATED = 100,
    BWK_QR_ERR_LENGTH_OVERFLOW = 101,
    BWK_QR_ERR_NON_CANONICAL_COMPACT_SIZE = 102,
    BWK_QR_ERR_COMPACT_SIZE_TOO_LARGE = 103,
    BWK_QR_ERR_INVALID_BOOL = 104,
    BWK_QR_ERR_INVALID_PRESENCE = 105,
    BWK_QR_ERR_STRING_TOO_LARGE = 106,
    BWK_QR_ERR_BYTES_TOO_LARGE = 107,
    BWK_QR_ERR_VEC_TOO_LARGE = 108,
    BWK_QR_ERR_INVALID_UTF8 = 110,
    BWK_QR_ERR_STRING_NUL = 111,

    BWK_QR_ERR_INVALID_MAGIC = 200,
    BWK_QR_ERR_RESERVED_VERSION = 201,
    BWK_QR_ERR_UNKNOWN_MESSAGE_TYPE = 202,
    BWK_QR_ERR_ERROR_STATUS_ON_REQUEST = 203,
    BWK_QR_ERR_UNKNOWN_DESCRIPTOR_FORM = 204,
    BWK_QR_ERR_UNKNOWN_SIGN_RESPONSE_KIND = 206,
    BWK_QR_ERR_UNKNOWN_KEY_KIND = 207,
    BWK_QR_ERR_SIGNATURE_LENGTH = 208,
    BWK_QR_ERR_GLOBAL_INPUT_INDEX = 209,
    BWK_QR_ERR_SCAN_PATH_AND_KEY = 210,
    BWK_QR_ERR_NO_SCAN = 211,

    BWK_QR_ERR_PATH_TOO_LONG = 300,
    BWK_QR_ERR_PATCH_TOO_LARGE = 301,
    BWK_QR_ERR_RESERVED_CAPABILITY_BITS = 302,
    BWK_QR_ERR_ERROR_CODE_OUT_OF_RANGE = 303,
    BWK_QR_ERR_ENCODE_VEC_TOO_LARGE = 304,
    BWK_QR_ERR_ENCODE_BYTES_TOO_LARGE = 305,
    BWK_QR_ERR_STRING_TOO_LONG = 306,
    BWK_QR_ERR_ENCODE_STRING_NUL = 307,
    BWK_QR_ERR_UNREACHABLE = 309,
    BWK_QR_ERR_DEFINED_SIGNATURE_KIND = 310,
    BWK_QR_ERR_RESERVED_NETWORK_BITS = 311,
    BWK_QR_ERR_DEFINED_STATE = 312,

    BWK_QR_ERR_NULL_POINTER = 400,
    BWK_QR_ERR_FFI_STRING_NUL = 401,
    BWK_QR_ERR_FFI_INVALID_UTF8 = 402,
    BWK_QR_ERR_FFI_INVALID_BOOL = 403,
    BWK_QR_ERR_UNKNOWN_TAG = 404,
    BWK_QR_ERR_UNEXPECTED_RESPONSE = 406,
    BWK_QR_ERR_FFI_GLOBAL_INPUT_INDEX = 407,

    BWK_QR_ERR_MUSIG_INPUT_COVERAGE = 500,
    BWK_QR_ERR_MUSIG_DERIVATION_COUNT = 501,
    BWK_QR_ERR_MUSIG_DUPLICATE_DERIVATION = 502,
    BWK_QR_ERR_MUSIG_HARDENED_INDEX = 503,
    BWK_QR_ERR_MUSIG_NONCE_COUNT = 505,
    BWK_QR_ERR_MUSIG_NONCE_INPUT_INDEX = 506,
    BWK_QR_ERR_MUSIG_DUPLICATE_NONCE = 507,
    BWK_QR_ERR_MUSIG_MISSING_INPUT = 508,

    BWK_QR_ERR_SP_DUPLICATE_SHARE = 600,
    BWK_QR_ERR_SP_DUPLICATE_PROOF = 601,
    BWK_QR_ERR_SP_MISSING_PROOF = 602,
    BWK_QR_ERR_SP_MISSING_SHARE = 603,

    BWK_QR_ERR_GET_INFO_MAX_ALIAS_TOO_LARGE = 700,
    BWK_QR_ERR_GET_INFO_FINGERPRINT_WHEN_NOT_READY = 701,

    BWK_QR_ERR_TAPROOT_SIGNATURE_LENGTH = 800,

    BWK_QR_ERR_NONCE_CACHE_INPUT_COVERAGE = 900,
    BWK_QR_ERR_NONCE_CACHE_EXPRESSION_RANGE = 901,
    BWK_QR_ERR_NONCE_CACHE_NONCE_COUNT = 902
};

/* A borrowed run of items. A NULL ptr means the field is absent, which is distinct
 * from a present but empty run (non-NULL ptr with len 0). */
typedef struct {
    const uint8_t *ptr;
    size_t len;
} bwk_qr_bytes;

/* BIP-32 child numbers with the hardened bit set. */
typedef struct {
    const uint32_t *ptr;
    uint8_t len;
} bwk_qr_path;

typedef struct {
    bwk_qr_path derivation_path;
    uint8_t kind; /* BWK_QR_KEY_* */
} bwk_qr_key_request;

typedef struct {
    const bwk_qr_key_request *ptr;
    size_t len;
} bwk_qr_key_request_list;

typedef struct {
    const char *const *ptr;
    size_t len;
} bwk_qr_string_list;

/* BIP-32 serialization of an extended public or private key. */
typedef struct {
    uint8_t bytes[BWK_QR_EXTENDED_KEY_LEN];
} bwk_qr_extended_key;

typedef struct {
    const bwk_qr_extended_key *ptr;
    size_t len;
} bwk_qr_extended_key_list;

/* Strings are UTF-8 and NUL-terminated. The codec rejects an interior NUL on both
 * sides, so a string never carries one. A NULL pointer means the field is absent. */

typedef struct {
    bwk_qr_string_list keys;
    const char *policy;
} bwk_qr_bip388;

typedef union {
    bwk_qr_path path;                     /* from the master key */
    uint8_t key[BWK_QR_SECRET_KEY_LEN];   /* big-endian scalar */
} bwk_qr_scan_value;

typedef struct {
    uint8_t fingerprint[BWK_QR_FINGERPRINT_LEN];
    bwk_qr_path spend_path; /* from the master key */
    uint8_t scan_kind;      /* BWK_QR_SCAN_*, selects the scan arm */
    bwk_qr_scan_value scan;
} bwk_qr_sp_keys;

typedef union {
    const char *bip380;
    bwk_qr_bip388 bip388;
    bwk_qr_sp_keys sp_keys;
} bwk_qr_descriptor_value;

typedef struct {
    uint8_t tag; /* BWK_QR_DESCRIPTOR_* */
    bwk_qr_descriptor_value value;
} bwk_qr_descriptor_body;

typedef struct {
    const char *alias;
    const bwk_qr_descriptor_body *body;
    bwk_qr_bytes proof;
} bwk_qr_descriptor;

typedef struct {
    const bwk_qr_descriptor *ptr;
    size_t len;
} bwk_qr_descriptor_list;

typedef struct {
    bwk_qr_key_request_list keys;
} bwk_qr_get_keys;

typedef struct {
    const char *descriptor_alias;
    const bwk_qr_descriptor_body *descriptor; /* NULL when absent */
} bwk_qr_register_descriptor;

typedef struct {
    const char *descriptor_alias;
    bwk_qr_path derivation_path;
    const char *address;                      /* NULL when absent */
    const bwk_qr_descriptor_body *descriptor; /* NULL when absent */
    bwk_qr_bytes proof;                       /* ptr NULL when absent */
} bwk_qr_verify_address;

typedef struct {
    bwk_qr_descriptor_list descriptors;
    bwk_qr_bytes psbt; /* BIP-174 serialization, carried unparsed */
    int16_t want_kind; /* BWK_QR_SIGN_RESPONSE_* or BWK_QR_ABSENT_KIND */
} bwk_qr_sign;

typedef struct {
    uint32_t keychain;
    uint32_t index; /* nonhardened */
} bwk_qr_musig_derivation;

typedef struct {
    const bwk_qr_musig_derivation *ptr;
    size_t len;
} bwk_qr_musig_derivation_list;

typedef struct {
    bwk_qr_descriptor descriptor; /* body must be present */
    uint8_t session_id[32];
    uint8_t max_inputs;
    bwk_qr_musig_derivation_list derivations;
} bwk_qr_prepare_musig;

typedef struct {
    uint8_t session_id[32];
    uint8_t attempt_id[32];
    bwk_qr_bytes psbt;
} bwk_qr_sign_musig;

/* start..=end: key expression indexes, at most BWK_QR_MAX_NONCE_EXPRESSIONS of them. */
typedef struct {
    uint8_t session_id[4];
    uint8_t has_session_ref; /* 0 or 1 */
    uint8_t session_ref[4];
    uint8_t max_inputs;
    bwk_qr_path derivation_path; /* from the master key */
    uint32_t start;
    uint32_t end;
} bwk_qr_prepare_nonces;

typedef union {
    bwk_qr_get_keys get_keys;
    bwk_qr_register_descriptor register_descriptor;
    bwk_qr_verify_address verify_address;
    bwk_qr_sign sign;
    bwk_qr_prepare_musig prepare_musig;
    bwk_qr_sign_musig sign_musig;
    bwk_qr_prepare_nonces prepare_nonces;
} bwk_qr_request_body;

typedef struct {
    uint8_t id[BWK_QR_REQUEST_ID_LEN];
    uint8_t message_type; /* BWK_QR_MESSAGE_*, selects the body arm */
    bwk_qr_request_body body;
} bwk_qr_request;

typedef struct {
    uint16_t major;
    uint16_t minor;
    uint32_t patch; /* at most 0x00ffffff */
    uint8_t flag;   /* BWK_QR_RELEASE_* */
} bwk_qr_firmware_version;

typedef struct {
    bwk_qr_extended_key_list keys; /* one per request key, in request order */
    uint8_t fingerprint[BWK_QR_FINGERPRINT_LEN];
    const char *vendor;
    const char *model;
    bwk_qr_firmware_version version;
    uint32_t capabilities; /* only the low six bits may be set */
} bwk_qr_keys;

typedef struct {
    const char *vendor;
    const char *model;
    bwk_qr_firmware_version version;
    uint32_t capabilities;   /* only the low six bits may be set */
    uint8_t state;           /* BWK_QR_STATE_* */
    uint8_t networks;        /* BWK_QR_NETWORK_* bits */
    uint32_t max_message;    /* bytes */
    uint8_t max_alias;       /* at most BWK_QR_MAX_DESCRIPTOR_ALIAS */
    uint8_t max_keys;
    uint16_t slots;          /* 0 when the signer relies on the proof of registration */
    uint8_t has_fingerprint; /* 0 or 1, and 1 only when state is BWK_QR_STATE_READY */
    uint8_t fingerprint[BWK_QR_FINGERPRINT_LEN];
} bwk_qr_info;

typedef struct {
    const char *descriptor_alias;
    int8_t registered; /* 0, 1 or BWK_QR_ABSENT_BOOL */
    int8_t stored;     /* 0, 1 or BWK_QR_ABSENT_BOOL */
    bwk_qr_bytes proof;
} bwk_qr_registration;

typedef struct {
    const char *uri; /* NULL when absent */
} bwk_qr_address_uri;

typedef struct {
    uint8_t public_key[BWK_QR_PUBLIC_KEY_LEN]; /* compressed */
    bwk_qr_bytes signature;
} bwk_qr_ecdsa;

typedef struct {
    bwk_qr_bytes signature;
} bwk_qr_tap_key;

typedef struct {
    uint8_t xonly_public_key[32];
    uint8_t tap_leaf_hash[32];
    bwk_qr_bytes signature;
} bwk_qr_tap_script;

typedef struct {
    uint8_t participant[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t aggregate[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BWK_QR_TAP_LEAF_HASH_LEN];
    uint8_t nonce[BWK_QR_MUSIG_PUB_NONCE_LEN];
} bwk_qr_musig_pub_nonce;

typedef struct {
    uint8_t participant[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t aggregate[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BWK_QR_TAP_LEAF_HASH_LEN];
    uint8_t signature[BWK_QR_MUSIG_PARTIAL_SIG_LEN];
} bwk_qr_musig_partial_sig;

typedef struct {
    uint8_t global; /* 0 for the input at input_index, 1 for the whole transaction */
    uint8_t scan_key[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t share[BWK_QR_PUBLIC_KEY_LEN];
} bwk_qr_sp_ecdh_share;

typedef struct {
    uint8_t global; /* 0 for the input at input_index, 1 for the whole transaction */
    uint8_t scan_key[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t proof[BWK_QR_DLEQ_PROOF_LEN]; /* BIP-374 */
} bwk_qr_sp_dleq_proof;

typedef struct {
    bwk_qr_musig_derivation derivation;
    uint32_t input_index;
    uint32_t expression_index;
    uint8_t participant[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t aggregate[BWK_QR_PUBLIC_KEY_LEN];
    uint8_t has_leaf_hash; /* 0 or 1 */
    uint8_t leaf_hash[BWK_QR_TAP_LEAF_HASH_LEN];
    uint8_t nonce[BWK_QR_MUSIG_PUB_NONCE_LEN];
} bwk_qr_musig_nonce;

typedef struct {
    const bwk_qr_musig_nonce *ptr;
    size_t len;
} bwk_qr_musig_nonce_list;

typedef struct {
    uint8_t session_id[32];
    uint8_t max_inputs;
    bwk_qr_musig_nonce_list nonces;
} bwk_qr_musig_prepared;

typedef struct {
    uint8_t session_id[32];
    uint8_t attempt_id[32];
    bwk_qr_bytes psbt;
} bwk_qr_musig_signed;

typedef struct {
    uint8_t bytes[BWK_QR_MUSIG_PUB_NONCE_LEN];
} bwk_qr_pub_nonce;

typedef struct {
    const bwk_qr_pub_nonce *ptr;
    size_t len;
} bwk_qr_pub_nonce_list;

/* nonces: (end - start + 1) * max_inputs entries, the one for key expression index j
 * and input i at (j - start) * max_inputs + i. */
typedef struct {
    uint8_t session_id[4];
    uint8_t session_ref[4];
    uint8_t max_inputs;
    uint32_t start;
    uint32_t end;
    bwk_qr_pub_nonce_list nonces;
} bwk_qr_nonces_prepared;

typedef union {
    bwk_qr_ecdsa ecdsa;
    bwk_qr_tap_key tap_key;
    bwk_qr_tap_script tap_script;
    bwk_qr_musig_pub_nonce musig_pub_nonce;
    bwk_qr_musig_partial_sig musig_partial_sig;
    bwk_qr_sp_ecdh_share sp_ecdh_share;
    bwk_qr_sp_dleq_proof sp_dleq_proof;
} bwk_qr_signature_value;

typedef struct {
    uint32_t input_index; /* 0 for a global silent payment entry */
    uint8_t kind; /* BWK_QR_SIGNATURE_*, selects the value arm */
    bwk_qr_signature_value value;
} bwk_qr_signature;

typedef struct {
    const bwk_qr_signature *ptr;
    size_t len;
} bwk_qr_signature_list;

typedef union {
    bwk_qr_bytes psbt;
    bwk_qr_signature_list signatures;
} bwk_qr_signed_value;

typedef struct {
    uint8_t kind; /* BWK_QR_SIGN_RESPONSE_*, selects the value arm */
    bwk_qr_signed_value value;
} bwk_qr_signed;

typedef struct {
    uint8_t error; /* BWK_QR_RESPONSE_ERROR_* */
    const char *message;
} bwk_qr_error_body;

typedef union {
    bwk_qr_keys keys;
    bwk_qr_registration registration;
    bwk_qr_address_uri address_uri;
    bwk_qr_signed signed_body;
    bwk_qr_musig_prepared musig_prepared;
    bwk_qr_musig_signed musig_signed;
    bwk_qr_nonces_prepared nonces_prepared;
    bwk_qr_info info;
    bwk_qr_error_body error;
} bwk_qr_response_body;

typedef struct {
    uint8_t id[BWK_QR_REQUEST_ID_LEN];
    uint8_t message_type; /* BWK_QR_MESSAGE_*, selects the body arm */
    bool is_error;        /* when true the body is the error arm */
    bwk_qr_response_body body;
} bwk_qr_response;

/* A byte buffer the codec allocated. Release it with bwk_qr_buf_free. */
typedef struct {
    uint8_t *ptr;
    size_t len;
} bwk_qr_buf;

/* Decodes a request. On BWK_QR_OK, *out owns the tree until bwk_qr_request_free.
 * err may be NULL; otherwise a failure writes a static message to it. */
int32_t bwk_qr_request_decode(const uint8_t *bytes, size_t len,
                              const bwk_qr_request **out, const char **err);

/* Releases a request from bwk_qr_request_decode. NULL is a no-op. */
void bwk_qr_request_free(const bwk_qr_request *request);

/* Encodes a response. On BWK_QR_OK, *out owns the bytes until bwk_qr_buf_free. */
int32_t bwk_qr_response_encode(const bwk_qr_response *response, bwk_qr_buf *out,
                               const char **err);

/* Releases a buffer from the codec. A NULL ptr is a no-op. */
void bwk_qr_buf_free(bwk_qr_buf buf);

#ifdef __cplusplus
}
#endif

#endif /* BWK_QR_PROTOCOL_H */
