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
#define BWK_QR_XPUB_LEN 78
#define BWK_QR_FINGERPRINT_LEN 4
#define BWK_QR_PUBLIC_KEY_LEN 33
#define BWK_QR_MODEL_LEN 16
#define BWK_QR_ERROR_MESSAGE_LEN 32
#define BWK_QR_MAX_PATH 255
#define BWK_QR_MAX_VEC 4096
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
    BWK_QR_MESSAGE_GET_XPUBS = 0x01,
    BWK_QR_MESSAGE_REGISTER_DESCRIPTOR = 0x02,
    BWK_QR_MESSAGE_ADDRESS_VERIFICATION = 0x03,
    BWK_QR_MESSAGE_SIGNING = 0x04,
    BWK_QR_MESSAGE_GET_SP_DESCRIPTOR = 0x05
};

/* Closed: the decoder rejects any other value. */
enum bwk_qr_descriptor_form {
    BWK_QR_DESCRIPTOR_BIP380 = 0x01,
    BWK_QR_DESCRIPTOR_BIP388 = 0x02
};

/* Closed: the decoder rejects any other value. */
enum bwk_qr_sign_response_kind {
    BWK_QR_SIGN_RESPONSE_PSBT = 0x01,
    BWK_QR_SIGN_RESPONSE_SIGNATURES = 0x02
};

/* Closed: the decoder rejects any other value. */
enum bwk_qr_signature_kind {
    BWK_QR_SIGNATURE_ECDSA = 0x01,
    BWK_QR_SIGNATURE_TAP_KEY = 0x02,
    BWK_QR_SIGNATURE_TAP_SCRIPT = 0x03
};

/* Open: a value outside this list is a newer flag and passes through unchanged. */
enum bwk_qr_release_flag {
    BWK_QR_RELEASE_STABLE = 0x00,
    BWK_QR_RELEASE_ALPHA = 0x01,
    BWK_QR_RELEASE_BETA = 0x02,
    BWK_QR_RELEASE_CANDIDATE = 0x03
};

/* Open: a value outside this list passes through as an unknown code, and must sit in
 * 0x0c..=0xfe to encode. */
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
    BWK_QR_RESPONSE_ERROR_VENDOR = 0xff
};

/* Absent markers for the tri-state fields. */
enum bwk_qr_absent {
    BWK_QR_ABSENT_BOOL = -1,
    BWK_QR_ABSENT_KIND = -1
};

/* What the four functions return. 100..=199 come from the byte reader, 200..=299
 * from the decoder, 300..=399 from the encoder and 400..=499 from this binding. */
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
    BWK_QR_ERR_INVALID_FIXED_STRING_PADDING = 109,
    BWK_QR_ERR_INVALID_UTF8 = 110,
    BWK_QR_ERR_STRING_NUL = 111,

    BWK_QR_ERR_INVALID_MAGIC = 200,
    BWK_QR_ERR_RESERVED_VERSION = 201,
    BWK_QR_ERR_UNKNOWN_MESSAGE_TYPE = 202,
    BWK_QR_ERR_ERROR_STATUS_ON_REQUEST = 203,
    BWK_QR_ERR_UNKNOWN_DESCRIPTOR_FORM = 204,
    BWK_QR_ERR_UNKNOWN_SIGNATURE_KIND = 205,
    BWK_QR_ERR_UNKNOWN_SIGN_RESPONSE_KIND = 206,

    BWK_QR_ERR_PATH_TOO_LONG = 300,
    BWK_QR_ERR_PATCH_TOO_LARGE = 301,
    BWK_QR_ERR_RESERVED_CAPABILITY_BITS = 302,
    BWK_QR_ERR_ERROR_CODE_OUT_OF_RANGE = 303,
    BWK_QR_ERR_ENCODE_VEC_TOO_LARGE = 304,
    BWK_QR_ERR_ENCODE_BYTES_TOO_LARGE = 305,
    BWK_QR_ERR_STRING_TOO_LONG = 306,
    BWK_QR_ERR_ENCODE_STRING_NUL = 307,
    BWK_QR_ERR_FIXED_STRING_TOO_LONG = 308,
    BWK_QR_ERR_UNREACHABLE = 309,

    BWK_QR_ERR_NULL_POINTER = 400,
    BWK_QR_ERR_FFI_STRING_NUL = 401,
    BWK_QR_ERR_FFI_INVALID_UTF8 = 402,
    BWK_QR_ERR_FFI_INVALID_BOOL = 403,
    BWK_QR_ERR_UNKNOWN_TAG = 404,
    BWK_QR_ERR_UNTERMINATED_FIXED_STRING = 405,
    BWK_QR_ERR_UNEXPECTED_RESPONSE = 406
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
    const bwk_qr_path *ptr;
    size_t len;
} bwk_qr_path_list;

typedef struct {
    const char *const *ptr;
    size_t len;
} bwk_qr_string_list;

typedef struct {
    uint8_t bytes[BWK_QR_XPUB_LEN];
} bwk_qr_xpub;

typedef struct {
    const bwk_qr_xpub *ptr;
    size_t len;
} bwk_qr_xpub_list;

/* Strings are UTF-8 and NUL-terminated. The codec rejects an interior NUL on both
 * sides, so a string never carries one. A NULL pointer means the field is absent. */

typedef struct {
    bwk_qr_string_list keys;
    const char *policy;
} bwk_qr_bip388;

typedef union {
    const char *bip380;
    bwk_qr_bip388 bip388;
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
    bwk_qr_path_list derivation_paths;
} bwk_qr_get_xpubs;

typedef struct {
    uint8_t _unused;
} bwk_qr_get_sp_descriptor;

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

typedef union {
    bwk_qr_get_xpubs get_xpubs;
    bwk_qr_register_descriptor register_descriptor;
    bwk_qr_verify_address verify_address;
    bwk_qr_sign sign;
    bwk_qr_get_sp_descriptor get_sp_descriptor;
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
    bwk_qr_xpub_list xpubs;
    uint8_t fingerprint[BWK_QR_FINGERPRINT_LEN];
    char model[BWK_QR_MODEL_LEN + 1];
    bwk_qr_firmware_version version;
    uint32_t capabilities; /* only the low four bits may be set */
} bwk_qr_xpubs;

typedef struct {
    const char *descriptor;
} bwk_qr_sp_descriptor;

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

typedef union {
    bwk_qr_ecdsa ecdsa;
    bwk_qr_tap_key tap_key;
    bwk_qr_tap_script tap_script;
} bwk_qr_signature_value;

typedef struct {
    uint32_t input_index;
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
    char message[BWK_QR_ERROR_MESSAGE_LEN + 1];
} bwk_qr_error_body;

typedef union {
    bwk_qr_xpubs xpubs;
    bwk_qr_registration registration;
    bwk_qr_address_uri address_uri;
    bwk_qr_signed signed_body;
    bwk_qr_sp_descriptor sp_descriptor;
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
