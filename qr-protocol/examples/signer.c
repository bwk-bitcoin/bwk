/* Smoke test for the C binding: read a signing request, answer with a PSBT.
 *
 * Build it against a staticlib crate that supplies the allocator and panic handler
 * and re-exports this crate's `ffi` module. See the README.
 */

#include <stdio.h>
#include <string.h>

#include "bwk_qr_protocol.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <request-file>\n", argv[0]);
        return 2;
    }

    static uint8_t blob[BWK_QR_MAX_BYTES];
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        perror("open");
        return 2;
    }
    size_t len = fread(blob, 1, sizeof blob, file);
    fclose(file);

    const bwk_qr_request *request = NULL;
    const char *err = NULL;
    int32_t code = bwk_qr_request_decode(blob, len, &request, &err);
    if (code != BWK_QR_OK) {
        fprintf(stderr, "decode failed (%d): %s\n", code, err);
        return 1;
    }
    if (request->message_type != BWK_QR_MESSAGE_SIGNING) {
        fprintf(stderr, "not a signing request\n");
        bwk_qr_request_free(request);
        return 1;
    }

    const bwk_qr_sign *sign = &request->body.sign;
    printf("psbt: %zu bytes, %zu descriptor(s)\n", sign->psbt.len,
           sign->descriptors.len);
    for (size_t i = 0; i < sign->descriptors.len; i++) {
        printf("  descriptor %zu: %s\n", i, sign->descriptors.ptr[i].alias);
    }

    /* A real signer would sign here. This one echoes the PSBT back unchanged. */
    bwk_qr_response response;
    memcpy(response.id, request->id, BWK_QR_REQUEST_ID_LEN);
    response.message_type = BWK_QR_MESSAGE_SIGNING;
    response.is_error = false;
    response.body.signed_body.kind = BWK_QR_SIGN_RESPONSE_PSBT;
    response.body.signed_body.value.psbt = sign->psbt;

    bwk_qr_buf out = {NULL, 0};
    code = bwk_qr_response_encode(&response, &out, &err);
    bwk_qr_request_free(request);
    if (code != BWK_QR_OK) {
        fprintf(stderr, "encode failed (%d): %s\n", code, err);
        return 1;
    }
    printf("response: %zu bytes\n", out.len);
    bwk_qr_buf_free(out);
    return 0;
}
