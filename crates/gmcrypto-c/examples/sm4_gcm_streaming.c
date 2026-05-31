/*
 * Example: SM4-GCM streaming (incremental-input) AEAD via the gmcrypto-c
 * C ABI. Encrypt a message in two chunks, then decrypt it in
 * differently-sized chunks and verify the tag.
 *
 * Requires the library built with the `sm4-aead` feature:
 *   cargo build -p gmcrypto-c --release   /* AEAD+XTS are always-on (v0.23) */
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      sm4_gcm_streaming.c -o sm4_gcm_streaming
 *   LD_LIBRARY_PATH=../../../target/release ./sm4_gcm_streaming
 *
 * Build (static):
 *   cc -I ../include sm4_gcm_streaming.c \
 *      ../../../target/release/libgmcrypto_c.a -o sm4_gcm_streaming-static
 *   ./sm4_gcm_streaming-static
 *
 * Per v0.4 W4 / Q4.14, this example is documentation-only; CI does not
 * build C examples. Run locally to confirm the streaming AEAD FFI works
 * end-to-end from C.
 *
 * Asymmetry to note: the ENCRYPTOR is output-streaming (each _update
 * returns the ciphertext for that chunk); the DECRYPTOR is
 * output-buffered / commit-on-verify (each _update emits nothing, and
 * the plaintext is released only by _finalize_verify after the tag
 * checks out).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gmcrypto.h"

int main(void) {
    uint8_t key[16];
    memset(key, 0x42, sizeof key);
    uint8_t nonce[12];
    memset(nonce, 0x01, sizeof nonce);
    const uint8_t aad[] = "header";
    const uint8_t pt[] = "streamed in two chunks across a block edge";
    size_t pt_len = sizeof(pt) - 1; /* drop the trailing NUL */

    /* ---- encrypt (two chunks) ---- */
    gmcrypto_sm4_gcm_encryptor_t *enc =
        gmcrypto_sm4_gcm_encryptor_new(key, nonce, sizeof nonce, aad, sizeof(aad) - 1);
    if (!enc) {
        fprintf(stderr, "encryptor_new failed\n");
        return 1;
    }

    uint8_t ct[128];
    size_t ct_len = 0, n = 0;
    size_t split = 20; /* first chunk 20 bytes, rest after */
    if (gmcrypto_sm4_gcm_encryptor_update(enc, pt, split, ct, sizeof ct, &n) != 0) {
        gmcrypto_sm4_gcm_encryptor_free(enc); /* _update does NOT consume on error */
        return 1;
    }
    ct_len += n;
    if (gmcrypto_sm4_gcm_encryptor_update(enc, pt + split, pt_len - split, ct + ct_len,
                                          sizeof ct - ct_len, &n) != 0) {
        gmcrypto_sm4_gcm_encryptor_free(enc);
        return 1;
    }
    ct_len += n;

    uint8_t tag[16];
    if (gmcrypto_sm4_gcm_encryptor_finalize(enc, tag) != 0) {
        return 1; /* this call frees enc */
    }

    /* ---- decrypt (different chunking: 16 bytes at a time) ---- */
    gmcrypto_sm4_gcm_decryptor_t *dec =
        gmcrypto_sm4_gcm_decryptor_new(key, nonce, sizeof nonce, aad, sizeof(aad) - 1);
    if (!dec) {
        return 1;
    }
    for (size_t off = 0; off < ct_len; off += 16) {
        size_t take = (ct_len - off < 16) ? (ct_len - off) : 16;
        if (gmcrypto_sm4_gcm_decryptor_update(dec, ct + off, take) != 0) {
            gmcrypto_sm4_gcm_decryptor_free(dec); /* _update does NOT consume on error */
            return 1;
        }
    }

    uint8_t out[128];
    size_t out_len = 0;
    /* commit-on-verify: plaintext appears only if the tag checks out */
    if (gmcrypto_sm4_gcm_decryptor_finalize_verify(dec, tag, sizeof tag, out, sizeof out,
                                                   &out_len) != 0) {
        fprintf(stderr, "verify failed\n");
        return 1; /* this call frees dec */
    }

    if (out_len == pt_len && memcmp(out, pt, pt_len) == 0) {
        printf("OK: round-tripped %zu bytes through streaming SM4-GCM\n", out_len);
        return 0;
    }
    fprintf(stderr, "mismatch\n");
    return 1;
}
