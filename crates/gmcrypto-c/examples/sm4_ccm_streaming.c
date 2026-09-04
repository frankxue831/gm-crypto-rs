/*
 * Example: SM4-CCM length-committed streaming AEAD via the gmcrypto-c C
 * ABI (v1.13). Commit to the plaintext length, encrypt in two chunks,
 * decrypt in differently-sized chunks and verify the tag, then show that
 * an UNDER-FED encryptor refuses to emit a tag.
 *
 * Build the library first. The AEAD symbols are always-on in gmcrypto-c,
 * so a default release build exports them — no feature flag:
 *   cargo build -p gmcrypto-c --release
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release sm4_ccm_streaming.c \
 *      -lgmcrypto_c -o sm4_ccm_streaming
 * Linux:
 *   LD_LIBRARY_PATH=../../../target/release ./sm4_ccm_streaming
 * macOS:
 *   DYLD_LIBRARY_PATH=../../../target/release ./sm4_ccm_streaming
 *
 * Build (static):
 *   cc -I ../include sm4_ccm_streaming.c \
 *      ../../../target/release/libgmcrypto_c.a -o sm4_ccm_streaming-static
 *   ./sm4_ccm_streaming-static
 *
 * CI syntax-checks this example. Link and run it locally to confirm the
 * streaming SM4-CCM FFI works end-to-end from C.
 *
 * Two things to notice versus the SM4-GCM streaming example:
 *   - The ENCRYPTOR commits to plaintext_len and tag_len at _new (CCM
 *     encodes both in its first CBC-MAC block). Feeding fewer bytes than
 *     committed makes _finalize fail; feeding more poisons the handle.
 *   - The DECRYPTOR is incremental-input BUFFERED, not streaming: each
 *     _update emits nothing, and the plaintext is released only by
 *     _finalize_verify after the tag checks out.
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
    const uint8_t pt[] = "a payload whose length the header already told us";
    size_t pt_len = sizeof(pt) - 1; /* drop the trailing NUL */
    const size_t tag_len = 16;

    /* ---- encrypt (commit to pt_len, then two chunks) ---- */
    gmcrypto_sm4_ccm_encryptor_t *enc = gmcrypto_sm4_ccm_encryptor_new(
        key, nonce, sizeof nonce, aad, sizeof(aad) - 1, pt_len, tag_len);
    if (!enc) {
        fprintf(stderr, "encryptor_new failed\n");
        return 1;
    }

    uint8_t ct[128];
    size_t ct_len = 0, n = 0;
    size_t split = 20; /* first chunk 20 bytes, rest after */
    if (gmcrypto_sm4_ccm_encryptor_update(enc, pt, split, ct, sizeof ct, &n) != 0) {
        gmcrypto_sm4_ccm_encryptor_free(enc); /* _update does NOT consume on error */
        return 1;
    }
    ct_len += n;
    if (gmcrypto_sm4_ccm_encryptor_update(enc, pt + split, pt_len - split, ct + ct_len,
                                          sizeof ct - ct_len, &n) != 0) {
        gmcrypto_sm4_ccm_encryptor_free(enc);
        return 1;
    }
    ct_len += n;

    uint8_t tag[16];
    size_t tag_out_len = 0;
    if (gmcrypto_sm4_ccm_encryptor_finalize(enc, tag, sizeof tag, &tag_out_len) != 0) {
        return 1; /* this call frees enc on every path */
    }

    /* ---- decrypt (buffered; different chunking: 16 bytes at a time) ---- */
    gmcrypto_sm4_ccm_decryptor_t *dec =
        gmcrypto_sm4_ccm_decryptor_new(key, nonce, sizeof nonce, aad, sizeof(aad) - 1);
    if (!dec) {
        return 1;
    }
    for (size_t off = 0; off < ct_len; off += 16) {
        size_t take = (ct_len - off < 16) ? (ct_len - off) : 16;
        if (gmcrypto_sm4_ccm_decryptor_update(dec, ct + off, take) != 0) {
            gmcrypto_sm4_ccm_decryptor_free(dec); /* _update does NOT consume on error */
            return 1;
        }
    }

    uint8_t out[128];
    size_t out_len = 0;
    /* commit-on-verify: plaintext appears only if the tag checks out */
    if (gmcrypto_sm4_ccm_decryptor_finalize_verify(dec, tag, tag_out_len, out, sizeof out,
                                                   &out_len) != 0) {
        fprintf(stderr, "verify failed\n");
        return 1; /* this call frees dec */
    }
    if (out_len != pt_len || memcmp(out, pt, pt_len) != 0) {
        fprintf(stderr, "mismatch\n");
        return 1;
    }

    /* ---- the length commitment: an under-fed encryptor emits no tag ---- */
    /* A fresh nonce for the second encryptor: never reuse (key, nonce), even
     * for a demonstration — the same pair with a different length is still a
     * nonce reuse. */
    nonce[0] ^= 0x80;
    gmcrypto_sm4_ccm_encryptor_t *short_enc = gmcrypto_sm4_ccm_encryptor_new(
        key, nonce, sizeof nonce, aad, sizeof(aad) - 1, pt_len, tag_len);
    if (!short_enc) {
        return 1;
    }
    if (gmcrypto_sm4_ccm_encryptor_update(short_enc, pt, split, ct, sizeof ct, &n) != 0) {
        gmcrypto_sm4_ccm_encryptor_free(short_enc);
        return 1;
    }
    size_t rejected_len = 99;
    if (gmcrypto_sm4_ccm_encryptor_finalize(short_enc, tag, sizeof tag, &rejected_len) == 0 ||
        rejected_len != 0) {
        fprintf(stderr, "under-fed encryptor must not emit a tag\n");
        return 1; /* short_enc is freed by _finalize either way */
    }

    printf("OK: round-tripped %zu bytes through length-committed streaming SM4-CCM; "
           "under-feed rejected\n", out_len);
    return 0;
}
