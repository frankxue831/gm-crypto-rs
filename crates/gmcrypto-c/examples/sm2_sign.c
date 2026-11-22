/*
 * Example: SM2 sign + verify via the gmcrypto-c C ABI.
 *
 * Build (Linux/macOS, dynamic):
 *   gcc -I ../include -L ../../../target/release sm2_sign.c \
 *       -lgmcrypto_c -o sm2_sign
 * Linux:
 *   LD_LIBRARY_PATH=../../../target/release ./sm2_sign
 * macOS:
 *   DYLD_LIBRARY_PATH=../../../target/release ./sm2_sign
 *
 * Build (static):
 *   gcc -I ../include sm2_sign.c \
 *       ../../../target/release/libgmcrypto_c.a -o sm2_sign-static
 *   ./sm2_sign-static
 *
 * CI syntax-checks this example. Link and run it locally to confirm the
 * SM2 signing FFI works end-to-end from C.
 */

#include <stdio.h>
#include <string.h>
#include "gmcrypto.h"

int main(void) {
    /* A pinned 32-byte big-endian SM2 scalar (from GB/T 32918.2 sample). */
    unsigned char d[GMCRYPTO_SM2_SCALAR_SIZE] = {
        0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1,
        0x3F, 0x36, 0xE3, 0x8A, 0xC6, 0xD3, 0x9F, 0x95,
        0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xB5, 0x1A,
        0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8,
    };

    gmcrypto_sm2_privkey_t* sk = gmcrypto_sm2_privkey_new(d);
    if (!sk) {
        fprintf(stderr, "gmcrypto_sm2_privkey_new failed\n");
        return 1;
    }

    /* Derive the public key directly from `sk` via gmcrypto_sm2_privkey_public_key
       and cross-check against the GB/T 32918.2 sample point coordinates. */
    gmcrypto_sm2_pubkey_t* pk = gmcrypto_sm2_privkey_public_key(sk);
    if (!pk) {
        fprintf(stderr, "gmcrypto_sm2_privkey_public_key failed\n");
        GMCRYPTO_ZEROIZE(d, sizeof d);
        gmcrypto_sm2_privkey_free(sk);
        return 1;
    }

    /* Expected X || Y from the GB/T 32918.2 sample:
       X = 09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020
       Y = CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13 */
    unsigned char expected_pub[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE] = {
        0x04,
        0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1,
        0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
        0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
        0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
        0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5,
        0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
        0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
        0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13,
    };
    unsigned char derived_pub[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE] = {0};
    if (gmcrypto_sm2_pubkey_to_sec1_uncompressed(pk, derived_pub) != GMCRYPTO_OK ||
        memcmp(derived_pub, expected_pub, sizeof expected_pub) != 0) {
        fprintf(stderr, "Derived public point mismatch\n");
        GMCRYPTO_ZEROIZE(d, sizeof d);
        gmcrypto_sm2_privkey_free(sk);
        gmcrypto_sm2_pubkey_free(pk);
        return 1;
    }

    const char* msg = "Hello from C via gmcrypto-c!";
    size_t msg_len = strlen(msg);

    unsigned char sig[128];
    size_t sig_len = 0;
    gmcrypto_sm2_hasher_t* hasher = NULL;
    int rc = gmcrypto_sm2_sign(
        sk,
        NULL, 0,             /* default signer ID "1234567812345678" */
        (const unsigned char*)msg, msg_len,
        sig, sizeof sig,
        &sig_len);
    if (rc != GMCRYPTO_OK) {
        fprintf(stderr, "gmcrypto_sm2_sign failed (rc=%d, required=%zu)\n",
                rc, sig_len);
        goto cleanup;
    }

    printf("Signed %zu bytes of message; produced %zu-byte DER signature.\n",
           msg_len, sig_len);

    int v = gmcrypto_sm2_verify(
        pk,
        NULL, 0,
        (const unsigned char*)msg, msg_len,
        sig, sig_len);
    if (v == GMCRYPTO_OK) {
        printf("Signature verified — OK.\n");
    } else {
        fprintf(stderr, "Signature failed to verify.\n");
        rc = 1;
        goto cleanup;
    }

    /* Tamper one bit and re-verify; should fail. */
    sig[5] ^= 1;
    v = gmcrypto_sm2_verify(
        pk,
        NULL, 0,
        (const unsigned char*)msg, msg_len,
        sig, sig_len);
    if (v != GMCRYPTO_OK) {
        printf("Tampered signature correctly rejected.\n");
    } else {
        fprintf(stderr, "BUG: tampered signature accepted!\n");
        rc = 1;
        goto cleanup;
    }

    /* Streaming digest flow: compute e = SM3(Z_A || M) in two chunks and
       cross-verify against single-shot gmcrypto_sm2_verify. */
    hasher = gmcrypto_sm2_hasher_new(pk);
    if (!hasher) {
        fprintf(stderr, "gmcrypto_sm2_hasher_new failed\n");
        rc = 1;
        goto cleanup;
    }
    unsigned char digest[GMCRYPTO_SM3_DIGEST_SIZE] = {0};
    if (gmcrypto_sm2_hasher_update(hasher, (const unsigned char*)msg, 10) != GMCRYPTO_OK ||
        gmcrypto_sm2_hasher_update(hasher, (const unsigned char*)msg + 10, msg_len - 10) != GMCRYPTO_OK) {
        fprintf(stderr, "gmcrypto_sm2_hasher_update failed\n");
        rc = 1;
        goto cleanup;
    }
    /* `_finalize` always consumes and frees `hasher`, even on error; transfer
       ownership to `h` and clear `hasher` so `cleanup` never double-frees. */
    gmcrypto_sm2_hasher_t* h = hasher;
    hasher = NULL;
    if (gmcrypto_sm2_hasher_finalize(h, digest) != GMCRYPTO_OK) {
        fprintf(stderr, "gmcrypto_sm2_hasher_finalize failed\n");
        rc = 1;
        goto cleanup;
    }
    unsigned char digest_sig[128];
    size_t digest_sig_len = 0;
    if (gmcrypto_sm2_sign_digest(sk, digest, digest_sig, sizeof digest_sig, &digest_sig_len) != GMCRYPTO_OK ||
        gmcrypto_sm2_verify_digest(pk, digest, digest_sig, digest_sig_len) != GMCRYPTO_OK ||
        gmcrypto_sm2_verify(pk, NULL, 0, (const unsigned char*)msg, msg_len, digest_sig, digest_sig_len) != GMCRYPTO_OK) {
        fprintf(stderr, "Streaming digest sign/verify failed\n");
        rc = 1;
    } else {
        printf("Streaming digest sign + verify cross-check — OK.\n");
    }

cleanup:
    /* Best-effort scrub of the raw private-scalar copy still in our stack
       buffer. The opaque key created from it is zeroized on free, but this
       caller-owned copy is our responsibility — see GMCRYPTO_ZEROIZE in
       gmcrypto.h. (Prefer a platform secure-zero where available.) */
    GMCRYPTO_ZEROIZE(d, sizeof d);
    gmcrypto_sm2_hasher_free(hasher);
    gmcrypto_sm2_privkey_free(sk);
    gmcrypto_sm2_pubkey_free(pk);
    return rc;
}
