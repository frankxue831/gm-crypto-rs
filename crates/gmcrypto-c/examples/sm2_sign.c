/*
 * Example: SM2 sign + verify via the gmcrypto-c C ABI.
 *
 * Build (Linux/macOS, dynamic):
 *   gcc -I ../include -L ../../../target/release -lgmcrypto_c \
 *       sm2_sign.c -o sm2_sign
 *   LD_LIBRARY_PATH=../../../target/release ./sm2_sign
 *
 * Build (static):
 *   gcc -I ../include sm2_sign.c \
 *       ../../../target/release/libgmcrypto_c.a -o sm2_sign-static
 *   ./sm2_sign-static
 *
 * Per v0.4 W4 / Q4.14, this example is documentation-only; CI does
 * not build C examples (no C toolchain pinned in the workflow). Run
 * locally to confirm the FFI surface works end-to-end from C.
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

    /* Derive the public-key bytes by exporting the private key's
       embedded scalar, then ask gmcrypto-core to recompute the
       public point. We could also pass a precomputed
       `04||X||Y` here. */
    unsigned char pub_bytes[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE] = {0};
    /* TODO: a `gmcrypto_sm2_privkey_to_pubkey` entry point would
       be a nice addition in v0.5; for now we rely on the Rust-side
       reconstruction via PKCS#8 round-trip or by deriving from a
       known test vector. For brevity, this example pins the
       public-key bytes from the GB/T 32918.2 sample. */
    /* X = 09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020
       Y = CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13 */
    pub_bytes[0] = 0x04;
    unsigned char x[32] = {
        0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1,
        0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
        0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
        0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    };
    unsigned char y[32] = {
        0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5,
        0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
        0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
        0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13,
    };
    memcpy(pub_bytes + 1, x, 32);
    memcpy(pub_bytes + 33, y, 32);

    gmcrypto_sm2_pubkey_t* pk = gmcrypto_sm2_pubkey_new(pub_bytes);
    if (!pk) {
        fprintf(stderr, "gmcrypto_sm2_pubkey_new failed (off-curve?)\n");
        gmcrypto_sm2_privkey_free(sk);
        return 1;
    }

    const char* msg = "Hello from C via gmcrypto-c!";
    size_t msg_len = strlen(msg);

    unsigned char sig[128];
    size_t sig_len = 0;
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
    }

cleanup:
    /* Best-effort scrub of the raw private-scalar copy still in our stack
       buffer. The opaque key created from it is zeroized on free, but this
       caller-owned copy is our responsibility — see GMCRYPTO_ZEROIZE in
       gmcrypto.h. (Prefer a platform secure-zero where available.) */
    GMCRYPTO_ZEROIZE(d, sizeof d);
    gmcrypto_sm2_privkey_free(sk);
    gmcrypto_sm2_pubkey_free(pk);
    return rc;
}
