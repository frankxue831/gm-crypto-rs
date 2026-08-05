/*
 * Example: SM4-CCM single-shot AEAD via the gmcrypto-c C ABI. Encrypt a
 * short message with associated data, decrypt it back, and then show that a
 * tampered tag is REJECTED — which is the whole point of an AEAD mode.
 *
 * Build the library first. Since v0.23 the AEAD symbols are always-on in
 * gmcrypto-c, so a default release build exports them — no feature flag:
 *   cargo build -p gmcrypto-c --release
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      sm4_ccm.c -o sm4_ccm
 *   LD_LIBRARY_PATH=../../../target/release ./sm4_ccm
 *
 * Build (static):
 *   cc -I ../include sm4_ccm.c \
 *      ../../../target/release/libgmcrypto_c.a -o sm4_ccm-static
 *   ./sm4_ccm-static
 *
 * Per v0.4 W4 / Q4.14, this example is documentation-only; CI does not
 * build C examples. Run locally to confirm the SM4-CCM FFI works end-to-end.
 *
 * How CCM differs from the SM4-GCM examples next door:
 *   - It is SINGLE-SHOT only. There is no incremental encryptor/decryptor
 *     pair and no opaque handle — one call each way.
 *   - The tag is NOT a separate out-parameter. `_encrypt` writes
 *     `ciphertext || tag` into ONE buffer of `pt_len + tag_len` bytes, and
 *     `_decrypt` takes that same combined buffer plus the `tag_len` that
 *     was used at encrypt time. Passing a different `tag_len` on decrypt
 *     is a failure, not a shorter tag check.
 *
 * Parameter domains (outside these ranges → GMCRYPTO_ERR, never UB):
 *   - `tag_len`   in {4, 6, 8, 10, 12, 14, 16} bytes.
 *   - `nonce_len` in [7, 13] bytes.
 *   - The nonce MUST be unique per message under a given key; reuse breaks
 *     confidentiality AND authenticity. It need not be secret.
 *   - `aad` is authenticated but not encrypted, and is never emitted — the
 *     receiver must already have it (here: a fixed header).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gmcrypto.h"

#define TAG_LEN 16

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%-12s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("  (%zu bytes)\n", len);
}

int main(void) {
    uint8_t key[GMCRYPTO_SM4_KEY_SIZE];
    memset(key, 0x42, sizeof key);

    /* 12 bytes is a common choice; anything in [7, 13] is accepted. */
    uint8_t nonce[12];
    memset(nonce, 0x01, sizeof nonce);

    const uint8_t aad[] = "header: authenticated, not encrypted";
    const size_t aad_len = sizeof(aad) - 1; /* drop the trailing NUL */
    const uint8_t pt[] = "attack at dawn";
    const size_t pt_len = sizeof(pt) - 1;

    /* ---- encrypt: out receives ciphertext || tag ---- */
    uint8_t out[64];
    size_t out_len = 0;
    if (gmcrypto_sm4_ccm_encrypt(key, nonce, sizeof nonce, aad, aad_len, pt, pt_len, TAG_LEN, out,
                                 sizeof out, &out_len) != GMCRYPTO_OK) {
        fprintf(stderr, "ccm encrypt failed\n");
        return 1;
    }
    if (out_len != pt_len + TAG_LEN) {
        fprintf(stderr, "unexpected output length %zu\n", out_len);
        return 1;
    }

    /* Print the two halves separately so the ct||tag layout is visible. */
    print_hex("ciphertext:", out, pt_len);
    print_hex("tag:", out + pt_len, TAG_LEN);

    /* ---- decrypt: feed back the WHOLE ct||tag buffer + the same tag_len ---- */
    uint8_t back[64];
    size_t back_len = 0;
    if (gmcrypto_sm4_ccm_decrypt(key, nonce, sizeof nonce, aad, aad_len, out, out_len, TAG_LEN,
                                 back, sizeof back, &back_len) != GMCRYPTO_OK) {
        fprintf(stderr, "ccm decrypt failed\n");
        return 1;
    }
    if (back_len != pt_len || memcmp(back, pt, pt_len) != 0) {
        fprintf(stderr, "round-trip mismatch\n");
        return 1;
    }
    printf("OK: round-tripped %zu bytes through SM4-CCM\n", back_len);

    /* ---- tamper: flip one bit of the tag; decrypt MUST refuse ---- */
    uint8_t tampered[64];
    memcpy(tampered, out, out_len);
    tampered[out_len - 1] ^= 0x01; /* last byte of the tag */

    uint8_t never[64];
    size_t never_len = 0;
    /*
     * A non-zero return is the ONLY thing a caller may conclude. Per the
     * failure-mode invariant every failure — bad tag, bad AAD, wrong nonce,
     * bad tag_len, too-small output buffer — returns the same opaque
     * GMCRYPTO_ERR. Do not branch on the value; distinguishing them is
     * precisely the oracle this API refuses to provide.
     */
    if (gmcrypto_sm4_ccm_decrypt(key, nonce, sizeof nonce, aad, aad_len, tampered, out_len, TAG_LEN,
                                 never, sizeof never, &never_len) == GMCRYPTO_OK) {
        fprintf(stderr, "FAIL: a tampered tag was accepted\n");
        return 1;
    }
    printf("OK: tampered tag rejected (no plaintext released)\n");

    /* The same refusal covers a tampered CIPHERTEXT byte. */
    memcpy(tampered, out, out_len);
    tampered[0] ^= 0x01;
    if (gmcrypto_sm4_ccm_decrypt(key, nonce, sizeof nonce, aad, aad_len, tampered, out_len, TAG_LEN,
                                 never, sizeof never, &never_len) == GMCRYPTO_OK) {
        fprintf(stderr, "FAIL: a tampered ciphertext was accepted\n");
        return 1;
    }
    printf("OK: tampered ciphertext rejected\n");

    /* ...and a modified AAD, which is authenticated even though it is not sent. */
    const uint8_t wrong_aad[] = "header: authenticated, not encrypteD";
    if (gmcrypto_sm4_ccm_decrypt(key, nonce, sizeof nonce, wrong_aad, sizeof(wrong_aad) - 1, out,
                                 out_len, TAG_LEN, never, sizeof never, &never_len) ==
        GMCRYPTO_OK) {
        fprintf(stderr, "FAIL: a modified AAD was accepted\n");
        return 1;
    }
    printf("OK: modified AAD rejected\n");

    GMCRYPTO_ZEROIZE(key, sizeof key);
    return 0;
}
