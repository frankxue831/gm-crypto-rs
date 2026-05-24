/*
 * Example: SM4-XTS single-shot tweakable-mode encryption via the
 * gmcrypto-c C ABI. Encrypt a 512-byte "disk sector" and decrypt it back,
 * using the sector number as the 16-byte tweak (GB/T 17964-2021).
 *
 * Requires the library built with the `sm4-xts` feature:
 *   cargo build -p gmcrypto-c --release --features sm4-xts
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      sm4_xts_sector.c -o sm4_xts_sector
 *   LD_LIBRARY_PATH=../../../target/release ./sm4_xts_sector
 *
 * Build (static):
 *   cc -I ../include sm4_xts_sector.c \
 *      ../../../target/release/libgmcrypto_c.a -o sm4_xts_sector-static
 *   ./sm4_xts_sector-static
 *
 * Per v0.4 W4 / Q4.14, this example is documentation-only; CI does not
 * build C examples. Run locally to confirm the SM4-XTS FFI works end-to-end.
 *
 * Notes:
 *   - The key is 32 bytes = Key1 || Key2 (two distinct 128-bit keys;
 *     Key1 == Key2 is rejected with GMCRYPTO_ERR).
 *   - The tweak is 16 raw bytes, conventionally the data-unit / sector
 *     number. It MUST be unique per sector under a given key (it is the
 *     caller's contract, exactly like a sector address) — reuse leaks
 *     equality structure.
 *   - SM4-XTS is CONFIDENTIALITY ONLY: there is no authentication tag,
 *     so it cannot detect tampering. Use an AEAD mode (SM4-GCM/CCM) if
 *     you need integrity.
 *   - Output length always equals input length (length-preserving).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gmcrypto.h"

/* Encode a 64-bit sector number as a 16-byte little-endian tweak. */
static void sector_tweak(uint64_t sector, uint8_t tweak[16]) {
    memset(tweak, 0, 16);
    for (int i = 0; i < 8; i++) {
        tweak[i] = (uint8_t)(sector >> (8 * i));
    }
}

int main(void) {
    /* 32-byte key = Key1 (0x11..) || Key2 (0x22..). */
    uint8_t key[GMCRYPTO_SM4_XTS_KEY_SIZE];
    memset(key, 0x11, 16);
    memset(key + 16, 0x22, 16);

    uint8_t tweak[GMCRYPTO_SM4_BLOCK_SIZE];
    sector_tweak(42, tweak); /* this sector's number */

    uint8_t sector[512];
    for (size_t i = 0; i < sizeof sector; i++) {
        sector[i] = (uint8_t)i;
    }

    /* ---- encrypt the sector ---- */
    uint8_t ct[512];
    size_t ct_len = 0;
    if (gmcrypto_sm4_xts_encrypt(key, tweak, sector, sizeof sector, ct, sizeof ct, &ct_len) !=
        GMCRYPTO_OK) {
        fprintf(stderr, "xts encrypt failed\n");
        return 1;
    }

    /* ---- decrypt it back (same key + tweak) ---- */
    uint8_t out[512];
    size_t out_len = 0;
    if (gmcrypto_sm4_xts_decrypt(key, tweak, ct, ct_len, out, sizeof out, &out_len) !=
        GMCRYPTO_OK) {
        fprintf(stderr, "xts decrypt failed\n");
        return 1;
    }

    if (out_len == sizeof sector && memcmp(out, sector, sizeof sector) == 0) {
        printf("OK: round-tripped a %zu-byte sector through SM4-XTS\n", out_len);
        return 0;
    }
    fprintf(stderr, "mismatch\n");
    return 1;
}
