/*
 * Example: SM4-XTS multi-sector ("disk region") encryption via the
 * gmcrypto-c C ABI. Encrypt a contiguous run of equal-size 512-byte sectors
 * IN PLACE and decrypt it back in place, using the helper that derives each
 * sector's tweak from a running sector number (GB/T 17964-2021).
 *
 * Contrast with sm4_xts_sector.c (the single-shot, out-of-place, one-data-unit
 * API): here one call covers N sectors, the buffer is transformed in place
 * (no second allocation — the disk-encryption use case), and the per-sector
 * tweak is derived automatically as little-endian-128(start_sector + i).
 *
 * Requires the library built with the `sm4-xts` feature:
 *   cargo build -p gmcrypto-c --release --features sm4-xts
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      sm4_xts_multisector.c -o sm4_xts_multisector
 *   LD_LIBRARY_PATH=../../../target/release ./sm4_xts_multisector
 *
 * Build (static):
 *   cc -I ../include sm4_xts_multisector.c \
 *      ../../../target/release/libgmcrypto_c.a -o sm4_xts_multisector-static
 *   ./sm4_xts_multisector-static
 *
 * Per v0.4 W4 / Q4.14, this example is documentation-only; CI does not build
 * C examples. Run locally to confirm the SM4-XTS sector FFI works end-to-end.
 *
 * Notes:
 *   - The key is 32 bytes = Key1 || Key2 (two distinct 128-bit keys;
 *     Key1 == Key2 is rejected with GMCRYPTO_ERR).
 *   - `start_sector` is a uint64_t logical block address (LBA); sector i in
 *     the run is encrypted under tweak = LE-128(start_sector + i). Sector
 *     numbers MUST be unique within an XTS-key namespace: do NOT encrypt
 *     multiple devices / partitions / snapshots under one key all starting at
 *     sector 0 — use absolute LBAs or a separate key per device. Reuse leaks
 *     block-equality structure.
 *   - The transform is IN PLACE: `buf` is both input and output. `buf_len`
 *     must be a whole multiple of `sector_size`. On GMCRYPTO_ERR (bad
 *     sector_size, bad buf_len multiple, weak key, null), `buf` is untouched.
 *   - SM4-XTS is CONFIDENTIALITY ONLY: there is no authentication tag, so it
 *     cannot detect tampering. Use an AEAD mode (SM4-GCM/CCM) for integrity.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gmcrypto.h"

#define SECTOR_SIZE 512
#define SECTOR_COUNT 8

int main(void) {
    /* 32-byte key = Key1 (0x11..) || Key2 (0x22..). */
    uint8_t key[GMCRYPTO_SM4_XTS_KEY_SIZE];
    memset(key, 0x11, 16);
    memset(key + 16, 0x22, 16);

    /* A contiguous 8-sector (4 KiB) region starting at LBA 2048. */
    const uint64_t start_sector = 2048;
    uint8_t buf[SECTOR_SIZE * SECTOR_COUNT];
    for (size_t i = 0; i < sizeof buf; i++) {
        buf[i] = (uint8_t)i;
    }

    uint8_t original[SECTOR_SIZE * SECTOR_COUNT];
    memcpy(original, buf, sizeof buf);

    /* ---- encrypt the whole region in place ---- */
    if (gmcrypto_sm4_xts_encrypt_sectors(key, SECTOR_SIZE, start_sector, buf,
                                         sizeof buf) != GMCRYPTO_OK) {
        fprintf(stderr, "xts encrypt_sectors failed\n");
        return 1;
    }

    if (memcmp(buf, original, sizeof buf) == 0) {
        fprintf(stderr, "ciphertext == plaintext (unexpected)\n");
        return 1;
    }

    /* ---- decrypt it back in place (same key + start_sector) ---- */
    if (gmcrypto_sm4_xts_decrypt_sectors(key, SECTOR_SIZE, start_sector, buf,
                                         sizeof buf) != GMCRYPTO_OK) {
        fprintf(stderr, "xts decrypt_sectors failed\n");
        return 1;
    }

    if (memcmp(buf, original, sizeof buf) == 0) {
        printf("OK: round-tripped %d sectors x %d bytes in place through SM4-XTS\n",
               SECTOR_COUNT, SECTOR_SIZE);
        return 0;
    }
    fprintf(stderr, "mismatch after round-trip\n");
    return 1;
}
