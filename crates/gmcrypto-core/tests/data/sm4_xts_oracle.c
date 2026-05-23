/* SM4-XTS reference oracle via OpenSSL 3.x libcrypto EVP API.
 *
 * Used to derive KAT vectors for gm-crypto-rs v0.12 SM4-XTS mode_xts.
 * Reproducibility: see docs/v0.12-xts-kat-sourcing.md.
 *
 * Build:  cc -O2 -I$(brew --prefix openssl@3)/include sm4_xts_oracle.c \
 *             $(brew --prefix openssl@3)/lib/libcrypto.dylib -o sm4_xts_oracle
 *
 * Encrypt usage:
 *   ./sm4_xts_oracle enc <key-hex-32B> <tweak-hex-16B> <pt-hex>
 *   -> prints ciphertext-hex  (same length as plaintext; XTS is length-preserving)
 *
 * Decrypt usage:
 *   ./sm4_xts_oracle dec <key-hex-32B> <tweak-hex-16B> <ct-hex>
 *   -> prints plaintext-hex
 *
 * Standard variant:
 *   SM4-XTS is the GB/T 17964-2021 national standard mode. OpenSSL 3.x
 *   exposes an `xts_standard` parameter with values {"GB", "IEEE"} that
 *   change BOTH the GF(2^128) tweak-doubling convention and the
 *   ciphertext-stealing layout (whole-block block 0 is the only output
 *   that coincides). This harness PINS `xts_standard=GB` explicitly so the
 *   vectors are deterministic regardless of the OpenSSL build's default,
 *   and so it matches gm-crypto-rs `sm4::mode_xts` (GB/T 17964-2021).
 *
 * Notes:
 *   - Fetched from the DEFAULT (non-FIPS) provider.
 *   - 32-byte key = Key1||Key2; the 16-byte tweak is the EVP IV (raw).
 *   - Padding disabled (length-preserving); single-shot Update + Final.
 *   - OpenSSL's default provider does NOT reject Key1==Key2; our Rust API
 *     does (GB/T 17964 / FIPS-aligned). Duplicate-key cases are asserted
 *     locally in mode_xts unit tests, not sourced here.
 */
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Strict hex decode: rejects odd length and any non-hex digit. */
static int hex2bin(const char *h, unsigned char **out, size_t *out_len) {
    size_t l = strlen(h);
    if (l % 2) return -1;
    *out_len = l / 2;
    *out = malloc(*out_len ? *out_len : 1);
    if (!*out) return -1;
    for (size_t i = 0; i < *out_len; i++) {
        int hi = hexval(h[2 * i]);
        int lo = hexval(h[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(*out); *out = NULL; return -1; }
        (*out)[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static void print_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(int argc, char **argv) {
    if (argc != 5 || (strcmp(argv[1], "enc") != 0 && strcmp(argv[1], "dec") != 0)) {
        fprintf(stderr, "usage: %s enc|dec key32 tweak16 data\n", argv[0]);
        return 2;
    }
    int encrypt = (strcmp(argv[1], "enc") == 0);

    unsigned char *key, *iv, *data;
    size_t key_len, iv_len, data_len;
    if (hex2bin(argv[2], &key, &key_len) ||
        hex2bin(argv[3], &iv, &iv_len) ||
        hex2bin(argv[4], &data, &data_len)) {
        fprintf(stderr, "hex decode failed\n");
        return 2;
    }
    if (key_len != 32) { fprintf(stderr, "key must be 32 bytes (Key1||Key2)\n"); return 2; }
    if (iv_len != 16) { fprintf(stderr, "tweak must be 16 bytes\n"); return 2; }
    if (data_len < 16 || data_len > (size_t)INT_MAX) {
        fprintf(stderr, "data must be 16..INT_MAX bytes\n"); return 2;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher) { fprintf(stderr, "SM4-XTS not in OpenSSL\n"); return 1; }

    /* Pin the GB/T 17964-2021 variant (default may vary by build). */
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_XTS_STANDARD, "GB", 0);
    params[1] = OSSL_PARAM_construct_end();

    unsigned char *outbuf = malloc(data_len + 32);
    if (!outbuf) { fprintf(stderr, "oom\n"); return 1; }
    int ol = 0, fl = 0;

    if (encrypt) {
        if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, params) != 1) { fprintf(stderr, "init fail\n"); return 1; }
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) { fprintf(stderr, "padding fail\n"); return 1; }
        if (EVP_EncryptUpdate(ctx, outbuf, &ol, data, (int)data_len) != 1) { fprintf(stderr, "update fail\n"); return 1; }
        if (EVP_EncryptFinal_ex(ctx, outbuf + ol, &fl) != 1) { fprintf(stderr, "final fail\n"); return 1; }
    } else {
        if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, params) != 1) { fprintf(stderr, "init fail\n"); return 1; }
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) { fprintf(stderr, "padding fail\n"); return 1; }
        if (EVP_DecryptUpdate(ctx, outbuf, &ol, data, (int)data_len) != 1) { fprintf(stderr, "update fail\n"); return 1; }
        if (EVP_DecryptFinal_ex(ctx, outbuf + ol, &fl) != 1) { fprintf(stderr, "final fail\n"); return 1; }
    }
    print_hex(outbuf, (size_t)(ol + fl));
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 0;
}
