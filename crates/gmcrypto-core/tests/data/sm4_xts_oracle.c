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
 * Notes:
 *   - SM4-XTS is fetched from the DEFAULT (non-FIPS) provider.
 *   - The 16-byte tweak is passed as the EVP IV directly (raw tweak).
 *   - Padding is disabled (length-preserving); single-shot Update.
 *   - OpenSSL's default provider does NOT reject Key1==Key2; our Rust
 *     API does (IEEE 1619 / FIPS-aligned). So duplicate-key cases are
 *     asserted locally in sm4_xts_kat.rs, not sourced here.
 */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex2bin(const char *h, unsigned char **out, size_t *out_len) {
    size_t l = strlen(h);
    if (l % 2) return -1;
    *out_len = l / 2;
    *out = malloc(*out_len ? *out_len : 1);
    if (!*out) return -1;
    for (size_t i = 0; i < *out_len; i++) {
        unsigned int b;
        if (sscanf(h + 2*i, "%2x", &b) != 1) return -1;
        (*out)[i] = (unsigned char)b;
    }
    return 0;
}

static void print_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(int argc, char **argv) {
    if (argc < 5) {
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

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher) { fprintf(stderr, "SM4-XTS not in OpenSSL\n"); return 1; }

    unsigned char *outbuf = malloc(data_len + 32);
    int ol = 0, fl = 0;

    if (encrypt) {
        if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) { fprintf(stderr, "init fail\n"); return 1; }
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_EncryptUpdate(ctx, outbuf, &ol, data, (int)data_len) != 1) { fprintf(stderr, "update fail\n"); return 1; }
        if (EVP_EncryptFinal_ex(ctx, outbuf + ol, &fl) != 1) { fprintf(stderr, "final fail\n"); return 1; }
    } else {
        if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) { fprintf(stderr, "init fail\n"); return 1; }
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_DecryptUpdate(ctx, outbuf, &ol, data, (int)data_len) != 1) { fprintf(stderr, "update fail\n"); return 1; }
        if (EVP_DecryptFinal_ex(ctx, outbuf + ol, &fl) != 1) { fprintf(stderr, "final fail\n"); return 1; }
    }
    print_hex(outbuf, ol + fl);
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 0;
}
