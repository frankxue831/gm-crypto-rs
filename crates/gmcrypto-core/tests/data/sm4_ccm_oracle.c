/* SM4-CCM reference oracle via OpenSSL 3.x libcrypto EVP API.
 *
 * Used to derive KAT vectors for gm-crypto-rs v0.8 SM4-CCM mode_ccm.
 * Reproducibility: see docs/v0.8-ccm-kat-sourcing.md.
 *
 * Build:  cc -I$(brew --prefix openssl@3)/include sm4_ccm_oracle.c \
 *             $(brew --prefix openssl@3)/lib/libcrypto.dylib -o sm4_ccm_oracle
 *
 * Encrypt usage:
 *   ./sm4_ccm_oracle enc <key-hex> <nonce-hex> <aad-hex> <pt-hex> <tag-len-bytes>
 *   -> prints ciphertext-hex tag-hex
 *
 * Decrypt usage:
 *   ./sm4_ccm_oracle dec <key-hex> <nonce-hex> <aad-hex> <ct-hex> <tag-hex>
 *   -> prints plaintext-hex (or "TAG_FAIL")
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
    if (argc < 7) {
        fprintf(stderr, "usage: %s enc|dec key nonce aad data tag_len_or_tag\n", argv[0]);
        return 2;
    }
    int encrypt = (strcmp(argv[1], "enc") == 0);

    unsigned char *key, *nonce, *aad, *data, *tag = NULL;
    size_t key_len, nonce_len, aad_len, data_len, tag_len;
    if (hex2bin(argv[2], &key, &key_len) ||
        hex2bin(argv[3], &nonce, &nonce_len) ||
        hex2bin(argv[4], &aad, &aad_len) ||
        hex2bin(argv[5], &data, &data_len)) {
        fprintf(stderr, "hex decode failed\n");
        return 2;
    }
    if (encrypt) {
        tag_len = (size_t)atoi(argv[6]);
    } else {
        if (hex2bin(argv[6], &tag, &tag_len)) { fprintf(stderr, "tag hex bad\n"); return 2; }
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;
    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-CCM", NULL);
    if (!cipher) { fprintf(stderr, "SM4-CCM not in OpenSSL\n"); return 1; }

    int outl = 0;
    unsigned char *outbuf = malloc(data_len + tag_len + 16);

    if (encrypt) {
        EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, NULL);
        EVP_EncryptInit_ex2(ctx, NULL, key, nonce, NULL);
        /* CCM needs total plaintext length up front */
        EVP_EncryptUpdate(ctx, NULL, &outl, NULL, (int)data_len);
        if (aad_len) EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);
        int ct_len = 0;
        EVP_EncryptUpdate(ctx, outbuf, &ct_len, data, (int)data_len);
        int final_len = 0;
        EVP_EncryptFinal_ex(ctx, outbuf + ct_len, &final_len);
        ct_len += final_len;
        unsigned char tag_buf[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)tag_len, tag_buf);
        print_hex(outbuf, ct_len);
        printf(" ");
        print_hex(tag_buf, tag_len);
        printf("\n");
    } else {
        EVP_DecryptInit_ex2(ctx, cipher, NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, tag);
        EVP_DecryptInit_ex2(ctx, NULL, key, nonce, NULL);
        EVP_DecryptUpdate(ctx, NULL, &outl, NULL, (int)data_len);
        if (aad_len) EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);
        int pt_len = 0;
        int rv = EVP_DecryptUpdate(ctx, outbuf, &pt_len, data, (int)data_len);
        if (rv <= 0) { printf("TAG_FAIL\n"); EVP_CIPHER_CTX_free(ctx); return 0; }
        print_hex(outbuf, pt_len);
        printf("\n");
    }
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 0;
}
