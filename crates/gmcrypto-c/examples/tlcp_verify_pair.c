/*
 * Example: TLCP [signature, encryption] certificate-pair verification through
 * the gmcrypto-c C ABI (v1.9). Loads four DER certificates — the sign leaf,
 * the enc leaf, their shared intermediate CA, and the trusted root — builds
 * the two leaf-first chains, and asks gmcrypto_tlcp_verify_pair whether the
 * pair links to the trusted root and is usable for its TLCP roles.
 *
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      tlcp_verify_pair.c -o tlcp_verify_pair
 *   LD_LIBRARY_PATH=../../../target/release ./tlcp_verify_pair \
 *      sign.der enc.der int.der root.der
 *
 * With the committed gmssl fixtures (run from this directory):
 *   ./tlcp_verify_pair \
 *      ../../gmcrypto-core/tests/data/x509_chain_sign.der \
 *      ../../gmcrypto-core/tests/data/x509_chain_enc.der \
 *      ../../gmcrypto-core/tests/data/x509_chain_int.der \
 *      ../../gmcrypto-core/tests/data/x509_chain_root.der
 *
 * Documentation-only (Q4.14): CI does not build C examples.
 *
 * *** READ THIS ***: a `1` here is STRUCTURAL trust — each chain links to the
 * trusted root and each leaf is usable for its TLCP role. It is NOT endpoint
 * authentication: it does NOT say "this is the server I dialed". Binding the
 * pair to the expected peer identity is the CALLER's job, permanently.
 */
#include "gmcrypto.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Read an entire file into a malloc'd buffer; caller frees. */
static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)n);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static gmcrypto_x509_certificate_t *load_cert(const char *path) {
    size_t len = 0;
    uint8_t *der = read_file(path, &len);
    if (!der) {
        fprintf(stderr, "cannot read %s\n", path);
        return NULL;
    }
    gmcrypto_x509_certificate_t *cert =
        gmcrypto_x509_certificate_from_der(der, len);
    free(der);
    return cert;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <sign.der> <enc.der> <int.der> <root.der>\n",
                argv[0]);
        return 2;
    }
    gmcrypto_x509_certificate_t *sign = load_cert(argv[1]);
    gmcrypto_x509_certificate_t *enc = load_cert(argv[2]);
    gmcrypto_x509_certificate_t *intermediate = load_cert(argv[3]);
    gmcrypto_x509_certificate_t *root = load_cert(argv[4]);
    if (!sign || !enc || !intermediate || !root) {
        fprintf(stderr, "a certificate failed to parse\n");
        return 1;
    }

    /* Leaf-first chains; the root is the trust anchor. */
    const gmcrypto_x509_certificate_t *sign_chain[2] = {sign, intermediate};
    const gmcrypto_x509_certificate_t *enc_chain[2] = {enc, intermediate};
    const gmcrypto_x509_certificate_t *anchors[1] = {root};

    int verified = 0;
    /* at_time = NULL skips the validity-window check (this library has no
     * clock). Pass a gmcrypto_x509_time_t* to enforce a comparison time. */
    int rc = gmcrypto_tlcp_verify_pair(sign_chain, 2, enc_chain, 2, anchors, 1,
                                       NULL, &verified);

    if (rc != GMCRYPTO_OK) {
        fprintf(stderr, "verify_pair: malformed arguments\n");
    } else if (verified) {
        printf("pair VERIFIES: both chains link to the trusted root and each "
               "leaf is usable for its TLCP role.\n");
        printf("(structural trust only — NOT proof this is the peer you "
               "dialed; bind identity yourself.)\n");
    } else {
        printf("pair does NOT verify.\n");
    }

    gmcrypto_x509_certificate_free(sign);
    gmcrypto_x509_certificate_free(enc);
    gmcrypto_x509_certificate_free(intermediate);
    gmcrypto_x509_certificate_free(root);
    return (rc == GMCRYPTO_OK && verified) ? 0 : 1;
}
