/*
 * x509_verify.c — X.509-with-SM2 leaf-vs-issuer signature verification
 * through the gmcrypto C ABI (v1.4).
 *
 * Doc-only example (CI does not build C examples). Compile + run locally:
 *
 *   cargo build -p gmcrypto-c --release
 *   cc -Wall -Wextra -o x509_verify \
 *      crates/gmcrypto-c/examples/x509_verify.c \
 *      -Icrates/gmcrypto-c/include -Ltarget/release -lgmcrypto_c
 *   ./x509_verify crates/gmcrypto-core/tests/data/x509_leaf.der \
 *                 crates/gmcrypto-core/tests/data/x509_ca.der
 *
 * NOTE — this is NOT certificate validation. A PASS means exactly "the
 * issuer certificate's subject key signed the leaf's tbsCertificate
 * bytes": no chain building, no time/validity decision (the validity
 * window is printed, never compared to a clock), no extension
 * interpretation, no revocation. See the gmcrypto-core x509 module docs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmcrypto.h"

static unsigned char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) {
        fclose(f);
        return NULL;
    }
    unsigned char *buf = malloc((size_t)n);
    if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <leaf.der> <issuer.der>\n", argv[0]);
        return 2;
    }

    size_t leaf_len = 0, issuer_len = 0;
    unsigned char *leaf_der = read_file(argv[1], &leaf_len);
    unsigned char *issuer_der = read_file(argv[2], &issuer_len);
    if (leaf_der == NULL || issuer_der == NULL) {
        fprintf(stderr, "error: cannot read input files\n");
        free(leaf_der);
        free(issuer_der);
        return 2;
    }

    int rc = 2;
    gmcrypto_x509_certificate_t *leaf = NULL, *issuer = NULL;
    gmcrypto_sm2_pubkey_t *issuer_key = NULL;

    leaf = gmcrypto_x509_certificate_from_der(leaf_der, leaf_len);
    issuer = gmcrypto_x509_certificate_from_der(issuer_der, issuer_len);
    if (leaf == NULL || issuer == NULL) {
        fprintf(stderr, "error: certificate parse failed\n");
        goto out;
    }

    /* Print the leaf's serial (pad-stripped, <= 20 bytes). */
    unsigned char serial[20];
    size_t serial_len = 0;
    if (gmcrypto_x509_certificate_serial_raw(leaf, serial, sizeof serial,
                                             &serial_len) != GMCRYPTO_OK) {
        fprintf(stderr, "error: serial accessor failed\n");
        goto out;
    }
    printf("leaf serial: ");
    for (size_t i = 0; i < serial_len; i++) {
        printf("%02x", serial[i]);
    }
    printf("\n");

    /* Print the validity window — EXPOSED ONLY, never compared to a
     * clock here: the validity decision belongs to the caller. */
    gmcrypto_x509_time_t nb, na;
    if (gmcrypto_x509_certificate_not_before(leaf, &nb) != GMCRYPTO_OK ||
        gmcrypto_x509_certificate_not_after(leaf, &na) != GMCRYPTO_OK) {
        fprintf(stderr, "error: validity accessor failed\n");
        goto out;
    }
    printf("leaf validity: %04u-%02u-%02uT%02u:%02u:%02uZ .. "
           "%04u-%02u-%02uT%02u:%02u:%02uZ (not checked against a clock)\n",
           nb.year, nb.month, nb.day, nb.hour, nb.minute, nb.second,
           na.year, na.month, na.day, na.hour, na.minute, na.second);

    /* The issuer certificate's SUBJECT key is the key that (allegedly)
     * signed the leaf. */
    issuer_key = gmcrypto_x509_certificate_subject_public_key(issuer);
    if (issuer_key == NULL) {
        fprintf(stderr, "error: issuer subject-key extraction failed\n");
        goto out;
    }

    if (gmcrypto_x509_certificate_verify_signature(leaf, issuer_key) ==
        GMCRYPTO_OK) {
        printf("PASS: issuer key signed the leaf tbsCertificate\n");
        rc = 0;
    } else {
        printf("FAIL: signature does not verify under the issuer key\n");
        rc = 1;
    }

out:
    gmcrypto_sm2_pubkey_free(issuer_key);
    gmcrypto_x509_certificate_free(issuer);
    gmcrypto_x509_certificate_free(leaf);
    free(leaf_der);
    free(issuer_der);
    return rc;
}
