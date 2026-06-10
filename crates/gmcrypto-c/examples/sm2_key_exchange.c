/*
 * Example: SM2 key exchange (GM/T 0003.3) with key confirmation via the
 * gmcrypto-c C ABI — a full two-party handshake in one process. Party A
 * (the initiator) and party B (the responder) agree on a 32-byte key;
 * both confirmation tags (S_B, S_A) are verified before either side
 * releases the key.
 *
 * The SM2-KX FFI is always-on (v1.2 / the v0.23 posture):
 *   cargo build -p gmcrypto-c --release
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      sm2_key_exchange.c -o sm2_key_exchange
 *   LD_LIBRARY_PATH=../../../target/release ./sm2_key_exchange
 *
 * Build (static):
 *   cc -I ../include sm2_key_exchange.c \
 *      ../../../target/release/libgmcrypto_c.a -o sm2_key_exchange-static
 *   ./sm2_key_exchange-static
 *
 * Per v0.4 W4 / Q4.14, this example is documentation-only; CI does not
 * build C examples. Run locally to confirm the key-exchange FFI works
 * end-to-end from C.
 *
 * Handle lifecycle to note:
 *  - the initiator handle is created ALREADY holding its ephemeral
 *    (R_A is written by _new); _confirm consumes + frees it — do NOT
 *    call _free afterwards;
 *  - the responder handle survives _respond (it holds the key pending
 *    A's confirmation tag) and is consumed + freed by _finish;
 *  - _free on either handle is the abandonment path only (peer never
 *    replied);
 *  - the agreed key lands in caller memory: WIPE IT when done (the
 *    library wipes its own internal copies, not yours).
 *
 * In a real deployment the two parties run on different machines and
 * exchange (R_A), (R_B, S_B), (S_A) over the network; identity strings
 * and static public keys are distributed out-of-band (id_len == 0
 * selects the GM/T default ID "1234567812345678").
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gmcrypto.h"

#define KLEN 32 /* agreed-key length in bytes (caller's choice) */

static void hexdump(const char *label, const uint8_t *p, size_t n) {
    printf("%s: ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    /* Static long-term keys. In production these come from key files /
     * HSM; here we derive both pairs from fixed scalars for the demo. */
    const uint8_t d_a[GMCRYPTO_SM2_SCALAR_SIZE] = {
        0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1, 0x6D, 0xF1, 0x16,
        0x49, 0x5F, 0x90, 0x69, 0x52, 0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C,
        0x4A, 0xE1, 0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29};
    const uint8_t d_b[GMCRYPTO_SM2_SCALAR_SIZE] = {
        0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA, 0x54, 0x37, 0xA5,
        0x93, 0x56, 0xB8, 0x23, 0x38, 0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19,
        0x90, 0x88, 0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5};

    gmcrypto_sm2_privkey_t *priv_a = gmcrypto_sm2_privkey_new(d_a);
    gmcrypto_sm2_privkey_t *priv_b = gmcrypto_sm2_privkey_new(d_b);
    if (!priv_a || !priv_b) {
        fprintf(stderr, "privkey_new failed\n");
        return 1;
    }

    /* Each party publishes its SEC1 public key out-of-band; a real peer
     * receives these bytes (e.g. from an SPKI certificate). Here we
     * hard-code the matching public points — the GM/T 0003.5
     * worked-example pairs for d_a / d_b above. */
    uint8_t pub_a_sec1[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
    uint8_t pub_b_sec1[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
    const uint8_t pa[] = {
        0x04, 0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 0x1D, 0xD8,
        0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB, 0xD3, 0xCC, 0xF4, 0xFF, 0xE2,
        0x6A, 0xA6, 0xF6, 0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
        0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 0x31, 0x69, 0x4B,
        0xEB, 0x20, 0xAA, 0x48, 0x9D, 0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC,
        0xF8, 0xC4, 0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F};
    const uint8_t pb[] = {
        0x04, 0x6A, 0xE8, 0x48, 0xC5, 0x7C, 0x53, 0xC7, 0xB1, 0xB5, 0xFA,
        0x99, 0xEB, 0x22, 0x86, 0xAF, 0x07, 0x8B, 0xA6, 0x4C, 0x64, 0x59,
        0x1B, 0x8B, 0x56, 0x6F, 0x73, 0x57, 0xD5, 0x76, 0xF1, 0x6D, 0xFB,
        0xEE, 0x48, 0x9D, 0x77, 0x16, 0x21, 0xA2, 0x7B, 0x36, 0xC5, 0xC7,
        0x99, 0x20, 0x62, 0xE9, 0xCD, 0x09, 0xA9, 0x26, 0x43, 0x86, 0xF3,
        0xFB, 0xEA, 0x54, 0xDF, 0xF6, 0x93, 0x05, 0x62, 0x1C, 0x4D};
    memcpy(pub_a_sec1, pa, sizeof pa);
    memcpy(pub_b_sec1, pb, sizeof pb);

    gmcrypto_sm2_pubkey_t *pub_a = gmcrypto_sm2_pubkey_new(pub_a_sec1);
    gmcrypto_sm2_pubkey_t *pub_b = gmcrypto_sm2_pubkey_new(pub_b_sec1);
    if (!pub_a || !pub_b) {
        fprintf(stderr, "pubkey_new failed\n");
        return 1;
    }

    /* ---- A: start the handshake; R_A goes to B. ---- */
    uint8_t r_a[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
    gmcrypto_sm2_kx_initiator_t *init = gmcrypto_sm2_kx_initiator_new(
        priv_a, pub_b, NULL, 0, NULL, 0, KLEN, r_a);
    if (!init) {
        fprintf(stderr, "initiator_new failed\n");
        return 1;
    }
    hexdump("A->B  R_A", r_a, sizeof r_a);

    /* ---- B: answer with (R_B, S_B); keep the handle for S_A. ---- */
    gmcrypto_sm2_kx_responder_t *resp = gmcrypto_sm2_kx_responder_new(
        priv_b, pub_a, NULL, 0, NULL, 0, KLEN);
    if (!resp) {
        fprintf(stderr, "responder_new failed\n");
        return 1;
    }
    uint8_t r_b[GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE];
    uint8_t s_b[GMCRYPTO_SM2_KX_CONFIRM_SIZE];
    if (gmcrypto_sm2_kx_responder_respond(resp, r_a, r_b, s_b) != GMCRYPTO_OK) {
        fprintf(stderr, "respond failed (invalid R_A?)\n");
        gmcrypto_sm2_kx_initiator_free(init);
        gmcrypto_sm2_kx_responder_free(resp);
        return 1;
    }
    hexdump("B->A  R_B", r_b, sizeof r_b);
    hexdump("B->A  S_B", s_b, sizeof s_b);

    /* ---- A: verify S_B, release K_A, emit S_A. (consumes `init`) ---- */
    uint8_t key_a[KLEN];
    uint8_t s_a[GMCRYPTO_SM2_KX_CONFIRM_SIZE];
    if (gmcrypto_sm2_kx_initiator_confirm(init, r_b, s_b, key_a, s_a) !=
        GMCRYPTO_OK) {
        fprintf(stderr, "confirm failed (S_B mismatch / bad R_B)\n");
        gmcrypto_sm2_kx_responder_free(resp);
        return 1;
    }
    hexdump("A->B  S_A", s_a, sizeof s_a);

    /* ---- B: verify S_A, release K_B. (consumes `resp`) ---- */
    uint8_t key_b[KLEN];
    if (gmcrypto_sm2_kx_responder_finish(resp, s_a, key_b) != GMCRYPTO_OK) {
        fprintf(stderr, "finish failed (S_A mismatch)\n");
        return 1;
    }

    hexdump("K_A", key_a, sizeof key_a);
    hexdump("K_B", key_b, sizeof key_b);
    if (memcmp(key_a, key_b, KLEN) != 0) {
        fprintf(stderr, "KEY MISMATCH\n");
        return 1;
    }
    printf("agreed: both parties hold the same %d-byte key, both tags "
           "verified\n",
           KLEN);

    /* The caller owns wiping the agreed key. */
    memset(key_a, 0, sizeof key_a);
    memset(key_b, 0, sizeof key_b);

    gmcrypto_sm2_privkey_free(priv_a);
    gmcrypto_sm2_privkey_free(priv_b);
    gmcrypto_sm2_pubkey_free(pub_a);
    gmcrypto_sm2_pubkey_free(pub_b);
    return 0;
}
