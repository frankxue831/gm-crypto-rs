/*
 * Example: a full TLCP (GB/T 38636) handshake-to-record flow through the
 * gmcrypto-c C ABI, in one process — the "the toolkit is callable from C"
 * artifact for v1.9. Four stages:
 *   1. no-confirmation SM2 key exchange (TLCP ECDHE) → a 48-byte pre_master;
 *   2. the key schedule → master_secret + the 128-byte CBC key block;
 *   3. SM4-CBC record protect/deprotect (MAC-then-encrypt) round-trip;
 *   4. Finished verify_data (client + server).
 *
 * The whole TLCP toolkit FFI is always-on (v1.9 / the v0.23 posture):
 *   cargo build -p gmcrypto-c --release
 *
 * Build (Linux/macOS, dynamic):
 *   cc -I ../include -L ../../../target/release -lgmcrypto_c \
 *      tlcp_handshake.c -o tlcp_handshake
 *   LD_LIBRARY_PATH=../../../target/release ./tlcp_handshake
 *
 * Build (static):
 *   cc -I ../include tlcp_handshake.c \
 *      ../../../target/release/libgmcrypto_c.a -o tlcp_handshake-static
 *   ./tlcp_handshake-static
 *
 * Documentation-only (Q4.14): CI does not build C examples. Run locally to
 * confirm the toolkit FFI works end-to-end from C.
 *
 * NOTE ON KEYS: only your own PRIVATE key is local; the peer's PUBLIC key
 * arrives in its certificate (see tlcp_verify_pair.c) or out-of-band — the C
 * ABI has no private→public derivation. The two static keypairs below were
 * derived offline for a self-contained demo.
 *
 * NOTE ON pre_master: TLCP pins it to 48 bytes in BOTH key-exchange variants.
 * ECDHE (shown here) uses the klen=48 KX output directly; the ECC
 * key-transport suite instead SM2-seals `version(2)||random(46)` to the
 * server's enc cert (via gmcrypto_sm2_encrypt) — same 48-byte input to
 * gmcrypto_tlcp_derive_master_secret.
 */
#include "gmcrypto.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void hex2bin(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* Static SM2 keypairs (party A initiator, party B responder). */
static const char *D_A =
    "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
static const char *P_A =
    "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F350"
    "20CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";
static const char *D_B =
    "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
static const char *P_B =
    "04D5548C7825CBB56150A3506CD57464AF8A1AE0519DFAF3C58221DC810CAF28"
    "DD921073768FE3D59CE54E79A49445CF73FED23086537027264D168946D479533E";

int main(void) {
    uint8_t da[32], db[32], pa[65], pb[65];
    hex2bin(D_A, da, 32);
    hex2bin(P_A, pa, 65);
    hex2bin(D_B, db, 32);
    hex2bin(P_B, pb, 65);

    /* --- 1. No-confirmation SM2 key exchange (TLCP ECDHE) --- */
    gmcrypto_sm2_privkey_t *a_priv = gmcrypto_sm2_privkey_new(da);
    gmcrypto_sm2_pubkey_t *b_pub = gmcrypto_sm2_pubkey_new(pb);
    gmcrypto_sm2_privkey_t *b_priv = gmcrypto_sm2_privkey_new(db);
    gmcrypto_sm2_pubkey_t *a_pub = gmcrypto_sm2_pubkey_new(pa);
    if (!a_priv || !b_pub || !b_priv || !a_pub) {
        fprintf(stderr, "key load failed\n");
        return 1;
    }

    const size_t klen = GMCRYPTO_TLCP_MASTER_SECRET_LEN; /* 48 */
    uint8_t r_a[65], r_b[65];
    gmcrypto_sm2_kx_initiator_t *init =
        gmcrypto_sm2_kx_initiator_new(a_priv, b_pub, NULL, 0, NULL, 0, klen, r_a);
    gmcrypto_sm2_kx_responder_t *resp =
        gmcrypto_sm2_kx_responder_new(b_priv, a_pub, NULL, 0, NULL, 0, klen);
    if (!init || !resp) {
        fprintf(stderr, "kx setup failed\n");
        return 1;
    }

    uint8_t pms_a[48], pms_b[48];
    /* B replies (R_B + its half of the agreed pre_master); A completes. The
     * completers CONSUME + FREE their handles — do NOT free them again. */
    if (gmcrypto_sm2_kx_responder_respond_unconfirmed(resp, r_a, r_b, pms_b) !=
        GMCRYPTO_OK) {
        fprintf(stderr, "responder failed\n");
        return 1;
    }
    if (gmcrypto_sm2_kx_initiator_derive_unconfirmed(init, r_b, pms_a) !=
        GMCRYPTO_OK) {
        fprintf(stderr, "initiator failed\n");
        return 1;
    }
    if (memcmp(pms_a, pms_b, 48) != 0) {
        fprintf(stderr, "pre_master mismatch\n");
        return 1;
    }
    printf("1. pre_master agreed (48 bytes) via no-confirmation SM2-KX\n");

    /* --- 2. Key schedule --- */
    uint8_t client_random[32], server_random[32];
    memset(client_random, 0x11, 32);
    memset(server_random, 0x22, 32);
    uint8_t master[48];
    if (gmcrypto_tlcp_derive_master_secret(pms_a, client_random, server_random,
                                           master) != GMCRYPTO_OK) {
        return 1;
    }
    uint8_t key_block[GMCRYPTO_TLCP_CBC_KEY_BLOCK_LEN];
    if (gmcrypto_tlcp_derive_key_block(master, client_random, server_random,
                                       key_block, sizeof key_block) !=
        GMCRYPTO_OK) {
        return 1;
    }
    printf("2. master_secret + 128-byte CBC key block derived\n");

    /* --- 3. SM4-CBC record protect / deprotect --- */
    /* role 0 = Client: protect (write) and deprotect (read) that direction. */
    gmcrypto_tlcp_record_keys_cbc_t *keys =
        gmcrypto_tlcp_record_keys_cbc_new(0, key_block);
    if (!keys) {
        return 1;
    }
    const uint8_t version[2] = {GMCRYPTO_TLCP_RECORD_VERSION_MAJOR,
                                GMCRYPTO_TLCP_RECORD_VERSION_MINOR};
    const uint8_t plaintext[] = "hello from a C TLCP client";
    const size_t pt_len = sizeof plaintext - 1;
    const uint64_t seq = 0; /* (key, seq) uniqueness is the caller's contract. */

    uint8_t record[256];
    size_t record_len = 0;
    if (gmcrypto_tlcp_protect_cbc(keys, seq, 23 /* application_data */, version,
                                  plaintext, pt_len, record, sizeof record,
                                  &record_len) != GMCRYPTO_OK) {
        return 1;
    }
    uint8_t recovered[256];
    size_t rec_len = 0;
    if (gmcrypto_tlcp_deprotect_cbc(keys, seq, 23, version, record, record_len,
                                    recovered, sizeof recovered, &rec_len) !=
        GMCRYPTO_OK) {
        return 1;
    }
    if (rec_len != pt_len || memcmp(recovered, plaintext, pt_len) != 0) {
        fprintf(stderr, "record round-trip mismatch\n");
        return 1;
    }
    printf("3. SM4-CBC record round-trip OK (%zu -> %zu -> %zu bytes)\n", pt_len,
           record_len, rec_len);

    /* --- 4. Finished verify_data --- */
    uint8_t transcript_hash[32];
    memset(transcript_hash, 0x33, 32); /* caller's SM3 over handshake msgs */
    uint8_t client_finished[12], server_finished[12];
    gmcrypto_tlcp_finished_verify_data(master, 0, transcript_hash,
                                       client_finished);
    gmcrypto_tlcp_finished_verify_data(master, 1, transcript_hash,
                                       server_finished);
    printf("4. Finished verify_data computed (client + server)\n");

    /* Wipe secrets the library handed to caller memory (it wipes its own
     * internal copies, not yours). */
    GMCRYPTO_ZEROIZE(pms_a, 48);
    GMCRYPTO_ZEROIZE(pms_b, 48);
    GMCRYPTO_ZEROIZE(master, 48);
    GMCRYPTO_ZEROIZE(key_block, sizeof key_block);
    gmcrypto_tlcp_record_keys_cbc_free(keys);
    gmcrypto_sm2_privkey_free(a_priv);
    gmcrypto_sm2_pubkey_free(b_pub);
    gmcrypto_sm2_privkey_free(b_priv);
    gmcrypto_sm2_pubkey_free(a_pub);

    printf("\nFull TLCP handshake-to-record flow completed from C.\n");
    return 0;
}
