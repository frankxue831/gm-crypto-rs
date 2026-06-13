//! TLCP key-schedule KATs — OpenSSL 3.x `TLS1-PRF` with `digest:SM3`
//! as the generating oracle (the v0.8 EVP-oracle pattern; gmssl 3.1.1
//! has no PRF CLI). Regen recipe: docs/v1.6-kat-sourcing.md.
#![cfg(feature = "tlcp")]

use gmcrypto_core::tlcp::key_schedule::{
    FINISHED_VERIFY_DATA_LEN, MASTER_SECRET_LEN, TlcpRole, derive_key_block, derive_master_secret,
    finished_verify_data,
};
use hex_literal::hex;

const PMS: [u8; 48] = [0xab; 48];
const CR: [u8; 32] = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const SR: [u8; 32] = hex!("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
const MS: [u8; 48] = hex!(
    "568d8178a9075903499ae2cafddcfff9945b5e28213f59a3fdc8c3e1c7a98d2aaeaa9d887b7c1528aef2f0f4fb937b02"
);
const KB128: [u8; 128] = hex!(
    "02b9e2efba3e3bc5829e3488db733a3caacd7cf2454f7fe33198acb9588a7114675483d61d73236a22016ea5d0066e42a3a740533b79c0469c997f843d08d5a985ec1698d6e891c271a84eeafadd7c0232027a9a361fc2d5b571ee936425dfc928baae7679e098c54611ddbd24ff015394c5199f4dfe01fb4b3aabf3d871f527"
);
const KB200_TAIL: [u8; 72] = hex!(
    "de445568e69cb0cf809b31d450a1d3ae533fa1ada9fbf632e482a94e28898a7857fc2cbcf46ab5f7105a4c6a2ab81709f9d699e087011dcdc7b1493114b3c1ef0d2a704f9bdca6e1"
);

#[test]
fn master_secret_matches_openssl_tls1_prf_sm3() {
    let mut out = [0u8; MASTER_SECRET_LEN];
    derive_master_secret(&PMS, &CR, &SR, &mut out);
    assert_eq!(out, MS);
}

#[test]
fn key_block_matches_openssl_at_cbc_gcm_and_long_lengths() {
    let mut kb128 = [0u8; 128];
    derive_key_block(&MS, &CR, &SR, &mut kb128);
    assert_eq!(kb128, KB128);

    // GCM carve = prefix (structural streaming pin).
    let mut kb40 = [0u8; 40];
    derive_key_block(&MS, &CR, &SR, &mut kb40);
    assert_eq!(kb40, KB128[..40]);

    // Multi-iteration long output (200 B = 7 SM3 blocks).
    let mut kb200 = [0u8; 200];
    derive_key_block(&MS, &CR, &SR, &mut kb200);
    assert_eq!(kb200[..128], KB128);
    assert_eq!(kb200[128..], KB200_TAIL);

    // Zero-length out: must not panic, touches nothing.
    derive_key_block(&MS, &CR, &SR, &mut []);

    // The §6.5.2 seed-order flip is load-bearing: swapping randoms
    // must NOT reproduce the vector.
    let mut swapped = [0u8; 128];
    derive_key_block(&MS, &SR, &CR, &mut swapped);
    assert_ne!(swapped, KB128);
}

#[test]
fn finished_verify_data_matches_openssl_both_roles() {
    let th = [0xcd; 32];
    let mut client = [0u8; FINISHED_VERIFY_DATA_LEN];
    finished_verify_data(&MS, TlcpRole::Client, &th, &mut client);
    assert_eq!(client, hex!("190587b8f0b4fa50e4b19c71"));

    let mut server = [0u8; FINISHED_VERIFY_DATA_LEN];
    finished_verify_data(&MS, TlcpRole::Server, &th, &mut server);
    assert_eq!(server, hex!("088e1e6ce3fce61e4a7e94d1"));
    assert_ne!(client, server, "role labels must separate");
}
