//! v0.4 W2 — RustCrypto-trait fit cross-validation.
//!
//! These tests verify that `Sm3` / `HmacSm3` / `Sm4Cipher` produce
//! byte-identical output through their `digest::Digest` /
//! `digest::Mac` / `cipher::BlockEncrypt` / `cipher::BlockDecrypt`
//! impls vs. the inherent methods. Gated on
//! `--features digest-traits,cipher-traits`.
//!
//! The whole file is `#![cfg(all(...))]`-gated so a default-features
//! `cargo test` doesn't even compile it.

#![cfg(all(feature = "digest-traits", feature = "cipher-traits"))]

use cipher::generic_array::GenericArray;
use cipher::{
    BlockDecrypt as CipherBlockDecrypt, BlockEncrypt as CipherBlockEncrypt,
    KeyInit as CipherKeyInit,
};
use digest::Digest;
use digest::Mac as DigestMac;
use gmcrypto_core::hmac::{HmacSm3, hmac_sm3};
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
use gmcrypto_core::sm3::{Sm3, hash};
use gmcrypto_core::sm4::Sm4Cipher;
use hex_literal::hex;

// -------- SM3 / digest::Digest -------------------------------------------

/// GB/T 32905-2016 Appendix A.1 — empty input via the `Digest` trait.
#[test]
fn sm3_digest_trait_empty() {
    let out = <Sm3 as Digest>::new().finalize();
    let inherent = hash(&[]);
    assert_eq!(out.as_slice(), inherent.as_slice());
    assert_eq!(
        out.as_slice(),
        hex!("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
    );
}

/// GB/T 32905-2016 Appendix A.1 — "abc" via streaming `Update` then `FixedOutput`.
#[test]
fn sm3_digest_trait_abc_streaming() {
    let mut hasher = <Sm3 as Digest>::new();
    Digest::update(&mut hasher, b"a");
    Digest::update(&mut hasher, b"bc");
    let out = hasher.finalize();
    assert_eq!(
        out.as_slice(),
        hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    );
    assert_eq!(out.as_slice(), hash(b"abc").as_slice());
}

/// Streaming-vs-one-shot equivalence under arbitrary chunking.
#[test]
fn sm3_digest_trait_streaming_equivalence() {
    let input = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let inherent = hash(input);
    let mut hasher = <Sm3 as Digest>::new();
    // Feed in non-uniform chunks (the trait must not see the chunking).
    for chunk in [&input[..1], &input[1..5], &input[5..32], &input[32..]] {
        Digest::update(&mut hasher, chunk);
    }
    assert_eq!(hasher.finalize().as_slice(), inherent.as_slice());
}

// -------- HMAC-SM3 / digest::Mac ------------------------------------------

/// RFC-4231-shaped HMAC-SM3 KAT via the `Mac` trait + `new_from_slice`
/// variable-key path.
#[test]
fn hmac_sm3_mac_trait_basic() {
    let key = [0x0bu8; 20];
    let msg = b"Hi There";
    let expected = hmac_sm3(&key, msg);

    let mac = <HmacSm3 as DigestMac>::new_from_slice(&key).expect("variable-length key accepted");
    let chained = DigestMac::chain_update(mac, msg);
    let tag = DigestMac::finalize(chained).into_bytes();

    assert_eq!(tag.as_slice(), expected.as_slice());
    assert_eq!(
        tag.as_slice(),
        hex!("51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"),
    );
}

/// Variable-length key cases all round-trip the trait path.
#[test]
fn hmac_sm3_mac_trait_variable_keys() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"Jefe", b"what do ya want for nothing?"),
        (
            &[0xaau8; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        ),
        (&[], &[]),
    ];
    for (key, msg) in cases {
        let inherent = hmac_sm3(key, msg);
        let mac =
            <HmacSm3 as DigestMac>::new_from_slice(key).expect("variable-length key accepted");
        let chained = DigestMac::chain_update(mac, msg);
        let tag = DigestMac::finalize(chained).into_bytes();
        assert_eq!(tag.as_slice(), inherent.as_slice());
    }
}

/// `digest::Mac::verify_slice` uses constant-time compare.
#[test]
fn hmac_sm3_mac_trait_verify() {
    let key = [0x0bu8; 20];
    let msg = b"Hi There";
    let tag_inherent = hmac_sm3(&key, msg);

    let mac = <HmacSm3 as DigestMac>::new_from_slice(&key).unwrap();
    let chained = DigestMac::chain_update(mac, msg);
    DigestMac::verify_slice(chained, &tag_inherent).expect("trait verify matches");
}

/// PBKDF2-HMAC-SM3 fed by `RustCrypto`'s `pbkdf2` crate via the trait
/// impl produces the same output as our in-crate `pbkdf2_hmac_sm3`.
///
/// Note: we vendor the PBKDF2 driver here as a tiny in-test impl to
/// avoid pulling the `pbkdf2` crate as a dev-dep. The point is to
/// demonstrate the trait-driven composition path; the byte
/// equivalence to our inherent path is the actual gate.
#[test]
fn hmac_sm3_drives_external_pbkdf2_shape() {
    // Drive PBKDF2 PRF=HMAC-SM3 through the trait surface manually.
    fn pbkdf2_via_trait(password: &[u8], salt: &[u8], iters: u32, out: &mut [u8]) {
        let hlen = 32;
        for (block_index, block) in out.chunks_mut(hlen).enumerate() {
            // INT(i) = block_index + 1 as 32-bit BE.
            let i = u32::try_from(block_index + 1).expect("block index fits in u32");
            let mut salt_int = alloc::vec::Vec::with_capacity(salt.len() + 4);
            salt_int.extend_from_slice(salt);
            salt_int.extend_from_slice(&i.to_be_bytes());

            // U_1 = PRF(password, salt || INT(i))
            let mac = <HmacSm3 as DigestMac>::new_from_slice(password)
                .expect("variable-length key accepted");
            let chained = DigestMac::chain_update(mac, &salt_int);
            let u1 = DigestMac::finalize(chained).into_bytes();

            let mut t = [0u8; 32];
            t.copy_from_slice(u1.as_slice());

            let mut u = [0u8; 32];
            u.copy_from_slice(u1.as_slice());
            for _ in 1..iters {
                let mac = <HmacSm3 as DigestMac>::new_from_slice(password).unwrap();
                let chained = DigestMac::chain_update(mac, u);
                let u_next = DigestMac::finalize(chained).into_bytes();
                u.copy_from_slice(u_next.as_slice());
                for j in 0..32 {
                    t[j] ^= u[j];
                }
            }
            block.copy_from_slice(&t[..block.len()]);
        }
    }
    extern crate alloc;

    let pw = b"password";
    let salt = b"salt";
    let iters = 4096u32;
    let mut via_trait = [0u8; 32];
    let mut via_inherent = [0u8; 32];
    pbkdf2_via_trait(pw, salt, iters, &mut via_trait);
    pbkdf2_hmac_sm3(pw, salt, iters, &mut via_inherent).expect("pbkdf2 ok");
    assert_eq!(via_trait, via_inherent);
}

// -------- SM4 / cipher::BlockEncrypt/Decrypt ------------------------------

/// GB/T 32907-2016 Appendix A.1 single-block KAT via the `BlockEncrypt`
/// trait.
#[test]
fn sm4_cipher_trait_single_block() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let pt = hex!("0123456789abcdeffedcba9876543210");
    let expected_ct = hex!("681edf34d206965e86b3e94f536e4246");

    let cipher: Sm4Cipher = <Sm4Cipher as CipherKeyInit>::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&pt);
    <Sm4Cipher as CipherBlockEncrypt>::encrypt_block(&cipher, &mut block);
    assert_eq!(block.as_slice(), &expected_ct);

    // Round-trip via the BlockDecrypt trait.
    <Sm4Cipher as CipherBlockDecrypt>::decrypt_block(&cipher, &mut block);
    assert_eq!(block.as_slice(), &pt);
}

/// Trait-path output is byte-identical to the inherent path.
#[test]
fn sm4_cipher_trait_matches_inherent() {
    let key = [0x42u8; 16];
    let pt = [0x37u8; 16];

    let mut buf_inherent = pt;
    let inherent_cipher = Sm4Cipher::new(&key);
    inherent_cipher.encrypt_block(&mut buf_inherent);

    let trait_cipher: Sm4Cipher = <Sm4Cipher as CipherKeyInit>::new(GenericArray::from_slice(&key));
    let mut buf_trait = GenericArray::clone_from_slice(&pt);
    <Sm4Cipher as CipherBlockEncrypt>::encrypt_block(&trait_cipher, &mut buf_trait);

    assert_eq!(buf_inherent.as_slice(), buf_trait.as_slice());
}
