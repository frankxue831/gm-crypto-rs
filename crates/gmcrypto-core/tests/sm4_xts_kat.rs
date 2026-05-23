//! v0.12 W2 — SM4-XTS Known-Answer Tests.
//!
//! Cross-validate `sm4::mode_xts` byte-for-byte against the OpenSSL 3.x EVP
//! `SM4-XTS` cipher with `xts_standard=GB` (GB/T 17964-2021, GM-T OID
//! `1.2.156.10197.1.104.10`). gmssl 3.1.1 lacks XTS, so OpenSSL EVP is the sole
//! oracle (see `docs/v0.12-xts-kat-sourcing.md`). Vectors generated 2026-05-23
//! against OpenSSL 3.6.2 (Homebrew openssl@3) via `tests/data/sm4_xts_oracle.c`.
//!
//! Note: this is the **GB** variant, not IEEE 1619 — the two differ in the
//! GF(2¹²⁸) tweak-doubling convention (GB uses the bit-reflected / GHASH-style
//! representation) and so produce different ciphertext for multi-block /
//! non-aligned data.

#![cfg(feature = "sm4-xts")]

use gmcrypto_core::sm4::mode_xts;
use hex_literal::hex;

struct XtsVector {
    name: &'static str,
    key: [u8; 32],
    tweak: [u8; 16],
    pt: &'static [u8],
    ct: &'static [u8],
}

const KEY: [u8; 32] = hex!("0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f");
const TWEAK: [u8; 16] = hex!("11111111111111111111111111111111");

const VECTORS: &[XtsVector] = &[
    XtsVector {
        name: "whole-block 16",
        key: KEY,
        tweak: TWEAK,
        pt: &hex!("00112233445566778899aabbccddeeff"),
        ct: &hex!("b3fbef63165a03942ea2b4b7bc67af80"),
    },
    XtsVector {
        name: "whole-block 32",
        key: KEY,
        tweak: TWEAK,
        pt: &hex!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
        ct: &hex!("b3fbef63165a03942ea2b4b7bc67af80455f6784df3b00cf4a388baf001da4c4"),
    },
    XtsVector {
        name: "cts 17 (r=1)",
        key: KEY,
        tweak: TWEAK,
        pt: &hex!("0011223344556677889900112233445566"),
        ct: &hex!("89956c7af6086bc701281ba668773d5852"),
    },
    XtsVector {
        name: "cts 20 (r=4)",
        key: KEY,
        tweak: TWEAK,
        pt: &hex!("00112233445566778899aabbccddeeff00112233"),
        ct: &hex!("e42c1aff8629401515f2edac4eedbe69b3fbef63"),
    },
];

#[test]
fn xts_kat_matches_openssl_gb() {
    for v in VECTORS {
        let ct = mode_xts::encrypt(&v.key, &v.tweak, v.pt).expect("valid params");
        assert_eq!(ct.as_slice(), v.ct, "encrypt mismatch: {}", v.name);
        let pt = mode_xts::decrypt(&v.key, &v.tweak, v.ct).expect("valid params");
        assert_eq!(pt.as_slice(), v.pt, "decrypt mismatch: {}", v.name);
    }
}

#[test]
fn xts_min_block_equals_prefix_of_longer() {
    // Block 0 depends only on T_0, so the 16-byte ct is a prefix of the
    // 32-byte ct (consistency check, independent of the oracle).
    let ct16 =
        mode_xts::encrypt(&KEY, &TWEAK, &hex!("00112233445566778899aabbccddeeff")).expect("valid");
    let ct32 = mode_xts::encrypt(
        &KEY,
        &TWEAK,
        &hex!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
    )
    .expect("valid");
    assert_eq!(&ct32[..16], ct16.as_slice());
}
