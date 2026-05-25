//! v0.15 W1 — SM4-XTS multi-sector (disk) helper tests.
//!
//! `mode_xts::{encrypt_sectors, decrypt_sectors}` encrypt/decrypt a contiguous
//! run of equal-size sectors **in place**, deriving sector `i`'s tweak as the
//! little-endian 128-bit encoding of `start_sector + i`. The spec is
//! **byte-identical to looping the single-shot `mode_xts::encrypt`/`decrypt`**
//! with those LE-128 tweaks (the single-shot is OpenSSL-`xts_standard=GB`-pinned
//! by `sm4_xts_kat.rs`, so this differential test transitively inherits the KAT).

#![cfg(feature = "sm4-xts")]

use gmcrypto_core::sm4::mode_xts::{self, XTS_KEY_SIZE};

const KEY: [u8; XTS_KEY_SIZE] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

/// A deterministic test pattern of `len` bytes.
#[allow(clippy::cast_possible_truncation)]
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ 0xA5)
        .collect()
}

/// Reference: encrypt each sector with the single-shot API + LE-128 tweak.
fn reference_encrypt(sector_size: usize, start_sector: u128, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, sector) in data.chunks(sector_size).enumerate() {
        let tweak = start_sector.wrapping_add(i as u128).to_le_bytes();
        out.extend_from_slice(&mode_xts::encrypt(&KEY, &tweak, sector).expect("valid sector"));
    }
    out
}

fn reference_decrypt(sector_size: usize, start_sector: u128, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, sector) in data.chunks(sector_size).enumerate() {
        let tweak = start_sector.wrapping_add(i as u128).to_le_bytes();
        out.extend_from_slice(&mode_xts::decrypt(&KEY, &tweak, sector).expect("valid sector"));
    }
    out
}

/// Assert the helper equals the single-shot loop for one shape (encrypt match +
/// in-place round-trip + decrypt match).
fn assert_shape(sector_size: usize, n: usize, start: u128) {
    let plain = pattern(sector_size * n);

    let mut buf = plain.clone();
    mode_xts::encrypt_sectors(&KEY, sector_size, start, &mut buf).expect("encrypt_sectors valid");
    assert_eq!(
        buf,
        reference_encrypt(sector_size, start, &plain),
        "encrypt mismatch ss={sector_size} n={n} start={start}"
    );

    // decrypt_sectors restores the original in place...
    mode_xts::decrypt_sectors(&KEY, sector_size, start, &mut buf).expect("decrypt_sectors valid");
    assert_eq!(
        buf, plain,
        "round-trip mismatch ss={sector_size} n={n} start={start}"
    );

    // ...and matches the single-shot decrypt loop on independent ciphertext.
    let ct = reference_encrypt(sector_size, start, &plain);
    let mut dbuf = ct.clone();
    mode_xts::decrypt_sectors(&KEY, sector_size, start, &mut dbuf).expect("decrypt_sectors valid");
    assert_eq!(dbuf, reference_decrypt(sector_size, start, &ct));
}

#[test]
fn matches_single_shot_loop_across_shapes() {
    // Dense sweep over small sizes (the SM4 default linear-scan S-box is slow in
    // debug, so keep the volume modest). Sector counts 1/2/3 cover the tweak
    // increment + α-doubling chain; 8 covers the SIMD batch fanout. Starts cross
    // LE-counter byte boundaries (0xfe -> 0x100, 0xffff -> 0x1_0000).
    for &sector_size in &[16usize, 32, 512] {
        for &n in &[1usize, 2, 3, 8] {
            for &start in &[0u128, 0xfe, 0xffff] {
                assert_shape(sector_size, n, start);
            }
        }
    }
}

#[test]
fn handles_large_sectors_and_high_lba() {
    // One realistic 4 KiB sector size at a large 64-bit-range starting LBA,
    // crossing the 2^32 boundary in the LE tweak counter.
    assert_shape(4096, 4, 0x1_0000_0000);
}

/// Absolute anchor: a `u128` sector number whose LE-128 encoding is the
/// all-`0x11` tweak that `sm4_xts_kat.rs`'s "whole-block 16" vector pins to
/// OpenSSL. One 16-byte sector ⇒ this is a hard KAT, not only a differential.
#[test]
fn absolute_kat_against_openssl_pinned_vector() {
    // 0x11 repeated 16x; LE/BE-agnostic since all bytes equal.
    let start_sector = u128::from_le_bytes([0x11; 16]);
    let pt = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected_ct = [
        0xb3, 0xfb, 0xef, 0x63, 0x16, 0x5a, 0x03, 0x94, 0x2e, 0xa2, 0xb4, 0xb7, 0xbc, 0x67, 0xaf,
        0x80,
    ];
    let mut buf = pt;
    mode_xts::encrypt_sectors(&KEY, 16, start_sector, &mut buf).expect("valid");
    assert_eq!(
        buf, expected_ct,
        "sector helper != OpenSSL-pinned ciphertext"
    );

    mode_xts::decrypt_sectors(&KEY, 16, start_sector, &mut buf).expect("valid");
    assert_eq!(buf, pt, "decrypt restores plaintext");
}

#[test]
fn empty_buffer_is_vacuous_success() {
    let mut buf: [u8; 0] = [];
    assert!(mode_xts::encrypt_sectors(&KEY, 512, 0, &mut buf).is_some());
    assert!(mode_xts::decrypt_sectors(&KEY, 512, 0, &mut buf).is_some());

    // ...but the key is still validated even with zero sectors: an empty buffer
    // under a weak key (Key1 == Key2) is still `None` (W0 codex finding —
    // "valid sector_size AND key" is the vacuous-success precondition).
    let mut weak = KEY;
    weak.copy_within(0..16, 16);
    assert!(mode_xts::encrypt_sectors(&weak, 512, 0, &mut buf).is_none());
}

#[test]
fn rejects_invalid_sector_size() {
    // not a multiple of 16
    assert!(mode_xts::encrypt_sectors(&KEY, 20, 0, &mut [0u8; 20]).is_none());
    // below one block
    assert!(mode_xts::encrypt_sectors(&KEY, 8, 0, &mut [0u8; 8]).is_none());
    // zero sector_size
    assert!(mode_xts::encrypt_sectors(&KEY, 0, 0, &mut []).is_none());
    // above the 16 MiB per-data-unit ceiling (validated before touching buf,
    // so an empty buffer is fine — no giant allocation needed)
    let too_big = (1usize << 20) * 16 + 16;
    assert!(mode_xts::encrypt_sectors(&KEY, too_big, 0, &mut []).is_none());
}

#[test]
fn rejects_non_multiple_buffer() {
    // 24 is not a whole multiple of the 16-byte sector size.
    let mut buf = [0u8; 24];
    let before = buf;
    assert!(mode_xts::encrypt_sectors(&KEY, 16, 0, &mut buf).is_none());
    assert_eq!(buf, before, "buf must be untouched on validation failure");
}

#[test]
fn rejects_weak_key_buf_untouched() {
    let mut weak = KEY;
    weak.copy_within(0..16, 16); // Key2 := Key1
    let mut buf = pattern(32);
    let before = buf.clone();
    assert!(mode_xts::encrypt_sectors(&weak, 16, 0, &mut buf).is_none());
    assert!(mode_xts::decrypt_sectors(&weak, 16, 0, &mut buf).is_none());
    assert_eq!(buf, before, "buf must be untouched on weak-key reject");
}

#[test]
fn rejects_sector_number_overflow_buf_untouched() {
    // 2 sectors starting at u128::MAX ⇒ sector 1 = MAX + 1 overflows ⇒ None,
    // and (per the in-place contract) buf is left untouched.
    let mut buf = pattern(32);
    let before = buf.clone();
    assert!(mode_xts::encrypt_sectors(&KEY, 16, u128::MAX, &mut buf).is_none());
    assert_eq!(buf, before, "buf must be untouched on overflow reject");

    // A single sector at u128::MAX is fine (no increment needed).
    let mut one = pattern(16);
    assert!(mode_xts::encrypt_sectors(&KEY, 16, u128::MAX, &mut one).is_some());
}
