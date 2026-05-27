//! SM4 in XTS mode (XEX-based tweaked-codebook with ciphertext stealing)
//! per **GB/T 17964-2021** — the SM4 national standard for the XTS tweakable
//! mode (GM-T OID `1.2.156.10197.1.104.10`).
//!
//! # What XTS is for
//!
//! XTS is a length-preserving, *tweakable* block-cipher mode designed for
//! random-access **disk/sector encryption**. Each data unit (sector) is
//! encrypted independently under a per-unit 16-byte *tweak* (the data-unit
//! number). It produces no ciphertext expansion and **no authentication tag**.
//!
//! # GB/T 17964 vs IEEE 1619
//!
//! This is the **GB** variant (`xts_standard=GB` in OpenSSL), **not** IEEE 1619
//! (the AES-XTS standard). The two differ in the GF(2¹²⁸) tweak-doubling
//! convention — GB/T 17964 uses the bit-reflected (GHASH-style) representation
//! — so they produce *different* ciphertext for multi-block / non-aligned data.
//! `mode_xts` is byte-identical to OpenSSL 3.x EVP `SM4-XTS` with
//! `xts_standard=GB`.
//!
//! # No authentication
//!
//! XTS provides **confidentiality only**. [`decrypt`] returning `Some` does
//! **not** mean the ciphertext is authentic — an attacker can flip ciphertext
//! and the plaintext changes unpredictably but undetectably. Callers needing
//! integrity must use an AEAD mode ([`super::mode_gcm`] / [`super::mode_ccm`]),
//! not XTS.
//!
//! # Tweak-uniqueness contract (caller-owned)
//!
//! The caller MUST supply a **unique** 16-byte `tweak` per data unit under a
//! given key — in disk use, the tweak is the sector number. Reusing a
//! `(key, tweak)` pair across different plaintexts leaks equality structure
//! (XTS is deterministic). The encoding of a sector number into the 16-byte
//! tweak (endianness/width) is the caller's responsibility; this module
//! consumes the raw 16 bytes as-is. Same posture as the CTR/GCM nonce
//! contracts.
//!
//! # Keys
//!
//! The 32-byte `key` is `Key1 ‖ Key2`: `Key1` encrypts the data blocks,
//! `Key2` encrypts the tweak. GB/T 17964 (and FIPS) mandate `Key1 ≠ Key2`;
//! equal halves are rejected with `None`.
//!
//! # Length bounds & failure mode
//!
//! `16 ≤ data_unit.len() ≤ 2²⁰·16` (16 MiB) — the NIST SP 800-38E ceiling of
//! 2²⁰ blocks per data unit. Lengths of any value in that range are supported,
//! including non-block-multiples via ciphertext stealing. Both [`encrypt`] and
//! [`decrypt`] return `Option<Vec<u8>>`; `None` is returned only for input
//! validation (`len` out of range, or `Key1 == Key2`). No distinguishing
//! variants, per the workspace failure-mode invariant. XTS has no tag, so there
//! is no MAC-failure path.
//!
//! # KAT sourcing
//!
//! gmssl 3.1.1 lacks XTS. KAT vectors come from OpenSSL 3.x EVP `SM4-XTS`
//! (`xts_standard=GB`); see [`docs/v0.12-xts-kat-sourcing.md`].
//!
//! # API
//!
//! ```rust
//! # #[cfg(feature = "sm4-xts")] {
//! use gmcrypto_core::sm4::{mode_xts, mode_xts::XTS_KEY_SIZE};
//!
//! let key: [u8; XTS_KEY_SIZE] = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! ];
//! let tweak: [u8; 16] = [0x11; 16];
//! let plaintext = b"a full data unit at least 16 bytes long";
//!
//! let ct = mode_xts::encrypt(&key, &tweak, plaintext).expect("valid");
//! let pt = mode_xts::decrypt(&key, &tweak, &ct).expect("valid");
//! assert_eq!(pt, plaintext);
//! # }
//! ```
//!
//! # Multi-sector (whole-disk) helper
//!
//! [`encrypt_sectors`] / [`decrypt_sectors`] process a contiguous run of
//! equal-size sectors **in place**, deriving sector `i`'s tweak as the
//! **little-endian 128-bit encoding** of `start_sector + i` (the standard
//! disk-XTS data-unit convention). This owns the sector-number → tweak encoding
//! the single-shot API leaves to the caller, removing the easy-to-get-wrong
//! step. Sectors are whole-block, so ciphertext stealing never triggers; the
//! result is byte-identical to looping the single-shot API per sector. The
//! **tweak-namespace contract** (sector numbers unique within the key namespace;
//! confidentiality only, no authentication) is the same as for the single-shot
//! API — see [`encrypt_sectors`].
//!
//! ```rust
//! # #[cfg(feature = "sm4-xts")] {
//! use gmcrypto_core::sm4::mode_xts::{self, XTS_KEY_SIZE};
//!
//! // Key1 ‖ Key2 — the two halves MUST differ (GB/T 17964 weak-key guard).
//! let mut key = [0u8; XTS_KEY_SIZE];
//! for (i, b) in key.iter_mut().enumerate() {
//!     *b = i as u8;
//! }
//!
//! let sector_size = 512;
//! let start_sector = 0x1000u128; // first logical block address in this run
//!
//! // A 2-sector (1 KiB) region, encrypted then decrypted back in place.
//! let mut region = [0xABu8; 1024];
//! let original = region;
//! mode_xts::encrypt_sectors(&key, sector_size, start_sector, &mut region).unwrap();
//! assert_ne!(region, original);
//! mode_xts::decrypt_sectors(&key, sector_size, start_sector, &mut region).unwrap();
//! assert_eq!(region, original);
//! # }
//! ```

use alloc::vec::Vec;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::cipher::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};

/// XTS combined key size: `Key1 ‖ Key2`, two SM4-128 keys (32 bytes).
pub const XTS_KEY_SIZE: usize = 2 * KEY_SIZE;

/// NIST SP 800-38E maximum: 2²⁰ blocks per data unit (16 MiB).
const MAX_LEN: usize = (1 << 20) * BLOCK_SIZE;

/// Multiply a 128-bit value by the GF(2¹²⁸) primitive element α (= x) in the
/// **GB/T 17964-2021** bit-reflected (GHASH-style) representation.
///
/// Treat byte 0 as the leading byte; right-shift the 128-bit value by one bit
/// (carry each byte's LSB into the next byte's MSB). If the bit shifted off the
/// end (LSB of byte 15) is 1, XOR the reduce constant `0xE1` into byte 0.
/// (`0xE1` is the bit-reversed `0x87`; IEEE 1619 uses the opposite little-endian
/// `<<1` / `0x87` convention, which yields *different* ciphertext.)
///
/// Constant-time: the reduce is a masked XOR, never a branch on the
/// (secret-derived) tweak. `carry` is 0 or 1; `wrapping_neg()` maps it to a
/// 0x00 / 0xFF mask.
fn mul_alpha(t: &mut [u8; BLOCK_SIZE]) {
    let mut carry = 0u8;
    for b in t.iter_mut() {
        let next = *b & 1;
        *b = (*b >> 1) | (carry << 7);
        carry = next;
    }
    t[0] ^= 0xE1 & carry.wrapping_neg();
}

/// XOR `b` into `a`, 16 bytes.
fn xor16(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

/// Validate the key/length and construct the two ciphers. Returns `None`
/// on out-of-range length or weak key (`Key1 == Key2`).
fn split_keys(key: &[u8; XTS_KEY_SIZE], len: usize) -> Option<(Sm4Cipher, Sm4Cipher)> {
    if !(BLOCK_SIZE..=MAX_LEN).contains(&len) {
        return None;
    }
    // Constant-time compare of the two 16-byte halves; the equal/not-equal
    // *outcome* gates the reject (a usage error, fine to reveal), but the
    // comparison leaks no byte positions.
    if bool::from(key[..KEY_SIZE].ct_eq(&key[KEY_SIZE..])) {
        return None;
    }
    // Copy each half into a fixed array (no fallible `try_into`, no panic
    // path) and zeroize the copies once the ciphers have absorbed them
    // (`Sm4Cipher` is itself `ZeroizeOnDrop`).
    let mut key1 = [0u8; KEY_SIZE];
    let mut key2 = [0u8; KEY_SIZE];
    key1.copy_from_slice(&key[..KEY_SIZE]);
    key2.copy_from_slice(&key[KEY_SIZE..]);
    let ciphers = (Sm4Cipher::new(&key1), Sm4Cipher::new(&key2));
    key1.zeroize();
    key2.zeroize();
    Some(ciphers)
}

/// Encrypt `data_unit` under (`key`, `tweak`) in SM4-XTS mode with full
/// ciphertext stealing. See the module docstring for the contracts.
#[must_use]
pub fn encrypt(
    key: &[u8; XTS_KEY_SIZE],
    tweak: &[u8; BLOCK_SIZE],
    data_unit: &[u8],
) -> Option<Vec<u8>> {
    let (c1, c2) = split_keys(key, data_unit.len())?;
    Some(xts_encrypt(&c1, &c2, tweak, data_unit))
}

/// Decrypt `data_unit` under (`key`, `tweak`) in SM4-XTS mode with full
/// ciphertext stealing. XTS is unauthenticated — see the module docstring.
#[must_use]
pub fn decrypt(
    key: &[u8; XTS_KEY_SIZE],
    tweak: &[u8; BLOCK_SIZE],
    data_unit: &[u8],
) -> Option<Vec<u8>> {
    let (c1, c2) = split_keys(key, data_unit.len())?;
    Some(xts_decrypt(&c1, &c2, tweak, data_unit))
}

/// Encrypt a contiguous run of equal-size sectors **in place** in SM4-XTS mode.
///
/// `buf` holds `buf.len() / sector_size` sectors back-to-back; sector `i`
/// (0-based) is encrypted independently under tweak = the **little-endian
/// 128-bit encoding** of `start_sector + i` (the standard disk-XTS data-unit
/// convention — see the module docstring). Because `sector_size` is a whole
/// number of 16-byte blocks, ciphertext stealing never occurs and the output is
/// byte-identical to looping [`encrypt`] over each sector with the corresponding
/// LE-128 tweak.
///
/// Returns `None` — **leaving `buf` untouched** — on any input-validation
/// failure: `sector_size` not a multiple of 16, `< 16`, or `> 16 MiB`;
/// `buf.len()` not a whole multiple of `sector_size`; `Key1 == Key2`; or
/// `start_sector + i` overflowing `u128`. `buf.len() == 0` (zero sectors) with a
/// valid `sector_size` and key is a vacuous `Some(())`.
///
/// **Confidentiality only** — XTS has no authentication tag; `Some(())` does not
/// imply integrity. **Tweak-namespace contract (caller-owned):** sector numbers
/// must be unique within the XTS-key namespace — do not encrypt multiple
/// devices / partitions / snapshots under one key all starting at sector 0
/// (use absolute LBAs or a separate key per device); reuse leaks block-equality
/// structure.
#[must_use]
pub fn encrypt_sectors(
    key: &[u8; XTS_KEY_SIZE],
    sector_size: usize,
    start_sector: u128,
    buf: &mut [u8],
) -> Option<()> {
    process_sectors(key, sector_size, start_sector, buf, true)
}

/// Decrypt a contiguous run of equal-size sectors **in place** in SM4-XTS mode.
///
/// The inverse of [`encrypt_sectors`] under the same `(key, sector_size,
/// start_sector)`. Same validation, failure mode (single `None`, `buf`
/// untouched), and caveats as [`encrypt_sectors`]. XTS is unauthenticated.
#[must_use]
pub fn decrypt_sectors(
    key: &[u8; XTS_KEY_SIZE],
    sector_size: usize,
    start_sector: u128,
    buf: &mut [u8],
) -> Option<()> {
    process_sectors(key, sector_size, start_sector, buf, false)
}

/// Shared core for [`encrypt_sectors`] / [`decrypt_sectors`]. **All validation
/// runs before `buf` is touched** (W0 codex finding): on any `None` path `buf`
/// is left unmodified, and the per-sector loop can never hit a mid-run overflow.
fn process_sectors(
    key: &[u8; XTS_KEY_SIZE],
    sector_size: usize,
    start_sector: u128,
    buf: &mut [u8],
    encrypt: bool,
) -> Option<()> {
    // 1. sector_size: a whole number of blocks within [16, 16 MiB].
    if !(BLOCK_SIZE..=MAX_LEN).contains(&sector_size) || sector_size % BLOCK_SIZE != 0 {
        return None;
    }
    // 2. buf must be a whole multiple of sector_size (0 sectors allowed).
    if buf.len() % sector_size != 0 {
        return None;
    }
    let sector_count = buf.len() / sector_size;
    // 3. The highest sector number (start_sector + sector_count - 1) must not
    //    overflow u128. Pre-checked here so the loop never overflows mid-run.
    if let Some(last) = sector_count.checked_sub(1) {
        start_sector.checked_add(last as u128)?;
    }
    // 4. Build both ciphers ONCE (validates key length + the constant-time
    //    Key1 == Key2 weak-key reject); reused across every sector. Does not
    //    touch buf, so a weak-key `None` still leaves buf unmodified.
    let (c1, c2) = split_keys(key, sector_size)?;

    // Scratch reused across all sectors (allocated once, not per sector).
    let nblocks = sector_size / BLOCK_SIZE;
    let mut blocks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(nblocks);
    let mut tweaks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(nblocks);

    for (i, sector) in buf.chunks_mut(sector_size).enumerate() {
        // Overflow was pre-validated in step 3, so this never wraps.
        let sector_num = start_sector.wrapping_add(i as u128);
        let tweak = sector_num.to_le_bytes();
        xts_sector_in_place(&c1, &c2, &tweak, sector, &mut blocks, &mut tweaks, encrypt);
    }
    Some(())
}

/// Transform one whole-block sector in place (no ciphertext stealing). Mirrors
/// the `rem == 0` path of [`xts_encrypt`] / [`xts_decrypt`] but writes back into
/// `sector` and reuses the caller-owned `blocks` / `tweaks` scratch (cleared on
/// entry) to avoid per-sector allocation. `encrypt` selects the direction; the
/// tweak sequence is identical either way.
fn xts_sector_in_place(
    c1: &Sm4Cipher,
    c2: &Sm4Cipher,
    tweak: &[u8; BLOCK_SIZE],
    sector: &mut [u8],
    blocks: &mut Vec<[u8; BLOCK_SIZE]>,
    tweaks: &mut Vec<[u8; BLOCK_SIZE]>,
    encrypt: bool,
) {
    // T_0 = SM4_E(Key2, tweak) — the tweak is encrypted with Key2 in both
    // directions.
    let mut t = *tweak;
    c2.encrypt_block(&mut t);

    blocks.clear();
    tweaks.clear();
    for chunk in sector.chunks_exact(BLOCK_SIZE) {
        let mut blk = [0u8; BLOCK_SIZE];
        blk.copy_from_slice(chunk);
        xor16(&mut blk, &t);
        blocks.push(blk);
        tweaks.push(t);
        mul_alpha(&mut t);
    }

    if encrypt {
        c1.encrypt_blocks(blocks);
    } else {
        c1.decrypt_blocks(blocks);
    }

    for (blk, tw) in blocks.iter_mut().zip(tweaks.iter()) {
        xor16(blk, tw);
    }
    // Scatter the transformed blocks back into the sector in place.
    for (chunk, blk) in sector.chunks_exact_mut(BLOCK_SIZE).zip(blocks.iter()) {
        chunk.copy_from_slice(blk);
    }

    // Wipe secret-derived tweak material (the data in `blocks` is the caller's
    // plaintext/ciphertext — already written back to `buf` — and is left as-is,
    // matching the single-shot path).
    t.zeroize();
    for tw in tweaks.iter_mut() {
        tw.zeroize();
    }
}

fn xts_encrypt(c1: &Sm4Cipher, c2: &Sm4Cipher, tweak: &[u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let full = len / BLOCK_SIZE;
    let rem = len % BLOCK_SIZE;
    // Blocks processed by the "normal" (non-CTS) path. When there is a partial
    // tail, the last *full* block is consumed by CTS instead.
    let normal = if rem == 0 { full } else { full - 1 };

    // T_0 = SM4_E(Key2, tweak).
    let mut t = *tweak;
    c2.encrypt_block(&mut t);

    // Normal blocks: PP_j = P_j ⊕ T_j, one batch encrypt, then ⊕ T_j back.
    let mut tweaks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(normal);
    let mut blocks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(normal);
    for j in 0..normal {
        let mut blk = [0u8; BLOCK_SIZE];
        blk.copy_from_slice(&data[j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE]);
        xor16(&mut blk, &t);
        blocks.push(blk);
        tweaks.push(t);
        mul_alpha(&mut t);
    }
    c1.encrypt_blocks(&mut blocks);
    for (blk, tw) in blocks.iter_mut().zip(tweaks.iter()) {
        xor16(blk, tw);
    }

    let mut out = Vec::with_capacity(len);
    for blk in &blocks {
        out.extend_from_slice(blk);
    }

    if rem != 0 {
        // CTS. `t` is now T_{q-1} (tweak for the last full block).
        let mut t_last = t;
        let mut t_steal = t;
        mul_alpha(&mut t_steal); // T_q

        // CC = SM4_E(Key1, P_{q-1} ⊕ T_{q-1}) ⊕ T_{q-1}.
        let mut cc = [0u8; BLOCK_SIZE];
        cc.copy_from_slice(&data[normal * BLOCK_SIZE..normal * BLOCK_SIZE + BLOCK_SIZE]);
        xor16(&mut cc, &t_last);
        c1.encrypt_block(&mut cc);
        xor16(&mut cc, &t_last);

        // PP = P_partial ‖ CC[rem..]; C_{q-1} = SM4_E(Key1, PP ⊕ T_q) ⊕ T_q.
        let mut pp = [0u8; BLOCK_SIZE];
        let partial = &data[normal * BLOCK_SIZE + BLOCK_SIZE..];
        pp[..rem].copy_from_slice(partial);
        pp[rem..].copy_from_slice(&cc[rem..]);
        xor16(&mut pp, &t_steal);
        c1.encrypt_block(&mut pp);
        xor16(&mut pp, &t_steal);

        // Output: [normal blocks] ‖ C_{q-1} (pp) ‖ CC[..rem].
        out.extend_from_slice(&pp);
        out.extend_from_slice(&cc[..rem]);

        // Wipe the secret-derived CTS tweak copies.
        t_last.zeroize();
        t_steal.zeroize();
    }

    // Wipe all secret-derived tweak material (the running tweak + the stored
    // per-block tweaks). The returned plaintext/ciphertext is the caller's to
    // manage, as in the other modes; `Sm4Cipher` zeroizes its keys on drop.
    t.zeroize();
    for tw in &mut tweaks {
        tw.zeroize();
    }
    out
}

fn xts_decrypt(c1: &Sm4Cipher, c2: &Sm4Cipher, tweak: &[u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let full = len / BLOCK_SIZE;
    let rem = len % BLOCK_SIZE;
    let normal = if rem == 0 { full } else { full - 1 };

    // Tweak is ENCRYPTED with Key2 even on decrypt: T_0 = SM4_E(Key2, tweak).
    let mut t = *tweak;
    c2.encrypt_block(&mut t);

    let mut tweaks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(normal);
    let mut blocks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(normal);
    for j in 0..normal {
        let mut blk = [0u8; BLOCK_SIZE];
        blk.copy_from_slice(&data[j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE]);
        xor16(&mut blk, &t);
        blocks.push(blk);
        tweaks.push(t);
        mul_alpha(&mut t);
    }
    c1.decrypt_blocks(&mut blocks);
    for (blk, tw) in blocks.iter_mut().zip(tweaks.iter()) {
        xor16(blk, tw);
    }

    let mut out = Vec::with_capacity(len);
    for blk in &blocks {
        out.extend_from_slice(blk);
    }

    if rem != 0 {
        // `t` is now T_{q-1}.
        let mut t_last = t;
        let mut t_steal = t;
        mul_alpha(&mut t_steal); // T_q

        // PP = SM4_D(Key1, C_{q-1} ⊕ T_q) ⊕ T_q (the stolen 16-byte block).
        let mut pp = [0u8; BLOCK_SIZE];
        pp.copy_from_slice(&data[normal * BLOCK_SIZE..normal * BLOCK_SIZE + BLOCK_SIZE]);
        xor16(&mut pp, &t_steal);
        c1.decrypt_block(&mut pp);
        xor16(&mut pp, &t_steal);

        // CC = C_partial ‖ PP[rem..]; P_{q-1} = SM4_D(Key1, CC ⊕ T_{q-1}) ⊕ T_{q-1}.
        let mut cc = [0u8; BLOCK_SIZE];
        let partial = &data[normal * BLOCK_SIZE + BLOCK_SIZE..];
        cc[..rem].copy_from_slice(partial);
        cc[rem..].copy_from_slice(&pp[rem..]);
        xor16(&mut cc, &t_last);
        c1.decrypt_block(&mut cc);
        xor16(&mut cc, &t_last);

        // Output: [normal blocks] ‖ P_{q-1} (cc) ‖ PP[..rem].
        out.extend_from_slice(&cc);
        out.extend_from_slice(&pp[..rem]);

        // Wipe the secret-derived CTS tweak copies.
        t_last.zeroize();
        t_steal.zeroize();
    }

    // Wipe all secret-derived tweak material (the running tweak + the stored
    // per-block tweaks). The returned plaintext is the caller's to manage, as
    // in the other modes; `Sm4Cipher` zeroizes its keys on drop.
    t.zeroize();
    for tw in &mut tweaks {
        tw.zeroize();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_alpha_no_carry_is_plain_right_shift() {
        // byte0 = 0x02 (LSB clear) -> right-shift -> 0x01, no carry out.
        let mut t = [0u8; 16];
        t[0] = 0x02;
        mul_alpha(&mut t);
        let mut expected = [0u8; 16];
        expected[0] = 0x01;
        assert_eq!(t, expected);
    }

    #[test]
    fn mul_alpha_carry_xors_0xe1() {
        // LSB of byte 15 set -> shifts off the end -> carry -> XOR 0xE1 into byte 0.
        let mut t = [0u8; 16];
        t[15] = 0x01;
        mul_alpha(&mut t);
        let mut expected = [0u8; 16];
        expected[0] = 0xE1;
        assert_eq!(t, expected);
    }

    const KEY: [u8; XTS_KEY_SIZE] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    const TWEAK: [u8; 16] = [0x11; 16];

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xts_round_trip_all_lengths() {
        for len in 16..=80usize {
            let pt: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0xA5).collect();
            let ct = encrypt(&KEY, &TWEAK, &pt).expect("valid");
            assert_eq!(ct.len(), pt.len(), "len-preserving at {len}");
            let rt = decrypt(&KEY, &TWEAK, &ct).expect("valid");
            assert_eq!(rt, pt, "round-trip at length {len}");
        }
    }

    #[test]
    fn xts_rejects_short_long_and_weak_key() {
        assert!(encrypt(&KEY, &TWEAK, &[0u8; 15]).is_none(), "len 15 < 16");
        assert!(encrypt(&KEY, &TWEAK, &[]).is_none(), "len 0");
        // len > 16 MiB rejected (the length check short-circuits before any
        // encryption, so the oversized buffer is never processed).
        assert!(
            encrypt(&KEY, &TWEAK, &alloc::vec![0u8; MAX_LEN + 1]).is_none(),
            "len > 16 MiB"
        );
        let mut weak = KEY;
        weak.copy_within(0..16, 16); // Key2 := Key1
        assert!(encrypt(&weak, &TWEAK, &[0u8; 16]).is_none(), "Key1 == Key2");
        assert!(decrypt(&weak, &TWEAK, &[0u8; 16]).is_none(), "Key1 == Key2");
    }
}
