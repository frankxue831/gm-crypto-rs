//! Fuzz target: the SM4-XTS multi-sector (disk) helpers,
//! `mode_xts::{encrypt_sectors, decrypt_sectors}`.
//!
//! Invariants:
//!
//! 1. **No panic** on either helper.
//! 2. **`encrypt_sectors` == looping the single-shot `encrypt`** once per
//!    sector, with sector `i` under tweak `LE-128(start_sector + i)`.
//! 3. **`decrypt_sectors` == looping the single-shot `decrypt`**, and the
//!    in-place round-trip recovers the plaintext.
//! 4. **`buf` is untouched on the `None` path** — the helpers pre-flight every
//!    validation before mutating, so a rejected call must leave the caller's
//!    buffer byte-identical.
//!
//! # What this adds over the deterministic tests
//!
//! `crates/gmcrypto-core/tests/sm4_xts_sectors.rs` already pins invariant (2)
//! across 36 shapes (`sector_size` × sector count × `start_sector`), so this
//! target is NOT the first coverage of it — say so plainly rather than let a
//! reader assume otherwise. What is genuinely fuzz-only here:
//!
//! - **Arbitrary `start_sector` across the full u128 range**, including runs
//!   that end exactly at `u128::MAX` and runs that overflow. The deterministic
//!   sweep tops out at `0x1_0000_0000`.
//! - **Arbitrary key and buffer content**, rather than fixed patterns.
//! - **Invariant (4) on the overflow path specifically.** Given the massaging
//!   below, sector-number overflow is the *only* rejection this target can
//!   reach, so every `None` here exercises the buf-untouched contract.
//!
//! # Layout
//!
//! `[key:32][start_sector:16 big-endian][sector_size_sel:1][buf:rest]`
//!
//! Manual slicing, no `arbitrary::Unstructured` — matching
//! `fuzz_sm4_xts_encrypt`, so a seed is a plain byte concatenation that stays
//! readable by hand and does not depend on `arbitrary`'s consumption order.
//!
//! `start_sector` is read big-endian purely so seeds read left-to-right; the
//! *tweak* derived from it is little-endian, per the disk-XTS convention.
//!
//! Sector sizes are kept small deliberately: `fuzz-nightly.yml` runs with
//! `-max_len=16384`, so a 4 KiB sector would admit at most 3 sectors and a
//! 64 KiB sector none at all. Capping the run at 8 sectors keeps each input
//! cheap without giving up multi-sector coverage.
#![no_main]

use gmcrypto_core::sm4::mode_xts::{self, XTS_KEY_SIZE};
use gmcrypto_core::sm4::BLOCK_SIZE;
use libfuzzer_sys::fuzz_target;

/// All whole multiples of 16 and inside `[16, 16 MiB]`, so `sector_size` never
/// causes a rejection on its own.
const SECTOR_SIZES: [usize; 3] = [16, 32, 512];

/// Cap the run so one input stays cheap.
const MAX_SECTORS: usize = 8;

/// key + start_sector + selector byte.
const HEADER: usize = XTS_KEY_SIZE + 16 + 1;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER + BLOCK_SIZE {
        return;
    }

    let mut key: [u8; XTS_KEY_SIZE] = data[..XTS_KEY_SIZE].try_into().unwrap();
    // XTS rejects Key1 == Key2; perturb so the input still reaches real work.
    if key[..BLOCK_SIZE] == key[BLOCK_SIZE..] {
        key[BLOCK_SIZE] ^= 0x01;
    }

    let start_sector =
        u128::from_be_bytes(data[XTS_KEY_SIZE..XTS_KEY_SIZE + 16].try_into().unwrap());
    let sector_size = SECTOR_SIZES[data[XTS_KEY_SIZE + 16] as usize % SECTOR_SIZES.len()];

    let tail = &data[HEADER..];
    let n = core::cmp::min(tail.len() / sector_size, MAX_SECTORS);
    if n == 0 {
        return;
    }
    let plain = &tail[..n * sector_size];

    // --- (2) encrypt_sectors == looped single-shot encrypt -------------------
    let mut got = plain.to_vec();
    if mode_xts::encrypt_sectors(&key, sector_size, start_sector, &mut got).is_none() {
        // sector_size, buf length and the key are all pre-massaged above, so
        // the ONLY rejection reachable here is sector-number overflow.
        assert_eq!(
            got, plain,
            "encrypt_sectors mutated buf on the None path (start_sector={start_sector}, \
             sector_size={sector_size}, n={n})"
        );
        return;
    }

    // Past this point the helper accepted the run, so `start_sector + i` did
    // not overflow for any i < n and `wrapping_add` is exact.
    let mut want = Vec::with_capacity(plain.len());
    for (i, sector) in plain.chunks(sector_size).enumerate() {
        let tweak = start_sector.wrapping_add(i as u128).to_le_bytes();
        want.extend_from_slice(
            &mode_xts::encrypt(&key, &tweak, sector)
                .expect("single-shot encrypt of a whole-block sector must succeed"),
        );
    }
    assert_eq!(
        got, want,
        "encrypt_sectors diverged from the looped single-shot \
         (start_sector={start_sector}, sector_size={sector_size}, n={n})"
    );

    // --- (3a) in-place round-trip -------------------------------------------
    let mut back = got.clone();
    mode_xts::decrypt_sectors(&key, sector_size, start_sector, &mut back)
        .expect("decrypt_sectors of self-produced ciphertext must succeed");
    assert_eq!(
        back, plain,
        "encrypt_sectors -> decrypt_sectors round-trip mismatch \
         (start_sector={start_sector}, sector_size={sector_size}, n={n})"
    );

    // --- (3b) decrypt_sectors == looped single-shot decrypt ------------------
    let mut want_dec = Vec::with_capacity(got.len());
    for (i, sector) in got.chunks(sector_size).enumerate() {
        let tweak = start_sector.wrapping_add(i as u128).to_le_bytes();
        want_dec.extend_from_slice(
            &mode_xts::decrypt(&key, &tweak, sector)
                .expect("single-shot decrypt of a whole-block sector must succeed"),
        );
    }
    assert_eq!(
        want_dec, plain,
        "decrypt_sectors diverged from the looped single-shot \
         (start_sector={start_sector}, sector_size={sector_size}, n={n})"
    );
});
