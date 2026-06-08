//! Fuzz target: HMAC-SM3 — DIFFERENTIAL one-shot vs streaming, plus the
//! constant-time `verify` path (correct tag accepts; one-bit-flipped rejects).
//!
//! SM3 / HMAC-SM3 were previously reached only indirectly (PBKDF2, parsers).
//!
//! Invariants for arbitrary key / message:
//!   * one-shot `hmac_sm3(key, msg)` byte-equals streaming
//!     `HmacSm3::new(key) -> update(..) -> finalize()`;
//!   * `verify` accepts the correct tag and rejects a tampered one.
#![no_main]

use gmcrypto_core::hmac::{hmac_sm3, HmacSm3};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [key_len:1][key][message...]. key_len up to 255 deliberately
    // exercises the `key.len() > 64` "hash the key first" branch.
    if data.is_empty() {
        return;
    }
    let klen = data[0] as usize;
    let rest = &data[1..];
    if rest.len() < klen {
        return;
    }
    let key = &rest[..klen];
    let msg = &rest[klen..];

    // One-shot reference.
    let oneshot = hmac_sm3(key, msg);

    // Streaming in irregular chunks.
    const SIZES: [usize; 6] = [1, 3, 7, 13, 31, 64];
    let mut mac = HmacSm3::new(key);
    let mut r = msg;
    let mut i = 0usize;
    while !r.is_empty() {
        let n = SIZES[i % SIZES.len()].min(r.len());
        mac.update(&r[..n]);
        r = &r[n..];
        i += 1;
    }
    let streamed = mac.finalize();
    assert_eq!(
        oneshot, streamed,
        "HMAC-SM3 one-shot vs streaming tag mismatch"
    );

    // verify() must accept the correct tag.
    let mut good = HmacSm3::new(key);
    good.update(msg);
    assert!(good.verify(&oneshot), "verify must accept the correct tag");

    // verify() must reject a single-bit-flipped tag.
    let mut tampered = oneshot;
    tampered[0] ^= 0x01;
    let mut bad = HmacSm3::new(key);
    bad.update(msg);
    assert!(!bad.verify(&tampered), "verify must reject a tampered tag");
});
