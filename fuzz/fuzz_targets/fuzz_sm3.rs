//! Fuzz target: SM3 (GB/T 32905) primitive — DIFFERENTIAL oracle.
//!
//! The one-shot `sm3::hash(data)` must byte-equal the streaming
//! `Sm3::new() -> update(..) -> finalize()` result for arbitrary input fed
//! in arbitrary-width chunks. Closes the "SM3 is only reached indirectly via
//! parsers, never fuzzed as a standalone primitive" coverage gap.
//!
//! Note: `sm3::hash` itself delegates to the same streaming core, so this is a
//! chunk-boundary-equivalence oracle (update-splitting, empty absorbs,
//! partial-block tails) rather than an independent reference implementation.
//!
//! Invariants exercised for ANY input:
//!   * neither path panics;
//!   * one-shot == streaming regardless of how the message is chunked
//!     (block-straddling absorbs, partial-block tails, empty input).
#![no_main]

use gmcrypto_core::sm3::{self, Sm3};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // One-shot reference digest.
    let oneshot = sm3::hash(data);

    // Streaming digest, fed in an irregular, input-independent chunk pattern
    // so different inputs exercise different update boundaries relative to the
    // 64-byte SM3 block (1, 2, 3, 5, 7, 13, 31, 64, 65, ...).
    const SIZES: [usize; 9] = [1, 2, 3, 5, 7, 13, 31, 64, 65];
    let mut hasher = Sm3::new();
    hasher.update(&[]); // empty absorb at the start must be a no-op
    let mut rest = data;
    let mut i = 0usize;
    while !rest.is_empty() {
        let n = SIZES[i % SIZES.len()].min(rest.len());
        hasher.update(&rest[..n]);
        hasher.update(&[]); // interleaved empty absorb must not change state
        rest = &rest[n..];
        i += 1;
    }
    let streamed = hasher.finalize();

    assert_eq!(
        oneshot,
        streamed,
        "SM3 one-shot vs streaming digest mismatch for {}-byte input",
        data.len()
    );
});
