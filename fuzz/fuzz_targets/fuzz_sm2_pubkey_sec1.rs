//! Fuzz target: `Sm2PublicKey::from_sec1_bytes` (65-byte uncompressed SEC1
//! point: 0x04 ‖ X ‖ Y; rejects malformed / off-curve / identity).
//! Invariant: any input returns `Some`/`None` — never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::sm2::Sm2PublicKey::from_sec1_bytes(data);
});
