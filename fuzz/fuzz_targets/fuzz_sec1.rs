//! Fuzz target: `sec1::decode` (RFC 5915 ECPrivateKey + SEC1 point).
//! Invariant: any input returns `Some`/`None` — never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::sec1::decode(data);
});
