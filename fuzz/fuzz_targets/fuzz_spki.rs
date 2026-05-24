//! Fuzz target: `spki::decode` (RFC 5280 SubjectPublicKeyInfo → SM2 point).
//! Invariant: any input returns `Some`/`None` — never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::spki::decode(data);
});
