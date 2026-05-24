//! Fuzz target: `pkcs8::decode` (RFC 5958 OneAsymmetricKey, unencrypted).
//! Invariant: any input returns `Ok`/`Err` — never panics / over-allocates.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::pkcs8::decode(data);
});
