//! Fuzz target: `pkcs8::decrypt` (RFC 8018 PBES2: PBKDF2-HMAC-SM3 + SM4-CBC).
//! The DER blob is attacker-controlled; the password is a fixed test value.
//! Invariant: any input returns `Ok`/`Err` (single `Failed`) — never panics.
//!
//! Coverage caveat (codex W2 review): the PBKDF2 iteration count is parsed
//! from the (attacker-controlled) PBES2 params, bounded by core's
//! `PBKDF2_MAX_ITERATIONS` (10_000_000). A high-but-valid count is CPU-bounded
//! by that cap (not unbounded), so it is a *slow* input, not a panic/OOM/hang
//! within libFuzzer's `-timeout`. The cap is the mitigation; this target proves
//! no panic, not constant-time-of-KDF.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::pkcs8::decrypt(data, b"password");
});
