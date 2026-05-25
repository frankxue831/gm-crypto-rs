//! Fuzz target: `pem::decode` (RFC 7468 PEM armor + embedded base64).
//!
//! Invariant under test: for ANY input, `decode` returns `Ok`/`Err` and never
//! panics, over-allocates, or hangs. `decode` takes `&str`, so we feed the raw
//! fuzz bytes through `from_utf8_lossy` (PEM is ASCII text; lossy mapping still
//! exercises the armor scanner + base64 decoder on hostile structure) and run
//! every label our wire formats use, so the label-match branch is fuzzed too.
#![no_main]

use libfuzzer_sys::fuzz_target;

const LABELS: &[&str] = &[
    "EC PRIVATE KEY",
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PUBLIC KEY",
    "CERTIFICATE",
];

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for label in LABELS {
        let _ = gmcrypto_core::pem::decode(&text, label);
    }
});
