//! Fuzz target: `asn1::sig::decode_sig` (DER SEQUENCE { r, s }).
//! Invariant: any input returns `Some`/`None` — never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::asn1::sig::decode_sig(data);
});
