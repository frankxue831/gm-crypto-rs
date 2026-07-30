//! Fuzz target: `asn1::ciphertext::{decode, encode}` (GM/T 0009 SM2 ciphertext
//! SEQUENCE { x, y, hash, ciphertext }). Validates structure, field-element
//! bounds, and C1 on-curve.
//!
//! Invariants:
//!
//! 1. **No panic** — any input returns `Some`/`None` (the v0.14 invariant).
//! 2. **Byte-idempotence** — a decoded ciphertext re-encodes to the exact input
//!    bytes, i.e. the decoder accepts exactly one encoding per value. Sound
//!    because `asn1::reader` rejects every non-minimal length form and every
//!    non-canonical INTEGER, `asn1::writer` emits only the minimal form, and
//!    the decoder rejects trailing bytes.
//! 3. **Value round-trip** — field-by-field.
//!
//! `Sm2Ciphertext` has no `PartialEq`, and deriving one to serve a fuzz target
//! would be an api-baseline change to a published type. All four of its fields
//! are `pub`, so the comparison is field-by-field instead.
#![no_main]

use gmcrypto_core::asn1::ciphertext;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(ct) = ciphertext::decode(data) else {
        return;
    };

    let re = ciphertext::encode(&ct);
    assert_eq!(
        re, data,
        "GM/T 0009 ciphertext re-encode is not byte-idempotent — decode \
         accepted a non-canonical spelling"
    );

    let ct2 = ciphertext::decode(&re).expect("a freshly encoded ciphertext must decode");
    assert_eq!(
        (ct2.x, ct2.y),
        (ct.x, ct.y),
        "C1 point mismatch after round-trip"
    );
    assert_eq!(ct2.hash, ct.hash, "C3 hash mismatch after round-trip");
    assert_eq!(
        ct2.ciphertext, ct.ciphertext,
        "C2 payload mismatch after round-trip"
    );
});
