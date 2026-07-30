//! Fuzz target: `asn1::sig::{decode_sig, encode_sig}` (DER SEQUENCE { r, s }).
//!
//! Invariants:
//!
//! 1. **No panic** — any input returns `Some`/`None` (the v0.14 invariant).
//! 2. **Byte-idempotence** — `decode_sig(x) == Some((r, s))` implies
//!    `encode_sig(r, s) == x`. This says the decoder accepts *exactly one*
//!    encoding of each signature value, which is strictly stronger than a value
//!    round-trip and needs no `PartialEq` on any published type.
//! 3. **Value round-trip** — re-decoding the re-encoding yields the same
//!    `(r, s)`. Free here, since the tuple is a pair of `[u8; 32]`.
//!
//! (2) is sound because the codec is strict-canonical in BOTH directions:
//! `asn1::reader` rejects every non-minimal length form and every non-canonical
//! INTEGER (empty content, sign-bit-set first byte, redundant `0x00` padding),
//! `asn1::writer` emits only the minimal form, and the decoder rejects trailing
//! bytes. A decoder that began accepting a second spelling of the same
//! signature — the classic DER-malleability foothold — fails here.
#![no_main]

use gmcrypto_core::asn1::sig::{decode_sig, encode_sig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((r, s)) = decode_sig(data) else {
        return;
    };

    let re = encode_sig(&r, &s);
    assert_eq!(
        re, data,
        "asn1::sig re-encode is not byte-idempotent — decode_sig accepted a \
         non-canonical spelling of this signature"
    );

    let (r2, s2) = decode_sig(&re).expect("a freshly encoded signature must decode");
    assert_eq!((r2, s2), (r, s), "asn1::sig value round-trip mismatch");
});
