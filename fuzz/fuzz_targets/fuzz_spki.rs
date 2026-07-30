//! Fuzz target: `spki::{decode, encode_uncompressed}` (RFC 5280
//! SubjectPublicKeyInfo → SM2 point).
//!
//! Invariants:
//!
//! 1. **No panic** — any input returns `Some`/`None` (the v0.14 invariant).
//! 2. **Byte-idempotence** — a decoded SPKI re-encodes to the exact input
//!    bytes. Sound because `decode` pins both OIDs, requires `unused_bits == 0`,
//!    and rejects trailing bytes, while `encode_uncompressed` emits exactly one
//!    form.
//! 3. **Value round-trip** — via the `[u8; 65]` SEC1 encoding.
//!
//! Two deliberate choices worth keeping:
//!
//! - This calls `encode_uncompressed(&key.to_sec1_uncompressed())` rather than
//!   `spki::encode`, which carries a point-at-infinity `.expect`. That panic is
//!   unreachable from a *decoded* key (decode rejects the identity), but routing
//!   around it keeps the target honest: a panic here should mean a codec bug,
//!   never a known-unreachable assertion.
//! - `Sm2PublicKey` has no `PartialEq`, and deriving one to serve a fuzz target
//!   would be an api-baseline change to a published type. The value comparison
//!   goes through the SEC1 bytes instead. (`ConstantTimeEq` is also available,
//!   but byte comparison is clearer and CT is irrelevant on a public key.)
#![no_main]

use gmcrypto_core::spki;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(key) = spki::decode(data) else {
        return;
    };

    let re = spki::encode_uncompressed(&key.to_sec1_uncompressed());
    assert_eq!(
        re, data,
        "SPKI re-encode is not byte-idempotent — spki::decode accepted a \
         non-canonical spelling of this SubjectPublicKeyInfo"
    );

    let key2 = spki::decode(&re).expect("a freshly encoded SPKI must decode");
    assert_eq!(
        key2.to_sec1_uncompressed(),
        key.to_sec1_uncompressed(),
        "SPKI value round-trip mismatch"
    );
});
