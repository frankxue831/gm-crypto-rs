//! Fuzz target: the raw SM2 ciphertext codecs — `decode_c1c3c2` /
//! `encode_c1c3c2` (modern) and `decode_c1c2c3_legacy`.
//!
//! Invariants:
//!
//! 1. **No panic** on either decoder (the v0.14 invariant).
//! 2. **Guard parity** — the two decoders accept exactly the same inputs.
//! 3. **Byte-idempotence** on the modern ordering.
//! 4. **Value round-trip** on the modern ordering, field-by-field.
//!
//! (2) is falsifiable rather than tautological, and it is worth recording why.
//! The two decoders apply *identical* guards — `len >= C1_LEN + C3_LEN`,
//! `input[0] == 0x04`, `read_field_element` over the same `1..33` and `33..65`
//! ranges, then the same `point_on_curve` — and differ only in where they split
//! the tail. So they must agree on acceptance, and a divergence means one
//! decoder's validation prologue drifted from the other's. That is exactly the
//! failure a duplicated prologue invites.
//!
//! The legacy half gets a differential rather than a round-trip because
//! `encode_c1c2c3_legacy` **does not exist, by design**: re-emitting the legacy
//! `C1||C2||C3` ordering would propagate it indefinitely. So the legacy leg is
//! checked against what the modern decoder sees in the same bytes — same C1,
//! and the same C2 length, since both derive it from the same total.
//!
//! `Sm2Ciphertext` has no `PartialEq`, and deriving one to serve a fuzz target
//! would be an api-baseline change to a published type; comparisons are
//! field-by-field.
#![no_main]

use gmcrypto_core::sm2::raw_ciphertext;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let modern = raw_ciphertext::decode_c1c3c2(data);
    let legacy = raw_ciphertext::decode_c1c2c3_legacy(data);

    assert_eq!(
        modern.is_some(),
        legacy.is_some(),
        "C1||C3||C2 and legacy C1||C2||C3 disagree on whether to accept this \
         input — the two decoders' guards have drifted apart"
    );

    let Some(ct) = modern else {
        return;
    };

    let re = raw_ciphertext::encode_c1c3c2(&ct);
    assert_eq!(
        re, data,
        "C1||C3||C2 re-encode is not byte-idempotent — decode_c1c3c2 accepted \
         a non-canonical spelling"
    );

    let ct2 = raw_ciphertext::decode_c1c3c2(&re).expect("a freshly encoded ciphertext must decode");
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

    // The legacy decoder reads the same C1 prefix from the same offsets and
    // derives its C2 length from the same total, so it must agree on both even
    // though it takes C3 from the tail rather than the middle.
    let lg = legacy.expect("parity asserted above");
    assert_eq!((lg.x, lg.y), (ct.x, ct.y), "legacy C1 extraction mismatch");
    assert_eq!(
        lg.ciphertext.len(),
        ct.ciphertext.len(),
        "legacy C2 length mismatch"
    );
});
