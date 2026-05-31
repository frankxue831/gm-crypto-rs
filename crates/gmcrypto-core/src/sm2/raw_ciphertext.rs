//! Raw byte-concatenation SM2 ciphertext codecs (NOT DER).
//!
//! Interop fallback for callers (older gmssl, OpenSSL with the GM
//! patchset, third-party libraries) that don't speak GM/T 0009 DER.
//! Modern emit + decode (`C1||C3||C2`); legacy decrypt-only path
//! (`C1||C2||C3`).
//!
//! Per the v0.3 scope (Q7.4 decision), the raw helpers live here in
//! [`crate::sm2`] rather than alongside the DER codec in
//! [`crate::asn1::ciphertext`] — the raw helpers are explicitly *not*
//! DER and the module placement makes that clear.
//!
//! # Wire format
//!
//! ```text
//! C1 (uncompressed point): 65 bytes = 0x04 || X (32) || Y (32)
//! C2:                      |M| bytes (variable)
//! C3:                      32 bytes (SM3 digest)
//!
//! modern (C1||C3||C2): [C1][C3][C2]   length = 65 + 32 + |M|
//! legacy (C1||C2||C3): [C1][C2][C3]   length = 65 + |M| + 32
//! ```
//!
//! `C1` is **65 bytes** (`0x04 || X || Y`) per Q7.5 — matches SEC1 /
//! SPKI / gmssl 3.1.1 emit. Decode side does not currently tolerate
//! the 64-byte form (no leading `0x04`); add behind a feature gate
//! only if a real-world W3 fixture demands it.
//!
//! # Failure-mode invariant
//!
//! Decoders return `None` for any malformed input. No distinguishing
//! variants per `CLAUDE.md` — the caller cannot tell "too short"
//! from "wrong byte at position N" from "(X, Y) off the curve".
//!
//! # Modern vs. legacy: pick before calling
//!
//! `decode_c1c3c2` and `decode_c1c2c3_legacy` do **not** auto-detect
//! the byte order — that would be a malleability/timing surface.
//! Callers know the source format (e.g. "this came from gmssl 3.x"
//! → modern; "this came from the OpenSSL GM-patch" → legacy).
//! Mismatched format yields `None` from the SM3 hash check inside
//! [`crate::sm2::decrypt()`] — never silently-corrupted plaintext.

use crate::asn1::ciphertext::Sm2Ciphertext;
use crate::sm2::curve::Fp;
use crate::sm2::encrypt::point_on_curve;
use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::ConstantTimeLess;

/// Length of the SEC1 uncompressed `C1` field (`0x04 || X || Y`).
pub const C1_LEN: usize = 65;
/// Length of the `C3` field (SM3 digest).
pub const C3_LEN: usize = 32;
/// SEC1 uncompressed-point tag byte.
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// A 32-byte big-endian SM2 field-element coordinate (`C1.x` / `C1.y`).
/// v0.22 reshaped these from `crypto_bigint::U256` to byte arrays; the
/// alias keeps the multi-return splitter signature readable.
type FieldBytes = [u8; 32];

/// Encode a parsed [`Sm2Ciphertext`] into the modern raw byte
/// concatenation: `C1 || C3 || C2`.
///
/// The `Sm2Ciphertext` carries `(x, y)` as 32-byte big-endian field
/// elements (v0.22; previously `U256`); this encoder serializes them
/// directly into the `0x04 || X || Y` C1 field.
#[must_use]
pub fn encode_c1c3c2(ct: &Sm2Ciphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(C1_LEN + C3_LEN + ct.ciphertext.len());
    out.push(SEC1_UNCOMPRESSED);
    out.extend_from_slice(&ct.x);
    out.extend_from_slice(&ct.y);
    out.extend_from_slice(&ct.hash);
    out.extend_from_slice(&ct.ciphertext);
    out
}

/// Decode the modern raw byte concatenation `C1 || C3 || C2` into a
/// [`Sm2Ciphertext`]. Validates:
///
/// - input is at least `C1_LEN + C3_LEN` bytes long;
/// - the leading tag byte is `0x04`;
/// - `X < p` and `Y < p` (field-element bounds — same rule as the
///   GM/T 0009 DER decoder);
/// - `(X, Y)` is on the SM2 curve (invalid-curve attack defense).
///
/// Returns `None` for any malformed input. Does not check `C3`'s
/// hash relationship to `(X, Y)` and `C2` — that lives in
/// [`crate::sm2::decrypt()`] and runs constant-time on the recipient
/// private key.
#[must_use]
pub fn decode_c1c3c2(input: &[u8]) -> Option<Sm2Ciphertext> {
    let (x, y, c3, c2) = split_c1_c3_c2(input)?;
    Some(Sm2Ciphertext {
        x,
        y,
        hash: c3,
        ciphertext: c2.to_vec(),
    })
}

/// Decode the **legacy** byte concatenation `C1 || C2 || C3`.
///
/// Targets gmssl pre-2018 and OpenSSL GM-patch outputs. **Decrypt-
/// only** — there is deliberately no `encode_c1c2c3_legacy`. Re-
/// emitting in this order would propagate the legacy form
/// indefinitely; new ciphertext emit always uses [`encode_c1c3c2`]
/// (or the GM/T 0009 DER form from [`crate::asn1::ciphertext`]).
///
/// Same validation as [`decode_c1c3c2`] (length, tag, field bounds,
/// on-curve). The `C2` length is derived as `input.len() - C1_LEN -
/// C3_LEN` after the C1 byte-pull and field-bound check; the legacy
/// order is simply different positions for `C2` / `C3` in the input.
#[must_use]
pub fn decode_c1c2c3_legacy(input: &[u8]) -> Option<Sm2Ciphertext> {
    if input.len() < C1_LEN + C3_LEN {
        return None;
    }
    if input[0] != SEC1_UNCOMPRESSED {
        return None;
    }
    let x = read_field_element(&input[1..33])?;
    let y = read_field_element(&input[33..65])?;
    let x_fp = Fp::new(&U256::from_be_slice(&x));
    let y_fp = Fp::new(&U256::from_be_slice(&y));
    if !point_on_curve(&x_fp, &y_fp) {
        return None;
    }
    // Legacy layout: after C1 (65 bytes), C2 spans (input.len() -
    // C1_LEN - C3_LEN) bytes, then C3 takes the final 32 bytes.
    let c2_len = input.len() - C1_LEN - C3_LEN;
    let c2 = &input[C1_LEN..C1_LEN + c2_len];
    let mut c3 = [0u8; C3_LEN];
    c3.copy_from_slice(&input[C1_LEN + c2_len..]);

    Some(Sm2Ciphertext {
        x,
        y,
        hash: c3,
        ciphertext: c2.to_vec(),
    })
}

/// Common modern-layout splitter. Returns `(x, y, c3, c2_slice)` or
/// `None` on any validation failure.
fn split_c1_c3_c2(input: &[u8]) -> Option<(FieldBytes, FieldBytes, [u8; C3_LEN], &[u8])> {
    if input.len() < C1_LEN + C3_LEN {
        return None;
    }
    if input[0] != SEC1_UNCOMPRESSED {
        return None;
    }
    let x = read_field_element(&input[1..33])?;
    let y = read_field_element(&input[33..65])?;
    let x_fp = Fp::new(&U256::from_be_slice(&x));
    let y_fp = Fp::new(&U256::from_be_slice(&y));
    if !point_on_curve(&x_fp, &y_fp) {
        return None;
    }
    let mut c3 = [0u8; C3_LEN];
    c3.copy_from_slice(&input[C1_LEN..C1_LEN + C3_LEN]);
    let c2 = &input[C1_LEN + C3_LEN..];
    Some((x, y, c3, c2))
}

/// Read a 32-byte big-endian slice as a field element, enforcing
/// `< p`. Returns the canonical `[u8; 32]` (v0.22; was `U256`) or
/// `None` if the value is out of range. Same field bound the GM/T 0009
/// DER decoder enforces; the caller reconstructs `Fp` for the on-curve
/// check.
fn read_field_element(bytes: &[u8]) -> Option<FieldBytes> {
    if bytes.len() != 32 {
        return None;
    }
    let v = U256::from_be_slice(bytes);
    let p = *Fp::MODULUS.as_ref();
    if !bool::from(v.ct_lt(&p)) {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::ProjectivePoint;
    use crate::sm2::{Sm2PrivateKey, decrypt, encrypt};
    use crypto_bigint::U256;
    use rand_core::UnwrapErr;

    // Helper: build a canonical Sm2Ciphertext using the SM2 generator's
    // affine coordinates as (x, y) — they pass on-curve and field-bound
    // checks by construction, with a test-fixed C2 / C3.
    fn sample_ct(c2: &[u8]) -> Sm2Ciphertext {
        let g = ProjectivePoint::generator();
        let (x, y) = g.to_affine().expect("G finite");
        Sm2Ciphertext {
            x: crate::u256_to_be32(&x.retrieve()),
            y: crate::u256_to_be32(&y.retrieve()),
            hash: [0xA5; C3_LEN],
            ciphertext: c2.to_vec(),
        }
    }

    /// Modern round-trip: arbitrary plaintext lengths.
    #[test]
    fn modern_round_trip_boundary_lengths() {
        for len in [0usize, 1, 16, 32, 100, 1024] {
            #[allow(clippy::cast_possible_truncation)]
            let c2: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let ct = sample_ct(&c2);
            let bytes = encode_c1c3c2(&ct);
            assert_eq!(bytes.len(), C1_LEN + C3_LEN + len);
            assert_eq!(bytes[0], 0x04);
            let recovered = decode_c1c3c2(&bytes).expect("decode");
            assert_eq!(recovered.x, ct.x);
            assert_eq!(recovered.y, ct.y);
            assert_eq!(recovered.hash, ct.hash);
            assert_eq!(recovered.ciphertext, ct.ciphertext);
        }
    }

    /// Decoder rejects too-short input.
    #[test]
    fn decode_rejects_too_short() {
        assert!(decode_c1c3c2(&[]).is_none());
        assert!(decode_c1c3c2(&[0x04; 32]).is_none());
        assert!(decode_c1c3c2(&[0x04; 65]).is_none()); // missing C3
        assert!(decode_c1c3c2(&[0x04; 96]).is_none()); // 65 + 31 < 65 + 32
        // 65 + 32 = 97 is the empty-C2 minimum; one byte below is rejected.
    }

    /// Decoder rejects wrong leading byte (compressed forms / identity).
    #[test]
    fn decode_rejects_wrong_tag() {
        let mut bytes = encode_c1c3c2(&sample_ct(b"hi"));
        bytes[0] = 0x02;
        assert!(decode_c1c3c2(&bytes).is_none());
        bytes[0] = 0x03;
        assert!(decode_c1c3c2(&bytes).is_none());
        bytes[0] = 0x00;
        assert!(decode_c1c3c2(&bytes).is_none());
    }

    /// Decoder rejects off-curve `(X, Y)`.
    #[test]
    fn decode_rejects_off_curve() {
        let mut bytes = encode_c1c3c2(&sample_ct(b"hi"));
        // Tweak one byte of X — almost certainly puts the point off-curve.
        bytes[5] ^= 0x01;
        assert!(decode_c1c3c2(&bytes).is_none());
    }

    /// Decoder rejects `X >= p`.
    #[test]
    fn decode_rejects_x_at_p() {
        let mut bytes = encode_c1c3c2(&sample_ct(b"hi"));
        let p = *Fp::MODULUS.as_ref();
        bytes[1..33].copy_from_slice(&p.to_be_bytes());
        assert!(decode_c1c3c2(&bytes).is_none());
    }

    /// Empty C2 round-trips.
    #[test]
    fn modern_empty_c2() {
        let ct = sample_ct(&[]);
        let bytes = encode_c1c3c2(&ct);
        assert_eq!(bytes.len(), C1_LEN + C3_LEN);
        let recovered = decode_c1c3c2(&bytes).expect("decode empty");
        assert_eq!(recovered.ciphertext.len(), 0);
    }

    /// Legacy decoder cross-check: hand-construct a `C1||C2||C3` blob
    /// from a known modern blob and verify the legacy decoder
    /// extracts the same `(x, y, c3, c2)`.
    #[test]
    fn legacy_decode_swaps_c2_c3_position() {
        let ct = sample_ct(b"legacy-format-test");
        let modern = encode_c1c3c2(&ct);
        // Build legacy by concatenating C1 || C2 || C3 in that order.
        let mut legacy = Vec::with_capacity(modern.len());
        legacy.extend_from_slice(&modern[..C1_LEN]);
        legacy.extend_from_slice(&modern[C1_LEN + C3_LEN..]); // C2
        legacy.extend_from_slice(&modern[C1_LEN..C1_LEN + C3_LEN]); // C3
        let recovered = decode_c1c2c3_legacy(&legacy).expect("legacy decode");
        assert_eq!(recovered.x, ct.x);
        assert_eq!(recovered.y, ct.y);
        assert_eq!(recovered.hash, ct.hash);
        assert_eq!(recovered.ciphertext, ct.ciphertext);
    }

    /// Same field-bound / curve-bound rejections apply on the legacy path.
    #[test]
    fn legacy_decode_rejects_off_curve() {
        let ct = sample_ct(b"x");
        let modern = encode_c1c3c2(&ct);
        let mut legacy = Vec::with_capacity(modern.len());
        legacy.extend_from_slice(&modern[..C1_LEN]);
        legacy.extend_from_slice(&modern[C1_LEN + C3_LEN..]);
        legacy.extend_from_slice(&modern[C1_LEN..C1_LEN + C3_LEN]);
        legacy[5] ^= 0x01;
        assert!(decode_c1c2c3_legacy(&legacy).is_none());
    }

    #[test]
    fn legacy_decode_rejects_too_short() {
        assert!(decode_c1c2c3_legacy(&[0x04; 64]).is_none());
        assert!(decode_c1c2c3_legacy(&[]).is_none());
    }

    /// End-to-end: encrypt with `sm2::encrypt` (DER), decode the DER
    /// to a `Sm2Ciphertext`, re-encode as raw modern, decode raw, and
    /// verify the roundtripped struct decrypts to the original
    /// plaintext via `sm2::decrypt`.
    #[test]
    fn modern_raw_round_trips_via_full_decrypt() {
        let d =
            U256::from_be_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let key = Sm2PrivateKey::from_scalar_inner(d).expect("valid d");
        let pk = key.public_key();
        let mut rng = UnwrapErr(getrandom::SysRng);
        let plaintext = b"raw-ciphertext modern roundtrip";
        let der = encrypt(&pk, plaintext, &mut rng).expect("encrypt");
        // DER → struct
        let ct = crate::asn1::ciphertext::decode(&der).expect("DER decode");
        // struct → raw modern
        let raw = encode_c1c3c2(&ct);
        // raw → struct
        let ct2 = decode_c1c3c2(&raw).expect("raw decode");
        // struct → DER (re-encode, since sm2::decrypt takes DER)
        let der2 = crate::asn1::ciphertext::encode(&ct2);
        let recovered = decrypt(&key, &der2).expect("decrypt round-trip");
        assert_eq!(recovered, plaintext);
    }
}
