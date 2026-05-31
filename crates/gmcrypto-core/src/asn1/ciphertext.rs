//! GM/T 0009-2012 §6 SM2 ciphertext DER encoding.
//!
//! Structure:
//!
//! ```text
//! SM2Cipher ::= SEQUENCE {
//!     XCoordinate INTEGER,         -- C1.x  (positive, ≤ 256 bits)
//!     YCoordinate INTEGER,         -- C1.y  (positive, ≤ 256 bits)
//!     HASH        OCTET STRING,    -- C3, exactly 32 bytes (SM3 digest)
//!     CipherText  OCTET STRING     -- C2, variable length
//! }
//! ```
//!
//! v0.3 re-implements on top of [`super::reader`] / [`super::writer`];
//! the wire output and accept/reject behaviour are byte-identical to
//! v0.2. Raw byte-concat formats (`C1 || C3 || C2`,
//! `C1 || C2 || C3`) live in [`crate::sm2::raw_ciphertext`] (W4); this
//! module remains DER-only.
//!
//! INTEGER decoding follows strict X.690 canonical-encoding rules
//! enforced in [`super::reader::read_integer`], plus two
//! ciphertext-specific deltas applied here:
//! - the canonical single-byte zero `02 01 00` is **accepted** as the
//!   field element `0` (a `(0, y)` point on the curve is a valid C1);
//! - 32-byte coordinates `≥ p` are **rejected** so that `Fp::new`
//!   cannot silently reduce a non-canonical encoding modulo `p`,
//!   which would create ciphertext malleability.
//!
//! Accepting non-canonical INTEGER encodings would create ciphertext
//! malleability — multiple distinct DER blobs mapping to the same
//! `(C1, C3, C2)` tuple. The strict-canonical reader rules + the
//! `< p` field bound here are the malleability defense.

use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::ConstantTimeLess;

use crate::sm2::curve::Fp;

use super::{reader, writer};

/// SM3 digest size — fixed at 32 bytes; the spec mandates it.
const HASH_LEN: usize = 32;

/// Parsed SM2 ciphertext components.
///
/// `x` and `y` are the affine coordinates of `C1 = kG`; `hash` is `C3`,
/// the SM3 digest computed during encryption; `ciphertext` is `C2`, the
/// KDF-XOR'd plaintext.
#[derive(Clone, Debug)]
pub struct Sm2Ciphertext {
    /// `C1.x` — 32-byte big-endian field element.
    ///
    /// v0.22 reshaped this from `crypto_bigint::U256` to `[u8; 32]` so the
    /// public API names no `crypto-bigint` type (`docs/v0.22-scope.md` §3
    /// Q22.4). The bytes are the canonical big-endian encoding of the
    /// coordinate; [`decode`] guarantees `x < p`, but a value built directly
    /// is **not** validated until [`crate::sm2::decrypt()`]'s on-curve check.
    pub x: [u8; 32],
    /// `C1.y` — 32-byte big-endian field element (see [`Sm2Ciphertext::x`]).
    pub y: [u8; 32],
    /// `C3 = SM3(x2 || M || y2)`. Always 32 bytes.
    pub hash: [u8; HASH_LEN],
    /// `C2 = M XOR KDF(x2 || y2, |M|)`. Length matches plaintext length.
    pub ciphertext: Vec<u8>,
}

/// Encode an [`Sm2Ciphertext`] as a GM/T 0009 SEQUENCE.
#[must_use]
pub fn encode(ct: &Sm2Ciphertext) -> Vec<u8> {
    let mut body = Vec::with_capacity(ct.ciphertext.len() + 80);
    writer::write_integer(&mut body, &ct.x);
    writer::write_integer(&mut body, &ct.y);
    writer::write_octet_string(&mut body, &ct.hash);
    writer::write_octet_string(&mut body, &ct.ciphertext);
    let mut out = Vec::with_capacity(body.len() + 4);
    writer::write_sequence(&mut out, &body);
    out
}

/// Decode a GM/T 0009 SEQUENCE into [`Sm2Ciphertext`]. Returns `None`
/// for any malformed input. **No distinguishing failure modes** —
/// malleability defense per the project's failure-mode invariant.
#[must_use]
pub fn decode(input: &[u8]) -> Option<Sm2Ciphertext> {
    let (body, rest) = reader::read_sequence(input)?;
    if !rest.is_empty() {
        return None;
    }
    let (x, body) = read_field_element(body)?;
    let (y, body) = read_field_element(body)?;
    let (hash_bytes, body) = reader::read_octet_string(body)?;
    let (ciphertext, body) = reader::read_octet_string(body)?;
    if !body.is_empty() {
        return None;
    }
    if hash_bytes.len() != HASH_LEN {
        return None;
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(hash_bytes);
    Some(Sm2Ciphertext {
        x,
        y,
        hash,
        ciphertext: ciphertext.to_vec(),
    })
}

/// Read a DER INTEGER and decode its content as a 32-byte unsigned
/// big-endian field element of `Fp`. Accepts zero (the canonical
/// `02 01 00`); rejects coordinates `≥ p` so that `Fp::new` cannot
/// silently reduce modulo `p` (which would create malleability).
fn read_field_element(input: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (bytes, rest) = reader::read_integer(input)?;
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    // Reject coordinates ≥ p. C1 coordinates are public; using
    // `ConstantTimeLess` matches the rest of the crate's idiom even
    // though no secret material flows here. v0.22 returns the canonical
    // `[u8; 32]` (was `U256`) but keeps this `< p` malleability bound at
    // the decode boundary unchanged.
    let value = U256::from_be_slice(&padded);
    let in_field: bool = value.ct_lt(Fp::MODULUS.as_ref()).into();
    if !in_field {
        return None;
    }
    Some((padded, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ct(ciphertext: Vec<u8>) -> Sm2Ciphertext {
        Sm2Ciphertext {
            x: crate::u256_to_be32(&U256::from_be_hex(
                "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
            )),
            y: crate::u256_to_be32(&U256::from_be_hex(
                "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321",
            )),
            hash: [0xa5u8; 32],
            ciphertext,
        }
    }

    /// Helper for hand-built malformed-blob tests: prepend `30 LEN`
    /// to a body. Mirrors the `push_length` boundary the writer
    /// enforces.
    fn wrap_sequence(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        writer::write_sequence(&mut out, body);
        out
    }

    /// Standard round-trip: encode → decode → equal.
    #[test]
    fn round_trip_short() {
        let ct = make_ct(b"hello world".to_vec());
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode round-trip");
        assert_eq!(decoded.x, ct.x);
        assert_eq!(decoded.y, ct.y);
        assert_eq!(decoded.hash, ct.hash);
        assert_eq!(decoded.ciphertext, ct.ciphertext);
    }

    /// Round-trip with a high-bit-set top byte on `x` — exercises the
    /// writer's INTEGER 0x00-pad path.
    #[test]
    fn round_trip_x_high_bit_set() {
        let mut ct = make_ct(b"x".to_vec());
        ct.x = crate::u256_to_be32(&U256::from_be_hex(
            "FFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA987654321",
        ));
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode high-bit round-trip");
        assert_eq!(decoded.x, ct.x);
    }

    /// Round-trip with a ciphertext spanning the 256-byte length boundary
    /// (exercises the 0x82 length encoding in the writer).
    #[test]
    fn round_trip_medium_ciphertext_300_bytes() {
        let mut payload = alloc::vec![0u8; 300];
        for (i, b) in payload.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = (i as u8).wrapping_mul(13);
            }
        }
        let ct = make_ct(payload.clone());
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode 300-byte round-trip");
        assert_eq!(decoded.ciphertext, payload);
    }

    /// Round-trip with empty ciphertext — RFC 5652 §6 doesn't forbid
    /// zero-length OCTET STRING content; our DER must accept it.
    #[test]
    fn round_trip_empty_ciphertext() {
        let ct = make_ct(Vec::new());
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode empty-ciphertext round-trip");
        assert!(decoded.ciphertext.is_empty());
    }

    /// Decode rejects garbage / truncated / empty input.
    #[test]
    fn rejects_malformed() {
        assert!(decode(&[]).is_none(), "empty input");
        assert!(decode(&[0x30]).is_none(), "truncated SEQUENCE header");
        assert!(decode(&[0x31, 0x00]).is_none(), "wrong outer tag");
        // SEQUENCE with declared body shorter than declared length
        assert!(decode(&[0x30, 0x05, 0x02, 0x01, 0x01]).is_none());
    }

    /// Decode rejects a hash field whose length is anything other than
    /// 32 bytes. SM3 always produces 32 bytes; smaller or larger is
    /// malformed.
    #[test]
    fn rejects_wrong_hash_length() {
        // Build a SEQUENCE where HASH OCTET STRING has 31 bytes instead of 32.
        let bad_hash = [0x55u8; 31];
        let ciphertext = b"x";
        let mut body = Vec::new();
        writer::write_integer(&mut body, &[0x01]);
        writer::write_integer(&mut body, &[0x02]);
        writer::write_octet_string(&mut body, &bad_hash);
        writer::write_octet_string(&mut body, ciphertext);
        let der = wrap_sequence(&body);
        assert!(
            decode(&der).is_none(),
            "31-byte HASH must be rejected; SM3 always produces 32 bytes"
        );
    }

    /// Strict canonical INTEGER: redundant `00`-pad on `x` rejected
    /// (the same rule `read_integer` enforces). Prevents
    /// ciphertext malleability across multiple DER encodings of the
    /// same `(x, y, hash, ct)` tuple.
    #[test]
    fn rejects_non_canonical_x_leading_zero() {
        // Build SEQUENCE with x = INTEGER 0x00 0x01 (BER-style, non-canonical).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x02, 0x00, 0x01]); // x: bad
        writer::write_integer(&mut body, &[0x02]); // y: ok
        writer::write_octet_string(&mut body, &[0u8; 32]);
        writer::write_octet_string(&mut body, b"");
        let der = wrap_sequence(&body);
        assert!(
            decode(&der).is_none(),
            "non-canonical 00-pad on x must be rejected"
        );
    }

    /// Strict canonical INTEGER: high-bit-set first byte (would be
    /// negative in two's complement) rejected on `y`.
    #[test]
    fn rejects_negative_y_encoding() {
        let mut body = Vec::new();
        writer::write_integer(&mut body, &[0x01]);
        body.extend_from_slice(&[0x02, 0x01, 0x80]); // y = INTEGER 0x80 (sign-bit set, no pad)
        writer::write_octet_string(&mut body, &[0u8; 32]);
        writer::write_octet_string(&mut body, b"");
        let der = wrap_sequence(&body);
        assert!(decode(&der).is_none());
    }

    /// Trailing garbage after the ciphertext OCTET STRING is rejected
    /// — strict DER parsing.
    #[test]
    fn rejects_trailing_bytes() {
        let ct = make_ct(b"hi".to_vec());
        let mut der = encode(&ct);
        der.push(0xff); // trailing garbage
        assert!(decode(&der).is_none());
    }

    /// Canonical DER encoding of zero (`02 01 00`) on `x` round-trips.
    /// `(0, y)` is a valid affine C1 if it lies on the curve; the wire
    /// format must accept the field element 0.
    #[test]
    fn round_trip_x_zero() {
        let mut ct = make_ct(b"z".to_vec());
        ct.x = [0u8; 32];
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode round-trip with x = 0");
        assert_eq!(decoded.x, [0u8; 32]);
        assert_eq!(decoded.y, ct.y);
    }

    /// Strict canonical INTEGER: a 32-byte coordinate ≥ p is rejected.
    /// Without this bound, `Fp::new` silently reduces the value modulo
    /// `p`, admitting a second DER blob for the same field element —
    /// ciphertext malleability. Regression test for the v0.2 codex
    /// pre-publish review finding.
    #[test]
    fn rejects_x_at_or_above_p() {
        // Build a SEQUENCE with x = p (the SM2 prime).
        let p = *Fp::MODULUS.as_ref();
        let p_bytes = p.to_be_bytes();
        let mut body = Vec::new();
        writer::write_integer(&mut body, &p_bytes);
        writer::write_integer(&mut body, &[0x01]);
        writer::write_octet_string(&mut body, &[0u8; 32]);
        writer::write_octet_string(&mut body, b"");
        let der = wrap_sequence(&body);
        assert!(
            decode(&der).is_none(),
            "x = p is not a field element and must be rejected"
        );

        // Also verify `2^256 - 1` is rejected (well above p).
        let max_bytes = [0xffu8; 32];
        let mut body = Vec::new();
        writer::write_integer(&mut body, &max_bytes);
        writer::write_integer(&mut body, &[0x01]);
        writer::write_octet_string(&mut body, &[0u8; 32]);
        writer::write_octet_string(&mut body, b"");
        let der = wrap_sequence(&body);
        assert!(decode(&der).is_none(), "x = 2^256 - 1 must be rejected");
    }

    /// Companion check: `p - 1` is the largest valid coordinate and
    /// must round-trip cleanly.
    #[test]
    fn round_trip_x_p_minus_one() {
        let p_minus_one = Fp::MODULUS.as_ref().wrapping_sub(&U256::ONE);
        let mut ct = make_ct(b"q".to_vec());
        ct.x = crate::u256_to_be32(&p_minus_one);
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode round-trip with x = p - 1");
        assert_eq!(decoded.x, crate::u256_to_be32(&p_minus_one));
    }

    /// The 0x83 length encoding boundary: a ciphertext payload exactly
    /// 65,536 bytes long forces 3-byte length.
    #[test]
    fn round_trip_65536_byte_ciphertext_uses_3byte_length() {
        let payload = alloc::vec![0xa5u8; 65_536];
        let ct = make_ct(payload.clone());
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode 65,536-byte round-trip");
        assert_eq!(decoded.ciphertext, payload);
    }
}
