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
//! v0.2 scope: this module ships **DER only**. Raw byte concatenation
//! formats (`C1 || C3 || C2` modern, `C1 || C2 || C3` legacy gmssl) are
//! out of scope until v0.3 — see `SECURITY.md` and `CLAUDE.md`.
//!
//! INTEGER decoding follows strict X.690 canonical-encoding rules,
//! adapted for the field-element range that C1 coordinates inhabit:
//! the leading `0x00` pad is allowed only when needed for sign
//! disambiguation; sign-bit-set first bytes (would be negative in
//! two's complement) are rejected; empty INTEGER content is rejected;
//! the canonical single-byte encoding of zero (`02 01 00`) is
//! accepted; and 32-byte coordinates `≥ p` are rejected so that
//! `Fp::new` cannot silently reduce a non-canonical encoding modulo
//! the field prime. The two SM2-specific deltas vs. the
//! [`crate::asn1::sig::decode_sig`] rules (which target `r, s ∈
//! [1, n-1]`) are documented inline in [`read_integer`]. Accepting
//! non-canonical encodings would create ciphertext malleability —
//! multiple distinct DER blobs mapping to the same `(C1, C3, C2)`.
//!
//! OCTET STRING decoding accepts any tag-length-value with a
//! non-indefinite length, since OCTET STRING values have no canonical-
//! form constraint analogous to INTEGER's leading-zero rule.
//!
//! No reusable `asn1::reader` / `asn1::writer` infrastructure here —
//! the v0.1 `asn1::sig` module-doc explicitly defers full ASN.1 to
//! v0.3, and `ciphertext.rs` mirrors `sig.rs`'s ad-hoc structure.

use alloc::vec::Vec;
use crypto_bigint::U256;
use subtle::ConstantTimeLess;

use crate::sm2::curve::Fp;

/// SM3 digest size — fixed at 32 bytes; the spec mandates it.
const HASH_LEN: usize = 32;

/// Parsed SM2 ciphertext components.
///
/// `x` and `y` are the affine coordinates of `C1 = kG`; `hash` is `C3`,
/// the SM3 digest computed during encryption; `ciphertext` is `C2`, the
/// KDF-XOR'd plaintext.
#[derive(Clone, Debug)]
pub struct Sm2Ciphertext {
    /// `C1.x`.
    pub x: U256,
    /// `C1.y`.
    pub y: U256,
    /// `C3 = SM3(x2 || M || y2)`. Always 32 bytes.
    pub hash: [u8; HASH_LEN],
    /// `C2 = M XOR KDF(x2 || y2, |M|)`. Length matches plaintext length.
    pub ciphertext: Vec<u8>,
}

/// Encode an [`Sm2Ciphertext`] as a GM/T 0009 SEQUENCE.
#[must_use]
pub fn encode(ct: &Sm2Ciphertext) -> Vec<u8> {
    let x_der = encode_integer(&ct.x.to_be_bytes());
    let y_der = encode_integer(&ct.y.to_be_bytes());
    let hash_der = encode_octet_string(&ct.hash);
    let ciphertext_der = encode_octet_string(&ct.ciphertext);
    let body_len = x_der.len() + y_der.len() + hash_der.len() + ciphertext_der.len();
    let mut out = Vec::with_capacity(body_len + 8);
    out.push(0x30); // SEQUENCE tag
    push_length(&mut out, body_len);
    out.extend_from_slice(&x_der);
    out.extend_from_slice(&y_der);
    out.extend_from_slice(&hash_der);
    out.extend_from_slice(&ciphertext_der);
    out
}

/// Decode a GM/T 0009 SEQUENCE into [`Sm2Ciphertext`]. Returns `None`
/// for any malformed input. **No distinguishing failure modes** —
/// malleability defense per the project's failure-mode invariant.
#[must_use]
pub fn decode(input: &[u8]) -> Option<Sm2Ciphertext> {
    let (tag, rest) = input.split_first()?;
    if *tag != 0x30 {
        return None;
    }
    let (body_len, rest) = read_length(rest)?;
    if rest.len() != body_len {
        return None;
    }
    let (x, rest) = read_integer(rest)?;
    let (y, rest) = read_integer(rest)?;
    let (hash_bytes, rest) = read_octet_string(rest)?;
    let (ciphertext, rest) = read_octet_string(rest)?;
    if !rest.is_empty() {
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

// ---------------------------------------------------------------------
// DER primitive helpers
//
// These mirror the corresponding helpers in `asn1::sig` to keep both
// shapes ad-hoc and self-contained until v0.3 ships a reusable subset.
// Keep the strict canonical-INTEGER rules in lockstep with sig.rs.
// ---------------------------------------------------------------------

fn encode_integer(value_be: &[u8]) -> Vec<u8> {
    // Strip leading zeros, then re-add one if the high bit is set
    // (positive integers need a leading 0x00 to disambiguate from
    // negative two's-complement).
    let mut start = 0;
    while start < value_be.len() - 1 && value_be[start] == 0 {
        start += 1;
    }
    let trimmed = &value_be[start..];
    let needs_pad = (trimmed[0] & 0x80) != 0;
    let int_len = trimmed.len() + usize::from(needs_pad);
    let mut out = Vec::with_capacity(int_len + 4);
    out.push(0x02); // INTEGER tag
    push_length(&mut out, int_len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

fn read_integer(input: &[u8]) -> Option<(U256, &[u8])> {
    let (tag, rest) = input.split_first()?;
    if *tag != 0x02 {
        return None;
    }
    let (int_len, rest) = read_length(rest)?;
    if rest.len() < int_len {
        return None;
    }
    let (int_bytes, rest_after) = rest.split_at(int_len);

    // Strict X.690 canonical rules adapted for ciphertext coordinates.
    // The shape is similar to `asn1::sig::read_integer` but **differs in
    // two places** because C1 coordinates inhabit `[0, p-1]` (a field
    // element range) while signature `r`/`s` inhabit `[1, n-1]`:
    //
    // - Length ≥ 1 (an INTEGER cannot be empty).
    // - For positive integers, the high bit of the first content byte
    //   must be clear; otherwise a leading 0x00 is required to
    //   disambiguate from a two's-complement negative.
    // - That leading-0x00 padding is allowed only when needed.
    // - **Zero is admissible.** The canonical DER encoding of zero is
    //   `02 01 00` (a single content byte 0x00), and a `(0, y)` point
    //   on the SM2 curve is a perfectly valid C1 — the signature path
    //   does not see this case because zero is excluded from `[1, n-1]`.
    // - **Coordinates ≥ p are rejected.** Without this bound, a
    //   32-byte INTEGER above `p` passes the canonical-encoding check,
    //   then `Fp::new` silently reduces it modulo `p`, admitting a
    //   second wire encoding for the same field element — a malleability
    //   primitive on the ciphertext path.
    if int_bytes.is_empty() {
        return None;
    }
    if int_bytes[0] & 0x80 != 0 {
        return None;
    }
    let bytes = if int_bytes[0] == 0x00 {
        if int_bytes.len() == 1 {
            // Canonical encoding of zero: `02 01 00`.
            int_bytes
        } else if int_bytes[1] & 0x80 == 0 {
            // Leading 0x00 followed by a high-bit-clear byte is
            // redundant padding (BER, not DER).
            return None;
        } else {
            &int_bytes[1..]
        }
    } else {
        int_bytes
    };
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    let value = U256::from_be_slice(&padded);
    // Reject coordinates ≥ p. C1 coordinates are public, so a
    // non-constant-time comparison is acceptable here; using
    // `ConstantTimeLess` matches the rest of the crate's idiom.
    let in_field: bool = value.ct_lt(Fp::MODULUS.as_ref()).into();
    if !in_field {
        return None;
    }
    Some((value, rest_after))
}

fn encode_octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(0x04); // OCTET STRING tag
    push_length(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn read_octet_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, rest) = input.split_first()?;
    if *tag != 0x04 {
        return None;
    }
    let (len, rest) = read_length(rest)?;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

fn push_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        #[allow(clippy::cast_possible_truncation)]
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        #[allow(clippy::cast_possible_truncation)]
        out.push(len as u8);
    } else if len < 65_536 {
        #[allow(clippy::cast_possible_truncation)]
        {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    } else if len < 16_777_216 {
        #[allow(clippy::cast_possible_truncation)]
        {
            out.push(0x83);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    } else {
        // Ciphertexts up to ~16 MB are supported. Anything larger is
        // an API misuse — SM2 envelope encryption is not designed for
        // bulk data; v0.2 callers should chunk via SM4-CBC + an outer
        // SM2 wrap.
        panic!("ciphertext DER length overflow (> 16 MB)");
    }
}

fn read_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    if *first < 0x80 {
        Some((*first as usize, rest))
    } else if *first == 0x81 {
        let (b, rest) = rest.split_first()?;
        if *b < 0x80 {
            return None; // not minimal
        }
        Some((*b as usize, rest))
    } else if *first == 0x82 {
        let (hi, rest) = rest.split_first()?;
        let (lo, rest) = rest.split_first()?;
        let len = ((*hi as usize) << 8) | (*lo as usize);
        if len < 256 {
            return None; // not minimal
        }
        Some((len, rest))
    } else if *first == 0x83 {
        let (b2, rest) = rest.split_first()?;
        let (b1, rest) = rest.split_first()?;
        let (b0, rest) = rest.split_first()?;
        let len = ((*b2 as usize) << 16) | ((*b1 as usize) << 8) | (*b0 as usize);
        if len < 65_536 {
            return None; // not minimal
        }
        Some((len, rest))
    } else {
        None // 4-byte+ lengths not supported in v0.2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ct(ciphertext: Vec<u8>) -> Sm2Ciphertext {
        Sm2Ciphertext {
            x: U256::from_be_hex(
                "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
            ),
            y: U256::from_be_hex(
                "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321",
            ),
            hash: [0xa5u8; 32],
            ciphertext,
        }
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
    /// `encode_integer` 0x00-pad path.
    #[test]
    fn round_trip_x_high_bit_set() {
        let mut ct = make_ct(b"x".to_vec());
        ct.x =
            U256::from_be_hex("FFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA987654321");
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode high-bit round-trip");
        assert_eq!(decoded.x, ct.x);
    }

    /// Round-trip with a ciphertext spanning the 256-byte length boundary
    /// (exercises the 0x82 length encoding in `push_length`).
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
        body.extend_from_slice(&encode_integer(&[0x01]));
        body.extend_from_slice(&encode_integer(&[0x02]));
        body.extend_from_slice(&encode_octet_string(&bad_hash));
        body.extend_from_slice(&encode_octet_string(ciphertext));
        let mut der = Vec::new();
        der.push(0x30);
        push_length(&mut der, body.len());
        der.extend_from_slice(&body);
        assert!(
            decode(&der).is_none(),
            "31-byte HASH must be rejected; SM3 always produces 32 bytes"
        );
    }

    /// Strict canonical INTEGER: redundant `00`-pad on `x` rejected
    /// (the same rule `asn1::sig::read_integer` enforces). Prevents
    /// ciphertext malleability across multiple DER encodings of the
    /// same `(x, y, hash, ct)` tuple.
    #[test]
    fn rejects_non_canonical_x_leading_zero() {
        // Build SEQUENCE with x = INTEGER 0x00 0x01 (BER-style, non-canonical).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x02, 0x00, 0x01]); // x: bad
        body.extend_from_slice(&encode_integer(&[0x02])); // y: ok
        body.extend_from_slice(&encode_octet_string(&[0u8; 32]));
        body.extend_from_slice(&encode_octet_string(b""));
        let mut der = Vec::new();
        der.push(0x30);
        push_length(&mut der, body.len());
        der.extend_from_slice(&body);
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
        body.extend_from_slice(&encode_integer(&[0x01]));
        body.extend_from_slice(&[0x02, 0x01, 0x80]); // y = INTEGER 0x80 (sign-bit set, no pad)
        body.extend_from_slice(&encode_octet_string(&[0u8; 32]));
        body.extend_from_slice(&encode_octet_string(b""));
        let mut der = Vec::new();
        der.push(0x30);
        push_length(&mut der, body.len());
        der.extend_from_slice(&body);
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
    /// format must accept the field element 0. Regression test for the
    /// previous decoder copying the signature INTEGER rule that
    /// rejected single-byte zero content.
    #[test]
    fn round_trip_x_zero() {
        let mut ct = make_ct(b"z".to_vec());
        ct.x = U256::ZERO;
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode round-trip with x = 0");
        assert_eq!(decoded.x, U256::ZERO);
        assert_eq!(decoded.y, ct.y);
    }

    /// Strict canonical INTEGER: a 32-byte coordinate ≥ p is rejected.
    /// Without this bound, `Fp::new` silently reduces the value modulo
    /// `p`, admitting a second DER blob for the same field element —
    /// ciphertext malleability. Regression test for the v0.2 review
    /// finding from the codex pre-publish review.
    #[test]
    fn rejects_x_at_or_above_p() {
        // Build a SEQUENCE with x = p (the SM2 prime). After Fp::new
        // reduction this would be 0; without the field-bound check the
        // wire-format admits this.
        let p = *Fp::MODULUS.as_ref();
        let p_bytes = p.to_be_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&encode_integer(&p_bytes));
        body.extend_from_slice(&encode_integer(&[0x01]));
        body.extend_from_slice(&encode_octet_string(&[0u8; 32]));
        body.extend_from_slice(&encode_octet_string(b""));
        let mut der = Vec::new();
        der.push(0x30);
        push_length(&mut der, body.len());
        der.extend_from_slice(&body);
        assert!(
            decode(&der).is_none(),
            "x = p is not a field element and must be rejected"
        );

        // Also verify `2^256 - 1` is rejected (well above p).
        let max_bytes = [0xffu8; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&encode_integer(&max_bytes));
        body.extend_from_slice(&encode_integer(&[0x01]));
        body.extend_from_slice(&encode_octet_string(&[0u8; 32]));
        body.extend_from_slice(&encode_octet_string(b""));
        let mut der = Vec::new();
        der.push(0x30);
        push_length(&mut der, body.len());
        der.extend_from_slice(&body);
        assert!(decode(&der).is_none(), "x = 2^256 - 1 must be rejected");
    }

    /// Companion check: `p - 1` is the largest valid coordinate and
    /// must round-trip cleanly.
    #[test]
    fn round_trip_x_p_minus_one() {
        let p_minus_one = Fp::MODULUS.as_ref().wrapping_sub(&U256::ONE);
        let mut ct = make_ct(b"q".to_vec());
        ct.x = p_minus_one;
        let der = encode(&ct);
        let decoded = decode(&der).expect("decode round-trip with x = p - 1");
        assert_eq!(decoded.x, p_minus_one);
    }

    /// The 0x83 length encoding boundary: a ciphertext payload exactly
    /// 65,536 bytes long forces 3-byte length.
    #[test]
    fn round_trip_65536_byte_ciphertext_uses_3byte_length() {
        let payload = alloc::vec![0xa5u8; 65_536];
        let ct = make_ct(payload.clone());
        let der = encode(&ct);
        // Sanity-check that the encoder used 0x83 somewhere (the
        // ciphertext OCTET STRING's length is 65_536, which needs 0x83).
        // Don't assert the exact byte position — just round-trip.
        let decoded = decode(&der).expect("decode 65,536-byte round-trip");
        assert_eq!(decoded.ciphertext, payload);
    }
}
