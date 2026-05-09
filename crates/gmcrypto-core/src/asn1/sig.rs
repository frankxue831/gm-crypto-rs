//! Minimal ASN.1 DER encoding for SM2 signatures.
//!
//! Only the shape `SEQUENCE { r INTEGER, s INTEGER }` is supported.
//! v0.3 will introduce a reusable reader/writer that generalizes this.

use alloc::vec::Vec;
use crypto_bigint::U256;

/// Encode (r, s) as a DER SEQUENCE.
#[must_use]
pub fn encode_sig(r: &U256, s: &U256) -> Vec<u8> {
    let r_der = encode_integer(&r.to_be_bytes());
    let s_der = encode_integer(&s.to_be_bytes());
    let body_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(body_len + 8);
    out.push(0x30); // SEQUENCE tag
    push_length(&mut out, body_len);
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

/// Decode a DER SEQUENCE { r, s } into two U256s. Returns `None` for any
/// malformed input. **No distinguishing failure modes.**
#[must_use]
pub fn decode_sig(input: &[u8]) -> Option<(U256, U256)> {
    let (tag, rest) = input.split_first()?;
    if *tag != 0x30 {
        return None;
    }
    let (body_len, rest) = read_length(rest)?;
    if rest.len() != body_len {
        return None;
    }
    let (r, rest) = read_integer(rest)?;
    let (s, rest) = read_integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    Some((r, s))
}

fn encode_integer(value_be: &[u8]) -> Vec<u8> {
    // Strip leading zeros, then re-add one if the high bit is set
    // (DER INTEGER is two's-complement; positive integers need a leading
    // 0x00 to disambiguate from negative).
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

    // Strict DER canonical-encoding rules (X.690 §8.3.2 / §10.2):
    //
    // - Length ≥ 1 (an INTEGER cannot be empty).
    // - For positive integers, the high bit of the first content byte
    //   must be clear; otherwise a leading 0x00 is required to
    //   disambiguate from a two's-complement negative.
    // - That leading-0x00 padding is allowed *only* when needed:
    //   if the first byte is 0x00 and the second byte's high bit
    //   is also clear, the encoding is non-canonical (BER, not DER).
    // - SM2 r/s are positive scalars in `[1, n-1]`, so a top-bit-set
    //   first byte is unambiguously a malformed signature, not a
    //   negative number we should accept.
    //
    // Accepting non-canonical or sign-bit-negative encodings would
    // create signature malleability — multiple distinct DER blobs
    // mapping to the same (r, s).
    if int_bytes.is_empty() {
        return None;
    }
    if int_bytes[0] & 0x80 != 0 {
        // High bit set on first byte → would be negative in two's
        // complement; SM2 has no such signatures.
        return None;
    }
    let bytes = if int_bytes[0] == 0x00 {
        // The leading 0x00 must be followed by a high-bit-set byte
        // (otherwise it's redundant padding — non-canonical).
        if int_bytes.len() < 2 || int_bytes[1] & 0x80 == 0 {
            return None;
        }
        &int_bytes[1..]
    } else {
        int_bytes
    };
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    Some((U256::from_be_slice(&padded), rest_after))
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
    } else {
        // Signatures never need this much length; the call site prevents it.
        panic!("signature DER length overflow");
    }
}

fn read_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    if *first < 0x80 {
        Some((*first as usize, rest))
    } else if *first == 0x81 {
        let (b, rest) = rest.split_first()?;
        if *b < 0x80 {
            return None;
        } // not minimal
        Some((*b as usize, rest))
    } else if *first == 0x82 {
        let (hi, rest) = rest.split_first()?;
        let (lo, rest) = rest.split_first()?;
        let len = ((*hi as usize) << 8) | (*lo as usize);
        if len < 256 {
            return None;
        } // not minimal
        Some((len, rest))
    } else {
        None // 4-byte lengths not supported in v0.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small() {
        let r = U256::from_u64(0x1234);
        let s = U256::from_u64(0x5678);
        let der = encode_sig(&r, &s);
        let (r2, s2) = decode_sig(&der).expect("round-trip");
        assert_eq!(r2, r);
        assert_eq!(s2, s);
    }

    #[test]
    fn round_trip_large_with_high_bit() {
        // A value with the high bit set requires a 0x00 pad in DER INTEGER.
        let r =
            U256::from_be_hex("FF00000000000000000000000000000000000000000000000000000000000001");
        let s =
            U256::from_be_hex("8000000000000000000000000000000000000000000000000000000000000002");
        let der = encode_sig(&r, &s);
        let (r2, s2) = decode_sig(&der).expect("round-trip");
        assert_eq!(r2, r);
        assert_eq!(s2, s);
    }

    #[test]
    fn malformed_returns_none() {
        assert!(decode_sig(&[]).is_none());
        assert!(decode_sig(&[0x30]).is_none()); // truncated
        assert!(decode_sig(&[0x31, 0x00]).is_none()); // wrong tag
        assert!(decode_sig(&[0x30, 0x05, 0x02, 0x01, 0x01]).is_none()); // body shorter than declared
    }

    /// Strict DER: redundant leading 0x00 (BER-style) must be rejected.
    /// Encoding INTEGER 1 as `02 02 00 01` is non-canonical; canonical
    /// is `02 01 01`.
    #[test]
    fn rejects_non_canonical_leading_zero() {
        // SEQ { INTEGER 0x00 0x01, INTEGER 0x01 }
        let bad = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        assert!(
            decode_sig(&bad).is_none(),
            "non-canonical 00-pad on small int must be rejected"
        );
    }

    /// Strict DER: a sign-bit-set first byte without 0x00 padding would
    /// represent a negative integer in two's complement. SM2 r/s are
    /// always positive in `[1, n-1]`, so this is malformed.
    #[test]
    fn rejects_negative_integer_encoding() {
        // SEQ { INTEGER 0x80, INTEGER 0x01 }
        let bad = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        assert!(
            decode_sig(&bad).is_none(),
            "high-bit-set first byte without 00 pad must be rejected"
        );
    }

    /// Strict DER: empty INTEGER content is not a valid encoding.
    #[test]
    fn rejects_empty_integer() {
        // SEQ { INTEGER (length 0), INTEGER 0x01 }
        let bad = [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01];
        assert!(
            decode_sig(&bad).is_none(),
            "empty INTEGER content must be rejected"
        );
    }
}
