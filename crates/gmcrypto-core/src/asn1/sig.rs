//! ASN.1 DER encoding for SM2 signatures.
//!
//! Shape: `SEQUENCE { r INTEGER, s INTEGER }`. v0.3 re-implements
//! on top of [`super::reader`] / [`super::writer`]; the wire output
//! and accept/reject behaviour are byte-identical to v0.2.
//!
//! Strict canonical-INTEGER discipline (rejecting empty content,
//! sign-bit-set first byte, redundant `0x00`-pad, lengths `> 32`)
//! lives in [`super::reader::read_integer`]; this module additionally
//! rejects single-byte `0x00` content (canonical zero) because SM2
//! signature scalars `r`, `s` lie in `[1, n-1]` — zero is malformed.

use alloc::vec::Vec;

use super::{reader, writer};

/// Encode `(r, s)` as a DER `SEQUENCE { r INTEGER, s INTEGER }`.
///
/// `r` and `s` are 32-byte big-endian scalars. v0.22 reshaped this from
/// `&crypto_bigint::U256` to `&[u8; 32]` so the public API names no
/// `crypto-bigint` type (`docs/v0.22-scope.md` §3 Q22.4); the emitted DER
/// is byte-identical (`write_integer` canonicalizes the same bytes).
#[must_use]
pub fn encode_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(72);
    writer::write_integer(&mut body, r);
    writer::write_integer(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 4);
    writer::write_sequence(&mut out, &body);
    out
}

/// Decode a DER `SEQUENCE { r, s }` into two 32-byte big-endian scalars.
/// Returns `None` for any malformed input. **No distinguishing failure
/// modes**.
///
/// v0.22 reshaped the return from `(U256, U256)` to `([u8; 32], [u8; 32])`
/// (Q22.4); the accept/reject behaviour is unchanged — all the
/// strict-canonical + zero/length rejects stay in [`read_scalar_in_range`].
/// Callers that need the numeric value (e.g. `verify_with_id`'s
/// `r < n` / `Fn::new` checks) reconstruct `U256::from_be_slice` themselves.
#[must_use]
pub fn decode_sig(input: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (body, rest) = reader::read_sequence(input)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, body) = read_scalar_in_range(body)?;
    let (s, body) = read_scalar_in_range(body)?;
    if !body.is_empty() {
        return None;
    }
    Some((r, s))
}

/// Read a DER INTEGER and decode its content as a 32-byte unsigned
/// big-endian scalar. Rejects:
/// - any encoding that fails the strict-canonical reader rules;
/// - the canonical zero `02 01 00` (since SM2 `r`, `s ∈ [1, n-1]`);
/// - content longer than 32 bytes (since SM2 scalars are 256-bit).
fn read_scalar_in_range(input: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (bytes, rest) = reader::read_integer(input)?;
    // SM2 r/s ∈ [1, n-1] → zero is invalid. The reader returns
    // `[0x00]` for canonical zero; reject that here.
    if bytes == [0x00] {
        return None;
    }
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    Some((padded, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn round_trip_small() {
        let r = crate::u256_to_be32(&U256::from_u64(0x1234));
        let s = crate::u256_to_be32(&U256::from_u64(0x5678));
        let der = encode_sig(&r, &s);
        let (r2, s2) = decode_sig(&der).expect("round-trip");
        assert_eq!(r2, r);
        assert_eq!(s2, s);
    }

    #[test]
    fn round_trip_large_with_high_bit() {
        // A value with the high bit set requires a 0x00 pad in DER INTEGER.
        let r = crate::u256_to_be32(&U256::from_be_hex(
            "FF00000000000000000000000000000000000000000000000000000000000001",
        ));
        let s = crate::u256_to_be32(&U256::from_be_hex(
            "8000000000000000000000000000000000000000000000000000000000000002",
        ));
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

    /// SM2 scalars must be non-zero. Canonical zero (`02 01 00`) on
    /// either component must be rejected. Regression test for the
    /// W1 port: the underlying `reader::read_integer` accepts zero
    /// (since it's used by ciphertext.rs); sig.rs's
    /// `read_scalar_in_range` is responsible for the post-read
    /// zero rejection.
    #[test]
    fn rejects_zero_scalar() {
        // SEQ { INTEGER 0x00, INTEGER 0x01 }
        let bad_r = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        assert!(decode_sig(&bad_r).is_none());
        // SEQ { INTEGER 0x01, INTEGER 0x00 }
        let bad_s = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
        assert!(decode_sig(&bad_s).is_none());
    }
}
