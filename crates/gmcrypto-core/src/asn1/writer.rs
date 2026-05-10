//! Strict-canonical DER writer primitives.
//!
//! Writers append to a caller-supplied [`Vec<u8>`]. Length encodings
//! use the minimal form: 1-byte (`< 128`), 2-byte (`0x81 LL`),
//! 3-byte (`0x82 HH LL`), 4-byte (`0x83 HH MM LL`). Lengths
//! `≥ 16 MiB` panic — the documented ceiling per `CLAUDE.md`;
//! callers chunk via SM4-CBC + outer SM2 wrap if they need more.
//!
//! INTEGER emit follows X.690 §8.3.2: leading zeros stripped, a
//! disambiguating `0x00` re-prepended if the high bit of the first
//! content byte is set.

use alloc::vec::Vec;

use super::reader::{
    MAX_DER_LEN, TAG_BIT_STRING, TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};

/// Append a minimal DER length encoding to `out`.
///
/// # Panics
/// Panics if `len >= MAX_DER_LEN` (16 MiB). Callers must chunk
/// before this boundary.
pub fn write_length(out: &mut Vec<u8>, len: usize) {
    #[allow(clippy::cast_possible_truncation)]
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65_536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else if len < MAX_DER_LEN {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        panic!("DER length overflow: {} >= {} bytes", len, MAX_DER_LEN);
    }
}

/// Append a DER INTEGER tag-length-value.
///
/// `value_be` is the unsigned big-endian magnitude; leading zeros
/// are stripped, then a `0x00` is re-prepended if the first content
/// byte has its high bit set (positive-integer disambiguation).
///
/// # Panics
/// Panics if `value_be` is empty.
pub fn write_integer(out: &mut Vec<u8>, value_be: &[u8]) {
    assert!(!value_be.is_empty(), "INTEGER content must be non-empty");
    let mut start = 0;
    while start < value_be.len() - 1 && value_be[start] == 0 {
        start += 1;
    }
    let trimmed = &value_be[start..];
    let needs_pad = (trimmed[0] & 0x80) != 0;
    let int_len = trimmed.len() + usize::from(needs_pad);
    out.push(TAG_INTEGER);
    write_length(out, int_len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
}

/// Append a DER OCTET STRING tag-length-value.
pub fn write_octet_string(out: &mut Vec<u8>, value: &[u8]) {
    out.push(TAG_OCTET_STRING);
    write_length(out, value.len());
    out.extend_from_slice(value);
}

/// Append a DER BIT STRING tag-length-value with the given
/// `unused_bits` count (must be `0..=7`) and content bytes.
///
/// # Panics
/// Panics if `unused_bits > 7`.
pub fn write_bit_string(out: &mut Vec<u8>, unused_bits: u8, value: &[u8]) {
    assert!(unused_bits <= 7, "BIT STRING unused_bits must be 0..=7");
    out.push(TAG_BIT_STRING);
    write_length(out, value.len() + 1);
    out.push(unused_bits);
    out.extend_from_slice(value);
}

/// Append a DER NULL — exactly `05 00`.
pub fn write_null(out: &mut Vec<u8>) {
    out.push(TAG_NULL);
    out.push(0x00);
}

/// Append a DER OBJECT IDENTIFIER. `encoded_subids` is the
/// pre-encoded sub-identifier bytes (e.g. from the constants in
/// [`super::oid`]).
///
/// # Panics
/// Panics if `encoded_subids` is empty.
pub fn write_oid(out: &mut Vec<u8>, encoded_subids: &[u8]) {
    assert!(!encoded_subids.is_empty(), "OID content must be non-empty");
    out.push(TAG_OID);
    write_length(out, encoded_subids.len());
    out.extend_from_slice(encoded_subids);
}

/// Append a DER SEQUENCE wrapping `body`: `30 LEN body`.
pub fn write_sequence(out: &mut Vec<u8>, body: &[u8]) {
    out.push(TAG_SEQUENCE);
    write_length(out, body.len());
    out.extend_from_slice(body);
}

/// Append a context-tagged `[n] EXPLICIT` field wrapping `inner`.
///
/// # Panics
/// Panics if `n > 30` (multi-byte tag form is not supported).
pub fn write_context_tagged_explicit(out: &mut Vec<u8>, n: u8, inner: &[u8]) {
    assert!(n <= 30, "multi-byte context tags not supported");
    // Class = context (0xA0); P/C = constructed (0x20).
    out.push(0xA0 | n);
    write_length(out, inner.len());
    out.extend_from_slice(inner);
}

/// Append a context-tagged `[n] IMPLICIT` primitive field with
/// `value` as the raw content.
///
/// # Panics
/// Panics if `n > 30`.
pub fn write_context_tagged_implicit(out: &mut Vec<u8>, n: u8, value: &[u8]) {
    assert!(n <= 30, "multi-byte context tags not supported");
    // Class = context (0x80); P/C = primitive (0x00).
    out.push(0x80 | n);
    write_length(out, value.len());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::reader;

    fn roundtrip_length(len: usize) {
        let mut out = Vec::new();
        write_length(&mut out, len);
        let (decoded, rest) = reader::read_length(&out).expect("decode");
        assert_eq!(decoded, len);
        assert!(rest.is_empty(), "no trailing bytes");
    }

    // ---------- write_length ----------

    #[test]
    fn length_one_byte() {
        roundtrip_length(0);
        roundtrip_length(1);
        roundtrip_length(127);
    }

    #[test]
    fn length_two_byte() {
        roundtrip_length(128);
        roundtrip_length(255);
    }

    #[test]
    fn length_three_byte() {
        roundtrip_length(256);
        roundtrip_length(65_535);
    }

    #[test]
    fn length_four_byte() {
        roundtrip_length(65_536);
        roundtrip_length(MAX_DER_LEN - 1);
    }

    #[test]
    #[should_panic(expected = "DER length overflow")]
    fn length_overflow_panics() {
        let mut out = Vec::new();
        write_length(&mut out, MAX_DER_LEN);
    }

    // ---------- write_integer ----------

    #[test]
    fn integer_round_trip_small() {
        let mut out = Vec::new();
        write_integer(&mut out, &[0x05]);
        let (bytes, _) = reader::read_integer(&out).unwrap();
        assert_eq!(bytes, &[0x05]);
    }

    #[test]
    fn integer_round_trip_high_bit_set() {
        let mut out = Vec::new();
        write_integer(&mut out, &[0x80, 0x01]);
        // Encoded as 02 03 00 80 01 — disambiguating 0x00 prepended.
        assert_eq!(out, alloc::vec![0x02, 0x03, 0x00, 0x80, 0x01]);
        let (bytes, _) = reader::read_integer(&out).unwrap();
        assert_eq!(bytes, &[0x80, 0x01]);
    }

    #[test]
    fn integer_strips_leading_zeros() {
        let mut out = Vec::new();
        write_integer(&mut out, &[0x00, 0x00, 0x05]);
        // Encoded as 02 01 05 — leading zeros dropped.
        assert_eq!(out, alloc::vec![0x02, 0x01, 0x05]);
    }

    #[test]
    fn integer_zero_round_trip() {
        let mut out = Vec::new();
        write_integer(&mut out, &[0x00]);
        // Canonical zero = 02 01 00.
        assert_eq!(out, alloc::vec![0x02, 0x01, 0x00]);
        let (bytes, _) = reader::read_integer(&out).unwrap();
        assert_eq!(bytes, &[0x00]);
    }

    // ---------- write_octet_string ----------

    #[test]
    fn octet_string_empty() {
        let mut out = Vec::new();
        write_octet_string(&mut out, &[]);
        assert_eq!(out, alloc::vec![0x04, 0x00]);
    }

    #[test]
    fn octet_string_round_trip() {
        let mut out = Vec::new();
        write_octet_string(&mut out, b"abc");
        assert_eq!(out, alloc::vec![0x04, 0x03, b'a', b'b', b'c']);
    }

    // ---------- write_bit_string ----------

    #[test]
    fn bit_string_round_trip() {
        let mut out = Vec::new();
        write_bit_string(&mut out, 0, &[0xAB, 0xCD]);
        assert_eq!(out, alloc::vec![0x03, 0x03, 0x00, 0xAB, 0xCD]);
        let (unused, bytes, rest) = reader::read_bit_string(&out).unwrap();
        assert_eq!(unused, 0);
        assert_eq!(bytes, &[0xAB, 0xCD]);
        assert!(rest.is_empty());
    }

    // ---------- write_null ----------

    #[test]
    fn null_round_trip() {
        let mut out = Vec::new();
        write_null(&mut out);
        assert_eq!(out, alloc::vec![0x05, 0x00]);
        assert_eq!(reader::read_null(&out), Some(&[][..]));
    }

    // ---------- write_oid ----------

    #[test]
    fn oid_round_trip() {
        // 1.2.840.113549.1.5.12 sub-identifier bytes.
        let subids: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
        let mut out = Vec::new();
        write_oid(&mut out, subids);
        let (parsed, _) = reader::read_oid(&out).unwrap();
        assert_eq!(parsed, subids);
    }

    // ---------- write_sequence ----------

    #[test]
    fn sequence_wrap() {
        let mut body = Vec::new();
        write_integer(&mut body, &[0x01]);
        write_integer(&mut body, &[0x02]);
        let mut out = Vec::new();
        write_sequence(&mut out, &body);
        assert_eq!(
            out,
            alloc::vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
    }

    // ---------- context tags ----------

    #[test]
    fn context_explicit_round_trip() {
        let mut inner = Vec::new();
        write_integer(&mut inner, &[0x01]);
        let mut out = Vec::new();
        write_context_tagged_explicit(&mut out, 0, &inner);
        assert_eq!(out, alloc::vec![0xA0, 0x03, 0x02, 0x01, 0x01]);
        let (parsed, _) = reader::read_context_tagged_explicit(&out, 0).unwrap();
        let (v, _) = reader::read_integer(parsed).unwrap();
        assert_eq!(v, &[0x01]);
    }

    #[test]
    fn context_implicit_round_trip() {
        let mut out = Vec::new();
        write_context_tagged_implicit(&mut out, 1, b"ab");
        assert_eq!(out, alloc::vec![0x81, 0x02, b'a', b'b']);
        let (parsed, _) = reader::read_context_tagged_implicit(&out, 1).unwrap();
        assert_eq!(parsed, b"ab");
    }

    #[test]
    #[should_panic(expected = "multi-byte context tags not supported")]
    fn context_explicit_above_30_panics() {
        let mut out = Vec::new();
        write_context_tagged_explicit(&mut out, 31, &[]);
    }
}
