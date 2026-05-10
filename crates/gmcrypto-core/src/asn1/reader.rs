//! Strict-canonical DER reader primitives.
//!
//! Each primitive returns `Option<(T, &[u8])>` — the parsed value and
//! the remaining input. `None` for any malformed input; **single
//! shape, every failure folds to `None`** per the project failure-
//! mode invariant. No structured error type is exposed.
//!
//! Readers borrow into the input slice (zero-allocation). Strict-
//! canonical-INTEGER discipline matches the v0.2 `asn1::sig` rules
//! (reject empty content, reject sign-bit-set first byte without
//! `0x00` pad, reject redundant `0x00` leading-pad). The canonical
//! single-byte zero (`02 01 00`) is **accepted** here; callers that
//! disallow zero (e.g. SM2 signatures where `r, s ∈ [1, n-1]`)
//! check `result.bytes() == &[0x00]` post-read.
//!
//! Maximum supported DER length: **16 MiB** (3-byte length encoding,
//! `0x83`-prefixed). Anything above that is rejected on read.

use alloc::vec::Vec;

/// Universal primitive INTEGER tag.
pub const TAG_INTEGER: u8 = 0x02;
/// Universal primitive BIT STRING tag.
pub const TAG_BIT_STRING: u8 = 0x03;
/// Universal primitive OCTET STRING tag.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// Universal primitive NULL tag.
pub const TAG_NULL: u8 = 0x05;
/// Universal primitive OBJECT IDENTIFIER tag.
pub const TAG_OID: u8 = 0x06;
/// Universal constructed SEQUENCE tag.
pub const TAG_SEQUENCE: u8 = 0x30;
/// Universal constructed SET tag.
pub const TAG_SET: u8 = 0x31;

/// Maximum DER length the reader/writer support: 16 MiB.
pub const MAX_DER_LEN: usize = 16_777_216;

/// Read a single-byte tag, asserting it equals `expected`.
#[must_use]
pub fn read_tag(input: &[u8], expected: u8) -> Option<&[u8]> {
    let (tag, rest) = input.split_first()?;
    if *tag == expected { Some(rest) } else { None }
}

/// Read a DER length encoding.
///
/// Supports the 1-byte form (`< 0x80`), the 2-byte (`0x81 LL`),
/// the 3-byte (`0x82 HH LL`), and the 4-byte (`0x83 HH MM LL`)
/// forms. Rejects non-minimal encodings and lengths
/// `≥ MAX_DER_LEN`.
#[must_use]
pub fn read_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    if *first < 0x80 {
        Some((*first as usize, rest))
    } else if *first == 0x81 {
        let (b, rest) = rest.split_first()?;
        if *b < 0x80 {
            return None; // not minimal: length < 128 must use the 1-byte form
        }
        Some((*b as usize, rest))
    } else if *first == 0x82 {
        let (hi, rest) = rest.split_first()?;
        let (lo, rest) = rest.split_first()?;
        let len = (usize::from(*hi) << 8) | usize::from(*lo);
        if len < 256 {
            return None; // not minimal
        }
        Some((len, rest))
    } else if *first == 0x83 {
        let (b2, rest) = rest.split_first()?;
        let (b1, rest) = rest.split_first()?;
        let (b0, rest) = rest.split_first()?;
        let len = (usize::from(*b2) << 16) | (usize::from(*b1) << 8) | usize::from(*b0);
        if len < 65_536 {
            return None; // not minimal
        }
        Some((len, rest))
    } else {
        // 4-byte+ lengths reject; 16 MiB is the documented ceiling.
        None
    }
}

/// Read a tag-length-value triple, asserting tag equals `expected`.
///
/// Returns the value bytes (borrowed) and the remainder after the
/// value.
#[must_use]
pub fn read_tlv(input: &[u8], expected: u8) -> Option<(&[u8], &[u8])> {
    let rest = read_tag(input, expected)?;
    let (len, rest) = read_length(rest)?;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Read a DER INTEGER.
///
/// Returns the canonical unsigned big-endian content bytes (with the
/// disambiguating `0x00` pad stripped, if present) and the
/// remainder. The single-byte `[0x00]` (canonical zero) is returned
/// as-is; callers that disallow zero must check `bytes == &[0x00]`
/// post-read.
///
/// Strict-canonical rules per X.690 §8.3.2 / §10.2:
/// - empty content rejected;
/// - sign-bit-set first byte without `0x00` pad rejected (would be
///   negative in two's complement);
/// - redundant `0x00` leading-pad (BER style) rejected.
#[must_use]
pub fn read_integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (bytes, rest) = read_tlv(input, TAG_INTEGER)?;
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] & 0x80 != 0 {
        return None; // would be negative in two's complement
    }
    let unsigned = if bytes[0] == 0x00 {
        if bytes.len() == 1 {
            // Canonical encoding of zero — accept and return [0x00].
            bytes
        } else if bytes[1] & 0x80 == 0 {
            // Leading 0x00 followed by a high-bit-clear byte is
            // redundant (BER, not DER).
            return None;
        } else {
            &bytes[1..]
        }
    } else {
        bytes
    };
    Some((unsigned, rest))
}

/// Read a DER OCTET STRING.
///
/// Returns the value bytes (borrowed) and the remainder.
#[must_use]
pub fn read_octet_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    read_tlv(input, TAG_OCTET_STRING)
}

/// Read a DER NULL — must be exactly `05 00`.
#[must_use]
pub fn read_null(input: &[u8]) -> Option<&[u8]> {
    let (value, rest) = read_tlv(input, TAG_NULL)?;
    if !value.is_empty() {
        return None;
    }
    Some(rest)
}

/// Read a DER OBJECT IDENTIFIER.
///
/// Returns the encoded sub-identifier bytes (per X.690 §8.19, no
/// outer `06 LEN` framing) and the remainder. Callers compare to
/// fixed encodings from [`super::oid`].
///
/// Sanity checks: non-empty content; the final byte's high bit is
/// clear (no continuation past the last sub-identifier).
#[must_use]
pub fn read_oid(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (value, rest) = read_tlv(input, TAG_OID)?;
    if value.is_empty() {
        return None;
    }
    // The final sub-identifier byte must not have the continuation bit set.
    if value[value.len() - 1] & 0x80 != 0 {
        return None;
    }
    Some((value, rest))
}

/// Read a DER BIT STRING.
///
/// Returns `(unused_bits, value_bytes, rest)`. `unused_bits` is the
/// count from the first content byte; for the SPKI uncompressed-
/// point case this MUST be `0` — caller checks. `unused_bits > 7`
/// is rejected. An empty BIT STRING value (no `unused_bits` byte
/// at all) is also rejected.
#[must_use]
pub fn read_bit_string(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (value, rest) = read_tlv(input, TAG_BIT_STRING)?;
    let (unused, bit_bytes) = value.split_first()?;
    if *unused > 7 {
        return None;
    }
    Some((*unused, bit_bytes, rest))
}

/// Read a DER SEQUENCE.
///
/// Returns the body bytes (borrowed) and the remainder after the
/// sequence. Callers iterate the body via further `read_*` calls
/// and check that the body slice is fully consumed.
#[must_use]
pub fn read_sequence(input: &[u8]) -> Option<(&[u8], &[u8])> {
    read_tlv(input, TAG_SEQUENCE)
}

/// Read a context-tagged `[n] EXPLICIT` field.
///
/// Returns the inner (constructed-content) bytes and the remainder.
/// Tag numbers above 30 (which would require multi-byte tag form)
/// are rejected — none of the W2 wire formats need them.
#[must_use]
pub fn read_context_tagged_explicit(input: &[u8], n: u8) -> Option<(&[u8], &[u8])> {
    if n > 30 {
        return None;
    }
    // Class = context (0xA0); P/C = constructed (0x20). These two share the
    // upper nibble 0xA0; tag number occupies the low 5 bits.
    let tag = 0xA0 | n;
    read_tlv(input, tag)
}

/// Read a context-tagged `[n] IMPLICIT` primitive field (no inner
/// constructed wrapper). Returns the value bytes and the remainder.
#[must_use]
pub fn read_context_tagged_implicit(input: &[u8], n: u8) -> Option<(&[u8], &[u8])> {
    if n > 30 {
        return None;
    }
    // Class = context (0x80); P/C = primitive (0x00).
    let tag = 0x80 | n;
    read_tlv(input, tag)
}

/// Read a `SEQUENCE OF` body and collect items via a closure.
///
/// `read_item` runs on the body slice and consumes one item per
/// call; iteration stops when the body is empty. Returns `None`
/// if any individual item read fails or the body has trailing
/// bytes the closure didn't consume.
#[must_use]
pub fn collect_sequence_of<'a, T, F>(body: &'a [u8], mut read_item: F) -> Option<Vec<T>>
where
    F: FnMut(&'a [u8]) -> Option<(T, &'a [u8])>,
{
    let mut items = Vec::new();
    let mut cursor = body;
    while !cursor.is_empty() {
        let (item, next) = read_item(cursor)?;
        items.push(item);
        cursor = next;
    }
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- read_length ----------

    #[test]
    fn length_one_byte_forms() {
        assert_eq!(read_length(&[0x00]), Some((0, &[][..])));
        assert_eq!(read_length(&[0x7F]), Some((127, &[][..])));
        // Trailing input after the length is preserved.
        assert_eq!(
            read_length(&[0x05, 0xAA, 0xBB]),
            Some((5, &[0xAA, 0xBB][..]))
        );
    }

    #[test]
    fn length_two_byte_form() {
        assert_eq!(read_length(&[0x81, 0x80]), Some((128, &[][..])));
        assert_eq!(read_length(&[0x81, 0xFF]), Some((255, &[][..])));
    }

    #[test]
    fn length_two_byte_non_minimal_rejected() {
        // 0x81 0x05 should have used the 1-byte form (0x05).
        assert_eq!(read_length(&[0x81, 0x05]), None);
        assert_eq!(read_length(&[0x81, 0x7F]), None);
    }

    #[test]
    fn length_three_byte_form() {
        assert_eq!(read_length(&[0x82, 0x01, 0x00]), Some((256, &[][..])));
        assert_eq!(read_length(&[0x82, 0xFF, 0xFF]), Some((65_535, &[][..])));
    }

    #[test]
    fn length_three_byte_non_minimal_rejected() {
        // 0x82 0x00 0xFF should have used the 1-byte form.
        assert_eq!(read_length(&[0x82, 0x00, 0xFF]), None);
        // 0x82 0x00 0xFF — len = 255 — non-minimal.
        assert_eq!(read_length(&[0x82, 0x00, 0xFF]), None);
    }

    #[test]
    fn length_four_byte_form() {
        assert_eq!(
            read_length(&[0x83, 0x01, 0x00, 0x00]),
            Some((65_536, &[][..]))
        );
        assert_eq!(
            read_length(&[0x83, 0xFF, 0xFF, 0xFF]),
            Some((16_777_215, &[][..]))
        );
    }

    #[test]
    fn length_four_byte_non_minimal_rejected() {
        assert_eq!(read_length(&[0x83, 0x00, 0xFF, 0xFF]), None);
    }

    #[test]
    fn length_above_max_rejected() {
        // 0x84 indicates 4 content bytes — not supported.
        assert_eq!(read_length(&[0x84, 0x01, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn length_truncated_rejected() {
        assert_eq!(read_length(&[]), None);
        assert_eq!(read_length(&[0x81]), None);
        assert_eq!(read_length(&[0x82, 0x01]), None);
        assert_eq!(read_length(&[0x83, 0x01, 0x00]), None);
    }

    // ---------- read_integer ----------

    #[test]
    fn integer_canonical_zero() {
        let (bytes, rest) = read_integer(&[0x02, 0x01, 0x00]).expect("zero");
        assert_eq!(bytes, &[0x00]);
        assert!(rest.is_empty());
    }

    #[test]
    fn integer_small_positive() {
        let (bytes, _) = read_integer(&[0x02, 0x01, 0x01]).unwrap();
        assert_eq!(bytes, &[0x01]);
        let (bytes, _) = read_integer(&[0x02, 0x01, 0x7F]).unwrap();
        assert_eq!(bytes, &[0x7F]);
    }

    #[test]
    fn integer_strips_disambiguating_pad() {
        // 0x80 alone would be negative; 0x00 0x80 is the canonical
        // unsigned encoding of 128.
        let (bytes, _) = read_integer(&[0x02, 0x02, 0x00, 0x80]).unwrap();
        assert_eq!(bytes, &[0x80]);
    }

    #[test]
    fn integer_rejects_redundant_pad() {
        // 0x00 0x01 — high bit of 0x01 is clear, so the 0x00 pad is
        // redundant (BER, non-canonical).
        assert!(read_integer(&[0x02, 0x02, 0x00, 0x01]).is_none());
    }

    #[test]
    fn integer_rejects_negative() {
        // 0x80 alone — sign bit set, no pad → would be negative in
        // two's complement. SM2 has no negative integers on the wire.
        assert!(read_integer(&[0x02, 0x01, 0x80]).is_none());
        assert!(read_integer(&[0x02, 0x01, 0xFF]).is_none());
    }

    #[test]
    fn integer_rejects_empty_content() {
        assert!(read_integer(&[0x02, 0x00]).is_none());
    }

    #[test]
    fn integer_rejects_wrong_tag() {
        assert!(read_integer(&[0x03, 0x01, 0x01]).is_none());
    }

    #[test]
    fn integer_preserves_remainder() {
        let (bytes, rest) = read_integer(&[0x02, 0x01, 0x05, 0xDE, 0xAD]).unwrap();
        assert_eq!(bytes, &[0x05]);
        assert_eq!(rest, &[0xDE, 0xAD]);
    }

    // ---------- read_octet_string ----------

    #[test]
    fn octet_string_round_trip() {
        let (value, rest) = read_octet_string(&[0x04, 0x03, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(value, &[0x01, 0x02, 0x03]);
        assert!(rest.is_empty());
    }

    #[test]
    fn octet_string_empty() {
        let (value, rest) = read_octet_string(&[0x04, 0x00]).unwrap();
        assert!(value.is_empty());
        assert!(rest.is_empty());
    }

    // ---------- read_null ----------

    #[test]
    fn null_canonical() {
        assert_eq!(read_null(&[0x05, 0x00]), Some(&[][..]));
        assert_eq!(read_null(&[0x05, 0x00, 0xFF]), Some(&[0xFF][..]));
    }

    #[test]
    fn null_with_content_rejected() {
        assert!(read_null(&[0x05, 0x01, 0x00]).is_none());
    }

    // ---------- read_oid ----------

    #[test]
    fn oid_id_pbkdf2() {
        // 1.2.840.113549.1.5.12 → 06 09 2A 86 48 86 F7 0D 01 05 0C
        let der = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C,
        ];
        let (value, rest) = read_oid(&der).unwrap();
        assert_eq!(value, &der[2..]);
        assert!(rest.is_empty());
    }

    #[test]
    fn oid_empty_rejected() {
        assert!(read_oid(&[0x06, 0x00]).is_none());
    }

    #[test]
    fn oid_unterminated_continuation_rejected() {
        // 0x80 has the high bit set → continuation, but it's the
        // last byte — malformed.
        assert!(read_oid(&[0x06, 0x01, 0x80]).is_none());
        assert!(read_oid(&[0x06, 0x02, 0x2A, 0x80]).is_none());
    }

    // ---------- read_bit_string ----------

    #[test]
    fn bit_string_zero_unused() {
        let (unused, bytes, rest) = read_bit_string(&[0x03, 0x03, 0x00, 0xAB, 0xCD]).unwrap();
        assert_eq!(unused, 0);
        assert_eq!(bytes, &[0xAB, 0xCD]);
        assert!(rest.is_empty());
    }

    #[test]
    fn bit_string_unused_above_7_rejected() {
        assert!(read_bit_string(&[0x03, 0x02, 0x08, 0xFF]).is_none());
    }

    #[test]
    fn bit_string_empty_value_rejected() {
        // 0x03 0x00 — no unused-bits byte at all.
        assert!(read_bit_string(&[0x03, 0x00]).is_none());
    }

    // ---------- read_sequence ----------

    #[test]
    fn sequence_round_trip() {
        // SEQUENCE { INTEGER 1, INTEGER 2 } = 30 06 02 01 01 02 01 02
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (body, rest) = read_sequence(&der).unwrap();
        assert_eq!(body, &der[2..]);
        assert!(rest.is_empty());
        // Iterate body.
        let (a, body) = read_integer(body).unwrap();
        let (b, body) = read_integer(body).unwrap();
        assert_eq!(a, &[0x01]);
        assert_eq!(b, &[0x02]);
        assert!(body.is_empty());
    }

    // ---------- context tags ----------

    #[test]
    fn context_explicit_round_trip() {
        // [0] EXPLICIT INTEGER 1 = A0 03 02 01 01
        let der = [0xA0, 0x03, 0x02, 0x01, 0x01];
        let (inner, rest) = read_context_tagged_explicit(&der, 0).unwrap();
        assert!(rest.is_empty());
        let (val, _) = read_integer(inner).unwrap();
        assert_eq!(val, &[0x01]);
    }

    #[test]
    fn context_implicit_round_trip() {
        // [1] IMPLICIT OCTET STRING "ab" = 81 02 61 62
        let der = [0x81, 0x02, 0x61, 0x62];
        let (value, rest) = read_context_tagged_implicit(&der, 1).unwrap();
        assert_eq!(value, b"ab");
        assert!(rest.is_empty());
    }

    #[test]
    fn context_explicit_wrong_number_rejected() {
        let der = [0xA0, 0x03, 0x02, 0x01, 0x01];
        assert!(read_context_tagged_explicit(&der, 1).is_none());
    }

    #[test]
    fn context_explicit_above_30_rejected() {
        // We don't support multi-byte tag form.
        assert!(read_context_tagged_explicit(&[0xBF, 0x1F, 0x00], 31).is_none());
    }

    // ---------- collect_sequence_of ----------

    #[test]
    fn collect_three_integers() {
        let body = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03];
        let items = collect_sequence_of(&body, |b| {
            let (v, rest) = read_integer(b)?;
            Some((v[0], rest))
        })
        .unwrap();
        assert_eq!(items, alloc::vec![1u8, 2, 3]);
    }

    #[test]
    fn collect_stops_on_short_input() {
        let body = [0x02, 0x01, 0x01, 0x02, 0x01]; // truncated second INTEGER
        let result: Option<Vec<u8>> = collect_sequence_of(&body, |b| {
            let (v, rest) = read_integer(b)?;
            Some((v[0], rest))
        });
        assert!(result.is_none());
    }
}
