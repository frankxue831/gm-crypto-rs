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
    // Strip a single leading 0x00 if present (DER's positive-int padding).
    let bytes = if int_bytes.first() == Some(&0x00) && int_bytes.len() > 1 {
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
}
