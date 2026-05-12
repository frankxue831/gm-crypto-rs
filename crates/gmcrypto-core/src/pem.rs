//! Hand-rolled PEM (RFC 7468) codec.
//!
//! Wraps and unwraps `-----BEGIN <LABEL>-----` ... `-----END <LABEL>-----`
//! armor around an arbitrary DER blob. Used by [`crate::pkcs8`],
//! [`crate::spki`], and [`crate::sec1`] for on-disk format support.
//!
//! # Posture
//!
//! - **Liberal decoder, conservative encoder.** [`decode`] accepts the
//!   relaxed RFC 7468 production: arbitrary whitespace (including CR,
//!   LF, tab, space) anywhere inside the body, and either CRLF or LF
//!   line terminators around the boundary lines. [`encode`] emits the
//!   strict RFC 1421 production: 64 base-64 characters per line, LF
//!   terminator, no trailing whitespace.
//! - **No external dependencies.** The base64 codec is embedded below
//!   (~80 LOC) per the v0.3 scope's zero-runtime-deps stance (Q7.1).
//! - **`no_std` + `alloc`.** No file-loading helpers in this module.
//!
//! # Failure-mode invariant
//!
//! [`decode`] returns `Result<Vec<u8>, Error>` with a single
//! [`Error::Failed`] variant. Distinguishing "wrong label" from "bad
//! base64" from "missing END line" is forbidden — see `CLAUDE.md`.

use alloc::vec::Vec;

/// PEM codec failure — alias for the workspace-wide [`crate::Error`].
///
/// Single uninformative variant per the project's failure-mode
/// invariant. Prior to v0.5 this was a distinct `pem::Error` enum;
/// v0.5 W5 unifies it with the workspace-wide type via this alias,
/// so import paths and non-exhaustive `match` callsites against
/// `pem::Error::Failed` continue to work. **One caveat:** the
/// workspace-wide type is `#[non_exhaustive]`, so downstream
/// **exhaustive** `match` arms must now add a wildcard `_ => ...`
/// (single-variant non-exhaustive enums require the wildcard from
/// outside-crate matches).
pub type Error = crate::Error;

/// Strict line length emitted by [`encode`]. RFC 1421 §4.3.2.4 fixes
/// 64 base-64 characters per line; RFC 7468 §3 keeps the same.
const LINE_LEN: usize = 64;

/// Encode `der` as a PEM block with the given `label`. Output is the
/// strict RFC 1421 form: 64 chars per line, LF terminators, no
/// trailing whitespace.
///
/// `label` must be ASCII per RFC 7468 §2 — non-ASCII labels would
/// round-trip but reject under strict-conformant decoders. The
/// callers in this crate use fixed labels (`"PRIVATE KEY"`,
/// `"PUBLIC KEY"`, `"ENCRYPTED PRIVATE KEY"`, `"EC PRIVATE KEY"`),
/// all ASCII.
///
/// # Panics
///
/// Never (encoded length is bounded by `4 · der.len() / 3 + small`,
/// well below the `Vec` allocation ceiling on any realistic input).
#[must_use]
pub fn encode(label: &str, der: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let body = base64_encode(der);
    // 4-line preamble + (body chunked into 64-char lines) + 4-line postamble.
    let line_count = body.len().div_ceil(LINE_LEN);
    let mut out =
        alloc::string::String::with_capacity(body.len() + line_count + 2 * (label.len() + 16));
    let _ = writeln!(out, "-----BEGIN {label}-----");
    let mut start = 0;
    while start < body.len() {
        let end = (start + LINE_LEN).min(body.len());
        out.push_str(&body[start..end]);
        out.push('\n');
        start = end;
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

/// Decode a PEM block, returning the raw DER bytes. The block's label
/// must equal `expected_label` exactly.
///
/// Liberal on whitespace (RFC 7468 §3): tabs, spaces, CR, and LF are
/// all stripped inside the body. The label must match exactly — case
/// sensitive, no fuzzy-match.
///
/// # Errors
///
/// Returns [`Error::Failed`] for any malformed input. Single
/// uninformative variant per the project's failure-mode invariant.
pub fn decode(input: &str, expected_label: &str) -> Result<Vec<u8>, Error> {
    let begin = alloc::format!("-----BEGIN {expected_label}-----");
    let end = alloc::format!("-----END {expected_label}-----");

    let begin_idx = input.find(&begin).ok_or(Error::Failed)?;
    let after_begin = &input[begin_idx + begin.len()..];
    let end_rel = after_begin.find(&end).ok_or(Error::Failed)?;
    let body = &after_begin[..end_rel];

    // Strip whitespace from the body. Anything else (printable
    // non-base64, non-ASCII) gets fed through to base64_decode, which
    // rejects it.
    let mut stripped = alloc::string::String::with_capacity(body.len());
    for ch in body.chars() {
        if !ch.is_ascii_whitespace() {
            stripped.push(ch);
        }
    }

    base64_decode(&stripped).ok_or(Error::Failed)
}

// --- base64 codec (RFC 4648 §4, "standard alphabet") ---

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard base64 with `=` padding. Output is
/// pure ASCII (no line breaks; [`encode`] inserts them).
#[must_use]
fn base64_encode(input: &[u8]) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(BASE64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(BASE64_ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        out.push(BASE64_ALPHABET[(b2 & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i];
        out.push(BASE64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(BASE64_ALPHABET[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out.push(BASE64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(BASE64_ALPHABET[((b1 & 0x0F) << 2) as usize] as char);
        out.push('=');
    }
    out
}

/// Decode a base64 string (no whitespace; caller pre-stripped).
/// Returns `None` for any malformed input.
#[must_use]
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    if bytes.is_empty() {
        return Some(Vec::new());
    }

    // Determine pad count from the suffix.
    let pad = if bytes.ends_with(b"==") {
        2usize
    } else {
        usize::from(bytes.ends_with(b"="))
    };
    let body_chars = bytes.len() - pad;

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        // Decode four input characters → three output bytes (minus
        // pad-driven trim on the final group).
        let last_group = i + 4 == bytes.len();
        let v0 = base64_lookup(bytes[i])?;
        let v1 = base64_lookup(bytes[i + 1])?;
        let (v2, v3) = if last_group {
            (
                if i + 2 < body_chars {
                    base64_lookup(bytes[i + 2])?
                } else {
                    if bytes[i + 2] != b'=' {
                        return None;
                    }
                    0
                },
                if i + 3 < body_chars {
                    base64_lookup(bytes[i + 3])?
                } else {
                    if bytes[i + 3] != b'=' {
                        return None;
                    }
                    0
                },
            )
        } else {
            (base64_lookup(bytes[i + 2])?, base64_lookup(bytes[i + 3])?)
        };

        let b0 = (v0 << 2) | (v1 >> 4);
        let b1 = (v1 << 4) | (v2 >> 2);
        let b2 = (v2 << 6) | v3;

        // Strict-canonical: the bits of the final-group sextets that
        // would have encoded the dropped output bytes must be zero.
        // pad=2: low 4 bits of v1 encode part of `b1` (which we drop)
        // and must be zero. pad=1: low 2 bits of v2 encode part of
        // `b2` (which we drop) and must be zero.
        if last_group {
            if pad == 2 && (v1 & 0x0F) != 0 {
                return None;
            }
            if pad == 1 && (v2 & 0x03) != 0 {
                return None;
            }
        }

        out.push(b0);
        if !last_group || pad <= 1 {
            out.push(b1);
        }
        if !last_group || pad == 0 {
            out.push(b2);
        }
        i += 4;
    }
    Some(out)
}

/// Reverse-lookup for the standard base64 alphabet. Returns `None` for
/// any non-alphabet byte (including `=`, which the caller handles
/// out-of-band via the suffix scan).
const fn base64_lookup(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- base64 codec ----------

    #[test]
    fn base64_round_trip_empty() {
        let bytes: &[u8] = &[];
        assert_eq!(base64_encode(bytes), "");
        assert_eq!(base64_decode("").as_deref(), Some(bytes));
    }

    #[test]
    fn base64_round_trip_one_byte() {
        // Single byte → "AA==" (RFC 4648 example: "f" = "Zg==").
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_decode("Zg==").as_deref(), Some(b"f".as_slice()));
    }

    #[test]
    fn base64_round_trip_two_bytes() {
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("Zm8=").as_deref(), Some(b"fo".as_slice()));
    }

    #[test]
    fn base64_round_trip_three_bytes() {
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_decode("Zm9v").as_deref(), Some(b"foo".as_slice()));
    }

    #[test]
    fn base64_rfc4648_test_vectors() {
        // RFC 4648 §10.
        for (raw, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(raw.as_bytes()), encoded);
            assert_eq!(
                base64_decode(encoded).as_deref(),
                Some(raw.as_bytes()),
                "decode {encoded:?}"
            );
        }
    }

    #[test]
    fn base64_decode_rejects_bad_chars() {
        assert!(base64_decode("Zm9*").is_none()); // '*' not in alphabet
        assert!(base64_decode("Zm9").is_none()); // length not multiple of 4
        assert!(base64_decode("Z===").is_none()); // 3 pads invalid
        assert!(base64_decode("====").is_none()); // all-pad invalid
    }

    /// Strict canonical: non-zero pad bits in the final quantum reject.
    /// `Zg==` is the canonical encoding of `[0x66]`. `Zh==` would
    /// embed `0x68` in v1's low 4 bits — non-canonical because the
    /// encoded byte is still `0x66` but the round-trip would silently
    /// drop the extra bits.
    #[test]
    fn base64_decode_rejects_non_canonical_pad_bits() {
        // 'Z' = 25, 'h' = 33. v1 = 33 = 0b100001. Low 4 bits = 0b0001 ≠ 0.
        assert!(base64_decode("Zh==").is_none());
        // 'Z' = 25, 'g' = 32. v1 = 32 = 0b100000. Low 4 bits = 0 — accept.
        assert!(base64_decode("Zg==").is_some());
        // 'Z' = 25, 'g' = 32, '8' = 60. v2 = 60 = 0b111100. Low 2 bits = 0 — accept.
        assert!(base64_decode("Zm8=").is_some());
        // Mutate to v2 with non-zero low 2 bits: '9' = 61 = 0b111101. Low 2 = 0b01 ≠ 0.
        assert!(base64_decode("Zm9=").is_none());
    }

    // ---------- PEM ----------

    #[test]
    fn pem_round_trip_short() {
        let der: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
        let pem = encode("EC PRIVATE KEY", der);
        let recovered = decode(&pem, "EC PRIVATE KEY").expect("decode");
        assert_eq!(recovered, der);
    }

    #[test]
    fn pem_round_trip_long_wraps_at_64() {
        // 100 bytes of DER → 168 chars of base64 → 3 lines of 64/64/40.
        let der: alloc::vec::Vec<u8> = (0..100u8).collect();
        let pem = encode("PRIVATE KEY", &der);
        // Body lines all ≤ 64 chars.
        for line in pem.lines() {
            if line.starts_with("---") {
                continue;
            }
            assert!(line.len() <= LINE_LEN, "body line too long: {line:?}");
        }
        let recovered = decode(&pem, "PRIVATE KEY").expect("decode");
        assert_eq!(recovered, der);
    }

    #[test]
    fn pem_label_must_match() {
        let pem = encode("PRIVATE KEY", b"\x30\x00");
        assert!(matches!(decode(&pem, "PUBLIC KEY"), Err(Error::Failed)));
    }

    #[test]
    fn pem_decode_rejects_missing_begin() {
        assert!(matches!(
            decode("garbage", "PRIVATE KEY"),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn pem_decode_rejects_missing_end() {
        let bad = "-----BEGIN PRIVATE KEY-----\nABCD\n";
        assert!(matches!(decode(bad, "PRIVATE KEY"), Err(Error::Failed)));
    }

    #[test]
    fn pem_decode_tolerates_crlf_and_extra_whitespace() {
        // CRLF terminators + extra whitespace inside the body.
        let pem = "-----BEGIN PRIVATE KEY-----\r\n\
                   MAMC\r\n\
                   AQU=\r\n\
                   -----END PRIVATE KEY-----\r\n";
        let recovered = decode(pem, "PRIVATE KEY").expect("decode");
        assert_eq!(recovered, [0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn pem_encoded_form_is_strict() {
        let der: alloc::vec::Vec<u8> = (0..200u8).collect();
        let pem = encode("PRIVATE KEY", &der);
        // Strict form: trailing newline; no \r; preamble + body + postamble.
        assert!(pem.ends_with('\n'));
        assert!(!pem.contains('\r'));
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.contains("\n-----END PRIVATE KEY-----\n"));
    }
}
