//! X.509-with-SM2: leaf certificate parse + SM2-with-SM3 signature verify
//! (v1.3; GM/T 0015 profile over the RFC 5280 structure).
//!
//! **This module makes NO trust decisions.** [`Certificate::from_der`]
//! tells you what a certificate *says*; `verify_signature` tells you whether
//! its SM2-with-SM3 signature over those exact wire bytes verifies against a
//! caller-supplied issuer public key — and nothing more. There is:
//!
//! - **no chain building** and no trust-anchor concept;
//! - **no time/validity decision** ([`X509Time`] values are exposed; this
//!   library has no clock — comparing them to "now" is the caller's call);
//! - **no extension interpretation** — extensions (including their
//!   `critical` flags, `keyUsage`, `basicConstraints`) are shape-checked
//!   and exposed raw, never evaluated;
//! - **no hostname matching, no revocation (CRL/OCSP), no policy logic.**
//!
//! A `true` from `verify_signature` means exactly "this issuer key signed
//! these tbsCertificate bytes" — it does NOT mean the certificate is valid,
//! current, or trustworthy. Callers building real PKI logic on top of this
//! must implement those decisions themselves (or wait for a future
//! chain-validation cycle).
//!
//! Accepted profile (single `None` for everything else, per the
//! failure-mode invariant): DER X.509 **v3**, signature algorithm
//! `sm2-sign-with-sm3` (1.2.156.10197.1.501, parameters absent or NULL,
//! outer == inner), SPKI `id-ecPublicKey` + `sm2p256v1` (enforced by the
//! existing [`crate::spki::decode`]). See `docs/v1.3-x509-sm2-design.md`.

extern crate alloc;

use crate::asn1::oid;
use crate::asn1::reader;
use crate::sm2::{DEFAULT_SIGNER_ID, Sm2PublicKey, verify_with_id};
use alloc::vec::Vec;

const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_BOOLEAN: u8 = 0x01;

/// A calendar timestamp parsed from a certificate `Validity` field
/// (`UTCTime` or `GeneralizedTime`, Zulu only).
///
/// Plain field-wise data with derived ordering — **this library has no
/// clock**, so any "is the certificate currently valid" decision is the
/// caller's, made against a time source the caller trusts.
///
/// Documented tolerance: RFC 5280 §4.1.2.5 says pre-2050 dates MUST be
/// `UTCTime`; a `GeneralizedTime` pre-2050 date is nevertheless accepted here
/// (the encoding choice is signature-covered either way).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct X509Time {
    /// Full year (`UTCTime` pivot per RFC 5280 §4.1.2.5.1: `YY >= 50` → 19YY).
    pub year: u16,
    /// Month, 1–12.
    pub month: u8,
    /// Day of month, 1–31 (calendar-exact day-per-month is NOT checked).
    pub day: u8,
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–59.
    pub second: u8,
}

fn two_digits(b: &[u8]) -> Option<u8> {
    match b {
        [a @ b'0'..=b'9', c @ b'0'..=b'9'] => Some((a - b'0') * 10 + (c - b'0')),
        _ => None,
    }
}

/// Parse one `Time` value (either tag), returning `(time, rest_after_tlv)`.
fn read_time(input: &[u8]) -> Option<(X509Time, &[u8])> {
    let (year, body, rest) = if let Some((v, rest)) = reader::read_tlv(input, TAG_UTC_TIME) {
        if v.len() != 13 {
            return None;
        }
        let yy = u16::from(two_digits(&v[0..2])?);
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &v[2..], rest)
    } else {
        let (v, rest) = reader::read_tlv(input, TAG_GENERALIZED_TIME)?;
        if v.len() != 15 {
            return None;
        }
        (
            u16::from(two_digits(&v[0..2])?) * 100 + u16::from(two_digits(&v[2..4])?),
            &v[4..],
            rest,
        )
    };
    // body = MMDDHHMMSS + 'Z' (Zulu only; offsets/fractions rejected by length).
    if body.len() != 11 || body[10] != b'Z' {
        return None;
    }
    let (month, day) = (two_digits(&body[0..2])?, two_digits(&body[2..4])?);
    let (hour, minute, second) = (
        two_digits(&body[4..6])?,
        two_digits(&body[6..8])?,
        two_digits(&body[8..10])?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some((
        X509Time {
            year,
            month,
            day,
            hour,
            minute,
            second,
        },
        rest,
    ))
}

/// Read an `AlgorithmIdentifier` that MUST be `sm2-sign-with-sm3` with absent
/// or NULL parameters (scope Q3.6). Returns `(full_algid_tlv_span, rest)` —
/// the full span feeds the outer==inner byte-equality rule (design §5.5),
/// which also rejects a mixed absent/NULL pair.
fn read_sm2_sig_algid(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, rest) = reader::read_sequence(input)?;
    let span = &input[..input.len() - rest.len()];
    let (oid_bytes, after_oid) = reader::read_oid(body)?;
    if oid_bytes != oid::SM2_SIGN_WITH_SM3 {
        return None;
    }
    if after_oid.is_empty() {
        Some((span, rest))
    } else {
        let after_null = reader::read_null(after_oid)?;
        if after_null.is_empty() {
            Some((span, rest))
        } else {
            None
        }
    }
}

/// Shape-check the `[3]` extensions content ONE level deep, with ZERO
/// interpretation (design §5.9): `Extensions ::= SEQUENCE SIZE(1..) OF
/// Extension`, each Extension framing as `SEQUENCE { extnID OID,
/// [critical BOOLEAN (one content byte)], extnValue OCTET STRING }`,
/// exactly consumed at every level. extnID values and `critical` flags are
/// never evaluated.
fn check_extensions_shape(content: &[u8]) -> Option<()> {
    let (seq, rest) = reader::read_sequence(content)?;
    if !rest.is_empty() || seq.is_empty() {
        return None;
    }
    let mut exts = seq;
    while !exts.is_empty() {
        let (ext, r) = reader::read_sequence(exts)?;
        let (_extn_id, after_oid) = reader::read_oid(ext)?;
        let after_bool = match reader::read_tlv(after_oid, TAG_BOOLEAN) {
            Some((b, rb)) => {
                if b.len() != 1 {
                    return None;
                }
                rb
            }
            None => after_oid,
        };
        let (_extn_value, after_value) = reader::read_octet_string(after_bool)?;
        if !after_value.is_empty() {
            return None;
        }
        exts = r;
    }
    Some(())
}

/// A parsed X.509 v3 certificate (GM/T 0015 profile: SM2-with-SM3
/// signature, sm2p256v1 SPKI).
///
/// Parsing makes **no trust decisions** — see the module docs for the full
/// list of what this type deliberately does NOT do. Field bytes are owned
/// copies of the exact wire encoding.
pub struct Certificate {
    tbs: Vec<u8>,
    serial: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    extensions: Option<Vec<u8>>,
    sig: Vec<u8>,
    not_before: X509Time,
    not_after: X509Time,
    subject_key: Sm2PublicKey,
}

impl Certificate {
    /// Strict-DER parse of an X.509 **v3** certificate in the accepted
    /// profile (module docs). Single `None` for EVERY malformed or
    /// out-of-profile input — the workspace failure-mode invariant.
    ///
    /// Parsing performs **no trust decisions**; a `Some` means only "the
    /// bytes frame as a well-formed certificate in the accepted profile and
    /// carry a valid SM2 subject public key".
    #[must_use]
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let (cert, rest) = reader::read_sequence(der)?;
        if !rest.is_empty() {
            return None;
        }

        // tbsCertificate — capture the exact wire TLV span (design §5.2);
        // verification never re-encodes.
        let (tbs_content, after_tbs) = reader::read_sequence(cert)?;
        let tbs_span = &cert[..cert.len() - after_tbs.len()];

        // ---- inside tbsCertificate ----
        // version [0] EXPLICIT INTEGER, value exactly 2 (v3 only, Q3.11);
        // the wrapper content must contain ONLY the INTEGER.
        let (ver_content, cur) = reader::read_context_tagged_explicit(tbs_content, 0)?;
        let (ver_int, ver_rest) = reader::read_integer(ver_content)?;
        if ver_int != [2] || !ver_rest.is_empty() {
            return None;
        }

        // serialNumber — strict INTEGER. Negative serials are REJECTED by
        // the reader (deliberate deviation from RFC 5280's "gracefully
        // handle"); the returned value bytes are DER-pad-stripped and the
        // 1..=20 bound applies to those stripped bytes (design §5.4).
        let (serial, cur) = reader::read_integer(cur)?;
        if serial.is_empty() || serial.len() > 20 {
            return None;
        }

        // inner signature AlgorithmIdentifier (full span kept for the
        // outer==inner byte-equality rule).
        let (algid_inner, cur) = read_sm2_sig_algid(cur)?;

        // issuer Name — raw TLV span, no interpretation (Q3.7).
        let (_, after_issuer) = reader::read_sequence(cur)?;
        let issuer = &cur[..cur.len() - after_issuer.len()];
        let cur = after_issuer;

        // validity — SEQUENCE of exactly two Times, body exactly consumed.
        let (val_content, cur) = reader::read_sequence(cur)?;
        let (not_before, val_rest) = read_time(val_content)?;
        let (not_after, val_rest) = read_time(val_rest)?;
        if !val_rest.is_empty() {
            return None;
        }

        // subject Name — raw TLV span.
        let (_, after_subject) = reader::read_sequence(cur)?;
        let subject = &cur[..cur.len() - after_subject.len()];
        let cur = after_subject;

        // subjectPublicKeyInfo — the full TLV span goes to the existing
        // spki::decode, which enforces id-ecPublicKey + sm2p256v1 + an
        // on-curve, non-identity point.
        let (_, after_spki) = reader::read_sequence(cur)?;
        let spki_span = &cur[..cur.len() - after_spki.len()];
        let subject_key = crate::spki::decode(spki_span)?;
        let cur = after_spki;

        // optional issuerUniqueID [1] / subjectUniqueID [2] — skipped.
        let cur = match reader::read_context_tagged_implicit(cur, 1) {
            Some((_, r)) => r,
            None => cur,
        };
        let cur = match reader::read_context_tagged_implicit(cur, 2) {
            Some((_, r)) => r,
            None => cur,
        };

        // optional extensions [3] — shape-checked one level deep, kept raw,
        // NEVER interpreted (critical flags included; design §5.9).
        let (extensions, cur) = match reader::read_context_tagged_explicit(cur, 3) {
            Some((ext_content, r)) => {
                check_extensions_shape(ext_content)?;
                (Some(ext_content), r)
            }
            None => (None, cur),
        };
        // tbsCertificate content fully consumed.
        if !cur.is_empty() {
            return None;
        }

        // ---- after tbsCertificate ----
        // outer AlgorithmIdentifier: full-TLV-span byte equality with the
        // inner one (design §5.5 — mixed absent/NULL params rejected).
        let (algid_outer, after_alg) = read_sm2_sig_algid(after_tbs)?;
        if algid_outer != algid_inner {
            return None;
        }

        // signatureValue: BIT STRING with 0 unused bits, last element. The
        // content's SEQUENCE{r,s} semantics are checked exclusively by
        // decode_sig inside verify_with_id (design §5.10) — a cert with
        // garbage here PARSES but never VERIFIES.
        let (unused, sig, after_sig) = reader::read_bit_string(after_alg)?;
        if unused != 0 || !after_sig.is_empty() {
            return None;
        }

        Some(Self {
            tbs: tbs_span.to_vec(),
            serial: serial.to_vec(),
            issuer: issuer.to_vec(),
            subject: subject.to_vec(),
            extensions: extensions.map(<[u8]>::to_vec),
            sig: sig.to_vec(),
            not_before,
            not_after,
            subject_key,
        })
    }

    /// Verify this certificate's SM2-with-SM3 signature against `issuer`
    /// over the **exact `tbsCertificate` wire bytes**, using the GM /
    /// RFC 8998 default ID `"1234567812345678"`.
    ///
    /// **This is NOT certificate validation.** `true` means exactly "this
    /// issuer key signed these tbs bytes" — no chain, no time/validity
    /// check, no keyUsage/basicConstraints/critical-extension evaluation,
    /// no revocation. See the module docs.
    #[must_use]
    pub fn verify_signature(&self, issuer: &Sm2PublicKey) -> bool {
        self.verify_signature_with_id(issuer, DEFAULT_SIGNER_ID)
    }

    /// As [`Certificate::verify_signature`], with a caller-supplied SM2 ID
    /// (RFC 8998 §3.2.1 mandates the default, but CA practice can vary).
    #[must_use]
    pub fn verify_signature_with_id(&self, issuer: &Sm2PublicKey, id: &[u8]) -> bool {
        verify_with_id(issuer, id, &self.tbs, &self.sig)
    }

    /// The subject's SM2 public key — infallible by construction (the SPKI
    /// was validated on-curve during parse).
    #[must_use]
    pub const fn subject_public_key(&self) -> Sm2PublicKey {
        self.subject_key
    }

    /// The exact `TBSCertificate` TLV bytes as they appeared on the wire
    /// (the bytes the signature covers).
    #[must_use]
    pub fn tbs_raw(&self) -> &[u8] {
        &self.tbs
    }

    /// The serial number as unsigned big-endian value bytes (the DER
    /// disambiguating pad is stripped), 1..=20 bytes. Negative serials are
    /// rejected at parse.
    #[must_use]
    pub fn serial_raw(&self) -> &[u8] {
        &self.serial
    }

    /// The issuer `Name` as its full raw DER TLV — no interpretation; use
    /// byte equality for matching (Q3.7).
    #[must_use]
    pub fn issuer_raw(&self) -> &[u8] {
        &self.issuer
    }

    /// The subject `Name` as its full raw DER TLV — no interpretation.
    #[must_use]
    pub fn subject_raw(&self) -> &[u8] {
        &self.subject
    }

    /// The `[3]` extensions content (the `Extensions` SEQUENCE TLV) if
    /// present — shape-checked at parse but NEVER interpreted, `critical`
    /// flags included. A caller building trust logic on top inherits
    /// RFC 5280 §4.2's "MUST reject unrecognized critical extensions"
    /// obligation.
    #[must_use]
    pub fn extensions_raw(&self) -> Option<&[u8]> {
        self.extensions.as_deref()
    }

    /// `notBefore` — exposed, never compared to a clock (the caller owns
    /// any validity-period decision).
    #[must_use]
    pub const fn not_before(&self) -> X509Time {
        self.not_before
    }

    /// `notAfter` — exposed, never compared to a clock.
    #[must_use]
    pub const fn not_after(&self) -> X509Time {
        self.not_after
    }

    /// Whether `subject` and `issuer` are byte-identical raw DER Names
    /// (the RFC 5280 self-issued notion, byte-strict). NOT a statement
    /// that the certificate is self-SIGNED — use
    /// [`Certificate::verify_signature`] with the cert's own
    /// [`Certificate::subject_public_key`] for that.
    #[must_use]
    pub fn is_self_issued(&self) -> bool {
        self.issuer == self.subject
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128, "test helper: short-form lengths only");
        let mut out = alloc::vec![tag, u8::try_from(content.len()).unwrap()];
        out.extend_from_slice(content);
        out
    }

    // ---- read_time ----

    fn utc(s: &str) -> Vec<u8> {
        tlv(TAG_UTC_TIME, s.as_bytes())
    }
    fn gtime(s: &str) -> Vec<u8> {
        tlv(TAG_GENERALIZED_TIME, s.as_bytes())
    }

    #[test]
    fn time_utctime_parses() {
        let der = utc("260611120000Z");
        let (t, rest) = read_time(&der).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            t,
            X509Time {
                year: 2026,
                month: 6,
                day: 11,
                hour: 12,
                minute: 0,
                second: 0
            }
        );
    }

    #[test]
    fn time_utctime_pivot() {
        assert_eq!(read_time(&utc("500101000000Z")).unwrap().0.year, 1950);
        assert_eq!(read_time(&utc("490101000000Z")).unwrap().0.year, 2049);
    }

    #[test]
    fn time_generalizedtime_parses() {
        let (t, _) = read_time(&gtime("20991231235959Z")).unwrap();
        assert_eq!(
            t,
            X509Time {
                year: 2099,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59
            }
        );
    }

    #[test]
    fn time_ordering_is_chronological() {
        let (a, _) = read_time(&utc("260611120000Z")).unwrap();
        let (b, _) = read_time(&utc("260611120001Z")).unwrap();
        let (c, _) = read_time(&gtime("20991231235959Z")).unwrap();
        assert!(a < b && b < c);
    }

    #[test]
    fn time_rejects_malformed() {
        for bad in [
            utc("260611120000"),           // wrong length (no Z, 12 chars)
            utc("2606111200000"),          // 13 chars but last not 'Z'
            utc("26061112000xZ"),          // non-digit
            utc("261311120000Z"),          // month 13
            utc("260600120000Z"),          // day 0... (day 0 rejected)
            utc("260611240000Z"),          // hour 24
            utc("260611126000Z"),          // minute 60
            utc("260611120060Z"),          // second 60
            gtime("20260611120000+0800Z"), // offset / wrong length
            gtime("2026061112000.5Z"),     // fraction / wrong shape
            tlv(0x16, b"260611120000Z"),   // wrong tag
        ] {
            assert!(read_time(&bad).is_none(), "accepted {bad:02x?}");
        }
    }

    // ---- read_sm2_sig_algid ----

    fn algid(params_null: bool) -> Vec<u8> {
        // oid::SM2_SIGN_WITH_SM3 is the sub-identifier CONTENT bytes (the
        // oid-module convention); the 06 LEN framing is added here.
        let mut body = tlv(0x06, oid::SM2_SIGN_WITH_SM3);
        if params_null {
            body.extend_from_slice(&[0x05, 0x00]);
        }
        tlv(0x30, &body)
    }

    #[test]
    fn algid_absent_and_null_params_accepted() {
        for null in [false, true] {
            let a = algid(null);
            let (span, rest) = read_sm2_sig_algid(&a).expect("valid algid rejected");
            assert_eq!(span, &a[..]);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn algid_mixed_forms_are_unequal_spans() {
        // The full-span byte-equality rule rejects a mixed absent/NULL pair
        // even though each form is individually acceptable (design §5.5).
        let absent = algid(false);
        let null = algid(true);
        let (s1, _) = read_sm2_sig_algid(&absent).unwrap();
        let (s2, _) = read_sm2_sig_algid(&null).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn algid_rejects_wrong_oid_and_bad_params() {
        // ecdsa-with-SHA256 OID instead.
        let wrong = tlv(
            0x30,
            &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        assert!(read_sm2_sig_algid(&wrong).is_none());
        // params = empty SEQUENCE instead of NULL.
        let mut body = tlv(0x06, oid::SM2_SIGN_WITH_SM3);
        body.extend_from_slice(&[0x30, 0x00]);
        assert!(read_sm2_sig_algid(&tlv(0x30, &body)).is_none());
        // trailing garbage after NULL.
        let mut body = tlv(0x06, oid::SM2_SIGN_WITH_SM3);
        body.extend_from_slice(&[0x05, 0x00, 0x00]);
        assert!(read_sm2_sig_algid(&tlv(0x30, &body)).is_none());
    }

    // ---- check_extensions_shape ----

    fn extension(oid_content: &[u8], critical: Option<u8>, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(0x06, oid_content);
        if let Some(b) = critical {
            body.extend_from_slice(&tlv(TAG_BOOLEAN, &[b]));
        }
        body.extend_from_slice(&tlv(0x04, value));
        tlv(0x30, &body)
    }

    #[test]
    fn extensions_shape_ok() {
        let e1 = extension(&[0x55, 0x1d, 0x0f], Some(0xFF), &[0x03, 0x02, 0x01, 0x06]);
        let e2 = extension(&[0x55, 0x1d, 0x13], None, &[0x30, 0x00]);
        let mut both = e1;
        both.extend_from_slice(&e2);
        assert!(check_extensions_shape(&tlv(0x30, &both)).is_some());
    }

    #[test]
    fn extensions_shape_rejects() {
        // Empty Extensions SEQUENCE (SIZE(1..) violated).
        assert!(check_extensions_shape(&tlv(0x30, &[])).is_none());
        // Element that is not an Extension SEQUENCE.
        assert!(check_extensions_shape(&tlv(0x30, &tlv(0x04, &[0x00]))).is_none());
        // Extension with trailing garbage after extnValue.
        let mut bad = tlv(0x06, &[0x55, 0x1d, 0x0f]);
        bad.extend_from_slice(&tlv(0x04, &[0x00]));
        bad.push(0x00);
        assert!(check_extensions_shape(&tlv(0x30, &tlv(0x30, &bad))).is_none());
        // Trailing bytes after the Extensions SEQUENCE.
        let ok = extension(&[0x55, 0x1d, 0x0f], None, &[0x00]);
        let mut outer = tlv(0x30, &ok);
        outer.push(0x00);
        assert!(check_extensions_shape(&outer).is_none());
    }
}
