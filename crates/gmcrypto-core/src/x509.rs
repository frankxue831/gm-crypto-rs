//! X.509-with-SM2: leaf certificate parse + SM2-with-SM3 signature verify
//! (v1.3; GM/T 0015 profile over the RFC 5280 structure).
//!
//! **Parsing and single-certificate verify make NO trust decisions.**
//! [`Certificate::from_der`] tells you what a certificate *says*;
//! `verify_signature` tells you whether its SM2-with-SM3 signature over those
//! exact wire bytes verifies against a caller-supplied issuer public key — and
//! nothing more. At the parse / single-verify layer there is:
//!
//! - **no chain building** and no trust-anchor concept;
//! - **no time/validity decision** ([`X509Time`] values are exposed; this
//!   library has no clock — comparing them to "now" is the caller's call);
//! - **no extension interpretation at parse time** — `from_der` shape-checks
//!   extensions and exposes them raw; *interpretation* of `keyUsage` /
//!   `basicConstraints` happens only in [`verify_chain`] (below), never in
//!   `from_der`;
//! - **no hostname matching, no revocation (CRL/OCSP), no policy logic.**
//!
//! A `true` from `verify_signature` means exactly "this issuer key signed
//! these tbsCertificate bytes" — it does NOT mean the certificate is valid,
//! current, or trustworthy.
//!
//! **v1.8 adds a deliberately narrow chain check.** [`verify_chain`] walks a
//! caller-ordered linear chain to a caller-trusted anchor (per-edge SM2
//! signature + raw-Name linking + intermediate CA-ness + an optional
//! caller-supplied comparison time + a depth cap), and [`KeyUsage`] /
//! [`BasicConstraints`] expose the two interpreted extensions. This is a
//! *structural* trust check — "does this chain link to a CA you trust" — and
//! still **NOT** endpoint authentication (whether the cert pair is *the peer
//! you dialed* is the caller's, permanently), **NOT** a clock decision (the
//! caller passes the time), **NOT** revocation / policy / name-constraints /
//! EKU. The TLCP [sign, enc] pair profile lives in `tlcp::chain`.
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

/// One parsed `Extension` plus the unconsumed `rest` of the
/// SEQUENCE-OF-`Extension` body after it.
struct ParsedExt<'a> {
    oid: &'a [u8],
    critical: bool,
    value: &'a [u8],
    rest: &'a [u8],
}

/// Parse ONE `Extension` from the front of a SEQUENCE-OF-`Extension` body.
/// `None` on a malformed element. The framing — `SEQUENCE { extnID OID,
/// [critical BOOLEAN (one content byte)], extnValue OCTET STRING }`, exactly
/// consumed — is the single source of truth shared by
/// [`check_extensions_shape`], [`find_extension`], and
/// [`has_unknown_critical`].
fn next_extension(exts: &[u8]) -> Option<ParsedExt<'_>> {
    let (ext, rest) = reader::read_sequence(exts)?;
    let (oid, after_oid) = reader::read_oid(ext)?;
    let (critical, after_bool) = match reader::read_tlv(after_oid, TAG_BOOLEAN) {
        Some((b, rb)) => {
            if b.len() != 1 {
                return None;
            }
            (b[0] != 0, rb)
        }
        None => (false, after_oid),
    };
    let (value, after_value) = reader::read_octet_string(after_bool)?;
    if !after_value.is_empty() {
        return None;
    }
    Some(ParsedExt {
        oid,
        critical,
        value,
        rest,
    })
}

/// Shape-check the `[3]` extensions content ONE level deep, with ZERO
/// interpretation (design §5.9): `Extensions ::= SEQUENCE SIZE(1..) OF
/// Extension`. extnID values and `critical` flags are never evaluated.
fn check_extensions_shape(content: &[u8]) -> Option<()> {
    let (seq, rest) = reader::read_sequence(content)?;
    if !rest.is_empty() || seq.is_empty() {
        return None;
    }
    let mut exts = seq;
    while !exts.is_empty() {
        exts = next_extension(exts)?.rest;
    }
    Some(())
}

/// The X.509 `keyUsage` extension (RFC 5280 §4.2.1.3) as a bitfield.
///
/// A public `BIT STRING` read — **NOT** a trust decision. *Which* bits a
/// role requires is decided by [`verify_chain`] / `tlcp::chain::verify_pair`,
/// not by parsing. Bit 0 is the most-significant bit of the first content
/// byte (DER `BIT STRING` order); bits 0–8 are named below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage {
    bits: u16,
}

impl KeyUsage {
    /// Parse the DER `BIT STRING` (the `extnValue` content of a `keyUsage`
    /// extension). `None` on malformed input.
    fn parse(bit_string_tlv: &[u8]) -> Option<Self> {
        let (unused, value, rest) = reader::read_bit_string(bit_string_tlv)?;
        if !rest.is_empty() || unused > 7 {
            return None;
        }
        let mut bits = 0u16;
        for i in 0u16..9 {
            let (byte, off) = ((i / 8) as usize, 7 - (i % 8));
            if byte < value.len() && (value[byte] >> off) & 1 == 1 {
                bits |= 1 << i;
            }
        }
        Some(Self { bits })
    }
    const fn has(self, i: u16) -> bool {
        self.bits & (1 << i) != 0
    }
    /// `digitalSignature` (bit 0).
    #[must_use]
    pub const fn digital_signature(self) -> bool {
        self.has(0)
    }
    /// `nonRepudiation` / `contentCommitment` (bit 1).
    #[must_use]
    pub const fn content_commitment(self) -> bool {
        self.has(1)
    }
    /// `keyEncipherment` (bit 2).
    #[must_use]
    pub const fn key_encipherment(self) -> bool {
        self.has(2)
    }
    /// `dataEncipherment` (bit 3).
    #[must_use]
    pub const fn data_encipherment(self) -> bool {
        self.has(3)
    }
    /// `keyAgreement` (bit 4).
    #[must_use]
    pub const fn key_agreement(self) -> bool {
        self.has(4)
    }
    /// `keyCertSign` (bit 5).
    #[must_use]
    pub const fn key_cert_sign(self) -> bool {
        self.has(5)
    }
    /// `cRLSign` (bit 6).
    #[must_use]
    pub const fn crl_sign(self) -> bool {
        self.has(6)
    }
    /// `encipherOnly` (bit 7).
    #[must_use]
    pub const fn encipher_only(self) -> bool {
        self.has(7)
    }
    /// `decipherOnly` (bit 8).
    #[must_use]
    pub const fn decipher_only(self) -> bool {
        self.has(8)
    }
}

/// The X.509 `basicConstraints` extension (RFC 5280 §4.2.1.9): the CA flag
/// plus an optional path-length constraint.
///
/// `path_len` is **parsed but NOT enforced** by [`verify_chain`] — v1.8 uses
/// a fixed [`MAX_CHAIN_DEPTH`] cap instead (scope D-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    /// The `cA` boolean (DEFAULT `FALSE`).
    pub is_ca: bool,
    /// The `pathLenConstraint`, if present. Parsed, not enforced.
    pub path_len: Option<u32>,
}

impl BasicConstraints {
    /// Parse the DER `SEQUENCE { cA BOOLEAN DEFAULT FALSE,
    /// pathLenConstraint INTEGER OPTIONAL }` (the `extnValue` content of a
    /// `basicConstraints` extension). `None` on malformed input.
    fn parse(seq_tlv: &[u8]) -> Option<Self> {
        let (content, rest) = reader::read_sequence(seq_tlv)?;
        if !rest.is_empty() {
            return None;
        }
        let (is_ca, after) = match reader::read_tlv(content, TAG_BOOLEAN) {
            Some((b, r)) => {
                if b.len() != 1 {
                    return None;
                }
                (b[0] != 0, r)
            }
            None => (false, content),
        };
        let path_len = if after.is_empty() {
            None
        } else {
            let (int, r) = reader::read_integer(after)?;
            if !r.is_empty() || int.len() > 4 {
                return None;
            }
            let mut v = 0u32;
            for &byte in int {
                v = (v << 8) | u32::from(byte);
            }
            Some(v)
        };
        Some(Self { is_ca, path_len })
    }
}

/// Find the extension with `extn_id` in the `Extensions` SEQUENCE TLV,
/// returning its `extnValue` content. `None` if absent. The blob was
/// already shape-checked by [`Certificate::from_der`]; this re-walk is
/// defensive (returns `None` on any malformed element). Returns the FIRST
/// match (RFC 5280 forbids duplicate extensions; `from_der` does not dedup).
fn find_extension<'a>(ext_tlv: &'a [u8], extn_id: &[u8]) -> Option<&'a [u8]> {
    let (seq, _) = reader::read_sequence(ext_tlv)?;
    let mut exts = seq;
    while !exts.is_empty() {
        let ext = next_extension(exts)?;
        if ext.oid == extn_id {
            return Some(ext.value);
        }
        exts = ext.rest;
    }
    None
}

/// `true` iff any extension is `critical` AND its `extnID` is not in `known`
/// (RFC 5280 §4.2 — refuse a critical constraint we do not process; scope
/// Q8.7b). Fail-closed on malformed input is not needed (`from_der` already
/// shape-checked) but the walk is defensive.
fn has_unknown_critical(ext_tlv: &[u8], known: &[&[u8]]) -> bool {
    let Some((seq, _)) = reader::read_sequence(ext_tlv) else {
        return false;
    };
    let mut exts = seq;
    while !exts.is_empty() {
        let Some(ext) = next_extension(exts) else {
            return false;
        };
        if ext.critical && !known.contains(&ext.oid) {
            return true;
        }
        exts = ext.rest;
    }
    false
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

    /// The parsed `keyUsage` extension if present and well-formed, else
    /// `None` (absent or malformed are not distinguished — a public
    /// structural read, not a trust-reason channel). NOT a trust decision.
    #[must_use]
    pub fn key_usage(&self) -> Option<KeyUsage> {
        KeyUsage::parse(find_extension(self.extensions.as_deref()?, oid::KEY_USAGE)?)
    }

    /// The parsed `basicConstraints` extension if present and well-formed,
    /// else `None`. `path_len` is exposed but NOT enforced by
    /// [`verify_chain`] (scope D-4). NOT a trust decision.
    #[must_use]
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        BasicConstraints::parse(find_extension(
            self.extensions.as_deref()?,
            oid::BASIC_CONSTRAINTS,
        )?)
    }

    /// Whether the `subject` Name is empty (a `SEQUENCE` with no content).
    ///
    /// `pub(crate)` for `tlcp::chain`'s pair-binding check (gated on its sole
    /// consumer, the `tlcp` feature), so that layer need not re-parse
    /// certificate DER. The `subject` TLV was validated as a SEQUENCE at
    /// parse; a decode failure here counts as empty (fail-closed).
    #[cfg(feature = "tlcp")]
    pub(crate) fn subject_is_empty(&self) -> bool {
        reader::read_sequence(&self.subject).is_none_or(|(content, _)| content.is_empty())
    }
}

/// Maximum total certificates (leaf + intermediates) in a chain accepted by
/// [`verify_chain`].
///
/// A denial-of-service / over-restriction guard — **NOT** a
/// `pathLenConstraint` substitute (scope D-4).
pub const MAX_CHAIN_DEPTH: usize = 8;

/// The extensions this profile PROCESSES: a *critical* extension whose OID
/// is not here is refused by [`verify_chain`] (scope Q8.7b).
const KNOWN_EXTS: &[&[u8]] = &[oid::KEY_USAGE, oid::BASIC_CONSTRAINTS];

fn within_window(cert: &Certificate, at: Option<X509Time>) -> bool {
    at.is_none_or(|t| cert.not_before <= t && t <= cert.not_after)
}

/// An issuer (intermediate) must be a CA: `basicConstraints CA=TRUE` AND
/// `keyUsage` present with `keyCertSign` (stricter than gotlcp, which skips
/// `keyCertSign`; RFC 5280 §4.2.1.3).
fn is_ca_issuer(cert: &Certificate) -> bool {
    cert.basic_constraints().is_some_and(|bc| bc.is_ca)
        && cert.key_usage().is_some_and(KeyUsage::key_cert_sign)
}

/// Verify a single linear certificate chain links to a caller-trusted
/// anchor.
///
/// `chain` is leaf-first in issuing order (`chain[0]` = the leaf,
/// `chain[1..]` = intermediates). `anchors` are certificates the caller
/// **declares** trusted. `at_time` (`Some`) enforces the validity window on
/// every certificate, including the matched anchor.
///
/// Returns `true` iff: there are 1 to [`MAX_CHAIN_DEPTH`] certificates; no
/// certificate carries an unknown *critical* extension; every adjacent edge
/// links by raw issuer↔subject Name byte-equality AND its SM2 signature
/// verifies; every intermediate is a CA (`CA=TRUE` + `keyCertSign`); the
/// topmost issuer is a trusted anchor (Name match + signature — **every**
/// same-Name anchor is tried, so CA key-rollover resolves by which key
/// actually signed); and (if `Some`) every certificate is within its window.
///
/// **⚠ This is NOT certificate validation and NOT endpoint authentication.**
/// It does not check the *leaf's* role keyUsage (that is
/// `tlcp::chain::verify_pair`'s job), and the matched anchor is trusted by
/// fiat — checked ONLY by Name + signature + window, never keyUsage / CA /
/// leaf-role, even when it coincides with the leaf. A `true` says the chain
/// links to a trusted CA, never "this is the peer I dialed" (endpoint
/// identity binding is the caller's, permanently). See the module docs.
#[must_use]
pub fn verify_chain(
    chain: &[Certificate],
    anchors: &[Certificate],
    at_time: Option<X509Time>,
) -> bool {
    if chain.is_empty() || chain.len() > MAX_CHAIN_DEPTH {
        return false;
    }
    for cert in chain {
        if cert
            .extensions
            .as_deref()
            .is_some_and(|e| has_unknown_critical(e, KNOWN_EXTS))
        {
            return false;
        }
        if !within_window(cert, at_time) {
            return false;
        }
    }
    // Intermediate edges: chain[i] is issued by chain[i+1], which must be a CA.
    for i in 0..chain.len() - 1 {
        let (subj, iss) = (&chain[i], &chain[i + 1]);
        if subj.issuer_raw() != iss.subject_raw() {
            return false;
        }
        if !subj.verify_signature(&iss.subject_public_key()) {
            return false;
        }
        if !is_ca_issuer(iss) {
            return false;
        }
    }
    // Top edge: chain.last() must be issued by a trusted anchor. Name match is
    // necessary, NOT sufficient — try every same-Name anchor, the signature
    // (and window) decides.
    let top = &chain[chain.len() - 1];
    anchors.iter().any(|a| {
        a.subject_raw() == top.issuer_raw()
            && within_window(a, at_time)
            && top.verify_signature(&a.subject_public_key())
    })
}

/// Test-only certificate minting — shared by `x509`'s `verify_chain` tests
/// and `tlcp::chain`'s `verify_pair` tests. Builds DER parseable by
/// [`Certificate::from_der`] and signs the tbs with a real SM2 key.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::sm2::{DEFAULT_SIGNER_ID, Sm2PrivateKey, Sm2PublicKey, sign_with_id};
    use alloc::vec::Vec;
    use getrandom::SysRng;

    /// DER TLV with a definite (short- or long-form) length.
    #[allow(clippy::cast_possible_truncation)]
    pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![tag];
        let n = content.len();
        if n < 128 {
            out.push(n as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut v = n;
            while v > 0 {
                len_bytes.push((v & 0xff) as u8);
                v >>= 8;
            }
            len_bytes.reverse();
            out.push(0x80 | len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
        out.extend_from_slice(content);
        out
    }

    /// A structurally-valid `Name`: a SEQUENCE whose content is `label` (the
    /// x509 layer treats Names as opaque byte-equal TLVs).
    pub fn name(label: &[u8]) -> Vec<u8> {
        der(0x30, label)
    }

    /// A test SM2 key from a small nonzero scalar seed (always in `[1, n-1]`).
    pub fn key(seed: u8) -> Sm2PrivateKey {
        let mut b = [0u8; 32];
        b[31] = seed.max(1);
        Option::from(Sm2PrivateKey::from_bytes_be(&b)).expect("valid test scalar")
    }

    /// A `keyUsage` Extension TLV asserting `bits` (0-based MSB-first).
    pub fn ku_ext(bits: &[u8], critical: bool) -> Vec<u8> {
        let mut val = [0u8; 2];
        for &b in bits {
            val[(b / 8) as usize] |= 1 << (7 - (b % 8));
        }
        let nbytes = usize::from(bits.iter().any(|&b| b >= 8)) + 1;
        let mut bs = alloc::vec![0u8]; // unused = 0
        bs.extend_from_slice(&val[..nbytes]);
        extension(
            crate::asn1::oid::KEY_USAGE,
            critical,
            &der(0x04, &der(0x03, &bs)),
        )
    }

    /// A `basicConstraints` Extension TLV.
    #[allow(clippy::cast_possible_truncation)]
    pub fn bc_ext(is_ca: bool, path_len: Option<u32>, critical: bool) -> Vec<u8> {
        let mut seq = Vec::new();
        if is_ca {
            seq.extend_from_slice(&[0x01, 0x01, 0xFF]);
        }
        if let Some(p) = path_len {
            seq.extend_from_slice(&der(0x02, &[p as u8]));
        }
        extension(
            crate::asn1::oid::BASIC_CONSTRAINTS,
            critical,
            &der(0x04, &der(0x30, &seq)),
        )
    }

    /// An arbitrary Extension TLV by raw OID content + inner extnValue bytes.
    pub fn raw_ext(oid_bytes: &[u8], critical: bool, value_inner: &[u8]) -> Vec<u8> {
        extension(oid_bytes, critical, &der(0x04, value_inner))
    }

    fn extension(oid_bytes: &[u8], critical: bool, octet_string_tlv: &[u8]) -> Vec<u8> {
        let mut body = der(0x06, oid_bytes);
        if critical {
            body.extend_from_slice(&[0x01, 0x01, 0xFF]);
        }
        body.extend_from_slice(octet_string_tlv);
        der(0x30, &body)
    }

    /// Mint a cert DER signed by `issuer_key`, with the given validity dates
    /// (`YYMMDDHHMMSSZ`). `exts` is the concatenation of Extension TLVs (empty
    /// ⇒ no `[3]` field).
    pub fn mint(
        issuer_key: &Sm2PrivateKey,
        issuer_name: &[u8],
        subject_name: &[u8],
        subject_key: &Sm2PublicKey,
        exts: &[u8],
        not_before: &str,
        not_after: &str,
    ) -> Vec<u8> {
        let algid = der(0x30, &der(0x06, crate::asn1::oid::SM2_SIGN_WITH_SM3));
        let mut tbs_body = der(0xA0, &der(0x02, &[0x02])); // [0] EXPLICIT INTEGER 2
        tbs_body.extend_from_slice(&der(0x02, &[0x01])); // serial
        tbs_body.extend_from_slice(&algid);
        tbs_body.extend_from_slice(issuer_name);
        let validity = der(
            0x30,
            &[
                der(0x17, not_before.as_bytes()),
                der(0x17, not_after.as_bytes()),
            ]
            .concat(),
        );
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(subject_name);
        tbs_body.extend_from_slice(&crate::spki::encode(subject_key));
        if !exts.is_empty() {
            tbs_body.extend_from_slice(&der(0xA3, &der(0x30, exts)));
        }
        let tbs = der(0x30, &tbs_body);
        let sig = sign_with_id(issuer_key, DEFAULT_SIGNER_ID, &tbs, &mut SysRng).expect("sign tbs");
        let mut sig_bs = alloc::vec![0u8]; // unused bits = 0
        sig_bs.extend_from_slice(&sig);
        let mut cert = tbs;
        cert.extend_from_slice(&algid);
        cert.extend_from_slice(&der(0x03, &sig_bs));
        der(0x30, &cert)
    }

    /// Mint + parse, panicking on a malformed mint (surfaces minting bugs).
    pub fn cert(
        issuer_key: &Sm2PrivateKey,
        issuer_name: &[u8],
        subject_name: &[u8],
        subject_key: &Sm2PublicKey,
        exts: &[u8],
    ) -> super::Certificate {
        let der_bytes = mint(
            issuer_key,
            issuer_name,
            subject_name,
            subject_key,
            exts,
            "260101000000Z",
            "270101000000Z",
        );
        super::Certificate::from_der(&der_bytes).expect("minted cert parses")
    }
}

#[cfg(test)]
mod v1_8_tests {
    use super::test_support::*;
    use super::*;
    use alloc::vec::Vec;

    // ---- KeyUsage reader (private parse) ----

    #[test]
    fn keyusage_bit_order() {
        // 03 02 05 A0 : unused=5, value 0xA0 = 1010_0000 → bits 0 (MSB) + 2.
        let k = KeyUsage::parse(&[0x03, 0x02, 0x05, 0xA0]).unwrap();
        assert!(k.digital_signature() && k.key_encipherment());
        assert!(!k.content_commitment() && !k.key_agreement() && !k.key_cert_sign());
        // 03 03 07 80 80 : bit 0 + bit 8 (decipherOnly).
        let k2 = KeyUsage::parse(&[0x03, 0x03, 0x07, 0x80, 0x80]).unwrap();
        assert!(k2.digital_signature() && k2.decipher_only());
        // malformed: trailing garbage / unused>7.
        assert!(KeyUsage::parse(&[0x03, 0x02, 0x05, 0xA0, 0x00]).is_none());
        assert!(KeyUsage::parse(&[0x03, 0x02, 0x08, 0xA0]).is_none());
    }

    #[test]
    fn basicconstraints_reader() {
        let ca = BasicConstraints::parse(&[0x30, 0x03, 0x01, 0x01, 0xFF]).unwrap();
        assert!(ca.is_ca && ca.path_len.is_none());
        let ca_pl =
            BasicConstraints::parse(&[0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00]).unwrap();
        assert!(ca_pl.is_ca && ca_pl.path_len == Some(0));
        let empty = BasicConstraints::parse(&[0x30, 0x00]).unwrap();
        assert!(!empty.is_ca && empty.path_len.is_none());
        // trailing garbage.
        assert!(BasicConstraints::parse(&[0x30, 0x03, 0x01, 0x01, 0xFF, 0x00]).is_none());
    }

    #[test]
    fn extension_helpers() {
        let known: &[&[u8]] = &[oid::KEY_USAGE, oid::BASIC_CONSTRAINTS];
        let ku = ku_ext(&[0], true);
        let unknown_crit = raw_ext(&[0x55, 0x1d, 0x25], true, &[0x05, 0x00]); // 2.5.29.37 EKU, critical
        let unknown_noncrit = raw_ext(&[0x55, 0x1d, 0x25], false, &[0x05, 0x00]);
        let with_crit = der(0x30, &[ku.clone(), unknown_crit].concat());
        let with_noncrit = der(0x30, &[ku, unknown_noncrit].concat());
        assert!(find_extension(&with_crit, oid::KEY_USAGE).is_some());
        assert!(find_extension(&with_crit, oid::BASIC_CONSTRAINTS).is_none());
        assert!(has_unknown_critical(&with_crit, known));
        assert!(!has_unknown_critical(&with_noncrit, known));
    }

    // ---- verify_chain (minted certs) ----

    /// Build a (leaf, int, root) trio sharing the standard linkage.
    fn trio() -> (Certificate, Certificate, Certificate) {
        let (rk, ik, lk) = (key(1), key(2), key(3));
        let (rn, in_, ln) = (name(b"root"), name(b"int"), name(b"leaf"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int = cert(&rk, &rn, &in_, &ik.public_key(), &ca_exts);
        let leaf = cert(&ik, &in_, &ln, &lk.public_key(), &ku_ext(&[0], true));
        (leaf, int, root)
    }

    #[test]
    fn valid_chain_to_anchor() {
        let (leaf, int, root) = trio();
        assert!(verify_chain(&[leaf, int], &[root], None));
    }

    #[test]
    fn wrong_signing_key_rejected() {
        // Leaf claims issuer=int but is signed by root's key → edge sig fails.
        let (rk, ik, lk) = (key(1), key(2), key(3));
        let (rn, in_, ln) = (name(b"root"), name(b"int"), name(b"leaf"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int = cert(&rk, &rn, &in_, &ik.public_key(), &ca_exts);
        let bad_leaf = cert(&rk, &in_, &ln, &lk.public_key(), &ku_ext(&[0], true));
        assert!(!verify_chain(&[bad_leaf, int], &[root], None));
    }

    #[test]
    fn non_ca_intermediate_rejected() {
        let (rk, ik, lk) = (key(1), key(2), key(3));
        let (rn, in_, ln) = (name(b"root"), name(b"int"), name(b"leaf"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        // int lacks CA=TRUE.
        let int = cert(&rk, &rn, &in_, &ik.public_key(), &ku_ext(&[5], true));
        let leaf = cert(&ik, &in_, &ln, &lk.public_key(), &ku_ext(&[0], true));
        assert!(!verify_chain(&[leaf, int], &[root], None));
    }

    #[test]
    fn broken_name_link_rejected() {
        let (rk, ik, lk) = (key(1), key(2), key(3));
        let (rn, in_, ln) = (name(b"root"), name(b"int"), name(b"leaf"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int = cert(&rk, &rn, &in_, &ik.public_key(), &ca_exts);
        // leaf's issuer says "other", not "int".
        let leaf = cert(
            &ik,
            &name(b"other"),
            &ln,
            &lk.public_key(),
            &ku_ext(&[0], true),
        );
        assert!(!verify_chain(&[leaf, int], &[root], None));
    }

    #[test]
    fn over_max_depth_rejected() {
        // Length check fires first, so the certs need not link — mint fresh
        // self-issued certs past the cap. anchors empty (never reached).
        let chain: Vec<Certificate> = (0..=MAX_CHAIN_DEPTH)
            .map(|i| {
                let k = key(u8::try_from(i + 1).unwrap());
                let n = name(b"x");
                cert(&k, &n, &n, &k.public_key(), &ku_ext(&[0], true))
            })
            .collect();
        assert!(chain.len() > MAX_CHAIN_DEPTH);
        assert!(!verify_chain(&chain, &[], None));
    }

    #[test]
    fn time_window_enforced() {
        let (leaf, int, root) = trio();
        let nb = leaf.not_before();
        let after = X509Time {
            year: leaf.not_after().year + 1,
            ..leaf.not_after()
        };
        let chain = [leaf, int];
        let anchors = [root];
        assert!(verify_chain(&chain, &anchors, Some(nb)));
        assert!(!verify_chain(&chain, &anchors, Some(after)));
    }

    #[test]
    fn try_all_anchors_second_valid() {
        let (rk, ik, lk) = (key(1), key(2), key(3));
        let decoy = key(9);
        let (rn, in_, ln) = (name(b"root"), name(b"int"), name(b"leaf"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let real_root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let decoy_root = cert(&decoy, &rn, &rn, &decoy.public_key(), &ca_exts); // same Name, wrong key
        let int = cert(&rk, &rn, &in_, &ik.public_key(), &ca_exts);
        let leaf = cert(&ik, &in_, &ln, &lk.public_key(), &ku_ext(&[0], true));
        let chain = [leaf, int];
        // decoy first, real second → any() must still find the right key.
        assert!(verify_chain(&chain, &[decoy_root, real_root], None));
        let decoy_only = cert(&decoy, &rn, &rn, &decoy.public_key(), &ca_exts);
        assert!(!verify_chain(&chain, &[decoy_only], None));
    }

    #[test]
    fn unknown_critical_extension_rejected() {
        let (rk, ik, lk) = (key(1), key(2), key(3));
        let (rn, in_, ln) = (name(b"root"), name(b"int"), name(b"leaf"));
        let ca_exts = [ku_ext(&[5], true), bc_ext(true, None, true)].concat();
        let root = cert(&rk, &rn, &rn, &rk.public_key(), &ca_exts);
        let int = cert(&rk, &rn, &in_, &ik.public_key(), &ca_exts);
        let anchors = [root];
        // 2.5.29.37 (EKU) marked CRITICAL → refused.
        let crit = [
            ku_ext(&[0], true),
            raw_ext(&[0x55, 0x1d, 0x25], true, &[0x05, 0x00]),
        ]
        .concat();
        let leaf_crit = cert(&ik, &in_, &ln, &lk.public_key(), &crit);
        let int2 = cert(&rk, &rn, &in_, &ik.public_key(), &ca_exts);
        assert!(!verify_chain(&[leaf_crit, int2], &anchors, None));
        // same OID NON-critical → ignored.
        let noncrit = [
            ku_ext(&[0], true),
            raw_ext(&[0x55, 0x1d, 0x25], false, &[0x05, 0x00]),
        ]
        .concat();
        let leaf_ok = cert(&ik, &in_, &ln, &lk.public_key(), &noncrit);
        assert!(verify_chain(&[leaf_ok, int], &anchors, None));
    }

    #[test]
    fn self_signed_leaf_as_own_anchor() {
        // S2 confirmation: an anchor coinciding with the leaf is Name+sig only.
        let sk = key(7);
        let sn = name(b"self");
        let leaf = cert(&sk, &sn, &sn, &sk.public_key(), &ku_ext(&[0], true));
        let anchor = cert(&sk, &sn, &sn, &sk.public_key(), &ku_ext(&[0], true));
        assert!(verify_chain(&[leaf], &[anchor], None));
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
