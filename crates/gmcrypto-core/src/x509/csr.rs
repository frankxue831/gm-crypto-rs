//! PKCS#10 Certificate Signing Requests (RFC 2986 / GM/T 0015) for SM2 keys.
//!
//! Supports both **construction + SM2-with-SM3 signing** ([`CsrBuilder`],
//! [`SubjectName`]) and **strict-DER parsing + self-signature verification**
//! ([`CertificationRequest`]), with RFC 7468 PEM helpers (`"CERTIFICATE REQUEST"`).
//!
//! # Profile
//!
//! - `version` is strictly `0` (`v1`).
//! - `subjectPKInfo` uses [`crate::spki`] (`id-ecPublicKey` + `sm2p256v1` +
//!   validated 65-byte uncompressed SEC1 point).
//! - `attributes` (`[0] IMPLICIT Attributes`) is structurally validated on parse;
//!   an optional RFC 2985 `extensionRequest` (`1.2.840.113549.1.9.14`) may carry
//!   requested X.509 extensions (such as `keyUsage` and `subjectAltName`).
//! - `signatureAlgorithm` is `sm2-sign-with-sm3` (`1.2.156.10197.1.501`),
//!   accepting absent or `NULL` parameters on parse and emitting absent
//!   parameters on build (matching GM/T 0015 and `GmSSL` 3.2.0).
//! - `signature` is a DER `BIT STRING` (`unused_bits == 0`) wrapping the DER
//!   `SEQUENCE { r, s }` SM2 signature over the exact wire
//!   `certificationRequestInfo` bytes.
//!
//! # Separation of parsing and verification
//!
//! Mirroring [`super::Certificate`], [`CertificationRequest::from_der`] and
//! [`CertificationRequest::from_pem`] perform structural and public-key
//! validation only; call [`CertificationRequest::verify_signature`] (default
//! SM2 signer ID `"1234567812345678"`) or
//! [`CertificationRequest::verify_signature_with_id`] to verify proof of
//! possession.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "x509")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use core::net::{IpAddr, Ipv4Addr};
//! use getrandom::SysRng;
//! use gmcrypto_core::sm2::Sm2PrivateKey;
//! use gmcrypto_core::x509::KeyUsage;
//! use gmcrypto_core::x509::csr::{CertificationRequest, CsrBuilder, SubjectName};
//!
//! let mut rng = SysRng;
//! let key = Sm2PrivateKey::generate(&mut rng)?;
//!
//! let subject = SubjectName::new()
//!     .country("CN")
//!     .organization("Example Org")
//!     .common_name("tls.example.com");
//!
//! let csr = CsrBuilder::new(subject)
//!     .key_usage(KeyUsage::DIGITAL_SIGNATURE.union(KeyUsage::KEY_ENCIPHERMENT), true)
//!     .san_dns("tls.example.com")
//!     .san_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
//!     .sign(&key, &mut rng)?;
//!
//! let pem = csr.to_pem();
//! let parsed = CertificationRequest::from_pem(&pem).ok_or("parse failed")?;
//! assert!(parsed.verify_signature());
//! assert_eq!(parsed.key_usage().map(KeyUsage::digital_signature), Some(true));
//! # Ok(()) }
//! # #[cfg(not(feature = "x509"))]
//! # fn main() {}
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use rand_core::TryCryptoRng;

use crate::asn1::oid;
use crate::asn1::reader::{self, MAX_DER_LEN};
use crate::asn1::writer;
use crate::pem;
use crate::sm2::{DEFAULT_SIGNER_ID, Sm2PrivateKey, Sm2PublicKey, sign_with_id, verify_with_id};
use crate::spki;

use super::{KeyUsage, check_extensions_shape, find_extension, read_sm2_sig_algid};

/// Conservative ceiling for CSR builder DER payloads so `writer::write_length`
/// (which panics at `>= 16 MiB`) is never reached on caller input.
const MAX_CSR_DER_LEN: usize = MAX_DER_LEN / 2;

/// Maximum single DNS SAN label/name byte length.
const MAX_SAN_DNS_LEN: usize = 65_535;

/// RFC 2986 `version = v1(0)`.
const CSR_VERSION_V1: u8 = 0;

/// RFC 7468 PEM label for PKCS#10 Certificate Signing Requests.
pub const PEM_LABEL: &str = "CERTIFICATE REQUEST";

/// Structured builder for an X.500 Subject Distinguished Name (`Name`).
///
/// Emits single-AVA `RelativeDistinguishedName` entries in standard order
/// (`C`, `ST`, `L`, `O`, `OU`, `CN`). `C` (`countryName`) is encoded as a
/// 2-letter ASCII `PrintableString` per RFC 5280 Appendix A.1; all other
/// attributes are encoded as `UTF8String`.
///
/// Leaving all fields unset encodes an empty `Name` (`30 00`), which is valid
/// under RFC 5280 when identity is carried solely in `subjectAltName`. Setting
/// any field to an empty string or setting `country` to anything other than 2
/// ASCII letters fails with [`crate::Error::Failed`] in [`SubjectName::to_der`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectName {
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    common_name: Option<String>,
}

impl SubjectName {
    /// Create an empty [`SubjectName`] builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            common_name: None,
        }
    }

    /// Set `countryName` (`C`, OID `2.5.4.6`). Must be 2 ASCII letters (e.g. `"CN"`).
    #[must_use]
    pub fn country(mut self, value: impl Into<String>) -> Self {
        self.country = Some(value.into());
        self
    }

    /// Set `stateOrProvinceName` (`ST`, OID `2.5.4.8`).
    #[must_use]
    pub fn state(mut self, value: impl Into<String>) -> Self {
        self.state = Some(value.into());
        self
    }

    /// Set `localityName` (`L`, OID `2.5.4.7`).
    #[must_use]
    pub fn locality(mut self, value: impl Into<String>) -> Self {
        self.locality = Some(value.into());
        self
    }

    /// Set `organizationName` (`O`, OID `2.5.4.10`).
    #[must_use]
    pub fn organization(mut self, value: impl Into<String>) -> Self {
        self.organization = Some(value.into());
        self
    }

    /// Set `organizationalUnitName` (`OU`, OID `2.5.4.11`).
    #[must_use]
    pub fn organizational_unit(mut self, value: impl Into<String>) -> Self {
        self.organizational_unit = Some(value.into());
        self
    }

    /// Set `commonName` (`CN`, OID `2.5.4.3`).
    #[must_use]
    pub fn common_name(mut self, value: impl Into<String>) -> Self {
        self.common_name = Some(value.into());
        self
    }

    /// Encode this subject name as a canonical DER `Name` (`SEQUENCE OF RDN`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Failed`] if any configured attribute value is
    /// empty, if `country` is not 2 ASCII letters, or if the encoded `Name`
    /// exceeds the DER length ceiling.
    pub fn to_der(&self) -> Result<Vec<u8>, crate::Error> {
        let mut rdns = Vec::new();

        if let Some(c) = &self.country {
            if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_alphabetic()) {
                return Err(crate::Error::Failed);
            }
            push_rdn_printable(&mut rdns, oid::COUNTRY_NAME, c);
        }

        let utf8_fields: [(&[u8], Option<&str>); 5] = [
            (oid::STATE_OR_PROVINCE_NAME, self.state.as_deref()),
            (oid::LOCALITY_NAME, self.locality.as_deref()),
            (oid::ORGANIZATION_NAME, self.organization.as_deref()),
            (
                oid::ORGANIZATIONAL_UNIT_NAME,
                self.organizational_unit.as_deref(),
            ),
            (oid::COMMON_NAME, self.common_name.as_deref()),
        ];

        for (attr_oid, val) in utf8_fields {
            if let Some(s) = val {
                if s.is_empty() || s.len() > MAX_CSR_DER_LEN {
                    return Err(crate::Error::Failed);
                }
                push_rdn_utf8(&mut rdns, attr_oid, s);
                if rdns.len() > MAX_CSR_DER_LEN {
                    return Err(crate::Error::Failed);
                }
            }
        }

        let mut out = Vec::with_capacity(rdns.len() + 4);
        writer::write_sequence(&mut out, &rdns);
        Ok(out)
    }
}

fn push_rdn_printable(out: &mut Vec<u8>, attr_oid: &[u8], value: &str) {
    let mut ava_body = Vec::with_capacity(attr_oid.len() + value.len() + 8);
    writer::write_oid(&mut ava_body, attr_oid);
    writer::write_printable_string(&mut ava_body, value);
    let mut ava = Vec::with_capacity(ava_body.len() + 4);
    writer::write_sequence(&mut ava, &ava_body);
    writer::write_set(out, &ava);
}

fn push_rdn_utf8(out: &mut Vec<u8>, attr_oid: &[u8], value: &str) {
    let mut ava_body = Vec::with_capacity(attr_oid.len() + value.len() + 8);
    writer::write_oid(&mut ava_body, attr_oid);
    writer::write_utf8_string(&mut ava_body, value);
    let mut ava = Vec::with_capacity(ava_body.len() + 4);
    writer::write_sequence(&mut ava, &ava_body);
    writer::write_set(out, &ava);
}

#[derive(Clone, Debug)]
enum SubjectSource {
    Structured(SubjectName),
    RawDer(Vec<u8>),
}

/// Builder for a PKCS#10 SM2 Certificate Signing Request ([`CertificationRequest`]).
///
/// Construct with [`CsrBuilder::new`] (using [`SubjectName`]) or
/// [`CsrBuilder::from_subject_raw`] (caller-encoded DER `Name` `SEQUENCE` TLV),
/// optionally attach requested X.509 extensions (`keyUsage`, `subjectAltName`),
/// and sign with [`CsrBuilder::sign`] or [`CsrBuilder::sign_with_id`].
#[derive(Clone, Debug)]
pub struct CsrBuilder {
    subject: SubjectSource,
    key_usage: Option<(KeyUsage, bool)>,
    san_dns: Vec<String>,
    san_ips: Vec<IpAddr>,
}

impl CsrBuilder {
    /// Create a CSR builder with a structured [`SubjectName`].
    #[must_use]
    pub const fn new(subject: SubjectName) -> Self {
        Self {
            subject: SubjectSource::Structured(subject),
            key_usage: None,
            san_dns: Vec::new(),
            san_ips: Vec::new(),
        }
    }

    /// Create a CSR builder with a caller-encoded DER `Name` (`SEQUENCE` TLV).
    ///
    /// The slice is validated structurally as a single DER `SEQUENCE` with no
    /// trailing bytes during [`CsrBuilder::sign`] / [`CsrBuilder::sign_with_id`].
    #[must_use]
    pub fn from_subject_raw(subject_der: &[u8]) -> Self {
        Self {
            subject: SubjectSource::RawDer(subject_der.to_vec()),
            key_usage: None,
            san_dns: Vec::new(),
            san_ips: Vec::new(),
        }
    }

    /// Request an X.509 `keyUsage` extension (`2.5.29.15`) inside the CSR's
    /// `extensionRequest` attribute.
    ///
    /// Replaces any previously configured `key_usage` on this builder. Per
    /// RFC 5280 §4.2.1.3, `usage` must have at least one bit set (an empty
    /// [`KeyUsage::empty`] fails at sign time).
    #[must_use]
    pub const fn key_usage(mut self, usage: KeyUsage, critical: bool) -> Self {
        self.key_usage = Some((usage, critical));
        self
    }

    /// Append a DNS name (`dNSName`, `[2] IMPLICIT IA5String`) to the CSR's
    /// requested `subjectAltName` extension (`2.5.29.17`).
    ///
    /// Must be non-empty printable ASCII (`0x20..=0x7E`); invalid names fail at
    /// sign time.
    #[must_use]
    pub fn san_dns(mut self, dns_name: impl Into<String>) -> Self {
        self.san_dns.push(dns_name.into());
        self
    }

    /// Append an IPv4 or IPv6 address (`iPAddress`, `[7] IMPLICIT OCTET STRING`)
    /// to the CSR's requested `subjectAltName` extension (`2.5.29.17`).
    #[must_use]
    pub fn san_ip(mut self, ip: IpAddr) -> Self {
        self.san_ips.push(ip);
        self
    }

    /// Build and sign the CSR under `key` using [`DEFAULT_SIGNER_ID`]
    /// (`"1234567812345678"`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Failed`] on invalid subject/extension inputs,
    /// RNG failure, or SM2 signing retry exhaustion.
    pub fn sign<R: TryCryptoRng>(
        &self,
        key: &Sm2PrivateKey,
        rng: &mut R,
    ) -> Result<CertificationRequest, crate::Error> {
        self.sign_with_id(key, DEFAULT_SIGNER_ID, rng)
    }

    /// Build and sign the CSR under `key` using an explicit SM2 signer `id`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Failed`] on invalid subject/extension inputs,
    /// over-length signer ID (`> MAX_ID_LEN`), RNG failure, or SM2 signing
    /// retry exhaustion.
    pub fn sign_with_id<R: TryCryptoRng>(
        &self,
        key: &Sm2PrivateKey,
        id: &[u8],
        rng: &mut R,
    ) -> Result<CertificationRequest, crate::Error> {
        let subject_der = match &self.subject {
            SubjectSource::Structured(name) => name.to_der()?,
            SubjectSource::RawDer(raw) => {
                if raw.len() > MAX_CSR_DER_LEN {
                    return Err(crate::Error::Failed);
                }
                let (_, rest) = reader::read_sequence(raw).ok_or(crate::Error::Failed)?;
                if !rest.is_empty() {
                    return Err(crate::Error::Failed);
                }
                raw.clone()
            }
        };

        let public_key = key.public_key();
        let spki_der = spki::encode(&public_key);

        let (attributes_content, extension_request) = self.encode_attributes()?;

        // CertificationRequestInfo ::= SEQUENCE {
        //   version INTEGER (0),
        //   subject Name,
        //   subjectPKInfo SubjectPublicKeyInfo,
        //   attributes [0] IMPLICIT Attributes
        // }
        let mut cri_body = Vec::with_capacity(
            3 + subject_der.len() + spki_der.len() + attributes_content.len() + 8,
        );
        writer::write_integer(&mut cri_body, &[CSR_VERSION_V1]);
        cri_body.extend_from_slice(&subject_der);
        cri_body.extend_from_slice(&spki_der);
        writer::write_context_tagged_explicit(&mut cri_body, 0, &attributes_content);
        if cri_body.len() > MAX_CSR_DER_LEN {
            return Err(crate::Error::Failed);
        }

        let mut cri_der = Vec::with_capacity(cri_body.len() + 4);
        writer::write_sequence(&mut cri_der, &cri_body);

        // Sign exact CertificationRequestInfo wire bytes.
        let sig_der = sign_with_id(key, id, &cri_der, rng)?;

        // signatureAlgorithm SEQUENCE { OID sm2-sign-with-sm3 } (parameters absent).
        let mut sig_alg_body = Vec::with_capacity(oid::SM2_SIGN_WITH_SM3.len() + 2);
        writer::write_oid(&mut sig_alg_body, oid::SM2_SIGN_WITH_SM3);
        let mut sig_alg = Vec::with_capacity(sig_alg_body.len() + 2);
        writer::write_sequence(&mut sig_alg, &sig_alg_body);

        // Outer CertificationRequest SEQUENCE.
        let mut csr_body = Vec::with_capacity(cri_der.len() + sig_alg.len() + sig_der.len() + 8);
        csr_body.extend_from_slice(&cri_der);
        csr_body.extend_from_slice(&sig_alg);
        writer::write_bit_string(&mut csr_body, 0, &sig_der);

        let mut csr_der = Vec::with_capacity(csr_body.len() + 4);
        writer::write_sequence(&mut csr_der, &csr_body);

        Ok(CertificationRequest {
            der: csr_der,
            cri: cri_der,
            subject: subject_der,
            subject_key: public_key,
            attributes: attributes_content,
            extension_request,
            sig: sig_der,
        })
    }

    fn encode_attributes(&self) -> Result<(Vec<u8>, Option<Vec<u8>>), crate::Error> {
        let mut exts_body = Vec::new();

        if let Some((ku, critical)) = self.key_usage {
            let ku_der = ku.encode_der().ok_or(crate::Error::Failed)?;
            write_extension(&mut exts_body, oid::KEY_USAGE, critical, &ku_der);
        }

        if !self.san_dns.is_empty() || !self.san_ips.is_empty() {
            let mut san_body = Vec::new();
            for dns in &self.san_dns {
                if dns.is_empty()
                    || dns.len() > MAX_SAN_DNS_LEN
                    || !dns.bytes().all(|b| (0x20..=0x7E).contains(&b))
                {
                    return Err(crate::Error::Failed);
                }
                writer::write_context_tagged_implicit(&mut san_body, 2, dns.as_bytes());
                if san_body.len() > MAX_CSR_DER_LEN {
                    return Err(crate::Error::Failed);
                }
            }
            for &ip in &self.san_ips {
                match ip {
                    IpAddr::V4(v4) => {
                        writer::write_context_tagged_implicit(&mut san_body, 7, &v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        writer::write_context_tagged_implicit(&mut san_body, 7, &v6.octets());
                    }
                }
                if san_body.len() > MAX_CSR_DER_LEN {
                    return Err(crate::Error::Failed);
                }
            }
            let mut san_seq = Vec::with_capacity(san_body.len() + 4);
            writer::write_sequence(&mut san_seq, &san_body);
            write_extension(&mut exts_body, oid::SUBJECT_ALT_NAME, false, &san_seq);
        }

        if exts_body.is_empty() {
            return Ok((Vec::new(), None));
        }
        if exts_body.len() > MAX_CSR_DER_LEN {
            return Err(crate::Error::Failed);
        }

        let mut exts_seq = Vec::with_capacity(exts_body.len() + 4);
        writer::write_sequence(&mut exts_seq, &exts_body);

        // Attribute ::= SEQUENCE { OID extensionRequest, SET { Extensions } }
        let mut attr_body = Vec::with_capacity(oid::EXTENSION_REQUEST.len() + exts_seq.len() + 8);
        writer::write_oid(&mut attr_body, oid::EXTENSION_REQUEST);
        writer::write_set(&mut attr_body, &exts_seq);

        let mut attrs_content = Vec::with_capacity(attr_body.len() + 4);
        writer::write_sequence(&mut attrs_content, &attr_body);

        Ok((attrs_content, Some(exts_seq)))
    }
}

fn write_extension(out: &mut Vec<u8>, extn_id: &[u8], critical: bool, extn_value: &[u8]) {
    let mut body = Vec::with_capacity(extn_id.len() + extn_value.len() + 12);
    writer::write_oid(&mut body, extn_id);
    if critical {
        writer::write_boolean(&mut body, true);
    }
    writer::write_octet_string(&mut body, extn_value);
    writer::write_sequence(out, &body);
}

/// A parsed or freshly signed PKCS#10 SM2 Certificate Signing Request (RFC 2986).
///
/// Parsing ([`Self::from_der`] / [`Self::from_pem`]) validates ASN.1 structure
/// and the embedded SM2 `SubjectPublicKeyInfo`, but does **not** verify the
/// self-signature. Call [`Self::verify_signature`] or
/// [`Self::verify_signature_with_id`] to check proof of possession.
#[derive(Clone, Debug)]
pub struct CertificationRequest {
    der: Vec<u8>,
    cri: Vec<u8>,
    subject: Vec<u8>,
    subject_key: Sm2PublicKey,
    attributes: Vec<u8>,
    extension_request: Option<Vec<u8>>,
    sig: Vec<u8>,
}

impl CertificationRequest {
    /// Strict-DER parse of an RFC 2986 SM2 PKCS#10 CSR.
    ///
    /// Returns `None` for any malformed or out-of-profile input (single opaque
    /// failure shape per the failure-mode invariant). Does **not** verify the
    /// self-signature; call [`Self::verify_signature`] or
    /// [`Self::verify_signature_with_id`] afterwards.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let (csr, rest) = reader::read_sequence(der)?;
        if !rest.is_empty() {
            return None;
        }

        // certificationRequestInfo — preserve exact wire span for verification.
        let (cri_body, after_cri) = reader::read_sequence(csr)?;
        let cri_span = &csr[..csr.len() - after_cri.len()];

        // version INTEGER { v1(0) }
        let (version, cur) = reader::read_integer(cri_body)?;
        if version != [CSR_VERSION_V1] {
            return None;
        }

        // subject Name (raw SEQUENCE TLV span)
        let (_, after_subject) = reader::read_sequence(cur)?;
        let subject_span = &cur[..cur.len() - after_subject.len()];
        let cur = after_subject;

        // subjectPKInfo (validated via spki::decode)
        let (_, after_spki) = reader::read_sequence(cur)?;
        let spki_span = &cur[..cur.len() - after_spki.len()];
        let subject_key = spki::decode(spki_span)?;
        let cur = after_spki;

        // attributes [0] IMPLICIT Attributes (tag 0xA0)
        let (attrs_content, cur) = reader::read_context_tagged_explicit(cur, 0)?;
        if !cur.is_empty() {
            return None;
        }
        let parsed_attrs = parse_attributes(attrs_content)?;

        // signatureAlgorithm: sm2-sign-with-sm3 (parameters absent or NULL)
        let (_, after_alg) = read_sm2_sig_algid(after_cri)?;

        // signature BIT STRING (unused_bits == 0, non-empty payload, no trailing bytes)
        let (unused, sig, after_sig) = reader::read_bit_string(after_alg)?;
        if unused != 0 || sig.is_empty() || !after_sig.is_empty() {
            return None;
        }

        Some(Self {
            der: der.to_vec(),
            cri: cri_span.to_vec(),
            subject: subject_span.to_vec(),
            subject_key,
            attributes: attrs_content.to_vec(),
            extension_request: parsed_attrs.extension_request.map(<[u8]>::to_vec),
            sig: sig.to_vec(),
        })
    }

    /// Decode a PEM-armored PKCS#10 CSR (`-----BEGIN CERTIFICATE REQUEST-----`).
    ///
    /// Returns `None` on invalid PEM, wrong label, or malformed/out-of-profile
    /// DER. Does **not** verify the self-signature.
    #[must_use]
    pub fn from_pem(pem_str: &str) -> Option<Self> {
        let der = pem::decode(pem_str, PEM_LABEL).ok()?;
        Self::from_der(&der)
    }

    /// Exact DER bytes of this CSR.
    #[must_use]
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Encode this CSR as PEM with the RFC 7468 `"CERTIFICATE REQUEST"` label.
    #[must_use]
    pub fn to_pem(&self) -> String {
        pem::encode(PEM_LABEL, &self.der)
    }

    /// Verify the CSR's SM2-with-SM3 self-signature over [`Self::cri_raw`]
    /// against [`Self::subject_public_key`], using [`DEFAULT_SIGNER_ID`]
    /// (`"1234567812345678"`).
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with_id(DEFAULT_SIGNER_ID)
    }

    /// Verify the CSR's SM2-with-SM3 self-signature using a caller-supplied
    /// SM2 signer ID.
    #[must_use]
    pub fn verify_signature_with_id(&self, id: &[u8]) -> bool {
        verify_with_id(&self.subject_key, id, &self.cri, &self.sig)
    }

    /// The subject's validated SM2 public key.
    #[must_use]
    pub const fn subject_public_key(&self) -> Sm2PublicKey {
        self.subject_key
    }

    /// The exact wire `CertificationRequestInfo` SEQUENCE TLV bytes (the
    /// bytes covered by the signature).
    #[must_use]
    pub fn cri_raw(&self) -> &[u8] {
        &self.cri
    }

    /// The subject `Name` as its full raw DER `SEQUENCE` TLV, matching
    /// [`super::Certificate::subject_raw`].
    #[must_use]
    pub fn subject_raw(&self) -> &[u8] {
        &self.subject
    }

    /// Raw content bytes inside the `[0] IMPLICIT Attributes` container
    /// (empty slice when the CSR carries no attributes).
    #[must_use]
    pub fn attributes_raw(&self) -> &[u8] {
        &self.attributes
    }

    /// The requested X.509 `Extensions` SEQUENCE TLV extracted from an RFC 2985
    /// `extensionRequest` attribute (`1.2.840.113549.1.9.14`), if present.
    #[must_use]
    pub fn extension_request_raw(&self) -> Option<&[u8]> {
        self.extension_request.as_deref()
    }

    /// Raw DER signature bytes (`SEQUENCE { r, s }`) carried inside the outer
    /// `signature` `BIT STRING`.
    #[must_use]
    pub fn signature_raw(&self) -> &[u8] {
        &self.sig
    }

    /// Parsed `keyUsage` extension from `extensionRequest`, if present and
    /// well-formed.
    #[must_use]
    pub fn key_usage(&self) -> Option<KeyUsage> {
        KeyUsage::parse(find_extension(
            self.extension_request.as_deref()?,
            oid::KEY_USAGE,
        )?)
    }
}

struct ParsedAttributes<'a> {
    extension_request: Option<&'a [u8]>,
}

/// Structurally validate the body of `[0] IMPLICIT Attributes` (`0+ Attribute
/// SEQUENCEs`) and return the single RFC 2985 `extensionRequest` `Extensions`
/// SEQUENCE TLV if present. Rejects duplicate `extensionRequest` attributes or
/// any malformed inner TLV framing.
fn parse_attributes(mut cur: &[u8]) -> Option<ParsedAttributes<'_>> {
    let mut ext_req: Option<&[u8]> = None;
    while !cur.is_empty() {
        let (attr_body, next) = reader::read_sequence(cur)?;
        let (attr_oid, after_oid) = reader::read_oid(attr_body)?;
        let (values_body, after_set) = reader::read_set(after_oid)?;
        if !after_set.is_empty() {
            return None;
        }
        if attr_oid == oid::EXTENSION_REQUEST {
            if ext_req.is_some() {
                return None;
            }
            check_extensions_shape(values_body)?;
            ext_req = Some(values_body);
        } else {
            let mut vals = values_body;
            while !vals.is_empty() {
                let (_, vnext) = reader::read_any_tlv(vals)?;
                vals = vnext;
            }
        }
        cur = next;
    }
    Some(ParsedAttributes {
        extension_request: ext_req,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use getrandom::SysRng;
    use subtle::ConstantTimeEq;

    #[test]
    fn round_trip_basic_der_and_pem() {
        let mut rng = SysRng;
        let key = Sm2PrivateKey::generate(&mut rng).expect("keygen");

        let subject = SubjectName::new()
            .country("CN")
            .state("Beijing")
            .locality("Haidian")
            .organization("Acme Corp")
            .organizational_unit("Crypto")
            .common_name("api.example.com");

        let csr = CsrBuilder::new(subject)
            .sign(&key, &mut rng)
            .expect("sign csr");

        assert!(csr.verify_signature());
        assert!(!csr.verify_signature_with_id(b"custom-id"));
        assert!(csr.attributes_raw().is_empty());
        assert!(csr.extension_request_raw().is_none());
        assert!(csr.key_usage().is_none());

        let parsed = CertificationRequest::from_der(csr.to_der()).expect("from_der");
        assert!(parsed.verify_signature());
        assert_eq!(parsed.to_der(), csr.to_der());
        assert_eq!(parsed.subject_raw(), csr.subject_raw());
        assert_eq!(parsed.cri_raw(), csr.cri_raw());
        assert_eq!(parsed.signature_raw(), csr.signature_raw());
        assert!(bool::from(
            parsed.subject_public_key().ct_eq(&key.public_key())
        ));

        let pem = csr.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let from_pem = CertificationRequest::from_pem(&pem).expect("from_pem");
        assert_eq!(from_pem.to_der(), csr.to_der());
        assert!(from_pem.verify_signature());
    }

    #[test]
    fn round_trip_custom_signer_id_and_extensions() {
        let mut rng = SysRng;
        let key = Sm2PrivateKey::generate(&mut rng).expect("keygen");
        let custom_id = b"custom-sm2-signer-id";

        let ku = KeyUsage::DIGITAL_SIGNATURE
            .union(KeyUsage::KEY_ENCIPHERMENT)
            .union(KeyUsage::KEY_AGREEMENT);

        let csr = CsrBuilder::new(SubjectName::new().common_name("服务.example.cn"))
            .key_usage(ku, true)
            .san_dns("svc.example.cn")
            .san_dns("*.svc.example.cn")
            .san_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .san_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
            .sign_with_id(&key, custom_id, &mut rng)
            .expect("sign with custom id");

        assert!(!csr.verify_signature(), "default ID must fail");
        assert!(csr.verify_signature_with_id(custom_id));

        let parsed = CertificationRequest::from_der(csr.to_der()).expect("parse");
        assert!(parsed.verify_signature_with_id(custom_id));
        assert!(!parsed.attributes_raw().is_empty());
        assert!(parsed.extension_request_raw().is_some());
        assert_eq!(parsed.key_usage(), Some(ku));

        // Verify SAN extension is present inside extension_request_raw.
        let san_val = find_extension(
            parsed.extension_request_raw().expect("ext req"),
            oid::SUBJECT_ALT_NAME,
        )
        .expect("SAN present");
        let (san_body, rest) = reader::read_sequence(san_val).expect("SAN seq");
        assert!(rest.is_empty());
        let (d1, r) = reader::read_context_tagged_implicit(san_body, 2).expect("dns1");
        assert_eq!(d1, b"svc.example.cn");
        let (d2, r) = reader::read_context_tagged_implicit(r, 2).expect("dns2");
        assert_eq!(d2, b"*.svc.example.cn");
        let (ip4, r) = reader::read_context_tagged_implicit(r, 7).expect("ipv4");
        assert_eq!(ip4, &[10, 0, 0, 1]);
        let (ip6, r) = reader::read_context_tagged_implicit(r, 7).expect("ipv6");
        assert_eq!(ip6, &Ipv6Addr::LOCALHOST.octets());
        assert!(r.is_empty());
    }

    #[test]
    fn key_usage_encode_parse_exhaustive_511_values() {
        assert!(KeyUsage::empty().encode_der().is_none());
        for raw_bits in 1u16..=0x1FF {
            let mut ku = KeyUsage::empty();
            let all = [
                KeyUsage::DIGITAL_SIGNATURE,
                KeyUsage::CONTENT_COMMITMENT,
                KeyUsage::KEY_ENCIPHERMENT,
                KeyUsage::DATA_ENCIPHERMENT,
                KeyUsage::KEY_AGREEMENT,
                KeyUsage::KEY_CERT_SIGN,
                KeyUsage::CRL_SIGN,
                KeyUsage::ENCIPHER_ONLY,
                KeyUsage::DECIPHER_ONLY,
            ];
            for (idx, flag) in all.iter().enumerate() {
                if (raw_bits >> idx) & 1 == 1 {
                    ku = ku.union(*flag);
                }
            }
            let der = ku.encode_der().expect("non-empty ku");
            assert_eq!(KeyUsage::parse(&der), Some(ku), "bits=0x{raw_bits:03x}");
        }
        // RFC 5280 §4.2.1.3 canonical minimal check: digitalSignature alone = 03 02 07 80.
        assert_eq!(
            KeyUsage::DIGITAL_SIGNATURE.encode_der().as_deref(),
            Some(&[0x03u8, 0x02, 0x07, 0x80][..])
        );
        // decipherOnly (bit 8) alone = 03 03 07 00 80.
        assert_eq!(
            KeyUsage::DECIPHER_ONLY.encode_der().as_deref(),
            Some(&[0x03u8, 0x03, 0x07, 0x00, 0x80][..])
        );
    }

    #[test]
    fn from_subject_raw_and_empty_subject_with_san() {
        let mut rng = SysRng;
        let key = Sm2PrivateKey::generate(&mut rng).expect("keygen");

        // Empty subject + SAN is valid under RFC 5280.
        let csr = CsrBuilder::new(SubjectName::new())
            .san_dns("empty-subject.example.com")
            .sign(&key, &mut rng)
            .expect("empty subject with SAN");
        assert_eq!(csr.subject_raw(), &[0x30, 0x00]);
        assert!(csr.verify_signature());

        // Raw DER Name escape hatch.
        let raw_name = SubjectName::new()
            .common_name("raw.example.com")
            .to_der()
            .expect("der");
        let csr_raw = CsrBuilder::from_subject_raw(&raw_name)
            .sign(&key, &mut rng)
            .expect("raw subject");
        assert_eq!(csr_raw.subject_raw(), raw_name.as_slice());
        assert!(csr_raw.verify_signature());

        // Malformed raw subject rejected.
        assert_eq!(
            CsrBuilder::from_subject_raw(&[0x04, 0x01, 0x00])
                .sign(&key, &mut rng)
                .unwrap_err(),
            crate::Error::Failed
        );
        assert_eq!(
            CsrBuilder::from_subject_raw(&[0x30, 0x00, 0xFF])
                .sign(&key, &mut rng)
                .unwrap_err(),
            crate::Error::Failed
        );
    }

    #[test]
    fn builder_rejects_invalid_inputs_and_rng_failure() {
        struct FailingRng;
        impl rand_core::TryRng for FailingRng {
            type Error = core::fmt::Error;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(core::fmt::Error)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(core::fmt::Error)
            }
            fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
                Err(core::fmt::Error)
            }
        }
        impl rand_core::TryCryptoRng for FailingRng {}

        let mut rng = SysRng;
        let key = Sm2PrivateKey::generate(&mut rng).expect("keygen");

        // Bad country codes.
        assert!(SubjectName::new().country("CHN").to_der().is_err());
        assert!(SubjectName::new().country("C1").to_der().is_err());
        assert!(SubjectName::new().country("").to_der().is_err());
        // Empty string attribute.
        assert!(SubjectName::new().common_name("").to_der().is_err());

        // Empty KeyUsage rejected.
        assert_eq!(
            CsrBuilder::new(SubjectName::new().common_name("a"))
                .key_usage(KeyUsage::empty(), false)
                .sign(&key, &mut rng)
                .unwrap_err(),
            crate::Error::Failed
        );

        // Invalid SAN DNS names rejected.
        for bad_dns in ["", "bad\nname", "非ASCII.cn"] {
            assert_eq!(
                CsrBuilder::new(SubjectName::new().common_name("a"))
                    .san_dns(bad_dns)
                    .sign(&key, &mut rng)
                    .unwrap_err(),
                crate::Error::Failed
            );
        }

        // RNG error collapses to Error::Failed.
        assert_eq!(
            CsrBuilder::new(SubjectName::new().common_name("a"))
                .sign(&key, &mut FailingRng)
                .unwrap_err(),
            crate::Error::Failed
        );
    }

    #[test]
    fn parser_rejects_malformed_and_tampered_csrs() {
        let mut rng = SysRng;
        let key = Sm2PrivateKey::generate(&mut rng).expect("keygen");
        let csr = CsrBuilder::new(SubjectName::new().common_name("tamper.test"))
            .sign(&key, &mut rng)
            .expect("sign");

        // Trailing byte rejected at parse.
        let mut trailing = csr.to_der().to_vec();
        trailing.push(0x00);
        assert!(CertificationRequest::from_der(&trailing).is_none());

        // Wrong PEM label rejected.
        let bad_pem = pem::encode("NEW CERTIFICATE REQUEST", csr.to_der());
        assert!(CertificationRequest::from_pem(&bad_pem).is_none());

        // Tampered CRI byte still parses structurally (when inside UTF8String)
        // but fails signature verification.
        let mut tampered = csr.to_der().to_vec();
        let needle = b"tamper.test";
        let pos = tampered
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("CN present");
        tampered[pos] ^= 0x01;
        let parsed_tampered = CertificationRequest::from_der(&tampered).expect("structurally ok");
        assert!(!parsed_tampered.verify_signature());

        // Version != 0 rejected.
        let spki_der = spki::encode(&key.public_key());
        let mut bad_cri_body = Vec::new();
        writer::write_integer(&mut bad_cri_body, &[1]); // v2 invalid
        writer::write_sequence(&mut bad_cri_body, &[]);
        bad_cri_body.extend_from_slice(&spki_der);
        writer::write_context_tagged_explicit(&mut bad_cri_body, 0, &[]);
        let mut bad_cri = Vec::new();
        writer::write_sequence(&mut bad_cri, &bad_cri_body);
        let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, &bad_cri, &mut rng).expect("sign");
        let mut alg_body = Vec::new();
        writer::write_oid(&mut alg_body, oid::SM2_SIGN_WITH_SM3);
        let mut alg = Vec::new();
        writer::write_sequence(&mut alg, &alg_body);
        let mut outer_body = Vec::new();
        outer_body.extend_from_slice(&bad_cri);
        outer_body.extend_from_slice(&alg);
        writer::write_bit_string(&mut outer_body, 0, &sig);
        let mut bad_csr = Vec::new();
        writer::write_sequence(&mut bad_csr, &outer_body);
        assert!(CertificationRequest::from_der(&bad_csr).is_none());

        // Duplicate extensionRequest attribute rejected.
        let mut ext_val = Vec::new();
        let ku_der = KeyUsage::DIGITAL_SIGNATURE.encode_der().expect("ku");
        write_extension(&mut ext_val, oid::KEY_USAGE, true, &ku_der);
        let mut exts_seq = Vec::new();
        writer::write_sequence(&mut exts_seq, &ext_val);
        let mut one_attr_body = Vec::new();
        writer::write_oid(&mut one_attr_body, oid::EXTENSION_REQUEST);
        writer::write_set(&mut one_attr_body, &exts_seq);
        let mut one_attr = Vec::new();
        writer::write_sequence(&mut one_attr, &one_attr_body);
        let mut dup_attrs = Vec::new();
        dup_attrs.extend_from_slice(&one_attr);
        dup_attrs.extend_from_slice(&one_attr);
        assert!(parse_attributes(&dup_attrs).is_none());
    }

    #[test]
    fn parses_gmssl_3_2_0_pinned_csr_kat() {
        // Real CSR generated by `gmssl reqgen -C CN -ST Beijing -L Haidian -O Acme -OU Eng -CN example.com`
        // (GmSSL 3.2.0, default SM2 ID "1234567812345678").
        let gmssl_pem = "\
-----BEGIN CERTIFICATE REQUEST-----
MIIBHzCBxgIBADBkMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHQmVpamluZzEQMA4G
A1UEBxMHSGFpZGlhbjENMAsGA1UEChMEQWNtZTEMMAoGA1UECxMDRW5nMRQwEgYD
VQQDEwtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABF9IVjd3
92QCei42s9n6qpyohYuKPXN9E7ntf4AfMTet/DWaLkBqW/1Pu0WW9A75m0p4VMT6
y49t2HiNnw6TjoKgADAKBggqgRzPVQGDdQNIADBFAiB95O12VGt8GHjI1Hs/bcMm
n4j9398Xuwp4mvdA4wQjLAIhAPxldeX2Y5U2271d6RZY3lVSeoqbfbXcNniBTLPQ
JVR2
-----END CERTIFICATE REQUEST-----";

        let parsed = CertificationRequest::from_pem(gmssl_pem).expect("parse GmSSL CSR");
        assert!(parsed.verify_signature(), "GmSSL CSR signature must verify");
        assert!(parsed.attributes_raw().is_empty());
        assert!(parsed.extension_request_raw().is_none());
        // Exact uncompressed public key check against `gmssl reqparse` output.
        let pk_bytes = parsed.subject_public_key().to_sec1_uncompressed();
        assert_eq!(pk_bytes[0], 0x04);
        assert_eq!(pk_bytes[1], 0x5F);
        assert_eq!(pk_bytes[64], 0x82);
    }
}
