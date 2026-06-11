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

// Implementation lands in Tasks 2–5 (docs/v1.3-x509-sm2-plan.md).
