//! Constant-time-designed pure-Rust SM2 / SM3 / SM4 primitives.
//!
//! `no_std` + `alloc`, no C dependency, MSRV 1.85. Every secret-touching path
//! is written against [`subtle`](https://docs.rs/subtle)'s constant-time
//! primitives — no `==`, no `if`, no `bool` on a secret-derived value — and
//! guarded in CI by a [`dudect`](https://docs.rs/dudect-bencher)-based
//! detectable-leak regression harness. Failure modes are deliberately
//! indistinguishable: fallible operations return one opaque [`Error`] or
//! `None`, never a reason.
//!
//! **This crate has not been independently audited.** Assurance is internal
//! (KAT vectors, gmssl interop, the timing harness, a `cargo-fuzz` suite) and
//! the project is solo-maintained with no support SLA. Read
//! [`SECURITY.md`](https://github.com/frankxue831/gm-crypto-rs/blob/main/SECURITY.md)
//! for the threat model and disclosure process, and the
//! [`README`](https://github.com/frankxue831/gm-crypto-rs#readme) for scope,
//! before relying on it.
//!
//! # Usage
//!
//! ```toml
//! [dependencies]
//! gmcrypto-core = "1.11"
//! ```
//!
//! `default = []` — the base build is the primitives below with no optional
//! dependency. Most of what this crate can do is opt-in; see
//! [Crate features](#crate-features).
//!
//! ```rust
//! use gmcrypto_core::sm2::{DEFAULT_SIGNER_ID, Sm2PrivateKey, sign_with_id, verify_with_id};
//! use gmcrypto_core::{sm3, sm4};
//! use getrandom::SysRng; // any `rand_core::TryCryptoRng`; this crate ships no RNG
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let secret_32 = [0x42u8; 32];
//! // SM3 (GB/T 32905): 32-byte digest.
//! let digest = sm3::hash(b"hello");
//!
//! // SM2 (GB/T 32918): sign and verify under the GB/T default signer ID.
//! let key = Sm2PrivateKey::from_bytes_be(&secret_32)   // your scalar, big-endian
//!     .into_option().ok_or("scalar out of range")?;
//! let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"hello", &mut SysRng)?;
//! assert!(verify_with_id(&key.public_key(), DEFAULT_SIGNER_ID, b"hello", &sig));
//!
//! // SM4-CBC (GB/T 32907), PKCS#7 padded. The IV is caller-supplied and must
//! // be unpredictable per message; a fixed one here only because it is an example.
//! let key = [0x42u8; sm4::KEY_SIZE];
//! let iv = [0x24u8; sm4::BLOCK_SIZE];
//! let ciphertext = sm4::mode_cbc::encrypt(&key, &iv, b"hello world");
//! let recovered = sm4::mode_cbc::decrypt(&key, &iv, &ciphertext)
//!     .ok_or("bad padding or length — one opaque None either way")?;
//! assert_eq!(recovered, b"hello world");
//! # Ok(()) }
//! ```
//!
//! Signing and public-key encryption take any `rand_core::TryCryptoRng`; an
//! RNG failure surfaces as the same opaque [`Error`] as any other failure.
//!
//! # Modules
//!
//! | | |
//! |---|---|
//! | [`sm2`] | SM2 sign / verify, encrypt / decrypt (GB/T 32918). With `sm2-key-exchange`: `sm2::key_exchange`, GM/T 0003.3 key agreement |
//! | [`sm3`] | SM3 hash (GB/T 32905), single-shot and streaming |
//! | [`sm4`] | SM4 block cipher (GB/T 32907) with ECB / CBC / CTR. With `sm4-aead`: GCM, CCM, incremental GCM. With `sm4-xts`: XTS |
//! | [`hmac`] | HMAC-SM3 (RFC 2104), single-shot and streaming |
//! | [`kdf`] | PBKDF2-HMAC-SM3 (RFC 8018 §5.2) |
//! | [`asn1`] | Strict-canonical DER for the two SM2 wire structures: RFC 3279 signatures, GM/T 0009 ciphertexts |
//! | [`pem`], [`spki`], [`sec1`], [`pkcs8`] | RFC 7468 PEM, RFC 5280 `SubjectPublicKeyInfo`, RFC 5915 `ECPrivateKey`, RFC 5958 `OneAsymmetricKey` with PBES2 encryption |
//! | `x509` | With `x509`: X.509-with-SM2 leaf parse and signature verify, linear chain verify. **No trust decisions** beyond structure |
//! | `tlcp` | With `tlcp`: TLCP (GB/T 38636-2020) key schedule, record protection, and — with `x509` — `[sign, enc]` pair verification. **Not a protocol implementation** |
//!
//! # Crate features
//!
//! `default = []`: `no_std` + `alloc`, no optional dependency. Every feature
//! is additive and opt-in. Items behind a feature are badged with it on
//! docs.rs.
//!
//! **Capability features** — pure-core, no new dependency unless stated:
//!
//! - `sm4-aead` — SM4-GCM and SM4-CCM (`sm4::mode_gcm`, `sm4::mode_ccm`),
//!   plus incremental-input GCM (`sm4::gcm_streaming`). Pulls the
//!   workspace-internal `gmcrypto-simd` for GHASH (CLMUL / PMULL, with a
//!   constant-time software fallback).
//! - `sm4-xts` — SM4-XTS sector mode (`sm4::mode_xts`), per GB/T 17964-2021:
//!   bit-reflected α-doubling, **not** IEEE 1619. Single-shot and in-place
//!   multi-sector. Confidentiality only — XTS does not authenticate.
//! - `sm2-key-exchange` — GM/T 0003.3 key agreement (`sm2::key_exchange`):
//!   consume-on-transition role state machines, single-use ephemerals, key
//!   released only after the peer's confirmation tag verifies. The
//!   standard-permitted no-confirmation completers are also provided for
//!   protocols — TLCP among them — that carry confirmation themselves.
//! - `x509` — X.509-with-SM2 certificate parse and signature verify (GM/T 0015
//!   profile), strict DER, v3 only. Public inputs only, so no constant-time
//!   obligation arises. Structural trust only — see the module docs.
//! - `tlcp` — the TLCP (GB/T 38636-2020) crypto toolkit: `P_SM3` key
//!   schedule, SM4-CBC and SM4-GCM record protection with a Lucky13-hardened
//!   CBC deprotect, and with `x509` the `[sign, enc]` double-certificate pair
//!   check. No handshake state machine, framing or I/O.
//!
//! **Implementation features** — byte-identical output, different code path:
//!
//! - `sm4-bitsliced` — routes the SM4 S-box through a table-less, gate-only
//!   bitsliced inversion in GF(2^8). Constant-time by construction: no table
//!   lookups, no branches on secret bits. The default path is a linear scan
//!   with the same property; this one is faster under SIMD.
//! - `sm4-bitsliced-simd` — packs that bitsliced S-box into AVX2 (`x86_64`) or
//!   NEON (aarch64) lanes for the batch paths, with runtime detection and a
//!   scalar fallback. Implies `sm4-bitsliced`; pulls `gmcrypto-simd`, where
//!   the crate's only `unsafe` lives.
//!
//! **Ecosystem trait fits** — each pulls one pre-1.0 `RustCrypto` crate, so a
//! breaking release of *that* crate is not covered by this crate's `SemVer`:
//!
//! - `digest-traits` — `digest::Digest` for [`sm3::Sm3`], `digest::Mac` for
//!   [`hmac::HmacSm3`] (`digest = "0.11"`).
//! - `cipher-traits` — `cipher::{BlockCipherEncrypt, BlockCipherDecrypt,
//!   KeyInit}` for [`sm4::Sm4Cipher`] (`cipher = "0.5"`).
//! - `aead-traits` — `aead::{AeadCore, AeadInOut, KeyInit}` for `sm4::Sm4Gcm`
//!   and `sm4::Sm4Ccm`, which yields the `Vec`-returning `aead::Aead` through
//!   that crate's blanket impl. Thin wrappers over `mode_gcm` / `mode_ccm`;
//!   every failure becomes the one opaque `aead::Error`. Implies `sm4-aead`
//!   (`aead = "0.6"`).
//! - `crypto-bigint-scalar` — [`sm2::Sm2PrivateKey::from_scalar`], taking a
//!   `crypto_bigint::U256` directly. The always-on `from_bytes_be` is the
//!   recommended constructor; this exists for callers who already hold the
//!   scalar as that type and accept `crypto-bigint`'s major-version contract.
//!
//! # `wasm32-unknown-unknown`
//!
//! Builds on the target, gated in CI at stable and MSRV. The crate does not
//! pull `getrandom`'s `wasm_js` backend or `wasm-bindgen` into its default
//! graph; wasm callers enable `wasm_js` in their own `Cargo.toml` and pass
//! `getrandom::SysRng` — or any other `rand_core::TryCryptoRng` — to the SM2
//! operations that need randomness.
//!
//! # Release notes
//!
//! Every published version is in
//! [`CHANGELOG.md`](https://github.com/frankxue831/gm-crypto-rs/blob/main/CHANGELOG.md).
//! The project is at 1.x and additive since 1.0.0; `cargo-semver-checks` gates
//! breaking changes in CI, and the three workspace crates release together at
//! one version.

#![no_std]
// v1.11.2 — "Available on crate feature `x` only" badges on docs.rs. The
// `docsrs` cfg is set ONLY by `[package.metadata.docs.rs] rustdoc-args`, so
// this is inert on stable and the `-D warnings` stable `cargo doc` gate in
// api-stability.yml is unaffected. `doc_auto_cfg` was REMOVED in 1.92 and
// merged into `doc_cfg` (rust-lang/rust#138907); under the merged feature the
// auto-labelling is on by default, so no per-item `doc(cfg(...))` is needed —
// 101 badges render from this one line, incl. compound gates like
// `tlcp` + `x509`. Still an unstable feature: if a future nightly moves it
// again, the docs.rs build for the affected version fails and the fix is a
// republish.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

extern crate alloc;

pub mod asn1;
pub mod hmac;
pub mod kdf;
pub mod pem;
pub mod pkcs8;
pub mod sec1;
pub mod sm2;
pub mod sm3;
pub mod sm4;
pub mod spki;
// v1.3 — X.509-with-SM2 leaf certificate parse + signature verify. Opt-in
// via the `x509` feature; default builds are byte-identical. NO trust
// decisions. See docs/v1.3-x509-sm2-design.md.
#[cfg(feature = "x509")]
pub mod x509;

// v1.6 — TLCP (GB/T 38636-2020) crypto toolkit. Key schedule only so
// far; the toolkit grows per docs/tlcp-decomposition.md §7. Default
// builds are byte-identical.
#[cfg(feature = "tlcp")]
pub mod tlcp;
// Not public API / not SemVer — low-level in-crate trait surface kept pub for internal cross-module + dev-crate use; the public trait fit is the opt-in RustCrypto digest/cipher impls.
#[doc(hidden)]
pub mod traits;

/// Internal helper: canonical 32-byte big-endian encoding of a `U256`.
///
/// `crypto-bigint`'s `Encoding::to_be_bytes` returns an `EncodedUint`
/// wrapper, not a `[u8; 32]`. v0.22 reshaped the byte-adjacent public
/// types (`asn1::sig` signatures, `asn1::ciphertext::Sm2Ciphertext`) to
/// `[u8; 32]` so the public API names no `crypto-bigint` type; this pins
/// the conversion in one place for the internal producers (sign / encrypt /
/// raw-ciphertext). Not part of the public API.
#[inline]
pub(crate) fn u256_to_be32(v: &crypto_bigint::U256) -> [u8; 32] {
    v.to_be_bytes().into()
}

/// Workspace-wide failure type.
///
/// Every fallible public surface in `gmcrypto-core` that does not
/// return `Option` / `bool` / `subtle::CtOption` returns
/// `Result<_, Error>`. The single `Failed` variant is deliberate per
/// the **failure-mode invariant** (see `SECURITY.md`): distinguishing
/// failure modes leaks information to padding-oracle / invalid-curve /
/// password-oracle attackers.
///
/// Per-module aliases keep the established import paths working:
/// `sm2::Error`, `pem::Error`, `pkcs8::Error` are type aliases for
/// this one type. Prior to v0.5 these were separate per-module enums
/// (`SignError`, `EncryptError`, `DecryptError`, `pem::Error`,
/// `pkcs8::Error`) all with a single `Failed` variant; v0.5 unifies
/// them per Q5.16 in `docs/v0.5-scope.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The operation failed. No further information is exposed —
    /// distinguishing failure modes leaks attacker-useful signal.
    Failed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("gmcrypto-core operation failed")
    }
}

impl core::error::Error for Error {}
