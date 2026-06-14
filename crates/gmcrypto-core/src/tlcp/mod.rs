//! TLCP (GB/T 38636-2020) cryptographic toolkit.
//!
//! Building blocks for the Transport Layer Cryptography Protocol —
//! NOT a protocol implementation: no handshake state machine, no
//! record *framing* (no 5-byte header assembly), no I/O, no trust
//! decisions. The decomposition of the protocol onto these pieces lives
//! in `docs/tlcp-decomposition.md`.
//!
//! Shipped so far: [`key_schedule`] (GB/T 38636 §6.5), [`record`]
//! (GB/T 38636 §6.3 record protection — the protect/deprotect
//! primitives for the four SM2-family suites; v1.7), and (with the
//! `x509` feature also on) [`chain`] (GB/T 38636 §4 certificate-pair
//! verification; v1.8). The no-confirmation SM2 key exchange TLCP's
//! ECDHE suites use is NOT here — it is standard SM2-KX generality and
//! lives on `sm2::key_exchange` behind the separate `sm2-key-exchange`
//! feature (a TLCP consumer enables both).

/// Certificate-pair verification — needs the `tlcp` **and** `x509` features.
#[cfg(feature = "x509")]
pub mod chain;
pub mod key_schedule;
pub mod record;
