//! TLCP (GB/T 38636-2020) cryptographic toolkit.
//!
//! Building blocks for the Transport Layer Cryptography Protocol —
//! NOT a protocol implementation: no handshake state machine, no
//! record framing, no I/O, no trust decisions. The decomposition of
//! the protocol onto these pieces lives in
//! `docs/tlcp-decomposition.md`.
//!
//! Shipped so far: [`key_schedule`] (GB/T 38636 §6.5). The
//! no-confirmation SM2 key exchange TLCP's ECDHE suites use is NOT
//! here — it is standard SM2-KX generality and lives on
//! `sm2::key_exchange` behind the separate `sm2-key-exchange` feature
//! (a TLCP consumer enables both).

pub mod key_schedule;
