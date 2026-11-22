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
//!
//! # Enabling
//!
//! ```toml
//! [dependencies]
//! gmcrypto-core = { version = "1.18", features = ["tlcp"] }
//! ```
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "tlcp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use getrandom::SysRng;
//! use gmcrypto_core::tlcp::{
//!     key_schedule::{
//!         FINISHED_VERIFY_DATA_LEN, MASTER_SECRET_LEN, TlcpRole,
//!         derive_key_block, derive_master_secret, finished_verify_data,
//!     },
//!     record::{
//!         CBC_KEY_BLOCK_LEN, RecordKeysCbc, TLCP_RECORD_VERSION,
//!         deprotect_cbc, protect_cbc,
//!     },
//! };
//!
//! let pre_master = [0x11u8; 48];
//! let client_random = [0x22u8; 32];
//! let server_random = [0x33u8; 32];
//!
//! let mut master = [0u8; MASTER_SECRET_LEN];
//! derive_master_secret(&pre_master, &client_random, &server_random, &mut master);
//!
//! let mut key_block = [0u8; CBC_KEY_BLOCK_LEN];
//! derive_key_block(&master, &client_random, &server_random, &mut key_block);
//!
//! let mut verify_data = [0u8; FINISHED_VERIFY_DATA_LEN];
//! finished_verify_data(&master, TlcpRole::Client, &[0x44u8; 32], &mut verify_data);
//! assert_eq!(verify_data.len(), 12);
//!
//! let client_keys = RecordKeysCbc::from_key_block(TlcpRole::Client, &key_block);
//! let record = protect_cbc(
//!     &client_keys,
//!     0,
//!     23, // application_data
//!     TLCP_RECORD_VERSION,
//!     b"hello tlcp",
//!     &mut SysRng,
//! )
//! .ok_or("protect failed")?;
//! let pt = deprotect_cbc(&client_keys, 0, 23, TLCP_RECORD_VERSION, &record)
//!     .ok_or("deprotect failed")?;
//! assert_eq!(pt, b"hello tlcp");
//! # Ok(()) }
//! # #[cfg(not(feature = "tlcp"))]
//! # fn main() {}
//! ```

/// Certificate-pair verification — needs the `tlcp` **and** `x509` features.
#[cfg(feature = "x509")]
pub mod chain;
pub mod key_schedule;
pub mod record;
