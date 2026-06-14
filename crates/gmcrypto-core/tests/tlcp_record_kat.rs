//! v1.7 — TLCP record-protection KAT (cfg-gated on `tlcp`).
//!
//! Each record's bytes are cross-validated by an INDEPENDENT oracle, the
//! `OpenSSL` + `GmSSL` cross-check sourcing posture (maintainer-chosen W3;
//! `docs/v1.7-kat-sourcing.md`):
//!
//! - **CBC**: `OpenSSL` 3.x EVP `SM4-CBC` (`-nopad`) for the cipher layer +
//!   `GmSSL` `sm3hmac` for the record MAC, hand-composed per the RFC 4346/5246
//!   framing (MAC-then-encrypt over `seq‖type‖version‖length‖plaintext`,
//!   TLS padding, front explicit IV).
//! - **GCM**: `GmSSL` `sm4 -gcm -aad_hex` (a full AEAD oracle) over the RFC
//!   5288 nonce (`salt‖seq`) + AAD (`seq‖type‖version‖length`).
//!
//! Generator: `tests/data/tlcp_record_kat_gen.py` (provenance). The `gotlcp`
//! full-handshake transcript replay remains a documented follow-up.
#![cfg(feature = "tlcp")]
#![allow(clippy::cast_possible_truncation, clippy::doc_markdown)]

use gmcrypto_core::tlcp::record::{RecordKeysCbc, TLCP_RECORD_VERSION, deprotect_cbc, protect_cbc};
use rand_core::{TryCryptoRng, TryRng};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Fills bytes incrementing from `start` — reproduces the deterministic
/// explicit IV the CBC oracle used (`0x20..0x2f`).
struct FixedRng(u8);
impl TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for b in dst.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
impl TryCryptoRng for FixedRng {}

const SEQ: u64 = 0x0001_0203_0405_0607;
const TYPE: u8 = 0x17; // application_data

/// CBC record == OpenSSL SM4-CBC (cipher) + GmSSL sm3hmac (MAC), byte-for-byte.
#[test]
fn cbc_record_kat_openssl_gmssl() {
    // mac_key = 0x01..0x20 (client_MAC), enc_key = 0x10..0x1f (client_key).
    let mut kb = [0u8; 128];
    for (i, b) in kb[..32].iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    for (i, b) in kb[64..80].iter_mut().enumerate() {
        *b = (0x10 + i) as u8;
    }
    let keys = RecordKeysCbc::client_half(&kb);
    let pt = b"TLCP record protection KAT";
    let expected = unhex(
        "202122232425262728292a2b2c2d2e2fa13de8c228d309130a0e36f6ade1ac41\
         b0f89193fd8b6d5c50a127ab7ad542f290206631b7b7de67bbc270edc5a8379e\
         35de6642033cbafb70a42ac1653825f7",
    );
    // protect with the IV (0x20..0x2f) the oracle fixed.
    let rec = protect_cbc(
        &keys,
        SEQ,
        TYPE,
        TLCP_RECORD_VERSION,
        pt,
        &mut FixedRng(0x20),
    )
    .expect("protect");
    assert_eq!(
        rec, expected,
        "protect_cbc must match the OpenSSL+GmSSL oracle"
    );
    // deprotect recovers the plaintext from the oracle record.
    assert_eq!(
        deprotect_cbc(&keys, SEQ, TYPE, TLCP_RECORD_VERSION, &expected).as_deref(),
        Some(&pt[..])
    );
    // last-byte tamper (the pad-length byte) → single None.
    let mut t = expected.clone();
    let n = t.len() - 1;
    t[n] ^= 0x01;
    assert!(deprotect_cbc(&keys, SEQ, TYPE, TLCP_RECORD_VERSION, &t).is_none());
    // wrong seq → None.
    assert!(deprotect_cbc(&keys, SEQ + 1, TYPE, TLCP_RECORD_VERSION, &expected).is_none());
}

/// GCM record == GmSSL `sm4 -gcm -aad_hex`, byte-for-byte.
#[cfg(feature = "sm4-aead")]
#[test]
fn gcm_record_kat_gmssl() {
    use gmcrypto_core::tlcp::record::{RecordKeysGcm, deprotect_gcm, protect_gcm};
    // enc_key = 0x30..0x3f (client_key), salt = a0 a1 a2 a3 (client_salt).
    let mut kb = [0u8; 40];
    for (i, b) in kb[..16].iter_mut().enumerate() {
        *b = (0x30 + i) as u8;
    }
    kb[32..36].copy_from_slice(&[0xa0, 0xa1, 0xa2, 0xa3]);
    let keys = RecordKeysGcm::client_half(&kb);
    let pt = b"TLCP GCM record KAT";
    let expected = unhex(
        "000102030405060744879f3adc0a1b61378e3fe0abd2ab0b087abf06983f93f0\
         56281522eaada9fda7e2a1",
    );
    let rec = protect_gcm(&keys, SEQ, TYPE, TLCP_RECORD_VERSION, pt).expect("protect");
    assert_eq!(
        rec, expected,
        "protect_gcm must match the GmSSL sm4 -gcm oracle"
    );
    assert_eq!(
        deprotect_gcm(&keys, SEQ, TYPE, TLCP_RECORD_VERSION, &expected).as_deref(),
        Some(&pt[..])
    );
    // tag tamper → None.
    let mut t = expected.clone();
    let n = t.len() - 1;
    t[n] ^= 0x01;
    assert!(deprotect_gcm(&keys, SEQ, TYPE, TLCP_RECORD_VERSION, &t).is_none());
    // wrong seq in AAD → None.
    assert!(deprotect_gcm(&keys, SEQ + 1, TYPE, TLCP_RECORD_VERSION, &expected).is_none());
}
