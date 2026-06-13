//! TLCP key schedule — GB/T 38636-2020 §6.5.
//!
//! The TLS-1.2-style PRF (`P_hash`, RFC 5246 §5 structure)
//! instantiated with HMAC-SM3, plus the three derivations the
//! protocol needs. Engine-shaped: explicit inputs, caller-supplied
//! output buffers (the caller owns placement AND wiping — the
//! `pbkdf2_hmac_sm3` discipline), no hidden state.
//!
//! Pinned facts (verification items D-2/D-7/D-10 of the
//! decomposition, resolved against the gotlcp reference
//! implementation):
//! - The pre-master secret is 48 bytes in BOTH TLCP key-exchange
//!   variants (ECC key transport: `version(2) ‖ random(46)`; ECDHE:
//!   SM2-KX output with klen = 48) — hence the typed `[u8; 48]`.
//! - TLCP handshake signatures (`ServerKeyExchange`,
//!   `CertificateVerify`) are plain SM2 message-mode signatures with
//!   the default signer ID; they need [`crate::sm2::sign_with_id`],
//!   not this module.
//! - An SM2 key-transport decrypt failure may abort the handshake:
//!   GM/T 0009 ciphertext is integrity-protected (C3), so the
//!   RSA-style random-PMS-substitution countermeasure is not
//!   load-bearing here.

use crate::hmac::HmacSm3;
use zeroize::Zeroize;

/// TLCP master secret length (GB/T 38636 §6.5.1).
pub const MASTER_SECRET_LEN: usize = 48;
/// TLCP Finished `verify_data` length (GB/T 38636 §6.4.5.10).
pub const FINISHED_VERIFY_DATA_LEN: usize = 12;

/// `P_SM3(secret, label ‖ seed1 ‖ seed2)` per RFC 5246 §5 (the
/// GB/T 38636 §6.5 PRF), writing exactly `out.len()` bytes.
///
/// `A(0) = label ‖ seeds; A(i) = HMAC(secret, A(i-1))`;
/// `out = HMAC(secret, A(1) ‖ label ‖ seeds) ‖ HMAC(secret, A(2) ‖ …) …`
///
/// Private by design (scope Q6.4): every TLCP use is one of the
/// three public derivations. The `A(i)` chain and each output block
/// are secret-derived and wiped; loop bounds depend only on the
/// public `out.len()`.
fn p_sm3(secret: &[u8], label: &[u8], seed1: &[u8], seed2: &[u8], out: &mut [u8]) {
    let mut a = {
        let mut h = HmacSm3::new(secret);
        h.update(label);
        h.update(seed1);
        h.update(seed2);
        h.finalize()
    };
    let mut offset = 0usize;
    while offset < out.len() {
        let mut h = HmacSm3::new(secret);
        h.update(&a);
        h.update(label);
        h.update(seed1);
        h.update(seed2);
        let mut block = h.finalize();
        let n = core::cmp::min(block.len(), out.len() - offset);
        out[offset..offset + n].copy_from_slice(&block[..n]);
        block.zeroize();
        offset += n;
        if offset < out.len() {
            let mut h = HmacSm3::new(secret);
            h.update(&a);
            let next = h.finalize();
            a.zeroize();
            a = next;
        }
    }
    a.zeroize();
}

/// Derive the 48-byte TLCP master secret (GB/T 38636 §6.5.1):
/// `PRF(pre_master, "master secret", client_random ‖ server_random)`.
///
/// `pre_master` is typed `[u8; 48]` — TLCP pins the pre-master secret
/// to 48 bytes in both key-exchange variants. The caller owns wiping
/// `out` (and its `pre_master` copy) when done.
pub fn derive_master_secret(
    pre_master: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    out: &mut [u8; 48],
) {
    p_sm3(
        pre_master,
        b"master secret",
        client_random,
        server_random,
        out,
    );
}

/// Expand the key block (GB/T 38636 §6.5.2):
/// `PRF(master_secret, "key expansion", server_random ‖ client_random)`.
///
/// The seed order FLIPS vs master-secret derivation (server first —
/// a KAT-pinned trap). Writes exactly `out.len()` bytes; the caller
/// carves per suite, in this order: client MAC key, server MAC key,
/// client key, server key, client IV, server IV (CBC suites:
/// 2×(32+16+16) = 128 bytes; GCM suites: 2×(0+16+4) = 40 bytes, the
/// 4-byte halves being the implicit nonce salts). Suite-agnostic by
/// design (engine-shaped, resumption-agnostic). `out.len() == 0` is
/// vacuously fine. The caller owns wiping `out`.
pub fn derive_key_block(
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    out: &mut [u8],
) {
    p_sm3(
        master_secret,
        b"key expansion",
        server_random,
        client_random,
        out,
    );
}

/// Finished-message role: selects the `verify_data` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlcpRole {
    /// `"client finished"`.
    Client,
    /// `"server finished"`.
    Server,
}

/// Compute Finished `verify_data` (GB/T 38636 §6.4.5.10):
/// `PRF(master_secret, label, SM3(handshake_messages))[0..12]`.
///
/// `transcript_hash` is the SM3 hash of all handshake messages up to
/// (excluding) this Finished — hashing the transcript is the caller's
/// (a [`crate::sm3::Sm3`] over the message bytes); this keeps the
/// function stateless and engine-shaped.
pub fn finished_verify_data(
    master_secret: &[u8; 48],
    role: TlcpRole,
    transcript_hash: &[u8; 32],
    out: &mut [u8; 12],
) {
    let label: &[u8] = match role {
        TlcpRole::Client => b"client finished",
        TlcpRole::Server => b"server finished",
    };
    p_sm3(master_secret, label, transcript_hash, b"", out);
}
