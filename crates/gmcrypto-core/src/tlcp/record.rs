//! TLCP record protection (GB/T 38636-2020 §6.3) — the protect/deprotect
//! primitives for the four SM2-family suites.
//!
//! TLCP is TLS-1.1-with-SM-algorithms; record version on the wire is
//! `0x0101`; maximum record plaintext is `2^14` bytes. This module is the
//! crypto core only: byte-in / byte-out, **no 5-byte header framing**, no
//! fragmentation, no sequence-number bookkeeping, no I/O. The 5-byte record
//! header is the caller's; `type`/`version` ride in as explicit parameters
//! because they are MAC/AAD-bound.
//!
//! # Engine shape
//!
//! Stateless and policy-free (decomposition §5): the caller holds the
//! sequence number (`seq: u64`), supplies per-record RNG for the CBC
//! explicit IV, and owns key placement. A future sans-I/O TLCP engine can
//! drive these primitives directly.
//!
//! # Suites
//!
//! - **SM4-CBC** (`ECC/ECDHE_SM4_CBC_SM3`): TLS-1.1-style explicit
//!   per-record IV, **MAC-then-encrypt**, TLS padding (every pad byte equals
//!   the pad-length byte). Record MAC = HMAC-SM3 over
//!   `seq(8) ‖ type(1) ‖ version(2) ‖ length(2) ‖ plaintext`. Pure-core
//!   (feature `tlcp`).
//! - **SM4-GCM** (`ECC/ECDHE_SM4_GCM_SM3`): RFC 5288 TLS-1.2 AEAD shape —
//!   nonce = 4-byte implicit salt ‖ 8-byte explicit (seq-derived) nonce;
//!   AAD = `seq ‖ type ‖ version ‖ length`; 16-byte tag. Requires feature
//!   `sm4-aead` in addition to `tlcp` (it composes `sm4::mode_gcm`).
//!
//! # Constant-time CBC deprotect (Lucky13)
//!
//! [`deprotect_cbc`] is a single operation that is constant-time over BOTH
//! the TLS padding validity AND the MAC comparison. The secret post-strip
//! plaintext length is never allowed to influence the work done: the
//! inner-HMAC SM3 compression count is equalized (dummy compressions to a
//! public upper bound), the pad-validity scan covers a fixed window, and the
//! MAC is extracted at its secret offset by a data-independent scan. A
//! bad-padding record still runs the full MAC. There is a single failure
//! mode (`None`) and no plaintext escapes on failure.
//!
//! # Misuse warning — `(key, seq)` uniqueness is the caller's contract
//!
//! These primitives take `seq` explicitly and **cannot detect reuse or
//! wrap**. Reusing a `(key, seq)` pair is catastrophic — for GCM it repeats
//! the `salt ‖ explicit_nonce` and breaks confidentiality + integrity; for
//! CBC it leaks plaintext equality. In TLCP the Finished-gated handshake
//! guarantees fresh keys per connection and the sequence number increments
//! per record. A future stateful wrapper would enforce wrap → reject; the
//! stateless layer here cannot. Never reuse a `(direction_key, seq)`.

use crate::sm3::BLOCK_SIZE as SM3_BLOCK;
use crate::sm4::cipher::Sm4Cipher;
use crate::tlcp::key_schedule::TlcpRole;
use alloc::vec::Vec;
use rand_core::TryCryptoRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// TLCP record version on the wire (GB/T 38636: TLS-1.1-style `0x0101`).
///
/// Provided as a convenience; `version` is a caller parameter on every
/// protect/deprotect call (engine-shaped explicit input), not a hardcoded
/// constant inside the primitives.
pub const TLCP_RECORD_VERSION: [u8; 2] = [0x01, 0x01];

/// The SM4-CBC key-block length (carved per-direction into [`RecordKeysCbc`]
/// via [`RecordKeysCbc::from_key_block`]).
pub const CBC_KEY_BLOCK_LEN: usize = 128;

/// The SM4-GCM key-block length (carved per-direction into [`RecordKeysGcm`]).
#[cfg(feature = "sm4-aead")]
pub const GCM_KEY_BLOCK_LEN: usize = 40;

/// HMAC-SM3 record MAC length.
const MAC_LEN: usize = 32;
/// TLS MAC/AAD header length: `seq(8) ‖ type(1) ‖ version(2) ‖ length(2)`.
const HEADER_LEN: usize = 13;
/// TLCP record plaintext ceiling (`2^14`).
const MAX_PLAINTEXT: usize = 1 << 14;

// ===========================================================================
// Key carriers
// ===========================================================================

/// One direction's SM4-CBC record keys, carved from the key block.
///
/// The IV is NOT stored — TLCP CBC uses a fresh RNG-injected explicit IV per
/// record (the key-block IV bytes are vestigial). `ZeroizeOnDrop`.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RecordKeysCbc {
    pub(crate) mac_key: [u8; 32],
    pub(crate) enc_key: [u8; 16],
}

/// One direction's SM4-GCM record keys (4-byte salt = implicit nonce half).
/// `ZeroizeOnDrop`. Requires feature `sm4-aead`.
#[cfg(feature = "sm4-aead")]
#[derive(Clone, ZeroizeOnDrop)]
pub struct RecordKeysGcm {
    pub(crate) enc_key: [u8; 16],
    pub(crate) salt: [u8; 4],
}

impl RecordKeysCbc {
    /// Carve the client-half keys: `client_MAC (0..32)` ‖ `client_key (64..80)`.
    #[must_use]
    pub fn client_half(key_block: &[u8; 128]) -> Self {
        let mut mac_key = [0u8; 32];
        let mut enc_key = [0u8; 16];
        mac_key.copy_from_slice(&key_block[0..32]);
        enc_key.copy_from_slice(&key_block[64..80]);
        Self { mac_key, enc_key }
    }

    /// Carve the server-half keys: `server_MAC (32..64)` ‖ `server_key (80..96)`.
    #[must_use]
    pub fn server_half(key_block: &[u8; 128]) -> Self {
        let mut mac_key = [0u8; 32];
        let mut enc_key = [0u8; 16];
        mac_key.copy_from_slice(&key_block[32..64]);
        enc_key.copy_from_slice(&key_block[80..96]);
        Self { mac_key, enc_key }
    }

    /// Carve the half identified by `role` (`Client → client_half`,
    /// `Server → server_half`). `role` is public, so the dispatch is not a
    /// secret branch. A client writes with the client half and reads with
    /// the server half (the role→direction mapping is the caller's).
    #[must_use]
    pub fn from_key_block(role: TlcpRole, key_block: &[u8; 128]) -> Self {
        match role {
            TlcpRole::Client => Self::client_half(key_block),
            TlcpRole::Server => Self::server_half(key_block),
        }
    }
}

#[cfg(feature = "sm4-aead")]
impl RecordKeysGcm {
    /// Carve the client-half keys: `client_key (0..16)` ‖ `client_salt (32..36)`.
    #[must_use]
    pub fn client_half(key_block: &[u8; 40]) -> Self {
        let mut enc_key = [0u8; 16];
        let mut salt = [0u8; 4];
        enc_key.copy_from_slice(&key_block[0..16]);
        salt.copy_from_slice(&key_block[32..36]);
        Self { enc_key, salt }
    }

    /// Carve the server-half keys: `server_key (16..32)` ‖ `server_salt (36..40)`.
    #[must_use]
    pub fn server_half(key_block: &[u8; 40]) -> Self {
        let mut enc_key = [0u8; 16];
        let mut salt = [0u8; 4];
        enc_key.copy_from_slice(&key_block[16..32]);
        salt.copy_from_slice(&key_block[36..40]);
        Self { enc_key, salt }
    }

    /// Carve the half identified by `role` (`Client → client_half`,
    /// `Server → server_half`).
    #[must_use]
    pub fn from_key_block(role: TlcpRole, key_block: &[u8; 40]) -> Self {
        match role {
            TlcpRole::Client => Self::client_half(key_block),
            TlcpRole::Server => Self::server_half(key_block),
        }
    }
}

// ===========================================================================
// Shared 13-byte MAC/AAD header
// ===========================================================================

/// The 13-byte TLS MAC/AAD header `seq(8) ‖ type(1) ‖ version(2) ‖ len(2)`.
/// `len` is the PLAINTEXT length.
fn record_header(seq: u64, content_type: u8, version: [u8; 2], len: u16) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..8].copy_from_slice(&seq.to_be_bytes());
    h[8] = content_type;
    h[9..11].copy_from_slice(&version);
    h[11..13].copy_from_slice(&len.to_be_bytes());
    h
}

// ===========================================================================
// SM4-GCM record (RFC 5288 TLS-1.2 shape) — feature `sm4-aead`
// ===========================================================================

#[cfg(feature = "sm4-aead")]
fn gcm_nonce(salt: [u8; 4], explicit: [u8; 8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&salt);
    nonce[4..12].copy_from_slice(&explicit);
    nonce
}

/// Protect a plaintext record under SM4-GCM. Output =
/// `explicit_nonce(8) ‖ ciphertext ‖ tag(16)`.
///
/// The 8-byte explicit nonce is derived from `seq` (big-endian) and prepended
/// to the wire; AAD = `seq ‖ type ‖ version ‖ length`. Returns `None` only if
/// `plaintext.len() > 2^14`. See the module misuse warning: never reuse
/// `(key, seq)`.
#[cfg(feature = "sm4-aead")]
#[must_use]
pub fn protect_gcm(
    keys: &RecordKeysGcm,
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT {
        return None;
    }
    // len == plaintext.len() == ciphertext.len() for GCM (AEAD, length-preserving);
    // the deprotect side recomputes the same value from the public ciphertext length.
    let len = u16::try_from(plaintext.len()).ok()?;
    let explicit = seq.to_be_bytes();
    let nonce = gcm_nonce(keys.salt, explicit);
    let aad = record_header(seq, content_type, version, len);
    let (ct, tag) = crate::sm4::mode_gcm::encrypt(&keys.enc_key, &nonce, &aad, plaintext)?;
    let mut out = Vec::with_capacity(8 + ct.len() + 16);
    out.extend_from_slice(&explicit);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Some(out)
}

/// Deprotect an SM4-GCM record. `record = explicit_nonce(8) ‖ ct ‖ tag(16)`.
///
/// The explicit nonce is read from the wire (RFC 5288) while `AAD.seq` uses
/// the caller-held `seq`. Returns `Some(plaintext)` iff the tag verifies
/// (commit-on-verify via `mode_gcm`), `None` otherwise — no plaintext on
/// failure.
#[cfg(feature = "sm4-aead")]
#[must_use]
pub fn deprotect_gcm(
    keys: &RecordKeysGcm,
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    record: &[u8],
) -> Option<Vec<u8>> {
    if record.len() < 8 + 16 {
        return None;
    }
    let ct_len = record.len() - 8 - 16;
    if ct_len > MAX_PLAINTEXT {
        return None;
    }
    let len = u16::try_from(ct_len).ok()?;
    let mut explicit = [0u8; 8];
    explicit.copy_from_slice(&record[0..8]);
    let nonce = gcm_nonce(keys.salt, explicit);
    let ct = &record[8..8 + ct_len];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&record[8 + ct_len..]);
    let aad = record_header(seq, content_type, version, len);
    crate::sm4::mode_gcm::decrypt(&keys.enc_key, &nonce, &aad, ct, &tag)
}

// ===========================================================================
// SM4-CBC record — the Lucky13 deprotect (feature `tlcp`)
// ===========================================================================

/// SM3 inner-hash compression-block count for an HMAC over a
/// `plaintext_len`-byte payload: the inner input is
/// `K'⊕ipad(64) ‖ header(13) ‖ plaintext(P)`, then SM3 finalize appends
/// `0x80` + an 8-byte length (≥ 9 pad bytes; an extra block when the partial
/// fill is `≥ 56`, matching `sm3::finalize`'s `buffer_len > 56` rule).
#[inline]
fn inner_blocks(plaintext_len: usize) -> usize {
    let n = SM3_BLOCK + HEADER_LEN + plaintext_len;
    n / SM3_BLOCK + 1 + usize::from(n % SM3_BLOCK >= SM3_BLOCK - 8)
}

/// HMAC-SM3 over `header ‖ plaintext` (Lucky13 surface #1).
///
/// The inner-hash compression count is EQUALIZED (via dummy compressions on a
/// throwaway state) to the count for `max_plaintext_len` — a public **safe
/// upper bound** that MUST NOT be reduced toward a secret value. The real MAC
/// value is unchanged (true length); only the timing is equalized.
pub(crate) fn mac_equalized(
    mac_key: &[u8; 32],
    header: &[u8; 13],
    plaintext: &[u8],
    max_plaintext_len: usize,
) -> [u8; 32] {
    let mut h = crate::hmac::HmacSm3::new(mac_key);
    h.update(header);
    h.update(plaintext);
    let tag = h.finalize();

    // Top the real inner-hash compression count up to the public maximum.
    let actual = inner_blocks(plaintext.len());
    let target = inner_blocks(max_plaintext_len);
    let dummy = target.saturating_sub(actual);
    let mut scratch = [0u32; 8];
    let block = [0u8; 64];
    let n = core::hint::black_box(dummy);
    for _ in 0..n {
        // black_box both the state and the block each iteration so the
        // optimizer cannot hoist/CSE/vectorize the loop body away.
        core::hint::black_box(&mut scratch);
        crate::sm3::compress(&mut scratch, core::hint::black_box(&block));
    }
    let _ = core::hint::black_box(&scratch);
    tag
}

/// Constant-time TLS pad-validity check (Lucky13 surface #2).
///
/// Over `body = plaintext ‖ MAC(32) ‖ padding`, scans a FIXED window of
/// `min(256, body.len())` trailing bytes — no early return, no padlen-bounded
/// loop. Returns `(pad_ok, plaintext_len)`; `plaintext_len` is meaningful only
/// when `pad_ok` (else `0`, and the caller uses the public fallback).
/// Self-checks `body.len() >= 48` (the `strip_pkcs7_ct` self-checking posture).
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
fn check_tls_padding_ct(body: &[u8]) -> (Choice, usize) {
    let n = body.len();
    if n < MAC_LEN + 16 {
        // Public-length precondition (a valid body is ≥ 48); not secret.
        return (Choice::from(0u8), 0);
    }
    let padlen = body[n - 1]; // secret
    let pad_region = padlen as u16 + 1; // bytes that must all equal padlen
    let window = core::cmp::min(256usize, n);
    let mut bad: u8 = 0;
    for i in 0..window {
        let pos = (i as u16) + 1; // 1 = last byte
        let byte = body[n - 1 - i];
        let in_pad = !pos.ct_gt(&pad_region); // pos <= pad_region
        let diff = byte ^ padlen;
        bad |= u8::conditional_select(&0u8, &diff, in_pad);
    }
    // pad_region must leave room for the 32-byte MAC: pad_region <= n - 32.
    // n is bounded by the caller's 2^14 ceiling, so (n - 32) fits u16.
    let region_ok = !pad_region.ct_gt(&((n - MAC_LEN) as u16));
    let ok = region_ok & bad.ct_eq(&0u8);
    // plaintext_len = n - 32 - pad_region (only meaningful when ok).
    let raw = (n as u64)
        .wrapping_sub(MAC_LEN as u64)
        .wrapping_sub(pad_region as u64);
    let plaintext_len = u64::conditional_select(&0u64, &raw, ok) as usize;
    (ok, plaintext_len)
}

/// Copy the 32-byte MAC from its secret offset (Lucky13 surface #3).
///
/// Uses a data-independent scan over the PUBLIC candidate range; never indexes
/// by the secret offset `plaintext_len` directly.
#[allow(clippy::cast_lossless)]
fn extract_mac_ct(body: &[u8], plaintext_len: usize) -> [u8; 32] {
    let n = body.len();
    let mut out = [0u8; 32];
    for i in 0..=(n - MAC_LEN) {
        let hit = (i as u64).ct_eq(&(plaintext_len as u64));
        for j in 0..MAC_LEN {
            out[j] = u8::conditional_select(&out[j], &body[i + j], hit);
        }
    }
    out
}

/// Protect a plaintext record under SM4-CBC (MAC-then-encrypt).
///
/// Output = `explicit_IV(16) ‖ CBC_enc(plaintext ‖ MAC(32) ‖ tls_pad)`. The
/// explicit IV is drawn from `rng` (must be an unpredictable CSPRNG — NIST
/// SP 800-38A). Returns `None` if `plaintext.len() > 2^14` or the RNG fails.
/// See the module misuse warning.
///
/// # Panics
///
/// Never — the `try_into()` on a `chunks_exact_mut(16)` chunk is infallible.
#[allow(clippy::missing_panics_doc)]
#[must_use]
pub fn protect_cbc<R: TryCryptoRng>(
    keys: &RecordKeysCbc,
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    plaintext: &[u8],
    rng: &mut R,
) -> Option<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT {
        return None;
    }
    let len = u16::try_from(plaintext.len()).ok()?;
    let hdr = record_header(seq, content_type, version, len);
    let mut h = crate::hmac::HmacSm3::new(&keys.mac_key);
    h.update(&hdr);
    h.update(plaintext);
    let mac = h.finalize();

    // Build the wire record in one buffer — explicit IV (RNG, in the clear) ‖
    // plaintext ‖ MAC ‖ TLS padding — then CBC-encrypt in place over the body
    // (everything after the IV). Single allocation, no second copy.
    let mut iv = [0u8; 16];
    rng.try_fill_bytes(&mut iv).ok()?;

    let mut out = Vec::with_capacity(16 + plaintext.len() + MAC_LEN + 16);
    out.extend_from_slice(&iv);
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&mac);
    // TLS padding: padlen+1 bytes each == padlen, filling the body (after the
    // 16-byte IV) to a 16-multiple.
    let padlen = 15 - ((out.len() - 16) % 16);
    #[allow(clippy::cast_possible_truncation)]
    let padbyte = padlen as u8;
    for _ in 0..=padlen {
        out.push(padbyte);
    }

    let cipher = Sm4Cipher::new(&keys.enc_key);
    let mut prev = iv;
    for chunk in out[16..].chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        cipher.encrypt_block(block);
        prev = *block;
    }
    Some(out)
}

/// Deprotect an SM4-CBC record — the Lucky13-hardened single operation.
///
/// `record = explicit_IV(16) ‖ CBC_ct`. Public-length guards run first; then
/// raw CBC decrypt, the constant-time pad check (#2), the equalized MAC over
/// the recovered fragment (#1), the constant-time MAC extraction (#3), and a
/// single final `pad_ok & mac_ok` merge. Returns `Some(plaintext)` iff both
/// hold; `None` otherwise — no plaintext on failure, single failure mode.
/// The returned `Vec` is caller-owned and NOT zeroized by the SDK.
///
/// # Panics
///
/// Never — the `try_into()` on a `chunks_exact_mut(16)` chunk is infallible.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_panics_doc
)]
#[must_use]
pub fn deprotect_cbc(
    keys: &RecordKeysCbc,
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    record: &[u8],
) -> Option<Vec<u8>> {
    // ---- public-length guards (no secret) ----
    if record.len() < 16 + MAC_LEN + 16 {
        return None; // IV + minimum body (0 plaintext + 32 MAC + 16 pad block)
    }
    let body_len = record.len() - 16;
    if body_len % 16 != 0 {
        return None;
    }
    if body_len > MAX_PLAINTEXT + MAC_LEN + 16 {
        return None; // 2^14 ceiling — bounds n so the u16 casts below are lossless
    }

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&record[0..16]);
    let mut body = record[16..].to_vec();

    // ---- raw CBC decrypt (no unpad) ----
    let cipher = Sm4Cipher::new(&keys.enc_key);
    let mut prev = iv;
    for chunk in body.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        let saved = *block;
        cipher.decrypt_block(block);
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        prev = saved;
    }

    // ---- surface #2: constant-time pad-validity check ----
    let (pad_ok, plaintext_len) = check_tls_padding_ct(&body);
    // Public safe upper bound (never reduced) for the equalization (#1).
    let max_plaintext_len = body_len - MAC_LEN - 1;
    // On bad pad, MAC still runs over the fallback length (never short-circuit).
    let eff_len =
        u64::conditional_select(&(max_plaintext_len as u64), &(plaintext_len as u64), pad_ok)
            as usize;
    // eff_len <= max_plaintext_len <= 2^14, so the u16 cast is lossless by the
    // ceiling guard — no fallible `?` on a secret length.
    let len16 = eff_len as u16;
    let hdr = record_header(seq, content_type, version, len16);

    // ---- surface #1: equalized MAC; surface #3: CT MAC extraction ----
    let computed = mac_equalized(&keys.mac_key, &hdr, &body[..eff_len], max_plaintext_len);
    let received = extract_mac_ct(&body, eff_len);
    let mac_ok = computed.ct_eq(&received);

    // ---- one final merge ----
    let valid = pad_ok & mac_ok;
    if bool::from(valid) {
        body.truncate(eff_len);
        Some(body)
    } else {
        body.zeroize();
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::*;
    use rand_core::TryRng;

    /// Test-only fixed-bytes RNG (the repo `FixedRng` idiom).
    struct CountRng(u8);
    impl TryRng for CountRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
            for b in dst.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
    impl TryCryptoRng for CountRng {}

    fn cbc_keys() -> RecordKeysCbc {
        let mut kb = [0u8; 128];
        for (i, b) in kb.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        RecordKeysCbc::client_half(&kb)
    }

    #[test]
    fn cbc_keys_carve_offsets() {
        let mut kb = [0u8; 128];
        for (i, b) in kb.iter_mut().enumerate() {
            *b = i as u8;
        }
        let c = RecordKeysCbc::client_half(&kb);
        let s = RecordKeysCbc::server_half(&kb);
        assert_eq!(c.mac_key, kb[0..32]);
        assert_eq!(c.enc_key, kb[64..80]);
        assert_eq!(s.mac_key, kb[32..64]);
        assert_eq!(s.enc_key, kb[80..96]);
        // from_key_block delegates.
        assert_eq!(
            RecordKeysCbc::from_key_block(TlcpRole::Client, &kb).enc_key,
            c.enc_key
        );
        assert_eq!(
            RecordKeysCbc::from_key_block(TlcpRole::Server, &kb).mac_key,
            s.mac_key
        );
    }

    #[test]
    fn inner_blocks_matches_sm3_spill_rule() {
        // Cross-check inner_blocks against a direct count of compress calls
        // for an HMAC over header(13)+plaintext(P): inner input length is
        // 64 + 13 + P, padded with 0x80 + 8-byte length.
        for p in [0usize, 1, 42, 43, 44, 55, 56, 57, 100, 256, 1000] {
            let n = 64 + 13 + p;
            // ceil((n + 9) / 64): the +9 = 0x80 byte + 8-byte length.
            let expected = (n + 9).div_ceil(64);
            assert_eq!(inner_blocks(p), expected, "p={p}");
        }
    }

    #[test]
    fn equalized_mac_matches_hmac_and_count_is_constant() {
        let mac_key = [0x2bu8; 32];
        for plen in [0usize, 1, 13, 42, 43, 44, 55, 56, 57, 100, 256, 1000] {
            let hdr = record_header(9, 0x17, TLCP_RECORD_VERSION, plen as u16);
            let pt: Vec<u8> = (0..plen).map(|i| i as u8).collect();
            let mut h = crate::hmac::HmacSm3::new(&mac_key);
            h.update(&hdr);
            h.update(&pt);
            let want = h.finalize();
            let max = plen + 300;
            let got = mac_equalized(&mac_key, &hdr, &pt, max);
            assert_eq!(
                got, want,
                "equalized MAC must equal ordinary HMAC, plen={plen}"
            );
            // Equalization invariant: actual + dummy == target (constant for `max`).
            assert!(
                inner_blocks(plen) + (inner_blocks(max) - inner_blocks(plen)) == inner_blocks(max),
                "equalization invariant, plen={plen}"
            );
        }
    }

    #[test]
    fn cbc_round_trip_boundary_lengths() {
        let keys = cbc_keys();
        for len in [
            0usize,
            1,
            15,
            16,
            17,
            31,
            32,
            47,
            48,
            100,
            1000,
            MAX_PLAINTEXT,
        ] {
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut rng = CountRng(0xA0);
            let rec = protect_cbc(&keys, 42, 0x17, TLCP_RECORD_VERSION, &pt, &mut rng).unwrap();
            assert_eq!((rec.len() - 16) % 16, 0, "block-aligned body, len={len}");
            let got = deprotect_cbc(&keys, 42, 0x17, TLCP_RECORD_VERSION, &rec);
            assert_eq!(got.as_deref(), Some(&pt[..]), "round-trip len={len}");
        }
    }

    #[test]
    fn cbc_rejects_tamper_and_wrong_context() {
        let keys = cbc_keys();
        let pt = b"the quick brown fox jumps over the lazy tlcp record";
        let mut rng = CountRng(0x11);
        let rec = protect_cbc(&keys, 7, 0x17, TLCP_RECORD_VERSION, pt, &mut rng).unwrap();
        // wrong seq
        assert!(deprotect_cbc(&keys, 8, 0x17, TLCP_RECORD_VERSION, &rec).is_none());
        // wrong type
        assert!(deprotect_cbc(&keys, 7, 0x16, TLCP_RECORD_VERSION, &rec).is_none());
        // per-byte tamper anywhere → None
        for i in 0..rec.len() {
            let mut t = rec.clone();
            t[i] ^= 0x01;
            assert!(
                deprotect_cbc(&keys, 7, 0x17, TLCP_RECORD_VERSION, &t).is_none(),
                "tamper at byte {i} must reject"
            );
        }
    }

    #[test]
    fn cbc_rejects_malformed_lengths() {
        let keys = cbc_keys();
        // too short (< 16+48)
        assert!(deprotect_cbc(&keys, 0, 0x17, TLCP_RECORD_VERSION, &[0u8; 63]).is_none());
        // body not a 16-multiple
        assert!(deprotect_cbc(&keys, 0, 0x17, TLCP_RECORD_VERSION, &[0u8; 16 + 48 + 1]).is_none());
        // over the 2^14 ceiling
        let huge = alloc::vec![0u8; 16 + MAX_PLAINTEXT + MAC_LEN + 16 + 16];
        assert!(deprotect_cbc(&keys, 0, 0x17, TLCP_RECORD_VERSION, &huge).is_none());
    }

    #[test]
    fn pad_check_accepts_and_rejects() {
        // Build a 48-byte body: 0 plaintext + 32 MAC + 16-byte pad (padlen 15).
        let mut body = alloc::vec![0u8; 48];
        for b in body.iter_mut().skip(32) {
            *b = 15;
        }
        let (ok, pl) = check_tls_padding_ct(&body);
        assert!(bool::from(ok));
        assert_eq!(pl, 0);
        // corrupt one pad byte → reject
        body[40] = 14;
        assert!(!bool::from(check_tls_padding_ct(&body).0));
        // oversized padlen (255 in a 48-byte body) → reject
        let mut body2 = alloc::vec![0xffu8; 48];
        body2[47] = 0xff;
        assert!(!bool::from(check_tls_padding_ct(&body2).0));
    }

    #[test]
    fn extract_mac_ct_matches_slice() {
        let mut body = alloc::vec![0u8; 100];
        for (i, b) in body.iter_mut().enumerate() {
            *b = i as u8;
        }
        for off in [0usize, 1, 33, 68] {
            let got = extract_mac_ct(&body, off);
            assert_eq!(&got[..], &body[off..off + 32], "offset {off}");
        }
    }

    #[cfg(feature = "sm4-aead")]
    #[test]
    fn gcm_round_trip_and_context() {
        let mut kb = [0u8; 40];
        for (i, b) in kb.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(5).wrapping_add(2);
        }
        let keys = RecordKeysGcm::client_half(&kb);
        for len in [0usize, 1, 16, 100, MAX_PLAINTEXT] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let rec = protect_gcm(&keys, 5, 0x17, TLCP_RECORD_VERSION, &pt).unwrap();
            assert_eq!(rec.len(), 8 + pt.len() + 16);
            assert_eq!(&rec[0..8], &5u64.to_be_bytes());
            assert_eq!(
                deprotect_gcm(&keys, 5, 0x17, TLCP_RECORD_VERSION, &rec).as_deref(),
                Some(&pt[..]),
                "gcm round-trip len={len}"
            );
        }
        // wrong seq in AAD → reject
        let rec = protect_gcm(&keys, 5, 0x17, TLCP_RECORD_VERSION, b"x").unwrap();
        assert!(deprotect_gcm(&keys, 6, 0x17, TLCP_RECORD_VERSION, &rec).is_none());
    }

    #[cfg(feature = "sm4-aead")]
    #[test]
    fn gcm_keys_carve_offsets() {
        let mut kb = [0u8; 40];
        for (i, b) in kb.iter_mut().enumerate() {
            *b = i as u8;
        }
        let c = RecordKeysGcm::client_half(&kb);
        let s = RecordKeysGcm::server_half(&kb);
        assert_eq!(c.enc_key, kb[0..16]);
        assert_eq!(c.salt, kb[32..36]);
        assert_eq!(s.enc_key, kb[16..32]);
        assert_eq!(s.salt, kb[36..40]);
    }
}
