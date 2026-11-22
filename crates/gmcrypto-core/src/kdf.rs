//! Key derivation functions over [HMAC-SM3](crate::hmac) and [SM3](crate::sm3).
//!
//! Choose the primitive that matches your input entropy:
//!
//! - **HKDF-SM3** ([`hkdf_sm3`], [`hkdf_sm3_extract`], [`hkdf_sm3_expand`]):
//!   RFC 5869 extract-then-expand over HMAC-SM3. Use this for **high-entropy**
//!   input key material (key-exchange shared secrets, master keys, CSPRNG
//!   output). It is fast and **not** password-hardened — never feed
//!   human-chosen passwords to HKDF directly.
//! - **PBKDF2-HMAC-SM3** ([`pbkdf2_hmac_sm3`]): RFC 8018 §5.2 over RFC 2104
//!   over SM3. Use this for turning **human-chosen passwords** into key
//!   material via a caller-chosen iteration count (used by
//!   [`pkcs8`](crate::pkcs8)'s PBES2 encrypted-private-key path).
//!
//! Two API choices here are deliberate and will not change:
//!
//! - **No default iteration count on PBKDF2.** `iterations` is a required
//!   parameter with no default, because a default is a number that ages
//!   silently: what was defensible in 2015 is not in 2026, and a caller who
//!   never chose one never revisits it. Choose from your own threat model and
//!   current hardware, write it down, and raise it deliberately. `0` is
//!   rejected.
//! - **The caller supplies the output buffer.** `output: &mut [u8]` sets the
//!   derived length and lets the caller place the key material where it can
//!   zeroize it. A `Vec`-returning signature would put secrets in an
//!   allocation this crate chose and the caller cannot reliably wipe.
//!
//! Returns `None` — never a reason — on invalid parameters (such as a zero
//! PBKDF2 iteration count, an empty output buffer, or an output length above
//! the primitive's RFC ceiling).
//!
//! # HKDF-SM3 example (high-entropy inputs)
//!
//! ```rust
//! use gmcrypto_core::kdf::{hkdf_sm3, hkdf_sm3_expand, hkdf_sm3_extract};
//! // `zeroize` is a dependency of this crate, not a re-export — add it to
//! // your own Cargo.toml to wipe derived key material.
//! use zeroize::Zeroize;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let shared_secret = [0x42u8; 32]; // e.g. from SM2 key exchange or CSPRNG
//!
//! // Single-shot extract-and-expand:
//! let mut session_key = [0u8; 32];
//! hkdf_sm3(b"protocol-salt", &shared_secret, b"session key v1", &mut session_key)
//!     .ok_or("invalid HKDF output length")?;
//!
//! // Or extract once into a 32-byte PRK and expand domain-separated subkeys:
//! let mut prk = hkdf_sm3_extract(b"protocol-salt", &shared_secret);
//! let mut enc_key = [0u8; 16];
//! let mut mac_key = [0u8; 32];
//! hkdf_sm3_expand(&prk, b"enc", &mut enc_key)
//!     .ok_or("invalid HKDF output length")?;
//! hkdf_sm3_expand(&prk, b"mac", &mut mac_key)
//!     .ok_or("invalid HKDF output length")?;
//! assert_ne!(enc_key[..], mac_key[..16]);
//!
//! prk.zeroize();
//! session_key.zeroize();
//! enc_key.zeroize();
//! mac_key.zeroize();
//! # Ok(()) }
//! ```
//!
//! # PBKDF2-HMAC-SM3 example (passwords)
//!
//! ```rust
//! use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
//! use zeroize::Zeroize;
//!
//! // 100_000 is illustrative, not a recommendation — pick yours, and note
//! // that a high count is a *cost you pay too*: this example is most of the
//! // runtime of this crate's doctest suite.
//! const ITERATIONS: u32 = 100_000;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut key = [0u8; 32];
//! pbkdf2_hmac_sm3(b"correct horse battery staple", b"per-user salt", ITERATIONS, &mut key)
//!     .ok_or("zero iterations or an empty output buffer")?;
//!
//! // The salt is what makes two users with the same password derive
//! // different keys. It is not a secret, but it must be per-user.
//! let mut other = [0u8; 32];
//! pbkdf2_hmac_sm3(b"correct horse battery staple", b"other salt", ITERATIONS, &mut other)
//!     .ok_or("zero iterations or an empty output buffer")?;
//! assert_ne!(key, other);
//!
//! key.zeroize();
//! other.zeroize();
//! # Ok(()) }
//! ```

use crate::hmac::{HmacSm3, hmac_sm3};
use crate::sm3::DIGEST_SIZE;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// Maximum HKDF-SM3 output length in bytes per RFC 5869 §2.3 (`255 × HashLen`,
/// i.e. `255 × 32 = 8160` bytes for SM3).
const HKDF_MAX_OUTPUT: usize = 255 * DIGEST_SIZE;

/// RFC 5869 §2.2 **HKDF-Extract** over HMAC-SM3:
/// `PRK = HMAC-SM3(salt', ikm)`.
///
/// Use this when extracting a uniform 32-byte pseudorandom key (`PRK`) from
/// high-entropy input key material (`ikm`) for one or more subsequent
/// [`hkdf_sm3_expand`] calls, or use [`hkdf_sm3`] for single-shot derivation.
///
/// # Inputs
///
/// - `salt`: optional non-secret salt value. Per RFC 5869 §2.2, an empty
///   `salt` (`&[]`) is treated identically to 32 zero bytes (`[0u8; 32]`).
/// - `ikm`: input key material of any length (empty `ikm` is allowed).
///
/// # Zeroization
///
/// Internal HMAC key/pad buffers are zeroized before return. Callers are
/// responsible for wiping `ikm` and the returned 32-byte `PRK` when no longer
/// needed.
///
/// # KAT cross-validation
///
/// Outputs match OpenSSL (`openssl kdf -kdfopt digest:SM3 -kdfopt mode:EXTRACT_ONLY ... HKDF`).
#[must_use]
pub fn hkdf_sm3_extract(salt: &[u8], ikm: &[u8]) -> [u8; DIGEST_SIZE] {
    if salt.is_empty() {
        hmac_sm3(&[0u8; DIGEST_SIZE], ikm)
    } else {
        hmac_sm3(salt, ikm)
    }
}

/// RFC 5869 §2.3 **HKDF-Expand** over HMAC-SM3.
///
/// Expands a 32-byte pseudorandom key `prk` (typically produced by
/// [`hkdf_sm3_extract`]) with context/application-specific `info` into
/// `output`, computing `T(i) = HMAC-SM3(prk, T(i-1) || info || i)` for
/// `i = 1..=ceil(output.len() / 32)` with `T(0)` empty and zero heap
/// allocation.
///
/// Empty `info` (`&[]`) is permitted.
///
/// # Failure modes
///
/// Returns `None` **before writing anything to `output`** when:
///
/// - `output.is_empty()` (`L == 0` is undefined for key derivation).
/// - `output.len() > 255 * 32` (`8160` bytes — RFC 5869 §2.3 single-byte
///   counter ceiling).
///
/// # Zeroization
///
/// The rolling `T(i)` state and internal [`HmacSm3`] compression states are
/// unconditionally zeroized before return. Callers are responsible for wiping
/// `prk` and `output`.
///
/// # KAT cross-validation
///
/// Outputs match OpenSSL (`openssl kdf -kdfopt digest:SM3 -kdfopt mode:EXPAND_ONLY ... HKDF`).
#[must_use]
pub fn hkdf_sm3_expand(prk: &[u8; DIGEST_SIZE], info: &[u8], output: &mut [u8]) -> Option<()> {
    if output.is_empty() || output.len() > HKDF_MAX_OUTPUT {
        return None;
    }

    let mut t = [0u8; DIGEST_SIZE];
    let mut counter: u8 = 0;

    for chunk in output.chunks_mut(DIGEST_SIZE) {
        // `output.len() <= 255 * DIGEST_SIZE`, so `chunks_mut(DIGEST_SIZE)`
        // yields at most 255 chunks and `counter` steps through `1..=255`.
        counter += 1;
        let mut mac = HmacSm3::new(prk);
        if counter > 1 {
            mac.update(&t);
        }
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }

    t.zeroize();
    Some(())
}

/// Single-shot **HKDF-SM3** (RFC 5869 extract-then-expand over HMAC-SM3).
///
/// Equivalent to [`hkdf_sm3_extract`] followed by [`hkdf_sm3_expand`], while
/// keeping and zeroizing the intermediate 32-byte `PRK` internally. Empty
/// `salt` is treated as 32 zero bytes; empty `ikm` and empty `info` are
/// permitted.
///
/// # Failure modes
///
/// Returns `None` **before writing anything to `output`** when
/// `output.is_empty()` or `output.len() > 255 * 32` (`8160` bytes).
///
/// # Zeroization
///
/// The intermediate `PRK`, rolling `T(i)` state, and internal HMAC buffers
/// are unconditionally zeroized before return (including on `None`). Callers
/// are responsible for wiping `ikm` and `output`.
///
/// # KAT cross-validation
///
/// Outputs match OpenSSL (`openssl kdf -kdfopt digest:SM3 ... HKDF`).
#[must_use]
pub fn hkdf_sm3(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) -> Option<()> {
    if output.is_empty() || output.len() > HKDF_MAX_OUTPUT {
        return None;
    }
    let mut prk = hkdf_sm3_extract(salt, ikm);
    let result = hkdf_sm3_expand(&prk, info, output);
    prk.zeroize();
    result
}

/// Derive `output.len()` bytes of key material from `password` and `salt`
/// using **PBKDF2-HMAC-SM3** (RFC 8018 §5.2 over RFC 2104 over SM3).
///
/// Writes the derived key directly into the caller-supplied `output`
/// buffer; no internal allocation other than a small per-block scratch
/// for `salt || INT(i)`.
///
/// # Failure modes
///
/// Returns `None` (no distinguishing variants per the project's
/// failure-mode invariant) when:
///
/// - `iterations == 0` (RFC 8018 requires `c ≥ 1`).
/// - `output.is_empty()` (a zero-length derived key is undefined).
/// - `output.len() > 32 × (2³² − 1)` — RFC 8018's theoretical maximum.
///   Unreachable on `usize ≤ 64 bits` in practice; the check is here
///   for spec purity and to prevent silent overflow on 128-bit
///   `usize` if that ever exists.
///
/// # Caller-supplied output
///
/// `output.len()` IS the derived-key length. Callers needing 32 bytes
/// pass a `&mut [u8; 32]`; callers needing arbitrary-length material
/// pass a `&mut [u8]` of the desired size.
///
/// # Iteration count guidance
///
/// No default. Pick `iterations` per current best practice (OWASP's
/// 2024 PBKDF2-SHA-256 baseline is 600,000; HMAC-SM3 is comparable
/// per-iteration cost). Defaults age badly; the v0.2 API deliberately
/// has none.
///
/// # Zeroization
///
/// Internal `salt || INT(i)` scratch and the per-block `T_i` / `U_j`
/// accumulators are zeroized before return. Callers are responsible for
/// wiping `output` and `password` themselves.
///
/// # KAT cross-validation
///
/// All KAT vectors below are computed by `gmssl pbkdf2` v3.1.1 with
/// `password="password"` and `salt=0x73616c74` ("salt"):
///
/// | iterations | outlen | derived-key prefix |
/// |---|---|---|
/// | 10000 | 32 | `738c8c43...c1265` |
/// | 10000 | 40 | `738c8c43...c126522b2c8a59d829331` |
/// | 100000 | 32 | `9b27884d...77bbcec2` |
#[must_use]
pub fn pbkdf2_hmac_sm3(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) -> Option<()> {
    if iterations == 0 || output.is_empty() {
        return None;
    }
    // RFC 8018 §5.2: dkLen ≤ hLen × (2³² − 1). hLen = 32 here.
    // Unreachable on usize ≤ 64 bits; check stays for spec purity.
    let max_dklen: u64 = (DIGEST_SIZE as u64) * u64::from(u32::MAX);
    if output.len() as u64 > max_dklen {
        return None;
    }

    // l = ceil(dkLen / hLen): number of HMAC-output-sized blocks needed.
    let hlen = DIGEST_SIZE;
    #[allow(clippy::cast_possible_truncation)]
    let l = output.len().div_ceil(hlen) as u32;

    // Per-block scratch: `salt || INT(i)` (the message argument to the
    // first HMAC call of each block).
    let mut salt_with_counter: Vec<u8> = Vec::with_capacity(salt.len() + 4);
    salt_with_counter.extend_from_slice(salt);
    salt_with_counter.extend_from_slice(&[0u8; 4]);
    let counter_offset = salt.len();

    let mut t = [0u8; DIGEST_SIZE]; // T_i accumulator (XOR of all U_j).
    let mut u = [0u8; DIGEST_SIZE]; // U_j current (rolling HMAC chain).

    for block_index in 1..=l {
        // Patch INT(i) bytes into the scratch buffer's tail.
        salt_with_counter[counter_offset..counter_offset + 4]
            .copy_from_slice(&block_index.to_be_bytes());

        // U_1 = HMAC(P, S || INT(i)).
        u = hmac_sm3(password, &salt_with_counter);
        // T_i seeded with U_1.
        t.copy_from_slice(&u);

        // U_2..U_c, accumulate XOR into T_i.
        for _ in 1..iterations {
            u = hmac_sm3(password, &u);
            for k in 0..hlen {
                t[k] ^= u[k];
            }
        }

        // Copy T_i into the output. The final block may be partial.
        let block_start = (block_index as usize - 1) * hlen;
        let block_end = (block_start + hlen).min(output.len());
        output[block_start..block_end].copy_from_slice(&t[..block_end - block_start]);
    }

    // Zeroize sensitive intermediates before return.
    salt_with_counter.zeroize();
    t.zeroize();
    u.zeroize();

    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hex-format a byte slice as a lowercase string.
    fn to_hex(bytes: &[u8]) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// gmssl-validated KAT: outlen=32 (exact one block), iter=10000.
    #[test]
    fn gmssl_iter10000_out32() {
        let mut dk = [0u8; 32];
        pbkdf2_hmac_sm3(b"password", b"salt", 10_000, &mut dk).expect("derive");
        assert_eq!(
            to_hex(&dk),
            "738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c1265"
        );
    }

    /// gmssl-validated KAT: outlen=20 (under one block — partial `T_1`).
    #[test]
    fn gmssl_iter10000_out20() {
        let mut dk = [0u8; 20];
        pbkdf2_hmac_sm3(b"password", b"salt", 10_000, &mut dk).expect("derive");
        assert_eq!(to_hex(&dk), "738c8c432372d98a73350bc252209e4cf2acdde7");
    }

    /// gmssl-validated KAT: outlen=40 (spans two blocks; `T_2` partial).
    #[test]
    fn gmssl_iter10000_out40() {
        let mut dk = [0u8; 40];
        pbkdf2_hmac_sm3(b"password", b"salt", 10_000, &mut dk).expect("derive");
        assert_eq!(
            to_hex(&dk),
            "738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c126522b2c8a59d829331"
        );
    }

    /// gmssl-validated KAT: outlen=64 (exact two blocks).
    #[test]
    fn gmssl_iter10000_out64() {
        let mut dk = [0u8; 64];
        pbkdf2_hmac_sm3(b"password", b"salt", 10_000, &mut dk).expect("derive");
        assert_eq!(
            to_hex(&dk),
            "738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c126522b2c8a59d8293314c29c1d7be95ca4a2b757103fba96c502b4adb39449b4807"
        );
    }

    /// gmssl-validated KAT: iter=100,000, outlen=32. Higher iteration
    /// count smoke test.
    #[test]
    fn gmssl_iter100000_out32() {
        let mut dk = [0u8; 32];
        pbkdf2_hmac_sm3(b"password", b"salt", 100_000, &mut dk).expect("derive");
        assert_eq!(
            to_hex(&dk),
            "9b27884dd1aef333a412d92d9fba434dc2394091335a1d0bd172942377bbcec2"
        );
    }

    /// Failure mode: `iterations == 0` rejected (RFC 8018 c ≥ 1).
    #[test]
    fn rejects_zero_iterations() {
        let mut dk = [0u8; 32];
        assert_eq!(pbkdf2_hmac_sm3(b"password", b"salt", 0, &mut dk), None);
    }

    /// Failure mode: empty output buffer rejected.
    #[test]
    fn rejects_empty_output() {
        let mut dk: [u8; 0] = [];
        assert_eq!(pbkdf2_hmac_sm3(b"password", b"salt", 1, &mut dk), None);
    }

    /// Different passwords must yield different keys.
    #[test]
    fn different_passwords_different_keys() {
        let mut dk_a = [0u8; 32];
        let mut dk_b = [0u8; 32];
        pbkdf2_hmac_sm3(b"password-a", b"salt", 1000, &mut dk_a).expect("derive");
        pbkdf2_hmac_sm3(b"password-b", b"salt", 1000, &mut dk_b).expect("derive");
        assert_ne!(dk_a, dk_b);
    }

    /// Different salts must yield different keys (under the same password).
    #[test]
    fn different_salts_different_keys() {
        let mut dk_a = [0u8; 32];
        let mut dk_b = [0u8; 32];
        pbkdf2_hmac_sm3(b"password", b"salt-a", 1000, &mut dk_a).expect("derive");
        pbkdf2_hmac_sm3(b"password", b"salt-b", 1000, &mut dk_b).expect("derive");
        assert_ne!(dk_a, dk_b);
    }

    /// Internal consistency: deriving `n` bytes then asking for `m < n`
    /// bytes should yield the first `m` bytes of the `n`-byte derivation.
    /// (PBKDF2's block structure: `T_1` is shared across all output sizes
    /// where `dkLen` overlaps `T_1`'s range.)
    #[test]
    fn shorter_output_is_prefix_of_longer() {
        let mut dk_long = [0u8; 64];
        let mut dk_short = [0u8; 20];
        pbkdf2_hmac_sm3(b"password", b"salt", 1000, &mut dk_long).expect("derive");
        pbkdf2_hmac_sm3(b"password", b"salt", 1000, &mut dk_short).expect("derive");
        assert_eq!(&dk_long[..20], &dk_short[..]);
    }

    // ---------- v1.18 W1: HKDF-SM3 (RFC 5869 over HMAC-SM3) ----------

    /// OpenSSL-validated KAT (`openssl kdf -kdfopt digest:SM3 ... HKDF`):
    /// RFC 5869 Appendix A.1 shape (22-byte IKM, 13-byte salt, 10-byte info,
    /// 42-byte OKM). Covers extract-only, expand-only, and single-shot.
    #[test]
    fn hkdf_openssl_kat_basic() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk = hkdf_sm3_extract(&salt, &ikm);
        assert_eq!(
            to_hex(&prk),
            "e0d6f7b0bd056327b7659f1f39ad850561fbcf4fb10fb58e88eafa55cf7cd01e"
        );

        let expected_okm =
            "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359b";
        let mut okm_expand = [0u8; 42];
        hkdf_sm3_expand(&prk, &info, &mut okm_expand).expect("expand");
        assert_eq!(to_hex(&okm_expand), expected_okm);

        let mut okm_oneshot = [0u8; 42];
        hkdf_sm3(&salt, &ikm, &info, &mut okm_oneshot).expect("hkdf");
        assert_eq!(okm_oneshot, okm_expand);
    }

    /// OpenSSL-validated KAT: RFC 5869 Appendix A.2 shape (80-byte IKM,
    /// 80-byte salt > 64-byte SM3 block size exercising HMAC hash-first key
    /// reduction, 80-byte info, 82-byte OKM).
    #[test]
    fn hkdf_openssl_kat_long_inputs() {
        let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();

        let prk = hkdf_sm3_extract(&salt, &ikm);
        assert_eq!(
            to_hex(&prk),
            "1a43a7fedb2d111eb33babd0d256c272aa3262cdb12e6b43d4321ae8888485d5"
        );

        let expected_okm = "c1226236bbdefa7921f9febe27b864f33e449201b436d8844ea53f58170dd6426defbd22ed1f3c5960f35523e62e3b6c0d657f2c61893436f539013199bfaef25aafd1e7726ede927623a9f5cbb8885c7e5d";
        let mut okm_expand = [0u8; 82];
        hkdf_sm3_expand(&prk, &info, &mut okm_expand).expect("expand");
        assert_eq!(to_hex(&okm_expand), expected_okm);

        let mut okm_oneshot = [0u8; 82];
        hkdf_sm3(&salt, &ikm, &info, &mut okm_oneshot).expect("hkdf");
        assert_eq!(okm_oneshot, okm_expand);
    }

    /// OpenSSL-validated KAT: RFC 5869 Appendix A.3 shape (empty salt and
    /// empty info; empty salt must equal 32 zero bytes).
    #[test]
    fn hkdf_openssl_kat_empty_salt_and_info() {
        let ikm = [0x0bu8; 22];

        let prk_empty = hkdf_sm3_extract(&[], &ikm);
        let prk_zeros = hkdf_sm3_extract(&[0u8; DIGEST_SIZE], &ikm);
        assert_eq!(prk_empty, prk_zeros);
        assert_eq!(
            to_hex(&prk_empty),
            "004fc37143377d072d74e82ff480e8d7937ec607411bc1ec65dd34401871ff9c"
        );

        let expected_okm =
            "c8c91a38ae2fb3b023a7c38ce9f0748f28230d59b6b950ba3ba949bf0d713a5774815778801741cb2034";
        let mut okm_empty = [0u8; 42];
        let mut okm_zeros = [0u8; 42];
        hkdf_sm3(&[], &ikm, &[], &mut okm_empty).expect("hkdf empty salt");
        hkdf_sm3(&[0u8; DIGEST_SIZE], &ikm, &[], &mut okm_zeros).expect("hkdf zero salt");
        assert_eq!(okm_empty, okm_zeros);
        assert_eq!(to_hex(&okm_empty), expected_okm);

        let mut okm_expand = [0u8; 42];
        hkdf_sm3_expand(&prk_empty, &[], &mut okm_expand).expect("expand empty info");
        assert_eq!(okm_expand, okm_empty);
    }

    /// OpenSSL-validated KAT: empty IKM (`&[]`), both with explicit salt/info
    /// and with all-empty inputs.
    #[test]
    fn hkdf_openssl_kat_empty_ikm() {
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk1 = hkdf_sm3_extract(&salt, &[]);
        assert_eq!(
            to_hex(&prk1),
            "ce9d751793328f8d71461b4fadc7d4a17d7dce4c6f7637ffe34f467a7c5f63b5"
        );
        let mut okm1 = [0u8; 32];
        hkdf_sm3(&salt, &[], &info, &mut okm1).expect("hkdf empty ikm");
        assert_eq!(
            to_hex(&okm1),
            "d5a555d4b9df4c27256195cf3608aedaecaadd48e3c12719659a53b1769d0553"
        );

        let prk2 = hkdf_sm3_extract(&[], &[]);
        assert_eq!(
            to_hex(&prk2),
            "0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261"
        );
        let mut okm2 = [0u8; 32];
        hkdf_sm3(&[], &[], &[], &mut okm2).expect("hkdf all empty");
        assert_eq!(
            to_hex(&okm2),
            "6071f9176291908880772c097e692e360c53707af2773c845e123ead3b3fb4d7"
        );
    }

    /// OpenSSL-validated KAT: multi-block boundary lengths `1, 31, 32, 33, 64`
    /// and the RFC 5869 ceiling `8160` (`255 × 32`) bytes.
    #[test]
    fn hkdf_openssl_kat_length_boundaries() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_sm3_extract(&salt, &ikm);

        let mut okm_max = alloc::vec![0u8; HKDF_MAX_OUTPUT];
        hkdf_sm3(&salt, &ikm, &info, &mut okm_max).expect("8160-byte derivation");
        assert_eq!(
            to_hex(&okm_max[..32]),
            "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36"
        );
        assert_eq!(
            to_hex(&okm_max[HKDF_MAX_OUTPUT - 32..]),
            "4380df5968d0f28eee3ddeaebb9f95798ccb83b33890b6c9c3e6b85787cb83e1"
        );
        assert_eq!(
            to_hex(&crate::sm3::hash(&okm_max)),
            "d298439103e24c9d568bceb921082c55ae96691a2df2ad5dcc729e2418d26185"
        );

        let mut okm_max_expand = alloc::vec![0u8; HKDF_MAX_OUTPUT];
        hkdf_sm3_expand(&prk, &info, &mut okm_max_expand).expect("8160-byte expand");
        assert_eq!(okm_max_expand, okm_max);

        let expected_boundaries: &[(usize, &str)] = &[
            (1, "c6"),
            (
                31,
                "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b",
            ),
            (
                32,
                "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36",
            ),
            (
                33,
                "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed",
            ),
            (
                64,
                "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359bc57c754245c6b5a5b974f538f7d23980f78114d63dab",
            ),
        ];

        for &(len, expected_hex) in expected_boundaries {
            let mut out = alloc::vec![0u8; len];
            hkdf_sm3(&salt, &ikm, &info, &mut out).expect("hkdf boundary");
            assert_eq!(to_hex(&out), expected_hex, "len={len}");
            assert_eq!(out.as_slice(), &okm_max[..len], "prefix len={len}");

            let mut out_exp = alloc::vec![0u8; len];
            hkdf_sm3_expand(&prk, &info, &mut out_exp).expect("expand boundary");
            assert_eq!(out_exp, out, "expand==oneshot len={len}");
        }
    }

    /// Failure modes: `L = 0` and `L = 8161` (`255 × 32 + 1`) must return
    /// `None` without modifying `output`.
    #[test]
    fn hkdf_rejects_invalid_lengths_without_touching_output() {
        let prk = hkdf_sm3_extract(b"salt", b"ikm");

        let mut empty: [u8; 0] = [];
        assert_eq!(hkdf_sm3_expand(&prk, b"info", &mut empty), None);
        assert_eq!(hkdf_sm3(b"salt", b"ikm", b"info", &mut empty), None);

        let mut over = alloc::vec![0xA5u8; HKDF_MAX_OUTPUT + 1];
        assert_eq!(hkdf_sm3_expand(&prk, b"info", &mut over), None);
        assert!(over.iter().all(|&b| b == 0xA5));

        assert_eq!(hkdf_sm3(b"salt", b"ikm", b"info", &mut over), None);
        assert!(over.iter().all(|&b| b == 0xA5));
    }

    /// Input sensitivity and domain separation: distinct `info`, `salt`, or
    /// `ikm` produce distinct outputs.
    #[test]
    fn hkdf_domain_separation_and_input_sensitivity() {
        let prk_a = hkdf_sm3_extract(b"salt-a", b"ikm-1");
        let prk_b = hkdf_sm3_extract(b"salt-b", b"ikm-1");
        let prk_c = hkdf_sm3_extract(b"salt-a", b"ikm-2");
        assert_ne!(prk_a, prk_b);
        assert_ne!(prk_a, prk_c);

        let mut key_enc = [0u8; 32];
        let mut key_mac = [0u8; 32];
        hkdf_sm3_expand(&prk_a, b"enc", &mut key_enc).expect("expand enc");
        hkdf_sm3_expand(&prk_a, b"mac", &mut key_mac).expect("expand mac");
        assert_ne!(key_enc, key_mac);
    }
}
