//! Key derivation functions.
//!
//! v0.2 ships [`pbkdf2_hmac_sm3`] only. Future v0.3+ may add HKDF and
//! other KDF flavors here.

use crate::hmac::hmac_sm3;
use crate::sm3::DIGEST_SIZE;
use alloc::vec::Vec;
use zeroize::Zeroize;

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
}
