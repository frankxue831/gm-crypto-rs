//! SM2 key exchange — GM/T 0003.3 (≡ GB/T 32918.3-2016) with key confirmation.
//!
//! Two role state-machines, `Sm2KxInitiator` and `Sm2KxResponder`. Pure-core;
//! reuses the SM2 curve arithmetic, the masked ephemeral sampler, the SM3 KDF,
//! `compute_z`, and the SEC1 point validation. Confidentiality of the agreed
//! key relies on the caller keeping each ephemeral single-use (the typestate
//! enforces it).

extern crate alloc;

use crate::sm2::curve::Fn;
use crypto_bigint::U256;

/// avf(x) = 2^127 + (x mod 2^127), per GB/T 32918.3 (w = 127 for SM2).
/// `x_be` is the affine x-coordinate of R as a 32-byte big-endian integer.
/// Constant-time: pure bit masking, no branch on `x`. The result is
/// < 2^128 < n, so `Fn::new` is an identity reduction.
fn avf(x_be: &[u8; 32]) -> Fn {
    let mut buf = [0u8; 32];
    // Keep the low 127 bits: bytes 17..32 in full (120 bits) + low 7 bits
    // of byte 16; then force bit 127 set.
    buf[17..32].copy_from_slice(&x_be[17..32]);
    buf[16] = (x_be[16] & 0x7F) | 0x80;
    Fn::new(&U256::from_be_slice(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn avf_sets_bit_127_and_masks_low_127() {
        // x = all-ones → x̄ = 2^127 + (2^127 - 1) = 2^128 - 1 (low 128 bits set).
        let x = [0xFFu8; 32];
        let got = avf(&x).retrieve();
        let expect = U256::from_be_hex(
            "00000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        );
        assert_eq!(got, expect);
    }

    #[test]
    fn avf_zero_input_yields_exactly_bit_127() {
        // x = 0 → x̄ = 2^127 (only the forced bit set).
        let x = [0u8; 32];
        let got = avf(&x).retrieve();
        let expect = U256::from_be_hex(
            "0000000000000000000000000000000080000000000000000000000000000000",
        );
        assert_eq!(got, expect);
    }
}
