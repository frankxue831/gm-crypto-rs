//! Lane-position-shifted exhaustive sweep for `sbox_x16` (NEON path).
//!
//! Per Q6.8 of `docs/v0.6-scope.md` (codex's phase 3 design flag
//! #4). Same shape as `tests/lane_position_x32.rs` but for the
//! 16-byte NEON path. 256 × 16 = 4096 test cases.
//!
//! On `aarch64` this exercises the real NEON intrinsic path
//! (compile-time baseline). On other targets it exercises the
//! scalar fallback.

// The aarch64 NEON test wraps the direct `sbox_x16_neon` call
// in an `unsafe { }` block; the lib crate's `unsafe_code = "warn"`
// doesn't apply to integration-test compilation units, so silence
// the lint here. Every unsafe block in this file carries a
// `// SAFETY:` comment.
#![allow(unsafe_code)]

use gmcrypto_simd::sm4::sbox_x16::{sbox_x16, sbox_x16_scalar};

#[rustfmt::skip]
const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const SBOX_ZERO: u8 = 0xD6;

/// `sbox_x16` dispatch: lane-position-shifted exhaustive sweep.
#[test]
fn dispatch_lane_position_sweep() {
    for b in 0u8..=255 {
        for lane in 0..16 {
            let mut input = [0u8; 16];
            input[lane] = b;
            let out = sbox_x16(&input);
            for (out_lane, &got) in out.iter().enumerate() {
                let expected = if out_lane == lane {
                    SM4_SBOX[b as usize]
                } else {
                    SBOX_ZERO
                };
                assert_eq!(
                    got, expected,
                    "dispatch x16: input byte 0x{b:02x} at lane {lane}, \
                     output lane {out_lane} got 0x{got:02x}, want 0x{expected:02x}",
                );
            }
        }
    }
}

#[test]
fn scalar_lane_position_sweep() {
    for b in 0u8..=255 {
        for lane in 0..16 {
            let mut input = [0u8; 16];
            input[lane] = b;
            let out = sbox_x16_scalar(&input);
            for (out_lane, &got) in out.iter().enumerate() {
                let expected = if out_lane == lane {
                    SM4_SBOX[b as usize]
                } else {
                    SBOX_ZERO
                };
                assert_eq!(
                    got, expected,
                    "scalar x16: input byte 0x{b:02x} at lane {lane}, \
                     output lane {out_lane} got 0x{got:02x}, want 0x{expected:02x}",
                );
            }
        }
    }
}

/// Direct NEON path on aarch64 hosts. NEON is compile-time
/// baseline so the test always runs on aarch64 without a runtime
/// detect.
#[cfg(target_arch = "aarch64")]
#[test]
fn neon_lane_position_sweep() {
    use gmcrypto_simd::sm4::sbox_x16::sbox_x16_neon;

    eprintln!("neon_lane_position_sweep: NEON path exercised (256 x 16 = 4096 cases)");
    for b in 0u8..=255 {
        for lane in 0..16 {
            let mut input = [0u8; 16];
            input[lane] = b;
            // SAFETY: NEON is baseline on aarch64.
            let out = unsafe { sbox_x16_neon(&input) };
            for (out_lane, &got) in out.iter().enumerate() {
                let expected = if out_lane == lane {
                    SM4_SBOX[b as usize]
                } else {
                    SBOX_ZERO
                };
                assert_eq!(
                    got, expected,
                    "NEON x16: input byte 0x{b:02x} at lane {lane}, \
                     output lane {out_lane} got 0x{got:02x}, want 0x{expected:02x}",
                );
            }
        }
    }
}

#[test]
fn dispatch_replicated_sweep() {
    for b in 0u8..=255 {
        let input = [b; 16];
        let out = sbox_x16(&input);
        let expected = SM4_SBOX[b as usize];
        for (lane, &got) in out.iter().enumerate() {
            assert_eq!(
                got, expected,
                "dispatch x16 replicated: input 0x{b:02x}, lane {lane} got 0x{got:02x}, want 0x{expected:02x}",
            );
        }
    }
}

#[test]
fn dispatch_sequential_fill_sweep() {
    for offset in 0u8..=255 {
        // i ∈ 0..16, fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        let input: [u8; 16] = core::array::from_fn(|i| offset.wrapping_add(i as u8));
        let out = sbox_x16(&input);
        for (lane, &got) in out.iter().enumerate() {
            let expected = SM4_SBOX[input[lane] as usize];
            assert_eq!(
                got, expected,
                "dispatch x16 sequential: offset 0x{offset:02x}, lane {lane}, \
                 input 0x{:02x}, got 0x{got:02x}, want 0x{expected:02x}",
                input[lane],
            );
        }
    }
}
