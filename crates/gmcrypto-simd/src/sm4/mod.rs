//! SM4 SIMD backends.
//!
//! v0.5 W4 phase 2 lands the AVX2 8-way packed bitsliced S-box
//! [`sbox_x8::sbox_x8`]. Phase 3 will add a NEON 4-way path.

pub mod sbox_x8;
