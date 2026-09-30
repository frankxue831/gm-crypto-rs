//! RESEARCH ONLY — branch `research/v1.16-gfni-measure`, never merged.
//! v1.16 Q16.5: `sbox_x32_avx2` vs `sbox_x32_gfni` on one GFNI host.
#![allow(unsafe_code, missing_docs, clippy::cast_possible_truncation)]

use gmcrypto_simd::sm4::sbox_x32::{sbox_x32_avx2, sbox_x32_gfni};
use std::hint::black_box;
use std::time::Instant;

const CALLS: u32 = 20_000_000;

fn time(f: unsafe fn(&[u8; 32]) -> [u8; 32]) -> f64 {
    let mut x: [u8; 32] = core::array::from_fn(|i| i as u8);
    let start = Instant::now();
    for _ in 0..CALLS {
        // SAFETY: main() asserted AVX2 and GFNI support before timing.
        x = unsafe { f(black_box(&x)) };
    }
    black_box(x);
    start.elapsed().as_secs_f64() * 1e9 / f64::from(CALLS)
}

fn main() {
    assert!(gmcrypto_simd::has_avx2(), "AVX2 required");
    assert!(gmcrypto_simd::has_gfni_avx2(), "GFNI+AVX2 required");
    for rep in 1..=5 {
        let avx2 = time(sbox_x32_avx2);
        let gfni = time(sbox_x32_gfni);
        println!("RESULT x32 rep={rep} avx2_ns={avx2:.3} gfni_ns={gfni:.3}");
    }
}
