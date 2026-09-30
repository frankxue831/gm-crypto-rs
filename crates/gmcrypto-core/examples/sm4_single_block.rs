//! RESEARCH ONLY — branch `research/v1.16-gfni-x4-measure`, never merged.
//! v1.16 §7 / x4 10% rule: key construction (`Sm4Cipher::new`) and
//! pre-keyed single-block encryption under `sm4-bitsliced-simd`. Built
//! twice: scalar-x4 dispatch and GFNI-x4 dispatch.
#![allow(missing_docs, clippy::cast_precision_loss)]

use gmcrypto_core::sm4::Sm4Cipher;
use std::hint::black_box;
use std::time::Instant;

const KEYS: u32 = 200_000;
const BLOCKS: u32 = 500_000;

fn main() {
    let label = std::env::args().nth(1).unwrap_or_else(|| "unlabelled".into());

    let mut key = [0x11u8; 16];
    let start = Instant::now();
    for i in 0..KEYS {
        key[0] = i.to_le_bytes()[0];
        black_box(Sm4Cipher::new(black_box(&key)));
    }
    let key_ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(KEYS);

    let cipher = Sm4Cipher::new(&[7u8; 16]);
    let mut block = [0x5Au8; 16];
    let start = Instant::now();
    for _ in 0..BLOCKS {
        cipher.encrypt_block(black_box(&mut block));
    }
    black_box(block);
    let block_ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(BLOCKS);

    println!("RESULT single build={label} key_ns={key_ns:.1} block_ns={block_ns:.1}");
}
