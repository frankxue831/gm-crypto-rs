//! RESEARCH ONLY — branch `research/v1.16-gfni-measure`, never merged.
//! v1.16 Q16.5: `Sm4Cipher` batch throughput (CTR keystream uses
//! `encrypt_blocks`, the CBC-decrypt fanout uses `decrypt_blocks`) at
//! 1 KiB and 256 KiB. Built twice: baseline dispatch and GFNI dispatch.
#![allow(missing_docs, clippy::cast_precision_loss)]

use gmcrypto_core::sm4::Sm4Cipher;
use std::hint::black_box;
use std::time::Instant;

const BYTES_PER_SAMPLE: usize = 64 * 1024 * 1024;

fn main() {
    let label = std::env::args().nth(1).unwrap_or_else(|| "unlabelled".into());
    let cipher = Sm4Cipher::new(&[7u8; 16]);
    for (size, blocks) in [("1KiB", 64usize), ("256KiB", 16_384)] {
        let mut buf = vec![[0x5Au8; 16]; blocks];
        let iters = BYTES_PER_SAMPLE / (blocks * 16);
        for op in ["encrypt_blocks", "decrypt_blocks"] {
            let start = Instant::now();
            for _ in 0..iters {
                if op == "encrypt_blocks" {
                    cipher.encrypt_blocks(black_box(&mut buf));
                } else {
                    cipher.decrypt_blocks(black_box(&mut buf));
                }
            }
            let mbps = (iters * blocks * 16) as f64 / start.elapsed().as_secs_f64() / 1e6;
            println!("RESULT batch build={label} op={op} size={size} mbps={mbps:.1}");
        }
    }
}
