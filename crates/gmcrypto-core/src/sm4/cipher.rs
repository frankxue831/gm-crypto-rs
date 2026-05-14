//! SM4 block cipher (GB/T 32907-2016).
//!
//! 128-bit block, 128-bit key, 32 Feistel-like rounds.
//!
//! # Constant-time stance
//!
//! v0.2 W1 ships SM4 with a [`subtle`]-style linear-scan S-box —
//! [`subtle::ConditionallySelectable::conditional_assign`] over all 256
//! possible byte inputs per S-box invocation. This costs ~256× per
//! lookup vs. an LUT-only implementation but keeps the cryptographic
//! side-channel posture consistent with the rest of the crate. A
//! bitsliced fast-path is deferred to v0.4 alongside the C-ABI / wasm
//! work.
//!
//! Throughput on the linear-scan S-box is ~1-2M blocks/sec
//! single-threaded on modern x86 (vs. ~150M for an LUT impl). Document
//! this on every callsite that cares about throughput.
//!
//! # Single-shot API
//!
//! v0.2 ships single-shot block-level `encrypt_block` / `decrypt_block`
//! only. Streaming `BlockCipher`-trait wiring lands in v0.3 alongside
//! the broader trait generalization.
//!
//! # KAT sources
//!
//! GB/T 32907-2016 Appendix A.1, two KATs under
//! key = plaintext = `01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10`:
//!
//! - Single-block ciphertext:
//!   `68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46`.
//! - 1,000,000-round ciphertext (encrypt 1M times under the same key):
//!   `59 52 98 c7 c6 fd 27 1f 04 02 f8 04 c3 3d 3f 66`.
//!
//! The 1M-round test is `#[ignore]`d by default — at debug-build
//! linear-scan-S-box speeds it takes minutes. Run with
//! `cargo test --release -- --ignored` before any release.

#[cfg(not(feature = "sm4-bitsliced"))]
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Block size in bytes (128 bits).
pub const BLOCK_SIZE: usize = 16;

/// Key size in bytes (128 bits).
pub const KEY_SIZE: usize = 16;

/// SM4 S-box (GB/T 32907-2016 §6.2).
///
/// `pub(crate)` so the `sm4::sbox_bitsliced` module (v0.4 W3) can
/// reference it for the exhaustive bitsliced-vs-table equivalence
/// test. Not part of the public API.
///
/// Under `--features sm4-bitsliced` the runtime path doesn't touch
/// `S_BOX` (the bitsliced S-box is table-less); only the bitsliced-
/// equivalence test in `sm4::sbox_bitsliced::tests` keeps a
/// reference. `#[allow(dead_code)]` suppresses the dead-code warning
/// on the non-test feature-on build path.
#[cfg_attr(feature = "sm4-bitsliced", allow(dead_code))]
#[rustfmt::skip]
pub(crate) const S_BOX: [u8; 256] = [
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

/// FK system parameter (GB/T 32907-2016 §7.3.1.1).
const FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

/// CK system parameter (GB/T 32907-2016 §7.3.1.2). Computed at compile
/// time per the spec: `ck_{i,j} = (4i+j)·7 mod 256`. Cross-checks
/// against the published values (e.g. `CK[0] = 0x00070e15`,
/// `CK[31] = 0x646b7279`) sit in the test module below.
const CK: [u32; 32] = {
    let mut ck = [0u32; 32];
    let mut i: u32 = 0;
    while i < 32 {
        let mut v: u32 = 0;
        let mut j: u32 = 0;
        while j < 4 {
            let byte = (4 * i + j).wrapping_mul(7) & 0xff;
            v = (v << 8) | byte;
            j += 1;
        }
        ck[i as usize] = v;
        i += 1;
    }
    ck
};

/// SM4 cipher with pre-computed round keys.
///
/// `Sm4Cipher` zeroizes its round-key buffer on drop via the workspace
/// `zeroize` policy. Construction runs the key schedule (32 round keys
/// × secret-key-touching S-box invocations); see the W1 dudect target
/// `ct_sm4_key_schedule`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sm4Cipher {
    round_keys: [u32; 32],
}

impl Sm4Cipher {
    /// Construct a cipher from a 128-bit key and run the key schedule.
    #[must_use]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mk = [
            u32::from_be_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_be_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_be_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_be_bytes([key[12], key[13], key[14], key[15]]),
        ];

        // K[0..3] = MK[0..3] XOR FK[0..3]; then 32 rounds expand to K[4..35].
        // Sliding 4-word window matches the round-function loop in `crypt`.
        let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];
        let mut round_keys = [0u32; 32];
        for i in 0..32 {
            let t = k[1] ^ k[2] ^ k[3] ^ CK[i];
            let new_k = k[0] ^ t_prime(t);
            round_keys[i] = new_k;
            k[0] = k[1];
            k[1] = k[2];
            k[2] = k[3];
            k[3] = new_k;
        }

        // The intermediate `mk` and `k` arrays held secret material; wipe
        // them before returning. (`round_keys` lives on in `self` and
        // zeroizes via `ZeroizeOnDrop`.)
        let mut mk = mk;
        mk.zeroize();
        k.zeroize();

        Self { round_keys }
    }

    /// Encrypt one 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        crypt(block, &self.round_keys, false);
    }

    /// Decrypt one 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        crypt(block, &self.round_keys, true);
    }

    /// v0.6 W6 — Batched SIMD-packed CBC-decrypt path. Runs the SM4
    /// decrypt round loop on `SIMD_BATCH` blocks in lockstep; the
    /// per-round `tau` (4 byte S-box lookups per block) gets fanned
    /// out across the full SIMD register width via
    /// `gmcrypto_simd::sm4::sbox_x32` (x86_64 AVX2: 8 blocks × 4 =
    /// 32 bytes packed in `__m256i`) or `sbox_x16` (aarch64 NEON:
    /// 4 blocks × 4 = 16 bytes packed in `uint8x16_t`). On other
    /// targets, `SIMD_BATCH = 1` and this falls back to a single
    /// [`decrypt_block`] call.
    ///
    /// Only [`super::cbc_streaming::Sm4CbcDecryptor`] calls this;
    /// the surface is `pub(super)` per Q5.10 ("no new public Rust
    /// API").
    ///
    /// [`decrypt_block`]: Self::decrypt_block
    #[cfg(all(feature = "sm4-bitsliced-simd", target_arch = "x86_64"))]
    pub(super) fn decrypt_blocks_simd(&self, blocks: &mut [[u8; BLOCK_SIZE]; SIMD_BATCH]) {
        crypt_batch_x8(blocks, &self.round_keys, true);
    }

    #[cfg(all(feature = "sm4-bitsliced-simd", target_arch = "aarch64"))]
    pub(super) fn decrypt_blocks_simd(&self, blocks: &mut [[u8; BLOCK_SIZE]; SIMD_BATCH]) {
        crypt_batch_x4(blocks, &self.round_keys, true);
    }

    #[cfg(all(
        feature = "sm4-bitsliced-simd",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    pub(super) fn decrypt_blocks_simd(&self, blocks: &mut [[u8; BLOCK_SIZE]; SIMD_BATCH]) {
        // SIMD_BATCH = 1 on this arch; just delegate.
        self.decrypt_block(&mut blocks[0]);
    }
}

/// v0.6 W6 — compile-time batch size for [`Sm4Cipher::decrypt_blocks_simd`].
///
/// - 8 on x86_64 (AVX2 `__m256i` = 32 bytes = 8 blocks × 4 `tau` bytes).
/// - 4 on aarch64 (NEON `uint8x16_t` = 16 bytes = 4 blocks × 4 `tau` bytes).
/// - 1 elsewhere (`decrypt_blocks_simd` collapses to `decrypt_block`).
#[cfg(all(feature = "sm4-bitsliced-simd", target_arch = "x86_64"))]
pub(super) const SIMD_BATCH: usize = 8;

#[cfg(all(feature = "sm4-bitsliced-simd", target_arch = "aarch64"))]
pub(super) const SIMD_BATCH: usize = 4;

#[cfg(all(
    feature = "sm4-bitsliced-simd",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub(super) const SIMD_BATCH: usize = 1;

impl crate::traits::BlockCipher for Sm4Cipher {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    /// Construct from a key slice. `key.len()` must equal
    /// [`KEY_SIZE`].
    ///
    /// # Panics
    ///
    /// Panics if `key.len() != KEY_SIZE`.
    fn new(key: &[u8]) -> Self {
        let key: &[u8; KEY_SIZE] = key
            .try_into()
            .expect("Sm4Cipher::new: key must be exactly 16 bytes");
        Self::new(key)
    }

    /// Encrypt one 16-byte block in place.
    ///
    /// # Panics
    ///
    /// Panics if `block.len() != BLOCK_SIZE`.
    fn encrypt_block(&self, block: &mut [u8]) {
        let block: &mut [u8; BLOCK_SIZE] = block
            .try_into()
            .expect("Sm4Cipher::encrypt_block: block must be exactly 16 bytes");
        Self::encrypt_block(self, block);
    }

    /// Decrypt one 16-byte block in place.
    ///
    /// # Panics
    ///
    /// Panics if `block.len() != BLOCK_SIZE`.
    fn decrypt_block(&self, block: &mut [u8]) {
        let block: &mut [u8; BLOCK_SIZE] = block
            .try_into()
            .expect("Sm4Cipher::decrypt_block: block must be exactly 16 bytes");
        Self::decrypt_block(self, block);
    }
}

#[cfg(feature = "cipher-traits")]
mod cipher_impl {
    //! `cipher::BlockEncrypt` / `cipher::BlockDecrypt`-compatible impl
    //! for [`Sm4Cipher`] (v0.4 W2; Q4.3).
    //!
    //! Behind the `cipher-traits` feature flag. The cipher 0.4 trait
    //! surface uses a rank-2 backend pattern: callers invoke
    //! `encrypt_with_backend` / `decrypt_with_backend` with a
    //! `BlockClosure`, and the impl calls the closure with a
    //! `BlockBackend`. Following the `aes` crate's pattern.
    //!
    //! Block size = 16 bytes; key size = 16 bytes. Output is byte-
    //! identical to the inherent
    //! [`Sm4Cipher::encrypt_block`] / [`Sm4Cipher::decrypt_block`].

    use super::{BLOCK_SIZE, KEY_SIZE, Sm4Cipher};
    use cipher::consts::{U1, U16};
    use cipher::crypto_common::{Key, KeyInit, KeySizeUser, ParBlocksSizeUser};
    use cipher::inout::InOut;
    use cipher::{
        BlockBackend, BlockCipher, BlockClosure, BlockDecrypt, BlockEncrypt, BlockSizeUser,
    };

    const _: () = assert!(BLOCK_SIZE == 16, "cipher trait fit assumes U16 block");
    const _: () = assert!(KEY_SIZE == 16, "cipher trait fit assumes U16 key");

    impl BlockSizeUser for Sm4Cipher {
        type BlockSize = U16;
    }

    impl KeySizeUser for Sm4Cipher {
        type KeySize = U16;
    }

    impl KeyInit for Sm4Cipher {
        fn new(key: &Key<Self>) -> Self {
            let key: &[u8; KEY_SIZE] = key.as_ref();
            Self::new(key)
        }
    }

    impl BlockCipher for Sm4Cipher {}

    struct Sm4Backend<'a> {
        cipher: &'a Sm4Cipher,
        decrypt: bool,
    }

    impl BlockSizeUser for Sm4Backend<'_> {
        type BlockSize = U16;
    }

    impl ParBlocksSizeUser for Sm4Backend<'_> {
        type ParBlocksSize = U1;
    }

    impl BlockBackend for Sm4Backend<'_> {
        #[inline]
        fn proc_block(&mut self, mut block: InOut<'_, '_, cipher::Block<Self>>) {
            let mut buf = [0u8; BLOCK_SIZE];
            buf.copy_from_slice(block.get_in().as_slice());
            if self.decrypt {
                self.cipher.decrypt_block(&mut buf);
            } else {
                self.cipher.encrypt_block(&mut buf);
            }
            block.get_out().copy_from_slice(&buf);
        }
        // ParBlocksSize = U1, so the default `proc_par_blocks` falls back
        // to `proc_block` for each block. No override needed.
    }

    impl BlockEncrypt for Sm4Cipher {
        fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
            f.call(&mut Sm4Backend {
                cipher: self,
                decrypt: false,
            });
        }
    }

    impl BlockDecrypt for Sm4Cipher {
        fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
            f.call(&mut Sm4Backend {
                cipher: self,
                decrypt: true,
            });
        }
    }
}

/// Run the 32-round Feistel-like SM4 transform in place. `reverse`
/// flips the round-key index direction — encrypt and decrypt share
/// the same data path under SM4's key-reversal property.
fn crypt(block: &mut [u8; BLOCK_SIZE], rk: &[u32; 32], reverse: bool) {
    let mut x = [
        u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ];
    for i in 0..32 {
        let rki = if reverse { rk[31 - i] } else { rk[i] };
        let t = x[1] ^ x[2] ^ x[3] ^ rki;
        let new_x = x[0] ^ t_round(t);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = new_x;
    }
    // Output is (X35, X34, X33, X32) — i.e. `x` reversed.
    let out = [x[3], x[2], x[1], x[0]];
    for (i, w) in out.iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
}

/// v0.6 W6 — AVX2 batched SM4 round loop on 8 blocks in lockstep.
///
/// Same algorithm as [`crypt`] for `N = 8` blocks; the difference is
/// that per round, all 8 blocks' `tau` inputs (32 bytes total) are
/// packed into one `__m256i` and S-boxed in a single
/// [`gmcrypto_simd::sm4::sbox_x32::sbox_x32`] call. 32× fewer SIMD
/// dispatches per batch vs 8 sequential [`crypt`] calls × 32 rounds
/// × 4 S-box bytes per round = 1024 single-byte `sbox_x8` dispatches.
///
/// The L transform (`l_round`) and the round-state shift stay
/// per-block — they're per-u32 bit rotations / XORs, not naturally
/// SIMD-packable in the same shape.
///
/// Behavior is byte-identical to 8 sequential `crypt` calls; verified
/// in `super::cbc_streaming::tests`.
#[cfg(all(feature = "sm4-bitsliced-simd", target_arch = "x86_64"))]
fn crypt_batch_x8(blocks: &mut [[u8; BLOCK_SIZE]; 8], rk: &[u32; 32], reverse: bool) {
    let mut x: [[u32; 4]; 8] = [[0; 4]; 8];
    for b in 0..8 {
        for w in 0..4 {
            x[b][w] = u32::from_be_bytes([
                blocks[b][w * 4],
                blocks[b][w * 4 + 1],
                blocks[b][w * 4 + 2],
                blocks[b][w * 4 + 3],
            ]);
        }
    }

    for i in 0..32 {
        let rki = if reverse { rk[31 - i] } else { rk[i] };

        // Pack all 8 blocks' tau inputs (8 × 4 = 32 bytes) into one
        // buffer, run a single SIMD S-box pass, then unpack.
        let mut t_bytes = [0u8; 32];
        for b in 0..8 {
            let t = x[b][1] ^ x[b][2] ^ x[b][3] ^ rki;
            t_bytes[b * 4..b * 4 + 4].copy_from_slice(&t.to_be_bytes());
        }
        let s_bytes = gmcrypto_simd::sm4::sbox_x32::sbox_x32(&t_bytes);

        // Per-block: apply L, XOR with x[0], shift state window.
        for b in 0..8 {
            let s = u32::from_be_bytes([
                s_bytes[b * 4],
                s_bytes[b * 4 + 1],
                s_bytes[b * 4 + 2],
                s_bytes[b * 4 + 3],
            ]);
            let new_x = x[b][0] ^ l_round(s);
            x[b][0] = x[b][1];
            x[b][1] = x[b][2];
            x[b][2] = x[b][3];
            x[b][3] = new_x;
        }
    }

    // Reverse-output per block (matches `crypt`'s tail).
    for b in 0..8 {
        let out = [x[b][3], x[b][2], x[b][1], x[b][0]];
        for w in 0..4 {
            blocks[b][w * 4..w * 4 + 4].copy_from_slice(&out[w].to_be_bytes());
        }
    }
}

/// v0.6 W6 — NEON batched SM4 round loop on 4 blocks in lockstep.
///
/// Same as [`crypt_batch_x8`] but for `N = 4` blocks; per-round
/// tau bytes (4 × 4 = 16) pack into one `uint8x16_t` and S-box
/// via [`gmcrypto_simd::sm4::sbox_x16::sbox_x16`].
#[cfg(all(feature = "sm4-bitsliced-simd", target_arch = "aarch64"))]
fn crypt_batch_x4(blocks: &mut [[u8; BLOCK_SIZE]; 4], rk: &[u32; 32], reverse: bool) {
    let mut x: [[u32; 4]; 4] = [[0; 4]; 4];
    for b in 0..4 {
        for w in 0..4 {
            x[b][w] = u32::from_be_bytes([
                blocks[b][w * 4],
                blocks[b][w * 4 + 1],
                blocks[b][w * 4 + 2],
                blocks[b][w * 4 + 3],
            ]);
        }
    }

    for i in 0..32 {
        let rki = if reverse { rk[31 - i] } else { rk[i] };

        let mut t_bytes = [0u8; 16];
        for b in 0..4 {
            let t = x[b][1] ^ x[b][2] ^ x[b][3] ^ rki;
            t_bytes[b * 4..b * 4 + 4].copy_from_slice(&t.to_be_bytes());
        }
        let s_bytes = gmcrypto_simd::sm4::sbox_x16::sbox_x16(&t_bytes);

        for b in 0..4 {
            let s = u32::from_be_bytes([
                s_bytes[b * 4],
                s_bytes[b * 4 + 1],
                s_bytes[b * 4 + 2],
                s_bytes[b * 4 + 3],
            ]);
            let new_x = x[b][0] ^ l_round(s);
            x[b][0] = x[b][1];
            x[b][1] = x[b][2];
            x[b][2] = x[b][3];
            x[b][3] = new_x;
        }
    }

    for b in 0..4 {
        let out = [x[b][3], x[b][2], x[b][1], x[b][0]];
        for w in 0..4 {
            blocks[b][w * 4..w * 4 + 4].copy_from_slice(&out[w].to_be_bytes());
        }
    }
}

/// Constant-time S-box lookup via [`subtle`] linear scan.
///
/// Compiles to a fixed 256-iteration loop; each iteration runs a
/// constant-time equality check and a constant-time conditional
/// assignment. Roughly 256× slower than a direct LUT lookup but
/// uniform over the input — see module-doc.
///
/// Default-features build uses this path. Under
/// `--features sm4-bitsliced` (v0.4 W3) [`tau`] swaps to the
/// table-less Itoh-Tsujii bitsliced implementation; this function
/// remains compiled but unused on the bitsliced path.
#[cfg(not(feature = "sm4-bitsliced"))]
#[inline]
fn sbox_ct(x: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..256u16 {
        #[allow(clippy::cast_possible_truncation)]
        let i_u8 = i as u8;
        let eq = i_u8.ct_eq(&x);
        result.conditional_assign(&S_BOX[i as usize], eq);
    }
    result
}

/// Apply the S-box to all four bytes of a `u32` (the τ transform,
/// GB/T 32907-2016 §6.3.1).
///
/// Default-features path uses the linear-scan [`sbox_ct`]. Under
/// `--features sm4-bitsliced` (v0.4 W3) this dispatches to the
/// table-less Itoh-Tsujii bitsliced S-box in
/// [`crate::sm4::sbox_bitsliced`]. Under
/// `--features sm4-bitsliced-simd` (v0.5 W4) it further dispatches to
/// [`crate::sm4::sbox_bitsliced_simd`] — in phase 1 a transparent
/// delegate to the single-block bitslice (byte-identical output);
/// phase 2 / phase 3 swap in AVX2 / NEON intrinsics behind the same
/// path.
// Under `sm4-bitsliced` the bitsliced S-box is `const fn`, which
// would let `tau` be const too — but the default linear-scan path
// uses runtime `subtle` ops that aren't const-eligible. Suppress the
// clippy lint that only fires on one feature config.
#[allow(clippy::missing_const_for_fn)]
#[inline]
fn tau(a: u32) -> u32 {
    let a_bytes = a.to_be_bytes();
    #[cfg(not(feature = "sm4-bitsliced"))]
    let b = [
        sbox_ct(a_bytes[0]),
        sbox_ct(a_bytes[1]),
        sbox_ct(a_bytes[2]),
        sbox_ct(a_bytes[3]),
    ];
    // `sm4-bitsliced-simd` implies `sm4-bitsliced` per Cargo.toml's
    // feature-dependency declaration. The dispatch ordering ensures
    // the SIMD path wins when both are enabled.
    #[cfg(all(feature = "sm4-bitsliced", not(feature = "sm4-bitsliced-simd")))]
    let b = [
        crate::sm4::sbox_bitsliced::sbox(a_bytes[0]),
        crate::sm4::sbox_bitsliced::sbox(a_bytes[1]),
        crate::sm4::sbox_bitsliced::sbox(a_bytes[2]),
        crate::sm4::sbox_bitsliced::sbox(a_bytes[3]),
    ];
    #[cfg(feature = "sm4-bitsliced-simd")]
    let b = [
        crate::sm4::sbox_bitsliced_simd::sbox(a_bytes[0]),
        crate::sm4::sbox_bitsliced_simd::sbox(a_bytes[1]),
        crate::sm4::sbox_bitsliced_simd::sbox(a_bytes[2]),
        crate::sm4::sbox_bitsliced_simd::sbox(a_bytes[3]),
    ];
    u32::from_be_bytes(b)
}

/// Linear transform `L` for the round function (GB/T 32907-2016 §6.3.2):
/// `L(B) = B XOR (B<<<2) XOR (B<<<10) XOR (B<<<18) XOR (B<<<24)`.
#[inline]
const fn l_round(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

/// Linear transform `L'` for the key schedule (GB/T 32907-2016 §7.3.1):
/// `L'(B) = B XOR (B<<<13) XOR (B<<<23)`.
#[inline]
const fn l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

/// Round-function composite transform `T(x) = L(τ(x))`.
#[inline]
fn t_round(x: u32) -> u32 {
    l_round(tau(x))
}

/// Key-schedule composite transform `T'(x) = L'(τ(x))`.
#[inline]
fn t_prime(x: u32) -> u32 {
    l_prime(tau(x))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-check the compile-time `CK` table against published values.
    #[test]
    fn ck_table_matches_published_endpoints() {
        assert_eq!(CK[0], 0x0007_0e15, "CK[0]");
        assert_eq!(CK[31], 0x646b_7279, "CK[31]");
        // Spot-check a middle entry: CK[7] = 0xc4cbd2d9 per spec.
        assert_eq!(CK[7], 0xc4cb_d2d9, "CK[7]");
    }

    /// GB/T 32907-2016 Appendix A.1: single-block KAT.
    #[test]
    fn gbt32907_single_block() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        // The spec KAT happens to use plaintext == key.
        let plaintext: [u8; 16] = key;
        let expected: [u8; 16] = [
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
            0x42, 0x46,
        ];

        let cipher = Sm4Cipher::new(&key);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected, "encrypt KAT mismatch");

        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "decrypt round-trip mismatch");
    }

    /// GB/T 32907-2016 Appendix A.1: 1,000,000-round KAT.
    ///
    /// Encrypt the same plaintext 1,000,000 times under the same key
    /// and verify the final ciphertext matches the spec. Slow on the
    /// linear-scan S-box at debug-build speeds (single-digit minutes);
    /// gated `#[ignore]` so default `cargo test --workspace` stays fast.
    /// Run with `cargo test --release -- --ignored` before any release.
    #[test]
    #[ignore = "1M-round KAT — run with --release --ignored before release"]
    fn gbt32907_one_million_rounds() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let expected: [u8; 16] = [
            0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d,
            0x3f, 0x66,
        ];

        let cipher = Sm4Cipher::new(&key);
        let mut block = key;
        for _ in 0..1_000_000 {
            cipher.encrypt_block(&mut block);
        }
        assert_eq!(block, expected, "1M-round KAT mismatch");
    }

    /// Random plaintext should round-trip through encrypt+decrypt.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let key: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xca, 0xfe, 0xba, 0xbe, 0xba, 0xad,
            0xf0, 0x0d,
        ];
        let plaintext: [u8; 16] = [
            0xa5, 0x5a, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0x1e, 0x2d, 0x3c,
            0x4b, 0x5a,
        ];
        let cipher = Sm4Cipher::new(&key);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);
        assert_ne!(block, plaintext, "ciphertext must differ from plaintext");
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "round-trip must restore plaintext");
    }

    /// Spot-check `sbox_ct` against the LUT for a handful of inputs.
    /// `sbox_ct` is the constant-time reformulation of `S_BOX[x]` and
    /// must agree with it for every `x` (otherwise we ship a broken
    /// cipher).
    ///
    /// Gated `cfg(not(feature = "sm4-bitsliced"))` because `sbox_ct`
    /// itself is gated off the bitsliced path; v0.4 W3's bitsliced
    /// impl has its own exhaustive-vs-S_BOX equivalence test in
    /// [`crate::sm4::sbox_bitsliced::tests::bitsliced_matches_table`].
    #[cfg(not(feature = "sm4-bitsliced"))]
    #[test]
    fn sbox_ct_matches_lut() {
        for x in 0..=255u8 {
            assert_eq!(
                sbox_ct(x),
                S_BOX[x as usize],
                "sbox_ct mismatch at x={x:#04x}"
            );
        }
    }
}
