//! `dudect-bencher` detectable-leak regression harness.
//!
//! Twelve targets, listed in the order the harness sorts them
//! (alphabetical):
//!
//! - `ct_fn_invert`         — direct `Fn::invert((1+d) mod n)` diagnostic (W0).
//! - `ct_fp_invert`         — direct `Fp::invert(Z)` diagnostic (W0).
//! - `ct_hmac_sm3`          — HMAC-SM3, class-split by key (W3).
//! - `ct_mul_g`             — fixed-base scalar multiplication `k·G`.
//! - `ct_mul_var`           — variable-base scalar multiplication `k·P`.
//! - `ct_pkcs8_decrypt`     — encrypted-PKCS#8 decrypt + parse, class-split
//!   by password bytes; both classes' blobs are valid for their class's
//!   password so both succeed via identical control flow (v0.3 W2).
//! - `ct_sign`              — `sign_raw_with_id`, class-split by private key `d`.
//! - `ct_sign_k_class`      — `sign_raw_with_id`, class-split by nonce `k`
//!   magnitude (`d` held fixed, both retry nonces class-tied via [`ClassKRng`]).
//! - `ct_sm2_decrypt`       — SM2 decrypt, class-split by recipient `d_B`,
//!   fixed ciphertext (encrypted to a third party so both classes fail at
//!   the MAC check via identical control flow; v0.2 Phase 3).
//! - `ct_sm4_encrypt_block` — SM4 "construct cipher + encrypt one block",
//!   class-split by master key bytes (W1).
//! - `ct_sm4_key_schedule`  — SM4 key schedule, class-split by master key (W1).
//! - `negative_control`     — deliberately-leaky function. The harness MUST flag
//!   this — if it doesn't, the harness wiring is broken.
//!
//! # Honest framing
//!
//! This harness *detects* timing leaks; it does *not* prove constant-time.
//! Low `|t|` means the test could not detect a leak within the budget given,
//! **not** that no leak exists.
//!
//! # `crypto-bigint::ConstMontyForm::invert` — v0.1 vs. main
//!
//! v0.1.0 shipped on `crypto-bigint = 0.6`, where direct measurement on
//! `Fn::invert((1+d) mod n)` between two random non-degenerate `d` values
//! showed `|tau| ≈ 0.70`. Inside `sign_raw_with_id`, where invert is ~1-2%
//! of total sign time, the signal diluted to `|tau| ≈ 0.04-0.14` — under
//! the 0.20 gate, so `ct_sign` passed.
//!
//! Main (post-publish, on `crypto-bigint = 0.7.3`) measures `|tau| ≈ 0.006`
//! on `ct_fn_invert` and `|tau| ≈ 0.006` on `ct_fp_invert` at 100K samples —
//! two orders of magnitude under the 0.20 gate, in the noise regime.
//! `ct_sign_k_class` measures `|tau| ≈ 0.07` (vs. `ct_sign`'s 0.004),
//! suggesting the nonce path has a slight signal that `ct_sign`'s
//! `d`-class split could not see; well under threshold, not a leak.
//!
//! The v0.2 Fermat-invert workstream is dropped on this evidence;
//! `pow_bounded_exp` remains a fallback if a future `crypto-bigint`
//! release regresses on this gate.
//!
//! # `ct_sign_k_class` — closing v0.1's structural blind spot
//!
//! v0.1's `ct_sign` was class-split by `d` while letting `k` be fresh-random
//! in every sample. A nonce-dependent leak distributes uniformly across
//! both classes and is **structurally undetectable** under that scheme.
//! `ct_sign_k_class` inverts the assignment: `d` held fixed, class-split
//! by nonce magnitude. **Both** retry nonces in the `SIGN_RETRY_BUDGET = 2`
//! loop are class-tied via [`ClassKRng`] — a class label that only
//! controls the first nonce and lets the second be fresh-random would
//! contaminate the signal (the second nonce becomes a noise source
//! distributing uniformly across both classes).
//!
//! # Why we gate on `|tau|`, not `|t|`
//!
//! `|t|` grows as `tau · sqrt(N)`, so any fixed `|t|` threshold becomes
//! more or less strict as the sample budget changes. `tau` is the
//! normalized, scale-free statistic — the same threshold works at any
//! budget, and a real timing leak (large `tau`) gets caught regardless
//! of how many samples we collect.
//!
//! # Iteration model
//!
//! Each bench function performs its own inner iteration loop with random
//! per-sample class assignment via the harness-supplied `BenchRng`. This
//! mirrors the idiomatic pattern shown in `dudect-bencher`'s own docs and
//! produces robust t-statistics in default (non-`--continuous`) mode.
//!
//! `DUDECT_SAMPLES` env var controls the per-bench sample count; default
//! `100_000`. The PR-gate workflow uses `10_000`; the nightly workflow
//! uses `100_000`. Both workflows share the same `|tau|` gate; the
//! larger nightly budget gives tighter empirical confidence on the
//! same threshold rather than enabling a tighter threshold.
//!
//! # Running
//!
//! v0.5 W5 — the bench harness uses `Sm2PrivateKey::from_scalar`
//! (renamed from `new` in v0.5) which is gated behind the
//! `crypto-bigint-scalar` feature flag (Cargo.toml's `[[bench]]`
//! entry sets `required-features = ["crypto-bigint-scalar"]`, so
//! `cargo bench` will activate it implicitly — but stating it
//! explicitly here is the safer documentation).
//!
//! ```text
//! cargo bench --bench timing_leaks --features crypto-bigint-scalar                       # 100K samples each (default)
//! DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features crypto-bigint-scalar # PR-smoke budget
//! DUDECT_SAMPLES=100000 cargo bench --bench timing_leaks --features crypto-bigint-scalar # nightly budget
//! ```
//!
//! The output line emitted by `dudect-bencher` for each bench is:
//!
//! ```text
//! bench <name>           : n == +X.XXXM, max t = +X.XXXXX, max tau = ..., (5/tau)^2 = ...
//! ```
//!
//! CI workflows parse this with a regex pinned to `max tau` (NOT `max t` — the
//! gate is on the scale-free `tau`, not the budget-dependent `t`):
//! `^bench\s+(\S+)\s*\.+\s*:.*?max tau\s*=\s*([+\-]?\d+\.\d+)`.

use core::convert::Infallible;
use crypto_bigint::U256;
use dudect_bencher::ctbench::{BenchMetadata, BenchName, BenchOpts, run_benches_console};
use dudect_bencher::{BenchRng, Class, CtRunner, rand::RngExt};
use getrandom::SysRng;
use gmcrypto_core::hmac::hmac_sm3;
use gmcrypto_core::pkcs8;
use gmcrypto_core::sm2::{
    DEFAULT_SIGNER_ID, Fn as Scalar, Fp, ProjectivePoint, Sm2PrivateKey, Sm2PublicKey, decrypt,
    encrypt, mul_g, mul_var, sign_raw_with_id,
};
use gmcrypto_core::sm4::Sm4Cipher;
use rand_core::{TryCryptoRng, TryRng, UnwrapErr};

/// Default per-bench sample count (smoke). Overridable via `DUDECT_SAMPLES`.
const DEFAULT_SAMPLES: usize = 100_000;

/// Read `DUDECT_SAMPLES` env var; fall back to [`DEFAULT_SAMPLES`] if unset
/// or unparseable.
fn sample_count() -> usize {
    std::env::var("DUDECT_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SAMPLES)
}

/// Deliberately leaks the secret's first byte via control flow.
///
/// `inline(never)` alone is not enough — release-mode optimization folds
/// the busy loop into a constant, collapsing both branches into O(1)
/// operations. We wrap the loop accumulator in `std::hint::black_box`
/// to force the compiler to emit each iteration, producing a real
/// timing differential the harness can detect.
#[inline(never)]
fn leaky_function(secret: &[u8]) -> u8 {
    if secret[0] == 0 {
        // Slow path: thousand-iteration busy loop, kept un-folded.
        let mut x = 0u8;
        for _ in 0..1_000 {
            x = std::hint::black_box(x).wrapping_add(1);
        }
        x
    } else {
        // Fast path: immediate return.
        secret[0]
    }
}

fn negative_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let left = [0u8; 32];
    let mut right = [0u8; 32];
    right[0] = 1;
    for _ in 0..sample_count() {
        let (class, input) = if rng.random::<bool>() {
            (Class::Left, &left)
        } else {
            (Class::Right, &right)
        };
        runner.run_one(class, || leaky_function(input));
    }
}

fn ct_mul_g(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Small scalar (k=1) vs near-n large scalar (k = n-5; the SM2 curve order
    // ends in `...39D54123`). Both are valid private-key scalars; a
    // constant-time fixed-window scalar mult should produce indistinguishable
    // timing distributions.
    let small = Scalar::new(&U256::ONE);
    let large = Scalar::new(&U256::from_be_hex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D5411E",
    ));
    for _ in 0..sample_count() {
        let (class, k) = if rng.random::<bool>() {
            (Class::Left, &small)
        } else {
            (Class::Right, &large)
        };
        runner.run_one(class, || mul_g(k));
    }
}

fn ct_mul_var(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Same small (k=1) vs near-n (k = n-5) class split as `ct_mul_g`.
    let small = Scalar::new(&U256::ONE);
    let large = Scalar::new(&U256::from_be_hex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D5411E",
    ));
    let g = ProjectivePoint::generator();
    for _ in 0..sample_count() {
        let (class, k) = if rng.random::<bool>() {
            (Class::Left, &small)
        } else {
            (Class::Right, &large)
        };
        runner.run_one(class, || mul_var(k, &g));
    }
}

fn ct_sign(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Two random-looking, full-bit-width private keys. Avoids the d=1
    // degenerate case (whose Montgomery form triggers a fast-path in
    // `crypto-bigint`'s ConstMontyForm operations — confirmed by direct
    // measurement to inflate |t| by ~20x).
    let key_small = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    ))
    .expect("sample D in [1, n-2]");
    let key_large = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "B9E5B7C12E48BAB7CC0E91A57F8A48E8C8F87DDD25EBF52F2A75E612CB1A9E4F",
    ))
    .expect("random D in [1, n-2]");
    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_small)
        } else {
            (Class::Right, &key_large)
        };
        // Target `sign_raw_with_id`, NOT `sign_with_id`. The latter ends
        // with `encode_sig` which is variable-time on `(r, s)` byte
        // patterns (leading-zero strip + conditional 0x00-pad). `(r, s)`
        // is public output, so this leak does not reveal secrets, but
        // dudect cannot tell the difference and would flag it. The
        // constant-time-relevant work — `compute_z`, `mul_g(k)`, the
        // `Fn::invert((1+d) mod n)`, the masked-select retry, and the
        // `ConditionallySelectable` merge of candidate `RsPair`s — all
        // happens inside `sign_raw_with_id`.
        //
        // `run_one` takes `Fn` (immutable closure), so construct the
        // zero-sized system RNG wrapper inside the closure.
        runner.run_one(class, || {
            let mut rng = UnwrapErr(SysRng);
            sign_raw_with_id(key, DEFAULT_SIGNER_ID, b"timing target", &mut rng)
        });
    }
}

/// Deterministic per-class RNG that emits a class-tied **pair** of `k`
/// values across two `fill_bytes(&mut [u8; 32])` calls.
///
/// `sign_raw_with_id` runs `SIGN_RETRY_BUDGET = 2` iterations, each
/// drawing a fresh nonce via `sample_nonzero_scalar`. A class label that
/// only controls the first `k` and lets the second be fresh-random
/// contaminates the harness — the second nonce becomes a noise source
/// that distributes uniformly across both classes. See W0 in the
/// v0.2 scope document.
///
/// Both pair elements are chosen so that the validity check inside
/// `sample_nonzero_scalar` (`candidate != 0 && candidate < n`) accepts
/// in one shot, so the bench's loop count is deterministic and the
/// timed window doesn't pick up rejection-sampling jitter.
struct ClassKRng {
    pair: [U256; 2],
    cursor: usize,
}

impl ClassKRng {
    /// Two small nonces: 1 and 3.
    const fn new_left() -> Self {
        Self {
            pair: [U256::from_u64(1), U256::from_u64(3)],
            cursor: 0,
        }
    }

    /// Two large nonces: `n-5` and `n-7` (the SM2 curve order ends in
    /// `...39D54123`). Both well within `[1, n-1]` and so accepted by
    /// `sample_nonzero_scalar`'s `candidate < n` check on first try.
    const fn new_right() -> Self {
        Self {
            pair: [
                U256::from_be_hex(
                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D5411E",
                ),
                U256::from_be_hex(
                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D5411C",
                ),
            ],
            cursor: 0,
        }
    }
}

impl TryRng for ClassKRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(
            dst.len(),
            32,
            "ClassKRng services exactly 32-byte fills (the SM2 nonce path)"
        );
        let value = self.pair[self.cursor % 2];
        self.cursor += 1;
        dst.copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

impl TryCryptoRng for ClassKRng {}

/// Class-split by **nonce magnitude**, with a fixed private key `d`.
///
/// The W0 target that `ct_sign` cannot see: a nonce-only timing leak
/// distributes uniformly across `ct_sign`'s `d`-class split, so it is
/// structurally undetectable there. This target inverts the class
/// assignment.
fn ct_sign_k_class(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    ))
    .expect("fixed sample D in [1, n-2]");
    for _ in 0..sample_count() {
        let class = if rng.random::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        let is_left = matches!(class, Class::Left);
        runner.run_one(class, || {
            let mut k_rng = if is_left {
                UnwrapErr(ClassKRng::new_left())
            } else {
                UnwrapErr(ClassKRng::new_right())
            };
            sign_raw_with_id(&key, DEFAULT_SIGNER_ID, b"timing target", &mut k_rng)
        });
    }
}

/// Direct diagnostic for `Fn::invert((1+d) mod n)` — site (1) of
/// `SECURITY.md`'s invert enumeration.
///
/// Pre-computes `(1 + d_class) mod n` outside the timed window so the
/// timing differential we measure is `invert` itself, not the field
/// addition. Sign-level dudect dilutes invert by ~50× because invert is
/// ~1-2% of total sign time; this target sees invert directly and
/// drives the W5 (Fermat-invert) decision tree.
fn ct_fn_invert(runner: &mut CtRunner, rng: &mut BenchRng) {
    let one = Scalar::new(&U256::ONE);
    let d_small = Scalar::new(&U256::from_be_hex(
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    ));
    let d_large = Scalar::new(&U256::from_be_hex(
        "B9E5B7C12E48BAB7CC0E91A57F8A48E8C8F87DDD25EBF52F2A75E612CB1A9E4F",
    ));
    let one_plus_d_small = one + d_small;
    let one_plus_d_large = one + d_large;
    for _ in 0..sample_count() {
        let (class, x) = if rng.random::<bool>() {
            (Class::Left, &one_plus_d_small)
        } else {
            (Class::Right, &one_plus_d_large)
        };
        runner.run_one(class, || x.invert());
    }
}

/// Direct diagnostic for `Fp::invert(Z)` — site (2) of `SECURITY.md`'s
/// invert enumeration.
///
/// Two arbitrary non-degenerate `Fp` values; the diagnostic interest is
/// whether the invert primitive itself is constant-time, not whether a
/// specific Z is realistic post-`mul_g(k)`. (Realism would not change
/// what we measure — `Fp::invert` is input-only-dependent.)
fn ct_fp_invert(runner: &mut CtRunner, rng: &mut BenchRng) {
    let z_small = Fp::new(&U256::from_u64(0x1234));
    let z_large = Fp::new(&U256::from_be_hex(
        "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210",
    ));
    for _ in 0..sample_count() {
        let (class, x) = if rng.random::<bool>() {
            (Class::Left, &z_small)
        } else {
            (Class::Right, &z_large)
        };
        runner.run_one(class, || x.invert());
    }
}

/// SM4 key schedule diagnostic. The 32-round key schedule runs the same
/// S-box-and-linear-transform pipeline as the round function on
/// secret-derived material — `ct_sm4_encrypt_block` would partially
/// cover this, but a dedicated target prevents an encryption-only
/// regression from masking a key-schedule leak.
fn ct_sm4_key_schedule(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_left)
        } else {
            (Class::Right, &key_right)
        };
        runner.run_one(class, || Sm4Cipher::new(key));
    }
}

/// SM4 encrypt-block diagnostic. Times "construct cipher from key +
/// encrypt one block" under a single window; a leak in either the key
/// schedule or the round function fires this target. Plaintext is
/// fixed; class split is on the master key bytes.
///
/// Under `--features sm4-bitsliced` (v0.4 W3) this target measures
/// the bitsliced S-box path; the default-features build measures the
/// linear-scan S-box. Per Q4.10, both paths gate at `|tau| < 0.20`.
/// The bitsliced path is constant-time-by-construction (pure-XOR /
/// AND gates over public-bit positions); this target is the dudect
/// regression gate on that property.
fn ct_sm4_encrypt_block(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let plaintext: [u8; 16] = [0u8; 16];
    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_left)
        } else {
            (Class::Right, &key_right)
        };
        runner.run_one(class, || {
            let cipher = Sm4Cipher::new(key);
            let mut block = plaintext;
            cipher.encrypt_block(&mut block);
            block
        });
    }
}

/// SM4-CTR encrypt diagnostic (v0.7 W3 — Q7.2). Class-split by master
/// key bytes; fixed counter + fixed plaintext (16 blocks = 256 bytes,
/// hits two full AVX2 batches on `x86_64` or four full NEON batches on
/// `aarch64` under `sm4-bitsliced-simd`; collapses to per-block loop
/// without the feature). Runs under all three matrix entries — CTR's
/// public surface dispatches into linear-scan / `sm4-bitsliced` /
/// `sm4-bitsliced-simd` paths through `Sm4Cipher::encrypt_blocks` (v0.7
/// W1), so the CT discipline is verified end-to-end on every cipher
/// path. NOT cfg-gated; same shape as `ct_sm4_encrypt_block`.
fn ct_sm4_ctr_encrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    use gmcrypto_core::sm4::mode_ctr;

    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let counter: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let plaintext: [u8; 256] = [0u8; 256];

    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_left)
        } else {
            (Class::Right, &key_right)
        };
        runner.run_one(class, || mode_ctr::encrypt(key, &counter, &plaintext));
    }
}

/// SM4 encrypt-block diagnostic — SIMD-packed bitsliced path (v0.5 W4).
///
/// Cfg-gated under `feature = "sm4-bitsliced-simd"`. Phase 1
/// transparently delegates to the v0.4 single-block bitslice, so the
/// measured byte sequence is identical to `ct_sm4_encrypt_block` under
/// `--features sm4-bitsliced`. Phase 2 swaps in AVX2 8-way intrinsics
/// (runtime detect; silent fallback to single-block on non-AVX2 CPUs);
/// phase 3 adds NEON 4-way + `Sm4CbcDecryptor` SIMD fanout. The gate
/// stays at `|tau| < 0.20` across all three phases (Q5.14 of
/// docs/v0.5-scope.md).
///
/// The target is provisioned in phase 1 so that the CI matrix entry,
/// gate threshold, and 100K-sample nightly-budget timing data have a
/// landing pad before the SIMD body lands. The bench function and its
/// `BenchMetadata` entry only compile when the feature is enabled, so
/// there's no overhead on the default-features / `sm4-bitsliced` build
/// paths.
#[cfg(feature = "sm4-bitsliced-simd")]
fn ct_sm4_encrypt_block_bitsliced_simd(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let plaintext: [u8; 16] = [0u8; 16];
    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_left)
        } else {
            (Class::Right, &key_right)
        };
        runner.run_one(class, || {
            let cipher = Sm4Cipher::new(key);
            let mut block = plaintext;
            cipher.encrypt_block(&mut block);
            block
        });
    }
}

/// v0.6 W6 — CBC-decrypt SIMD-fanout target (Q6.7 of
/// `docs/v0.6-scope.md`).
///
/// Exercises the new `Sm4CbcDecryptor::decrypt_batch` path: a
/// fixed-size ciphertext (16 blocks = 2 × SIMD_BATCH on x86_64,
/// 4 × SIMD_BATCH on aarch64, 16 × SIMD_BATCH elsewhere) is
/// stream-decrypted under a class-split master key. The dudect
/// harness measures the full decrypt-stream-and-finalize timeline;
/// the per-round `tau` is dispatched through `sbox_x32` (AVX2) or
/// `sbox_x16` (NEON) when the feature is enabled.
///
/// Class split by master key bytes (matching
/// `ct_sm4_encrypt_block` / `ct_sm4_encrypt_block_bitsliced_simd`).
/// Same `|tau| < 0.20` gate as other SM4 targets. The two classes
/// share identical control flow (both decrypts succeed) so only
/// key-dependent timing differentials surface.
#[cfg(feature = "sm4-bitsliced-simd")]
fn ct_sm4_cbc_decrypt_fanout(runner: &mut CtRunner, rng: &mut BenchRng) {
    use gmcrypto_core::sm4::cbc_streaming::Sm4CbcDecryptor;

    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    // 16 blocks = 256 bytes. On x86_64 with SIMD_BATCH=8 this runs
    // two full SIMD batches plus the held-back tail; on aarch64
    // with SIMD_BATCH=4 it runs four full batches. Ciphertext is
    // pre-built for each class (each is a valid encrypt under its
    // own key) so both decrypt paths share identical control flow.
    let plaintext: [u8; 256] = [0u8; 256];
    let ct_left = gmcrypto_core::sm4::mode_cbc::encrypt(&key_left, &iv, &plaintext);
    let ct_right = gmcrypto_core::sm4::mode_cbc::encrypt(&key_right, &iv, &plaintext);

    for _ in 0..sample_count() {
        let (class, key, ct) = if rng.random::<bool>() {
            (Class::Left, &key_left, &ct_left)
        } else {
            (Class::Right, &key_right, &ct_right)
        };
        runner.run_one(class, || {
            let mut dec = Sm4CbcDecryptor::new(key, &iv);
            dec.update(ct);
            dec.finalize()
                .expect("dudect: valid ciphertext must decrypt")
        });
    }
}

/// v0.8 W4 — SM4-GCM decrypt diagnostic (Q8.7 of
/// `docs/v0.7-aead-scope.md`). Class-split by master key; both
/// classes' `(ciphertext, tag)` tuples are valid encrypts under their
/// **own** keys, so both decrypt paths reach the tag-compare with
/// identical control flow. Mirrors `ct_sm2_decrypt`'s shape (both
/// classes succeed → identical timing surface; only key-bit
/// differentials surface). Exercises the full SM4-GCM stack: key
/// schedule, H derivation, GHASH chain (rides CLMUL on `x86_64` /
/// PMULL on `aarch64` / software Karatsuba elsewhere), GCTR, tag
/// compare.
///
/// Cfg-gated on `sm4-aead` so the target only compiles in CI matrix
/// slots that exercise the AEAD path. Same `|tau| < 0.20` gate as
/// the rest of the SM4 surface.
#[cfg(feature = "sm4-aead")]
fn ct_sm4_gcm_decrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    use gmcrypto_core::sm4::mode_gcm;

    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let aad: [u8; 16] = [0xAA; 16];
    let plaintext: [u8; 256] = [0u8; 256];

    let (ct_left, tag_left) = mode_gcm::encrypt(&key_left, &nonce, &aad, &plaintext);
    let (ct_right, tag_right) = mode_gcm::encrypt(&key_right, &nonce, &aad, &plaintext);

    for _ in 0..sample_count() {
        let (class, key, ct, tag) = if rng.random::<bool>() {
            (Class::Left, &key_left, &ct_left, &tag_left)
        } else {
            (Class::Right, &key_right, &ct_right, &tag_right)
        };
        runner.run_one(class, || {
            mode_gcm::decrypt(key, &nonce, &aad, ct, tag)
                .expect("dudect: valid (ct, tag) must verify")
        });
    }
}

/// v0.8 W4 — SM4-CCM decrypt diagnostic (Q8.7 of
/// `docs/v0.7-aead-scope.md`). Same class-split-by-key shape as
/// `ct_sm4_gcm_decrypt`. Exercises the full SM4-CCM stack:
/// CBC-MAC chain (uses `Sm4Cipher::encrypt_block` in a tight loop),
/// CTR stream (rides v0.7 W1 batch API + v0.6 SIMD fanout under
/// `sm4-bitsliced-simd`), constant-time tag compare. Fixed
/// `tag_len = 16` and 12-byte nonce; covers the most-common shape.
#[cfg(feature = "sm4-aead")]
fn ct_sm4_ccm_decrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    use gmcrypto_core::sm4::mode_ccm;

    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let aad: [u8; 16] = [0xAA; 16];
    let plaintext: [u8; 256] = [0u8; 256];

    let ct_with_tag_left =
        mode_ccm::encrypt(&key_left, &nonce, &aad, &plaintext, 16).expect("valid params");
    let ct_with_tag_right =
        mode_ccm::encrypt(&key_right, &nonce, &aad, &plaintext, 16).expect("valid params");

    for _ in 0..sample_count() {
        let (class, key, ct) = if rng.random::<bool>() {
            (Class::Left, &key_left, &ct_with_tag_left)
        } else {
            (Class::Right, &key_right, &ct_with_tag_right)
        };
        runner.run_one(class, || {
            mode_ccm::decrypt(key, &nonce, &aad, ct, 16)
                .expect("dudect: valid (ct, tag) must verify")
        });
    }
}

/// v0.9 W3 — incremental-input buffered SM4-GCM decrypt diagnostic
/// (Q9.5 of `docs/v0.9-scope.md`). Same class-split-by-key shape as
/// `ct_sm4_gcm_decrypt`; both classes' (chunked ct, tag) verify under
/// their own key so both reach `finalize_verify` via identical
/// control flow. Drives the buffered decryptor in two chunks to
/// exercise the partial-block GHASH accumulator path. Exercises key
/// schedule, `H = SM4_E(key, 0^128)`, the running GHASH (rides CLMUL on
/// `x86_64` / PMULL on `aarch64` / software Karatsuba elsewhere), GCTR,
/// and the constant-time tag compare. `|tau| < 0.20`.
#[cfg(feature = "sm4-aead")]
fn ct_sm4_gcm_decrypt_buffered(runner: &mut CtRunner, rng: &mut BenchRng) {
    use gmcrypto_core::sm4::{Sm4GcmDecryptor, mode_gcm};

    let key_left: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let key_right: [u8; 16] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let aad: [u8; 16] = [0xAA; 16];
    let plaintext: [u8; 256] = [0u8; 256];

    let (ct_left, tag_left) = mode_gcm::encrypt(&key_left, &nonce, &aad, &plaintext);
    let (ct_right, tag_right) = mode_gcm::encrypt(&key_right, &nonce, &aad, &plaintext);

    for _ in 0..sample_count() {
        let (class, key, ct, tag) = if rng.random::<bool>() {
            (Class::Left, &key_left, &ct_left, &tag_left)
        } else {
            (Class::Right, &key_right, &ct_right, &tag_right)
        };
        runner.run_one(class, || {
            let mut dec = Sm4GcmDecryptor::new(key, &nonce, &aad);
            // Two chunks: 100 bytes then the rest — straddles block
            // boundaries so the partial-block GHASH path is exercised.
            dec.update(&ct[..100]);
            dec.update(&ct[100..]);
            dec.finalize_verify(tag)
                .expect("dudect: valid (ct, tag) must verify")
        });
    }
}

/// HMAC-SM3 diagnostic. Class-split by key bytes; fixed message.
/// HMAC moves the secret key into both inner and outer SM3 hash
/// invocations (`K' XOR ipad` and `K' XOR opad`), so a key-dependent
/// timing leak shows up here. PBKDF2-HMAC-SM3 (W4) is covered by this
/// target's inner PRF — no separate `ct_pbkdf2_hmac_sm3` target.
fn ct_hmac_sm3(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key_left: [u8; 32] = [0x42u8; 32];
    let key_right: [u8; 32] = [0xa5u8; 32];
    // Fixed 64-byte message — exercises one full SM3 block of HMAC's
    // inner-hash input plus the per-block padding.
    let message: [u8; 64] = [0u8; 64];
    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_left)
        } else {
            (Class::Right, &key_right)
        };
        runner.run_one(class, || hmac_sm3(key, &message));
    }
}

/// SM2 decrypt diagnostic. Class-split by recipient private key `d_B`;
/// fixed ciphertext (encrypted to a **third** key's public key, so both
/// classes fail decryption at the MAC check via the same code path).
/// Timing differential is purely on `d_B`'s bits — the secret-touching
/// scalar mult `mul_var(d_B, C1)` plus `to_affine`'s `Fp::invert` are
/// the dominant constant-time-relevant work.
fn ct_sm2_decrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key_left = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
    ))
    .expect("valid d for class Left");
    let key_right = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    ))
    .expect("valid d for class Right");
    // Encrypt to a THIRD party so that both classes fail at the MAC
    // check via identical control flow. The class label then identifies
    // only `d_B`; nothing else.
    let recipient_priv = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "B9E5B7C12E48BAB7CC0E91A57F8A48E8C8F87DDD25EBF52F2A75E612CB1A9E4F",
    ))
    .expect("valid d for recipient");
    let recipient_pk = Sm2PublicKey::from_point(recipient_priv.public_key());
    let mut sys_rng = UnwrapErr(SysRng);
    let ciphertext =
        encrypt(&recipient_pk, b"timing target", &mut sys_rng).expect("encrypt to recipient");

    for _ in 0..sample_count() {
        let (class, key) = if rng.random::<bool>() {
            (Class::Left, &key_left)
        } else {
            (Class::Right, &key_right)
        };
        runner.run_one(class, || decrypt(key, &ciphertext));
    }
}

/// PKCS#8 decrypt diagnostic. Class-split by **password bytes**; both
/// classes use a **valid** encrypted blob (each class's blob was
/// produced under that class's password), so both sides succeed at
/// PBES2 + decode + scalar reconstruction via identical control flow.
/// The new W2 surface this target adds defense-in-depth on:
///
/// 1. PBKDF2-HMAC-SM3 over caller-supplied password (already
///    structurally covered by `ct_hmac_sm3`).
/// 2. SM4-CBC decrypt + PKCS#7 strip (already covered structurally
///    by `ct_sm4_*` + `mode_cbc::decrypt`'s subtle PKCS#7 strip).
/// 3. **New:** `ECPrivateKey` ASN.1 parse over derived plaintext bytes,
///    feeding into `Sm2PrivateKey::from_scalar`'s constant-time
///    range check (`from_scalar` renamed from `new` in v0.5 W5).
///
/// Iteration count is held at 1024 — low enough to keep the per-sample
/// cost manageable, high enough that PBKDF2 dominates the timed
/// window (matches `kdf::pbkdf2_hmac_sm3` smoke test budgets).
fn ct_pkcs8_decrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = Sm2PrivateKey::from_scalar(U256::from_be_hex(
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    ))
    .expect("valid d");

    let salt: [u8; 16] = [0xAB; 16];
    let iv: [u8; 16] = [0xCD; 16];
    let iterations = 1024u32;

    let pw_left: [u8; 16] = [0x42; 16];
    let pw_right: [u8; 16] = [0xA5; 16];
    let blob_left = pkcs8::encrypt(&key, &pw_left, &salt, iterations, &iv).expect("encrypt left");
    let blob_right =
        pkcs8::encrypt(&key, &pw_right, &salt, iterations, &iv).expect("encrypt right");

    for _ in 0..sample_count() {
        let (class, pw, blob) = if rng.random::<bool>() {
            (Class::Left, &pw_left, &blob_left)
        } else {
            (Class::Right, &pw_right, &blob_right)
        };
        runner.run_one(class, || {
            // Both classes succeed; the only timing differential is in
            // the secret-touching PBKDF2 + SM4-CBC paths and the ASN.1
            // parse over the derived plaintext.
            pkcs8::decrypt(blob, pw)
        });
    }
}

/// Custom `main` (instead of `ctbench_main!`) so we can pre-filter `--bench`
/// from argv. `cargo bench` injects `--bench` as the first arg by libtest
/// convention; dudect-bencher's clap parser doesn't recognize it and would
/// error out.
#[allow(clippy::too_many_lines)] // bench registry is declarative; splitting hurts clarity
fn main() {
    // Drop libtest-convention args that dudect-bencher doesn't understand.
    // `--bench` is the only one cargo currently injects, but include the
    // related flags that may appear in future cargo versions.
    let args: Vec<String> = std::env::args()
        .filter(|a| !matches!(a.as_str(), "--bench" | "--test"))
        .collect();

    // Manual flag parsing: dudect-bencher supports --filter <STR>,
    // --continuous [STR], --out <FILE>. Parse just what we need; anything
    // else is ignored.
    let mut filter: Option<String> = None;
    let mut continuous = false;
    let mut file_out: Option<std::path::PathBuf> = None;
    let mut iter = args.iter().skip(1); // skip program name
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--filter" => {
                filter = iter.next().cloned();
            }
            "--continuous" => {
                continuous = true;
                // optional next arg
                if let Some(next) = iter.clone().next() {
                    if !next.starts_with("--") {
                        filter = iter.next().cloned();
                    }
                }
            }
            "--out" => {
                file_out = iter.next().map(std::path::PathBuf::from);
            }
            _ => { /* ignore */ }
        }
    }

    #[allow(unused_mut)] // mutated only under feature = "sm4-bitsliced-simd"
    let mut benches = vec![
        BenchMetadata {
            name: BenchName("negative_control"),
            seed: None,
            benchfn: negative_control,
        },
        BenchMetadata {
            name: BenchName("ct_mul_g"),
            seed: None,
            benchfn: ct_mul_g,
        },
        BenchMetadata {
            name: BenchName("ct_mul_var"),
            seed: None,
            benchfn: ct_mul_var,
        },
        BenchMetadata {
            name: BenchName("ct_sign"),
            seed: None,
            benchfn: ct_sign,
        },
        BenchMetadata {
            name: BenchName("ct_sign_k_class"),
            seed: None,
            benchfn: ct_sign_k_class,
        },
        BenchMetadata {
            name: BenchName("ct_fn_invert"),
            seed: None,
            benchfn: ct_fn_invert,
        },
        BenchMetadata {
            name: BenchName("ct_fp_invert"),
            seed: None,
            benchfn: ct_fp_invert,
        },
        BenchMetadata {
            name: BenchName("ct_sm4_key_schedule"),
            seed: None,
            benchfn: ct_sm4_key_schedule,
        },
        BenchMetadata {
            name: BenchName("ct_sm4_encrypt_block"),
            seed: None,
            benchfn: ct_sm4_encrypt_block,
        },
        BenchMetadata {
            name: BenchName("ct_sm4_ctr_encrypt"),
            seed: None,
            benchfn: ct_sm4_ctr_encrypt,
        },
        BenchMetadata {
            name: BenchName("ct_hmac_sm3"),
            seed: None,
            benchfn: ct_hmac_sm3,
        },
        BenchMetadata {
            name: BenchName("ct_sm2_decrypt"),
            seed: None,
            benchfn: ct_sm2_decrypt,
        },
        BenchMetadata {
            name: BenchName("ct_pkcs8_decrypt"),
            seed: None,
            benchfn: ct_pkcs8_decrypt,
        },
    ];

    // v0.5 W4 — append the SIMD-packed-bitsliced target only when the
    // feature is on. Phase 1 measures the same byte sequence as
    // `ct_sm4_encrypt_block` under `sm4-bitsliced`; phase 2 / phase 3
    // swap the inner body. The gate stays at `|tau| < 0.20` across
    // all three phases (Q5.14).
    #[cfg(feature = "sm4-bitsliced-simd")]
    benches.push(BenchMetadata {
        name: BenchName("ct_sm4_encrypt_block_bitsliced_simd"),
        seed: None,
        benchfn: ct_sm4_encrypt_block_bitsliced_simd,
    });

    // v0.6 W6 — CBC-decrypt SIMD-fanout target (Q6.7). Measures the
    // `Sm4CbcDecryptor::decrypt_batch` path that batches
    // `SIMD_BATCH` ciphertext blocks through `sbox_x32` (x86_64) or
    // `sbox_x16` (aarch64). Same `|tau| < 0.20` gate as the rest
    // of the SM4 surface; class-split by master key.
    #[cfg(feature = "sm4-bitsliced-simd")]
    benches.push(BenchMetadata {
        name: BenchName("ct_sm4_cbc_decrypt_fanout"),
        seed: None,
        benchfn: ct_sm4_cbc_decrypt_fanout,
    });

    // v0.8 W4 — SM4-GCM / SM4-CCM decrypt targets (Q8.7). Cfg-gated
    // on `sm4-aead`; class-split by master key with valid (ct, tag)
    // pairs for both classes (no failure-path divergence). Same
    // `|tau| < 0.20` gate as the rest of the SM4 surface.
    #[cfg(feature = "sm4-aead")]
    benches.push(BenchMetadata {
        name: BenchName("ct_sm4_gcm_decrypt"),
        seed: None,
        benchfn: ct_sm4_gcm_decrypt,
    });
    #[cfg(feature = "sm4-aead")]
    benches.push(BenchMetadata {
        name: BenchName("ct_sm4_ccm_decrypt"),
        seed: None,
        benchfn: ct_sm4_ccm_decrypt,
    });

    // v0.9 W3 — incremental-input buffered SM4-GCM decrypt target
    // (Q9.5). Same class-split-by-key shape + `|tau| < 0.20` gate;
    // drives `Sm4GcmDecryptor` (commit-on-verify) instead of the
    // single-shot `mode_gcm::decrypt`.
    #[cfg(feature = "sm4-aead")]
    benches.push(BenchMetadata {
        name: BenchName("ct_sm4_gcm_decrypt_buffered"),
        seed: None,
        benchfn: ct_sm4_gcm_decrypt_buffered,
    });

    let opts = BenchOpts {
        continuous,
        filter,
        file_out,
    };

    run_benches_console(opts, benches).expect("run_benches_console");
}
