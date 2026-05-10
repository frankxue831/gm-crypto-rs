//! `dudect-bencher` detectable-leak regression harness.
//!
//! Seven targets, listed in the order the harness sorts them (alphabetical):
//!
//! - `ct_fn_invert`     — direct `Fn::invert((1+d) mod n)` diagnostic.
//! - `ct_fp_invert`     — direct `Fp::invert(Z)` diagnostic.
//! - `ct_mul_g`         — fixed-base scalar multiplication `k·G`.
//! - `ct_mul_var`       — variable-base scalar multiplication `k·P`.
//! - `ct_sign`          — `sign_raw_with_id`, class-split by private key `d`.
//! - `ct_sign_k_class`  — `sign_raw_with_id`, class-split by nonce `k` magnitude
//!   (`d` held fixed, both retry nonces class-tied via [`ClassKRng`]).
//! - `negative_control` — deliberately-leaky function. The harness MUST flag
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
//! ```text
//! cargo bench --bench timing_leaks                          # 100K samples each (default)
//! DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks     # PR-smoke budget
//! DUDECT_SAMPLES=100000 cargo bench --bench timing_leaks    # nightly budget
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
use gmcrypto_core::sm2::{
    DEFAULT_SIGNER_ID, Fn as Scalar, Fp, ProjectivePoint, Sm2PrivateKey, mul_g, mul_var,
    sign_raw_with_id,
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
    let key_small = Sm2PrivateKey::new(U256::from_be_hex(
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
    ))
    .expect("sample D in [1, n-2]");
    let key_large = Sm2PrivateKey::new(U256::from_be_hex(
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
    let key = Sm2PrivateKey::new(U256::from_be_hex(
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

/// Custom `main` (instead of `ctbench_main!`) so we can pre-filter `--bench`
/// from argv. `cargo bench` injects `--bench` as the first arg by libtest
/// convention; dudect-bencher's clap parser doesn't recognize it and would
/// error out.
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

    let benches = vec![
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
    ];

    let opts = BenchOpts {
        continuous,
        filter,
        file_out,
    };

    run_benches_console(opts, benches).expect("run_benches_console");
}
