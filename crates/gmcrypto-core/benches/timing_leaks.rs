//! `dudect-bencher` detectable-leak regression harness.
//!
//! Four targets, listed in the order the harness sorts them (alphabetical):
//!
//! - `ct_mul_g`         — fixed-base scalar multiplication `k·G`.
//! - `ct_mul_var`       — variable-base scalar multiplication `k·P`.
//! - `ct_sign`          — `sign_raw_with_id` (sign without DER encoding).
//! - `negative_control` — deliberately-leaky function. The harness MUST flag
//!   this — if it doesn't, the harness wiring is broken.
//!
//! # Honest framing
//!
//! This harness *detects* timing leaks; it does *not* prove constant-time.
//! Low `|t|` means the test could not detect a leak within the budget given,
//! **not** that no leak exists.
//!
//! # Known v0.1 limitation: `crypto-bigint`'s `ConstMontyForm::invert` is
//! not constant-time across different inputs.
//!
//! Direct measurement on this harness shows `|tau| ≈ 0.70` for
//! `Fn::invert((1+d) mod n)` between two random non-degenerate `d`
//! values. This is the dominant signal when invert is exercised in
//! isolation. Inside `sign_raw_with_id`, where invert is ~1-2% of total
//! sign time, the signal dilutes to `|tau| ≈ 0.04-0.14` — within the
//! harness's `|tau| < 0.20` gate, so `ct_sign` passes today.
//!
//! # Honest admission: this class-split is blind to nonce-path leaks
//!
//! `ct_sign` splits its two classes by private key `d` and lets the
//! per-sample nonce `k` be fresh-random in every sample of every class.
//! This catches the `(1+d).invert()` leak (diluted as above), but it
//! is **structurally blind** to a nonce-only leak — for example the
//! `Fp::invert(Z)` inside `kg.to_affine()` after `mul_g(k)`, where `Z`
//! is derived from the secret `k`. Such a leak distributes uniformly
//! across both classes and cannot show up as a between-class timing
//! difference.
//!
//! `ct_mul_g` / `ct_mul_var` are class-split by scalar magnitude and
//! so partially exercise the nonce path, but they don't call
//! `to_affine` inside the timed window, so they also miss this site.
//!
//! A `ct_sign` pass is therefore **not** evidence that signing is
//! leak-free on the nonce path. It is evidence only that the `(1+d)`
//! invert leak stays under the gate at current sign-step proportions.
//! See `SECURITY.md`'s "Known v0.1 limitation" section for the full
//! posture.
//!
//! v0.2 replaces both secret-touching invert sites with a Fermat-invert
//! via `pow_bounded_exp` (after first validating the `pow` path is
//! itself constant-time) and reworks the harness to add a class split
//! by `k` (with `d` held fixed) to specifically exercise the nonce
//! path the v0.1 class layout cannot see.
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
//! The output line emitted by `dudect-bencher` 0.6 for each bench is:
//!
//! ```text
//! bench <name>           : n == +X.XXXM, max t = +X.XXXXX, max tau = ..., (5/tau)^2 = ...
//! ```
//!
//! CI workflows parse this with a regex pinned to `^bench\s+(\S+)\s*:.*?max t = ([+-]\d+\.\d+)`.

use crypto_bigint::U256;
use dudect_bencher::ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts};
use dudect_bencher::{rand::Rng, BenchRng, Class, CtRunner};
use gmcrypto_core::sm2::{
    mul_g, mul_var, sign_raw_with_id, Fn as Scalar, ProjectivePoint, Sm2PrivateKey,
    DEFAULT_SIGNER_ID,
};
use rand_core::OsRng;

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
        let (class, input) = if rng.gen::<bool>() {
            (Class::Left, &left)
        } else {
            (Class::Right, &right)
        };
        runner.run_one(class, || leaky_function(input));
    }
}

fn ct_mul_g(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Small scalar (k=1) vs large scalar (k=n-1). Both are valid private-key
    // scalars; a constant-time fixed-window scalar mult should produce
    // indistinguishable timing distributions.
    let small = Scalar::new(&U256::ONE);
    let large = Scalar::new(&U256::from_be_hex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D5411E",
    ));
    for _ in 0..sample_count() {
        let (class, k) = if rng.gen::<bool>() {
            (Class::Left, &small)
        } else {
            (Class::Right, &large)
        };
        runner.run_one(class, || mul_g(k));
    }
}

fn ct_mul_var(runner: &mut CtRunner, rng: &mut BenchRng) {
    let small = Scalar::new(&U256::ONE);
    let large = Scalar::new(&U256::from_be_hex(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D5411E",
    ));
    let g = ProjectivePoint::generator();
    for _ in 0..sample_count() {
        let (class, k) = if rng.gen::<bool>() {
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
        let (class, key) = if rng.gen::<bool>() {
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
        // `run_one` takes `Fn` (immutable closure), so we can't capture
        // `&mut OsRng`. `OsRng` is a unit struct that delegates to
        // `getrandom`, so constructing it inside the closure is cheap.
        runner.run_one(class, || {
            sign_raw_with_id(key, DEFAULT_SIGNER_ID, b"timing target", &mut OsRng)
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

    // Manual flag parsing: dudect-bencher 0.6 supports --filter <STR>,
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
    ];

    let opts = BenchOpts {
        continuous,
        filter,
        file_out,
    };

    run_benches_console(opts, benches).expect("run_benches_console");
}
