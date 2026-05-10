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
//! # `ConstMontyForm::invert` posture across `crypto-bigint` versions
//!
//! Published v0.1.0 ships against `crypto-bigint = 0.6`, where direct
//! measurement on this harness showed `|tau| ≈ 0.70` for
//! `Fn::invert((1+d) mod n)` between two random non-degenerate `d`
//! values. Inside `sign_raw_with_id`, where invert is ~1-2% of total
//! sign time, that signal diluted to `|tau| ≈ 0.04-0.14` — under the
//! 0.20 gate, so `ct_sign` passed.
//!
//! Main has since upgraded to `crypto-bigint = 0.7.3`. Re-measurement
//! at 100K samples shows isolated `Fn::invert` at `|tau| ≈ 0.006-0.010`
//! and `ct_sign` at `|tau| ≈ 0.01-0.03` — both comfortably under the
//! 0.20 gate, with the upstream isolated invert leak now below the
//! harness's detection threshold.
//!
//! # Honest admission: this class-split is blind to nonce-path leaks
//!
//! This is independent of which `crypto-bigint` version is in use —
//! it is a property of how `ct_sign` splits its test classes.
//!
//! `ct_sign` splits its two classes by private key `d` and lets the
//! per-sample nonce `k` be fresh-random in every sample of every class.
//! This catches the `(1+d).invert()` leak (diluted on 0.6, no longer
//! detectable on 0.7.3), but it is **structurally blind** to a
//! nonce-only leak — for example the `Fp::invert(Z)` inside
//! `kg.to_affine()` after `mul_g(k)`, where `Z` is derived from the
//! secret `k`. Such a leak distributes uniformly across both classes
//! and cannot show up as a between-class timing difference.
//!
//! `ct_mul_g` / `ct_mul_var` are class-split by scalar magnitude and
//! so partially exercise the nonce path, but they don't call
//! `to_affine` inside the timed window, so they also miss this site.
//!
//! A `ct_sign` pass is therefore **not** evidence that signing is
//! leak-free on the nonce path. With 0.6 it meant the `(1+d)` invert
//! leak stayed under the gate at current sign-step proportions; with
//! 0.7.3 it means the same leak has gone below noise. In neither case
//! does it speak to a `k`-only leak. See `SECURITY.md`'s
//! "`ConstMontyForm::invert` posture" section for the full picture.
//!
//! v0.2 reworks the harness to add a class split by `k` (with `d`
//! held fixed) to specifically exercise the nonce path the existing
//! class layout cannot see. The original v0.2 plan to also replace
//! both invert sites with a Fermat-invert via `pow_bounded_exp` is no
//! longer load-bearing on 0.7.3, but may still ship as
//! defense-in-depth once the `k`-class target validates whether
//! site (2) actually leaks under direct measurement.
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
//! CI workflows parse this with a regex pinned to `^bench\s+(\S+)\s*:.*?max t = ([+-]\d+\.\d+)`.

use crypto_bigint::U256;
use dudect_bencher::ctbench::{BenchMetadata, BenchName, BenchOpts, run_benches_console};
use dudect_bencher::{BenchRng, Class, CtRunner, rand::RngExt};
use getrandom::SysRng;
use gmcrypto_core::sm2::{
    DEFAULT_SIGNER_ID, Fn as Scalar, ProjectivePoint, Sm2PrivateKey, mul_g, mul_var,
    sign_raw_with_id,
};
use rand_core::UnwrapErr;

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
    // Small scalar (k=1) vs large scalar (k=n-1). Both are valid private-key
    // scalars; a constant-time fixed-window scalar mult should produce
    // indistinguishable timing distributions.
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
    ];

    let opts = BenchOpts {
        continuous,
        filter,
        file_out,
    };

    run_benches_console(opts, benches).expect("run_benches_console");
}
