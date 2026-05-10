# CLAUDE.md

Pure-Rust SM2/SM3 SDK. **v0.1.0 published to crates.io 2026-05-10** (on
`crypto-bigint 0.6`). `main` is now on `0.7.3` for v0.2 prep — the version
landed in `a670ce3` / `89abfb9` / `22b77a2` post-publish; the published 0.1.0
tarball is unchanged. Single-crate workspace: `crates/gmcrypto-core/`.

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file lists the constraints a coding agent will violate by default.

## Hard constraints (non-negotiable)

- `unsafe_code = "forbid"` workspace-wide. Don't add `unsafe`.
- `#![no_std]` + `alloc` only inside `crates/gmcrypto-core/src/`. No `std::` paths.
  The `std` feature exists but is reserved for v0.3+ wire-format I/O.
- **Constant-time discipline on secrets.** Never `==` / `if` / Rust `bool` on a
  secret-derived value. Use `subtle::{Choice, ConditionallySelectable,
  ConstantTimeEq, ConstantTimeLess, CtOption}`. The SM2 sign retry loop runs
  a fixed `K=2` iterations regardless of which (if any) candidate is valid.
- **Failure-mode invariant.** `verify_with_id` returns `bool` (never `Result`).
  `SignError` has exactly one variant (`Failed`). DER decode returns `Option`,
  never specific error variants. PRs that distinguish failure modes get rejected
  on sight — see `SECURITY.md`. Don't make errors "more helpful."
- `Cargo.lock` is **gitignored** (lib-crate policy). Don't `git add` it.
  For `cargo deny` runs, generate via `cargo generate-lockfile` first.
- MSRV is **1.85**, edition **2024** (post-publish bump in `89abfb9`).
  `crypto-bigint 0.7` requires 1.85.
- `sign_raw_with_id` is `#[doc(hidden)] pub` for the dudect harness only and is
  **not covered by SemVer**. Don't expand its surface or expose it publicly.

## Commands (project-specific gotchas)

```bash
# Tests — note: NOT --all-targets. That runs benches in test mode and the
# CI 15-min timeout was hit during v0.1 prep. `cargo build --all-targets`
# is fine; `cargo test --all-targets` is not.
cargo test --workspace

# Format / lint — match CI exactly.
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Supply chain — note: --exclude-dev (dev-deps are exempt from the ban list).
cargo deny check --exclude-dev

# MSRV reproducibility.
cargo +1.85 build -p gmcrypto-core
cargo build -p gmcrypto-core --no-default-features  # confirms no_std posture

# Dudect harness. Default 100K samples (~75s); CI smoke uses 10K.
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks   # PR-smoke budget
DUDECT_SAMPLES=100000 cargo bench --bench timing_leaks   # nightly budget

# gmssl interop (gated; needs gmssl 3.1.1 installed).
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl
```

## Dudect harness gate

Located at `crates/gmcrypto-core/benches/timing_leaks.rs`. Ten targets:

| Target | Gate | Meaning |
|---|---|---|
| `negative_control` | `\|tau\| > 1.0` | MUST fire — proves harness wiring. |
| `ct_mul_g` | `\|tau\| < 0.20` | Fixed-base scalar mult. |
| `ct_mul_var` | `\|tau\| < 0.20` | Variable-base scalar mult. |
| `ct_sign` | `\|tau\| < 0.20` | `sign_raw_with_id`, class-split by private key `d` (NOT `sign_with_id` — DER is variable-time on public output). |
| `ct_sign_k_class` | `\|tau\| < 0.20` | `sign_raw_with_id`, class-split by nonce `k` magnitude with `d` held fixed (W0; both retry nonces class-tied). |
| `ct_fn_invert` | `\|tau\| < 0.20` | Direct `Fn::invert((1+d) mod n)` diagnostic (W0). |
| `ct_fp_invert` | `\|tau\| < 0.20` | Direct `Fp::invert(Z)` diagnostic (W0). |
| `ct_sm4_key_schedule` | `\|tau\| < 0.20` | SM4 key schedule, class-split by master key bytes (W1). |
| `ct_sm4_encrypt_block` | `\|tau\| < 0.20` | SM4 "construct cipher + encrypt one block" timed under one window, class-split by master key bytes (W1). |
| `ct_hmac_sm3` | `\|tau\| < 0.20` | HMAC-SM3 keyed MAC, class-split by master key (W3). Structurally covers PBKDF2-HMAC-SM3's (W4) inner PRF. |

Gate on **`|tau|`** (scale-free), not `|t|` (grows as `tau · sqrt(N)` so any
fixed `|t|` threshold is budget-dependent). Same gate at every sample budget;
more samples = tighter empirical confidence on the same threshold.

## v0.1 timing-leak narrative — resolved on main by the 0.7 upgrade

Published v0.1.0 (on `crypto-bigint = 0.6`) measured `|tau| ≈ 0.70` directly
on `ConstMontyForm::invert`. Main is on `0.7.3` and the v0.2 W0 harness
expansion (`ct_sign_k_class`, `ct_fn_invert`, `ct_fp_invert`) closed the
structural blind spot. At 100K samples on main:

| target | `\|tau\|` |
|---|---|
| `ct_fn_invert` | 0.0071 |
| `ct_fp_invert` | 0.0063 |
| `ct_sign_k_class` | 0.0708 |
| `ct_sign` | 0.0044 |

All four under the 0.10 W5 Branch A threshold; two orders of magnitude under
the 0.20 gate. The v0.2 Fermat-invert workstream was dropped on this evidence.
`pow_bounded_exp` remains a fallback if a future `crypto-bigint` release
regresses on this gate. See `SECURITY.md` for the full posture.

The three secret-touching `invert` sites:

1. `Fn::invert((1+d) mod n)` in `sign_raw_with_id` — secret-dependent. Now
   directly diagnosable via `ct_fn_invert`.
2. `Fp::invert(Z)` in `to_affine()` after `mul_g(k)` — nonce-dependent. Now
   directly diagnosable via `ct_fp_invert`; sign-level diagnosable via
   `ct_sign_k_class`.
3. `Fp::invert(Z)` in `to_affine()` from `compute_z` — public input, harmless.

## Architecture map

```
crates/gmcrypto-core/
  src/
    lib.rs
    sm3.rs                  # single-file SM3 hash
    sm2/
      curve.rs              # Fp, Fn (ConstMontyForm wrappers), curve constants
      point.rs              # ProjectivePoint + RCB add/double (eprint 2015/1060)
      scalar_mul.rs         # mul_g (fixed-base, delegates to mul_var in v0.1) + mul_var
      private_key.rs        # Sm2PrivateKey + ZeroizeOnDrop
      public_key.rs         # Sm2PublicKey
      sign.rs               # sign_with_id, sign_raw_with_id, compute_z, MAX_ID_LEN
      verify.rs             # verify_with_id (returns bool, rejects identity pubkey + over-long ID)
    sm4/                    # v0.2 W1
      cipher.rs             # Sm4Cipher (block cipher) + subtle linear-scan S-box
      mode_cbc.rs           # encrypt/decrypt with PKCS#7 padding; caller-supplied unpredictable IV
    hmac.rs                 # v0.2 W3 — HMAC-SM3 (single-shot, RFC 2104, gmssl-cross-validated)
    kdf.rs                  # v0.2 W4 — PBKDF2-HMAC-SM3 (caller-supplied output buffer)
    asn1/
      sig.rs                # SEQUENCE { r, s } with strict canonical INTEGER
  benches/timing_leaks.rs   # dudect harness (custom main; --bench is filtered out)
  tests/                    # integration tests (incl. gated gmssl interop)

.github/workflows/
  ci.yml                    # build/test on stable + 1.85 MSRV; deny --exclude-dev
  dudect-pr.yml             # 10K samples, |tau| gate, path-allowlisted
  dudect-nightly.yml        # 100K samples, same gate, 30-day artifact retention

docs/v0.1.0-release-review.md  # pre-publish reviewer checklist (template for v0.2)
```

`getrandom` is a direct workspace dep (`0.4.2`, `sys_rng` feature) — added
alongside the `rand_core 0.10` upgrade in `a670ce3` because `rand_core` no
longer ships `getrandom` integration in the same crate.

## Workflow notes

- Branch model: direct commits to `main` for the maintainer; external PRs go
  through CI + dudect-pr.yml. The dudect smoke is path-allowlisted so doc-only
  PRs skip the bench job.
- Tags are SSH-signed (`gpg.format = ssh`). Verify locally with
  `git tag -v vX.Y.Z` after configuring `gpg.ssh.allowedSignersFile`.
- `cargo publish` is the irreversible step. Use `docs/v0.1.0-release-review.md`
  as the template before publishing v0.2.

## Don't

- Don't add a `Cargo.toml` `authors` field (privacy — removed at `982a2fc`).
- Don't reduce the SM2 retry-loop iteration count or short-circuit on first valid
  candidate. Fixed-K masked-select is the constant-time invariant.
- Don't reference any external "Java prototype" / `gm-crypto-lite-java` repo.
  The Rust repo is standalone; that prototype was personal scaffolding.
- Don't replace the SM4 `subtle`-style linear-scan S-box with a direct LUT
  ("just for performance"). The throughput trade is documented as deliberate;
  bitsliced S-box is the v0.4 fast-path workstream — not v0.2.
- Don't generate the SM4-CBC IV inside `mode_cbc::encrypt`. Per NIST SP 800-38A
  Appendix C, CBC IVs must be **unpredictable** and caller-supplied; smuggling
  an `OsRng` into the API hides the contract from callers and conflates
  primitive-level concerns with RNG selection.
- Don't make `mode_cbc::decrypt` distinguish between failure modes (length
  not multiple of 16, bad pad_len, inconsistent padding bytes). Single `None`
  per the failure-mode invariant — anything else is a padding-oracle vector.
- Don't add an iteration-count default to `pbkdf2_hmac_sm3`. Defaults age
  badly (the OWASP baseline shifts every 2-3 years); callers pick. The API
  takes `iterations: u32` for a reason.
- Don't make `pbkdf2_hmac_sm3` allocate the output buffer. The
  caller-supplied `&mut [u8]` is the API contract — it kills the
  allocation-failure question and matches RustCrypto's pbkdf2 discipline.
- Don't make `hmac_sm3` a streaming `HmacSm3::new`/`update`/`finalize` shape
  in v0.2. Streaming `Mac` trait wiring lands in v0.3 alongside the broader
  trait generalization.
