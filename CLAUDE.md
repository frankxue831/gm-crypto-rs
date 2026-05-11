# CLAUDE.md

Pure-Rust SM2/SM3/SM4 SDK. **v0.1.0 published to crates.io 2026-05-10**;
**v0.2.0 published 2026-05-10**; **v0.3.0 prep on `main` 2026-05-11**
(W1 reusable ASN.1 reader/writer, W2 PEM/PKCS#8/SPKI/SEC1, W3 full
bidirectional gmssl interop, W4 raw byte-concat ciphertext, W5
streaming traits + HmacSm3 + Sm4Cbc{En,De}cryptor, W6 comb-table
`mul_g`). Single-crate workspace: `crates/gmcrypto-core/`.

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file lists the constraints a coding agent will violate by default.

## Hard constraints (non-negotiable)

- `unsafe_code = "forbid"` workspace-wide. Don't add `unsafe`.
- `#![no_std]` + `alloc` only inside `crates/gmcrypto-core/src/`. No `std::` paths.
  The `std` feature exists but is reserved for future file-I/O wire-format
  helpers (v0.4+).
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

Located at `crates/gmcrypto-core/benches/timing_leaks.rs`. **Twelve
targets** (v0.3 added `ct_pkcs8_decrypt`):

| Target | Gate | Meaning |
|---|---|---|
| `negative_control` | `\|tau\| > 1.0` | MUST fire — proves harness wiring. |
| `ct_mul_g` | `\|tau\| < 0.20` | Fixed-base scalar mult. v0.3 W6 replaced the body with a comb-table walk; constant-time-designed lookup preserved. 10K-sample smoke after W6: `\|tau\| ≈ 0.04`. |
| `ct_mul_var` | `\|tau\| < 0.20` | Variable-base scalar mult. |
| `ct_sign` | `\|tau\| < 0.20` | `sign_raw_with_id`, class-split by private key `d` (NOT `sign_with_id` — DER is variable-time on public output). |
| `ct_sign_k_class` | nightly only: `\|tau\| < 0.25` | `sign_raw_with_id`, class-split by nonce `k` magnitude with `d` held fixed (W0; both retry nonces class-tied). v0.4 release-prep: **dropped from the PR-smoke (10K) allowlist** — observed values span [0.21–0.37] across seven runs on the GH Actions ubuntu-24.04 runner, with no structure tied to code changes. The 100K nightly gate at 0.25 is retained (signal-to-noise is meaningful there). The direct invert diagnostics (`ct_fn_invert` / `ct_fp_invert`) are the actual invert-leak regression guards at the PR budget; `ct_sign_k_class` is a composite that dilutes invert signal by ~50× per the v0.2 W0 analysis. The bench still runs (data lands in the artifact log) but doesn't gate at 10K. |
| `ct_fn_invert` | `\|tau\| < 0.20` | Direct `Fn::invert((1+d) mod n)` diagnostic (W0). |
| `ct_fp_invert` | `\|tau\| < 0.20` | Direct `Fp::invert(Z)` diagnostic (W0). |
| `ct_sm4_key_schedule` | `\|tau\| < 0.20` | SM4 key schedule, class-split by master key bytes (v0.2 W1). |
| `ct_sm4_encrypt_block` | `\|tau\| < 0.20` | SM4 "construct cipher + encrypt one block" timed under one window, class-split by master key bytes (v0.2 W1). |
| `ct_hmac_sm3` | `\|tau\| < 0.20` | HMAC-SM3 keyed MAC, class-split by master key (v0.2 W3). Structurally covers PBKDF2-HMAC-SM3's (v0.2 W4) inner PRF, the v0.3 W5 streaming `HmacSm3` (Q7.6 deliberately skipped a separate target), and the PBKDF2 sub-path of v0.3 W2's encrypted PKCS#8 path. |
| `ct_sm2_decrypt` | `\|tau\| < 0.20` | SM2 decrypt, class-split by recipient `d_B`, fixed ciphertext encrypted to a third party so both classes fail at MAC via identical control flow (v0.2 Phase 3). |
| `ct_pkcs8_decrypt` | `\|tau\| < 0.20` | Encrypted-PKCS#8 decrypt + parse, class-split by password bytes; both classes' blobs are valid for their class's password so both succeed via identical control flow (v0.3 W2). 10K-sample smoke: `\|tau\| ≈ 0.04`. |

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
    sm3.rs                  # single-file SM3 hash (impls v0.3 W5 Hash trait)
    sm2/
      curve.rs              # Fp, Fn (ConstMontyForm wrappers), curve constants
      point.rs              # ProjectivePoint + RCB add/double (eprint 2015/1060)
      scalar_mul.rs         # mul_g (v0.3 W6: comb-table walk) + mul_var
      comb_table.rs         # v0.3 W6 — precomputed 64×16 table for k·G, spin::Once lazy init
      private_key.rs        # Sm2PrivateKey + ZeroizeOnDrop; v0.3 W2 adds from_sec1_be / to_sec1_be (#[doc(hidden)], not-SemVer)
      public_key.rs         # Sm2PublicKey; v0.3 W2 adds from_sec1_bytes / to_sec1_uncompressed + ConstantTimeEq
      sign.rs               # sign_with_id, sign_raw_with_id, compute_z, MAX_ID_LEN
      verify.rs             # verify_with_id (returns bool, rejects identity pubkey + over-long ID)
      encrypt.rs            # v0.2 Phase 3 — encrypt() + KDF + point_on_curve (pub(crate) for W2/W4)
      decrypt.rs            # v0.2 Phase 3 — decrypt() with constant-time MAC compare, zeroize on fail
      raw_ciphertext.rs     # v0.3 W4 — encode_c1c3c2 / decode_c1c3c2 / decode_c1c2c3_legacy
    sm4/                    # v0.2 W1
      cipher.rs             # Sm4Cipher (block cipher) + subtle linear-scan S-box; v0.3 W5 impls BlockCipher trait
      mode_cbc.rs           # encrypt/decrypt with PKCS#7 padding; caller-supplied unpredictable IV
      cbc_streaming.rs      # v0.3 W5 — Sm4CbcEncryptor / Sm4CbcDecryptor (buffer-back-by-one on decrypt)
    hmac.rs                 # v0.2 W3 — single-shot hmac_sm3; v0.3 W5 — streaming HmacSm3 (impls Mac trait)
    kdf.rs                  # v0.2 W4 — PBKDF2-HMAC-SM3 (caller-supplied output buffer)
    asn1/
      reader.rs             # v0.3 W1 — strict-canonical DER reader primitives
      writer.rs             # v0.3 W1 — DER writer primitives (16 MiB ceiling)
      oid.rs                # v0.3 W1 — const-fn OID encoder + 7 algorithm-identifier OIDs
      sig.rs                # SEQUENCE { r, s } — ports over W1 reader/writer in v0.3
      ciphertext.rs         # GM/T 0009 SM2 ciphertext SEQUENCE — ports over W1 in v0.3
    pem.rs                  # v0.3 W2 — RFC 7468 PEM + embedded base64 (hand-rolled, no_std)
    spki.rs                 # v0.3 W2 — RFC 5280 SubjectPublicKeyInfo for SM2
    sec1.rs                 # v0.3 W2 — RFC 5915 ECPrivateKey + SEC1 uncompressed point (04||X||Y)
    pkcs8.rs                # v0.3 W2 — RFC 5958 OneAsymmetricKey + RFC 8018 PBES2 (PBKDF2-HMAC-SM3 + SM4-CBC)
    traits.rs               # v0.3 W5 — in-crate Hash / Mac / BlockCipher traits (RustCrypto fit deferred to v0.4)
  benches/timing_leaks.rs   # dudect harness — 12 targets (v0.3 added ct_pkcs8_decrypt)
  tests/                    # integration tests
    interop_gmssl.rs        # v0.2 HMAC/PBKDF2 + v0.3 W3 bidirectional SM2 sign/verify, SM2 encrypt/decrypt, SM4-CBC
    v0_3_pkcs8_kat.rs       # v0.3 W2 — gmssl 3.1.1 PKCS#8/SPKI fixture round-trip
    data/                   # v0.3 W2 binary KAT fixtures + regen recipe (Q7.9 decision)

.github/workflows/
  ci.yml                    # build/test on stable + 1.85 MSRV; deny --exclude-dev
  dudect-pr.yml             # 10K samples, |tau| gate, path-allowlisted
  dudect-nightly.yml        # 100K samples, same gate, 30-day artifact retention

docs/
  v0.1.0-release-review.md  # pre-publish reviewer checklist (template)
  v0.3-scope.md             # v0.3 scope doc + Q7.1–Q7.10 sign-off decisions
```

`getrandom` is a direct workspace dep (`0.4.2`, `sys_rng` feature) — added
alongside the `rand_core 0.10` upgrade in `a670ce3` because `rand_core` no
longer ships `getrandom` integration in the same crate.

`spin = "0.10"` (with `default-features = false, features = ["once"]`) is
a v0.3 W6 runtime dep — the only no_std-compatible, no-unsafe primitive
for the comb-table lazy init. Per Q7.8 it's the explicit alternative to
`std::sync::LazyLock` (forbidden in `no_std`) and `once_cell::race::OnceBox`.
Added to `deny.toml`'s allowlist with a comment pointing back to Q7.8.

## Workflow notes

- Branch model: direct commits to `main` for the maintainer; external PRs go
  through CI + dudect-pr.yml. The dudect smoke is path-allowlisted so doc-only
  PRs skip the bench job.
- Tags are SSH-signed (`gpg.format = ssh`). Verify locally with
  `git tag -v vX.Y.Z` after configuring `gpg.ssh.allowedSignersFile`.
- `cargo publish` is the irreversible step. Use `docs/v0.1.0-release-review.md`
  as the template before publishing v0.3.

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
- Streaming `HmacSm3` lands in v0.3 W5 alongside the in-crate `Mac` trait.
  v0.3+ keeps the single-shot `hmac_sm3` function for backward compat; do
  not remove it.
- Don't ship `encode_c1c2c3_legacy` in any version. The legacy byte
  concatenation `C1||C2||C3` is **decrypt-only** in v0.3 W4
  (`decode_c1c2c3_legacy`); adding an emit path would propagate the
  legacy ordering forever.
- Don't change `mul_g`'s public signature when working on `comb_table.rs`.
  The W6 invariant is "comb-table walk under an unchanged
  `pub fn mul_g(k: &Fn) -> ProjectivePoint`".
- Don't drop the W6 `spin::Once` lazy-init primitive for "just unsafe and
  faster". `unsafe_code = forbid` is non-negotiable; the comb-table init
  needs thread-safe one-time init, and `spin::Once` is the smallest crate
  that provides it. `std::sync::LazyLock` and `std::sync::OnceLock` are
  both `std` — forbidden in `no_std`. Hand-rolled init requires `unsafe`
  (raw pointer deref of `static mut` or `AtomicPtr`).
- Don't make `sm2::decrypt` distinguish failure modes (malformed DER,
  off-curve C1, all-zero KDF, MAC mismatch). Single `Failed` variant.
  Distinguishing them is a padding-oracle / invalid-curve attack vector.
- Don't drop the `point_on_curve` check on `C1` in `sm2::decrypt`. The
  invalid-curve attack leaks `d_B` bits via a small-order rogue subgroup;
  the check is the standard ECC defense.
- Don't expose the SM2 `kdf` (in `sm2::encrypt`) or `point_on_curve`
  helpers in the public API. `kdf` is `pub(super)` for `sm2::decrypt`'s
  use only; `point_on_curve` and `projective_from_affine` are
  `pub(crate)` (widened by W2 so `spki`/`sec1`/`raw_ciphertext` can
  reuse them at the import boundary). The top-level `kdf.rs` is reserved
  for PBKDF2.
- Don't make `pkcs8::decrypt` distinguish wrong-password from malformed-
  PEM from valid-PEM-but-bad-inner-ECPrivateKey. Single `Failed`
  variant per the failure-mode invariant — anything else is a
  password-oracle / inner-ASN.1 distinguishing-attack vector.
- Don't expose v0.3 W2's `Sm2PrivateKey::to_sec1_be` publicly without
  the `#[doc(hidden)]` marker. Per Q7.2 it's **not SemVer-stable** —
  same posture as `sign_raw_with_id`. Callers must zeroize the
  returned `[u8; 32]` themselves; document the contract on the method.

## Agent gotchas

- **MSRV 1.85** — don't use `Integer::is_multiple_of` (stable in 1.87).
  Use `n % m == 0` / `% m != 0`. Clippy catches it at PR time, but
  the detour wastes a fmt+clippy cycle.
- **`gmssl sm2keygen -out priv.pem`** writes the encrypted PKCS#8 to
  the file **and** prints the SPKI public key to stdout by default.
  Use `-pubout pub.pem` to capture it separately.
- **`gmssl sm2encrypt`** emits GM/T 0009 DER only. No `-binary` flag
  in 3.1.1 — a raw byte-concat W4 fixture cannot be sourced directly
  from gmssl.
- **Integration-test scratch dir** — use `env!("CARGO_TARGET_TMPDIR")`
  (cargo-managed; no `tempfile` dev-dep needed). v0.3 W3 interop
  tests use it.
- **Workspace version** lives at `[workspace.package].version` in the
  root `Cargo.toml`; all crates inherit via `version.workspace = true`.
  `cargo metadata --format-version 1` verifies the resolved version.
- **`cargo fmt --all` invalidates the Edit tool's file-state cache.**
  Re-Read any file you'll edit after running fmt, or Edit errors with
  "file has been modified since read".
- **Codex review prompts must stay short** (~500 words). Longer prompts
  silently hang for 25+ min with empty `--output-last-message` files
  and need `pkill -f "codex exec"`. Stack-rank focus questions; don't
  paste full file contents.
- **Stacked PRs**: `gh pr create --base <unmerged-branch>` targets an
  open PR's head. After the parent merges, GitHub auto-retargets the
  stacked PR to `main`. Used by v0.3 W2→W3 and the release-prep chain.
- **`pub(crate) const` inside a `pub(crate) mod`** trips
  clippy::pub-in-priv. Use plain `pub` on the inner items — the outer
  module's `pub(crate)` already gates visibility.
