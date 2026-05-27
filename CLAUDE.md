# CLAUDE.md

Pure-Rust SM2/SM3/SM4 SDK. **v0.15.0 published to crates.io 2026-05-28**
— **SM4-XTS multi-sector (disk) helper**: `sm4::mode_xts::{encrypt_sectors,
decrypt_sectors}` encrypt/decrypt a contiguous run of equal-size disk
sectors **in place** (`&mut [u8] -> Option<()>`), sector `i` under
tweak = **little-endian-128(`start_sector + i`)** (the standard disk-XTS
data-unit convention — matches the shipped `sm4_xts_sector.c` LE example +
IEEE 1619 / SP 800-38E; owns the encoding the v0.12 single-shot API left
to the caller). Byte-identical to looping the single-shot `encrypt`/
`decrypt` per sector (transitively OpenSSL `xts_standard=GB`-pinned); whole-
block sectors (no ciphertext stealing); ciphers built **once** via
`split_keys` + reused `[[u8;16]]` scratch (no per-sector alloc, no unsafe /
no `as_chunks_mut`); single `None` for **all** validation (`sector_size`
not a multiple of 16 / outside `[16,16 MiB]`; `buf.len()` not a whole
multiple; `Key1==Key2`; sector-number overflow) with **`buf` untouched**
(all validation pre-flighted before the loop); `buf.len()==0` → vacuous
`Some(())` (but key still validated, so empty + weak key → `None`).
**Confidentiality only — no auth.** Under the existing **`sm4-xts`**
feature: **no new dep, no new feature flag, no new SIMD, no new dudect
target** (`ct_sm4_xts_decrypt` covers the per-sector path — τ≈0.025).
Per `docs/v0.15-scope.md` Q15.1–Q15.12 (codex-reviewed W0+W1). C FFI
deferred to v0.16 (core-in-vN / FFI-in-vN+1 cadence). **crates.io skips
`0.14.0`** (the unpublished fuzzing cycle); workspace `version`
**0.13.0 → 0.15.0**. Default-features build byte-identical to 0.13.0.
**Earlier — v0.14 = parser-fuzzing assurance on `main`
2026-05-25 — NOT a crates.io release** (the initial `cargo-fuzz` sweep
found zero crashes, so the published crates are byte-unchanged; per
`docs/v0.14-scope.md` Q14.11 a clean run merges as infra/assurance and is
not published). New **workspace-excluded `fuzz/` crate** (`cargo-fuzz` /
libFuzzer, nightly-only, never in the published dep graph): **16 targets**
over the full untrusted-input decode/decrypt surface of `gmcrypto-core`
(PEM, PKCS#8 decode/decrypt, SPKI, SEC1, DER reader primitives, SM2 DER +
raw ciphertext, SM2 decrypt + verify, SM4-CBC/GCM/CCM/XTS decrypt), each
proving the failure-mode invariant on adversarial bytes — **no panic / no
OOM / no hang**. Capped nightly job `.github/workflows/fuzz-nightly.yml`
(cron + `workflow_dispatch`, self-hosted, pinned `cargo-fuzz 0.13.1`, NOT
a PR gate). Codex-reviewed W0+W1+W2+W3. Workspace `version` stays
**0.13.0** (no bump). The 3 published crates' default builds are
byte-identical; `cargo {build,test,clippy} --workspace`, `cargo deny`,
MSRV-1.85, and `cargo publish` are all unaffected by `fuzz/`.
**Earlier — v0.13.0 published 2026-05-24** —
**C FFI for SM4-XTS**: expose the v0.12 `sm4::mode_xts` core through the
`gmcrypto-c` C ABI behind a forwarding **`sm4-xts`** feature
(`= ["gmcrypto-core/sm4-xts"]`, no new dep), per `docs/v0.13-scope.md`
Q13.1–Q13.12 (codex-reviewed W0+W1+W2). Two new symbols
`gmcrypto_sm4_xts_encrypt`/`_decrypt` mirror the single-shot SM4-GCM FFI
shape minus nonce/AAD/tag: 32-byte key `Key1‖Key2` (via the new
always-on `GMCRYPTO_SM4_XTS_KEY_SIZE`=32 const), raw 16-byte tweak,
`data` ptr+len → length-preserving `(out,out_capacity,out_actual_len)`
output, byte-identical to core `mode_xts`. Single `GMCRYPTO_ERR`
(data_len ∉ [16,16MiB], `Key1==Key2`, null, or buffer-too-small →
`*out_actual_len`=required len). **Confidentiality only — no auth.**
`regen-header` does **NOT** need to imply `sm4-xts` (unlike v0.10's
cfg-gated opaque streaming structs): cbindgen emits free-fn prototypes +
the always-on `#define` from source regardless of cfg, so the committed
header just gains the 2 protos + 1 const and the drift gate stays green
under the existing `--features regen-header` command. 5 new c_smoke
tests (whole-block + CTS equivalence vs core + round-trip;
short/weak-key/small-buffer → ERR); doc-only example
`crates/gmcrypto-c/examples/sm4_xts_sector.c`. No new `gmcrypto-core`
API, **no new dudect target** (thin shim — core's `ct_sm4_xts_decrypt`
covers it), no new dep. Additive; default build of both crates
byte-unchanged.
**v0.12.0** — **SM4-XTS** (tweakable disk/sector mode): new `sm4::mode_xts::{encrypt,
decrypt}` + `XTS_KEY_SIZE` behind the opt-in **`sm4-xts`** feature
(pure-core, **no new dep**), per `docs/v0.12-scope.md` Q12.1–Q12.13
(codex-reviewed). **GB/T 17964-2021** (GM-T OID 1.2.156.10197.1.104.10),
**not IEEE 1619** — the two differ in the GF(2¹²⁸) tweak doubling: GB is
the **bit-reflected (GHASH-style)** convention (right-shift, reduce
`0xE1` into byte 0, masked-carry constant-time); IEEE is `<<1`/`0x87`.
Byte-identical to OpenSSL 3.x EVP `SM4-XTS` `xts_standard=GB` (KAT 16/32/
48/64 whole + 17/20/31 CTS; gmssl 3.1.1 lacks XTS → no interop test, the
v0.8 CCM-sourcing posture; oracle `crates/gmcrypto-core/tests/data/
sm4_xts_oracle.c` pins `xts_standard=GB`). 32-byte key `Key1‖Key2` + raw
16-byte tweak; **full ciphertext stealing** (CTS, lengths `[16 B,16 MiB]`
= NIST SP 800-38E 2²⁰-block ceiling); single `None` (len out of range or
`Key1==Key2`, stricter than OpenSSL's default provider which permits
equal halves); **confidentiality only — no auth tag**. Whole-block bulk
rides `Sm4Cipher::encrypt_blocks` (SIMD fanout under `sm4-bitsliced-simd`);
α-doubling is multiply-by-x in-core (not GHASH → no `gmcrypto-simd` dep).
New dudect `ct_sm4_xts_decrypt` (cfg `sm4-xts`, CTS-length, `|tau|<0.20`).
Also **fixed a latent CI bug**: `MATRIX_FEATURES` was `env`-scoped to the
dudect bench step only, so the parse step's `sm4-bitsliced-simd`/`sm4-aead`/
`sm4-xts` conditional gates never fired (since v0.5/v0.8) — re-declared on
the parse step in both dudect workflows. C FFI for XTS deferred to v0.13.
Additive; default-features build unaffected.
**v0.11.0** — **RustCrypto trait-fit modernization**: migrate the opt-in
`digest-traits` / `cipher-traits` impls from `digest 0.10` / `cipher 0.4`
to `digest 0.11` / `cipher 0.5` (the `crypto-common 0.2` / `hybrid-array`
generation), in-place, both deps together (per `docs/v0.11-scope.md`
Q11.1–Q11.11, codex-reviewed). `sm3.rs` `Digest` impl **unchanged**;
`hmac.rs` `crypto_common`→`common` re-export, and `Mac` is now a blanket
impl over `Update+FixedOutput+MacMarker` so HMAC construction moves to
`KeyInit::new_from_slice` (`digest 0.11`'s `Mac` dropped the `KeyInit`
supertrait — `HmacSm3` still impls `KeyInit`); `sm4/cipher.rs` backend
reshaped to cipher 0.5's **separate** `BlockCipherEncBackend` /
`BlockCipherDecBackend` (`BlockEncrypt`/`BlockDecrypt` →
`BlockCipherEncrypt`/`BlockCipherDecrypt`; `BlockCipher` marker removed;
`generic-array` → `hybrid-array` `Array`; `Sm4{Enc,Dec}Backend` re-wrap
the unchanged inherent `encrypt_block`/`decrypt_block`). Two new
trait-surface tests in `rustcrypto_traits.rs` (cipher-0.5 multi-block
backend + HMAC `KeyInit` key-length). **Default-features build unaffected;
byte-identical output** (full KAT + gmssl 3.1.1 interop 11/11). MSRV
stays 1.85 (whole new line declares `rust-version 1.85`); single
`crypto-common 0.2` in tree, **no `generic-array`** on the digest/cipher
path. No new `gmcrypto-core` public API; no new dudect target; opt-in
features only. **BREAKING for trait-fit consumers** (bump your own
`digest`/`cipher`). `aead 0.6` trait fit re-deferred (still 0.6.0-rc.10);
v0.11 lands the `crypto-common 0.2` line it will need.
**v0.10.0** — **streaming AEAD FFI for SM4-GCM** (exposes the v0.9
incremental-input buffered encryptor/decryptor through the `gmcrypto-c` C
ABI per Q9.6): 9 FFI symbols + 2 opaque handle types
(`gmcrypto_sm4_gcm_encryptor_{new,update,finalize,finalize_with_tag_len,
free}` output-streaming + `gmcrypto_sm4_gcm_decryptor_{new,update,
finalize_verify,free}` commit-on-verify), behind the `sm4-aead` feature
on `gmcrypto-c`. `_finalize*` consume+free; single `GMCRYPTO_ERR`;
`regen-header` **implies** `sm4-aead` (cbindgen drops cfg-gated opaque
struct types otherwise). C example
`crates/gmcrypto-c/examples/sm4_gcm_streaming.c`. Scope doc
`docs/v0.10-scope.md` (Q10.1–Q10.11). Additive only.
**v0.9.0** — **AEAD ergonomics** (extends the v0.8 AEAD core with the
three items v0.8 deferred): GCM tag-length parameterization via
`GcmTagLen` newtype + `mode_gcm::encrypt_with_tag_len` /
`decrypt_with_tag_len` (W1; NIST SP 800-38D §5.2.1.2 truncated tags
`{4,8,12,13,14,15,16}`) + incremental-input buffered SM4-GCM
`sm4::gcm_streaming::{Sm4GcmEncryptor, Sm4GcmDecryptor}` (W2; encryptor
output-streaming, decryptor output-buffered / commit-on-verify;
differential-KAT-equal to single-shot across arbitrary chunking) + new
dudect target `ct_sm4_gcm_decrypt_buffered` (W3) + 6 single-shot AEAD C
FFI symbols `gmcrypto_sm4_gcm_*` / `gmcrypto_sm4_ccm_*` behind a
forwarding `sm4-aead` feature on `gmcrypto-c` (W4). Scope doc
`docs/v0.9-scope.md` (Q9.1–Q9.10, codex-reviewed).
**v0.8.0 prep landed on `main` 2026-05-15** — AEAD core: SM4-GCM (NIST
SP 800-38D / GM/T 0009 / RFC 8998; byte-identical to gmssl 3.1.1
`sm4 -gcm`) + SM4-CCM (NIST SP 800-38C / RFC 3610 / GM/T 0009; byte-
identical to OpenSSL 3.x EVP `SM4-CCM` across 8 KAT scenarios since
gmssl 3.1.1 lacks `-ccm`) + GHASH primitive in `gmcrypto-simd::ghash`
(CLMUL on `x86_64` / PMULL on `aarch64` / software Karatsuba fallback)
+ dudect targets `ct_sm4_gcm_decrypt` / `ct_sm4_ccm_decrypt` + CI
matrix slot `sm4-bitsliced-simd,sm4-aead`. Sourcing-decision doc at
`docs/v0.8-ccm-kat-sourcing.md`.
Three-crate workspace:
`crates/gmcrypto-core/` (the no_std crypto core; default-member) +
`crates/gmcrypto-c/` (FFI shim; cdylib + staticlib + cbindgen header) +
`crates/gmcrypto-simd/` (SIMD backend; rlib-only, opt-in via
`gmcrypto-core`'s `sm4-bitsliced-simd` or `sm4-aead` feature).

**Throughput-win + AEAD arc retrospective (v0.5 → v0.12):**
v0.5.0 = W4 phase 1 scaffolding (transparent delegate).
v0.5.1 = W4 phase 2 (AVX2 `sbox_x8` in `gmcrypto-simd`, runtime detect).
v0.6.0 = W4 phase 3 / W6 (`sbox_x32` AVX2 + `sbox_x16` NEON + CBC-decrypt fanout).
v0.7.0 = cipher modes (public batch API + SM4-CTR + AEAD scope doc).
v0.8.0 = AEAD core (GHASH primitive + SM4-GCM + SM4-CCM single-shot).
v0.9.0 = AEAD ergonomics (GCM tag-len param + incremental-input buffered GCM + single-shot AEAD C FFI; per `docs/v0.9-scope.md` Q9.1–Q9.10).
v0.10.0 = streaming AEAD FFI for SM4-GCM (gmcrypto-c; 9 symbols + 2 opaque types exposing the v0.9 encryptor/decryptor to C; anchor-only per `docs/v0.10-scope.md` Q10.1–Q10.11).
v0.11.0 = RustCrypto trait-fit modernization (digest 0.10→0.11 / cipher 0.4→0.5; crypto-common 0.2 / hybrid-array; opt-in features only, byte-identical output; per `docs/v0.11-scope.md` Q11.1–Q11.11).
v0.12.0 = SM4-XTS single-shot tweakable disk/sector mode (GB/T 17964-2021 / GM-T OID 1.2.156.10197.1.104.10, **not** IEEE 1619 — bit-reflected α-doubling; full ciphertext stealing; byte-identical to OpenSSL EVP SM4-XTS xts_standard=GB; pure-core opt-in `sm4-xts`, no new dep; per `docs/v0.12-scope.md` Q12.1–Q12.13). Also fixed the latent dudect CI gate bug (MATRIX_FEATURES env scoping).
v0.13.0 = C FFI for SM4-XTS (`gmcrypto_sm4_xts_encrypt`/`_decrypt` + `GMCRYPTO_SM4_XTS_KEY_SIZE` in `gmcrypto-c` behind a forwarding `sm4-xts` feature; single-shot, byte-identical to core `mode_xts`, single `GMCRYPTO_ERR`, confidentiality-only; the deferred v0.12 FFI half on the v0.8-core→v0.10-FFI cadence; per `docs/v0.13-scope.md` Q13.1–Q13.12). No new `gmcrypto-core` API, no new dudect target, no new dep; additive.
v0.14 = parser fuzzing (`cargo-fuzz`/libFuzzer over the full untrusted-input decode/decrypt surface; 16 targets; failure-mode-invariant assurance — no panic/OOM/hang; per `docs/v0.14-scope.md` Q14.1–Q14.12). **Assurance/infra only — NOT a crates.io release** (initial sweep found zero crashes → published crates byte-unchanged → no version bump, no publish, per Q14.11). New workspace-excluded `fuzz/` crate + nightly CI; codex-reviewed W0–W3.
v0.15.0 = SM4-XTS multi-sector (disk) helper (`sm4::mode_xts::{encrypt_sectors, decrypt_sectors}`: in-place `&mut [u8] -> Option<()>` over a run of equal-size sectors, tweak_i = LE-128(start_sector + i); byte-identical to looping the v0.12 single-shot per sector; whole-block / no CTS; ciphers built once + reused scratch; single None with buf untouched; confidentiality-only; per `docs/v0.15-scope.md` Q15.1–Q15.12, codex-reviewed W0+W1). **Pure-core: no new dep/feature/SIMD/dudect target** (`ct_sm4_xts_decrypt` covers the per-sector path). C FFI deferred to v0.16. crates.io skips 0.14.0; workspace version 0.13.0 → 0.15.0; default build byte-identical.
v0.16+ = (candidate) C FFI for the SM4-XTS sector helper + round-trip/differential parser fuzzing + streaming-decryptor fuzzing + RustCrypto aead trait fit (blocked: aead still 0.6.0-rc.10) + pinned dudect runner + `cargo fuzz coverage` in CI + AVX-512 sbox_x64 + CCM buffered input + a v1.0 readiness pass (per `docs/v0.15-scope.md` §5/§6 Q16.x).

Read `README.md`, `SECURITY.md`, `CONTRIBUTING.md` for the user-facing posture.
This file lists the constraints a coding agent will violate by default.

## Hard constraints (non-negotiable)

- `unsafe_code = "forbid"` on `gmcrypto-core`. Don't add `unsafe`.
  **Exceptions** (both `unsafe_code = "warn"`, both with `// SAFETY:`
  comments per `unsafe` block):
  - `gmcrypto-c` (v0.4 W4 FFI shim) — raw-pointer FFI primitives
    (`Box::from_raw`, `#[unsafe(no_mangle)]`, slice reconstruction)
    cannot be expressed without `unsafe`.
  - `gmcrypto-simd` (v0.5 W4 phase 2 SIMD backend) — AVX2 (x86_64)
    and later NEON (aarch64) intrinsics from `core::arch::*` are
    `unsafe fn`; `#[target_feature(enable = "...")] unsafe fn` is
    the only stable-Rust mechanism on MSRV 1.85 to combine runtime
    CPU dispatch with intrinsic calls. See `docs/v0.5-scope.md`
    Q5.11 addendum for the architectural reset that landed
    alongside W4 phase 2.
- `#![no_std]` + `alloc` only inside `crates/gmcrypto-core/src/`. No `std::` paths.
  The reserved `std` Cargo feature flag was **removed in v0.5 W5
  (Q5.18)** — a no-op feature flag had negative documentation value.
  A future file-I/O helper would land under a specific name like
  `std-file-io`, not the generic `std`. `gmcrypto-c` is `std`-OK
  (it's the language-binding layer, not the no_std crypto primitives).
- **Constant-time discipline on secrets.** Never `==` / `if` / Rust `bool` on a
  secret-derived value. Use `subtle::{Choice, ConditionallySelectable,
  ConstantTimeEq, ConstantTimeLess, CtOption}`. The SM2 sign retry loop runs
  a fixed `K=2` iterations regardless of which (if any) candidate is valid.
- **Failure-mode invariant.** `verify_with_id` returns `bool` (never `Result`).
  Every fallible `Result`-returning public API uses the workspace-wide
  `gmcrypto_core::Error` (v0.5 W5) with a single `Failed` variant. Module
  aliases `sm2::Error`, `pem::Error`, `pkcs8::Error` all point at the same
  type. DER decode returns `Option`, never specific error variants. PRs
  that distinguish failure modes get rejected on sight — see
  `SECURITY.md`. Don't make errors "more helpful."
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
# v0.4 W2 / W3 / v0.8 W2-W3 — opt-in features each get their own clippy pass.
cargo clippy -p gmcrypto-core --features digest-traits,cipher-traits --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-bitsliced --all-targets -- -D warnings
cargo clippy -p gmcrypto-core --features sm4-aead --all-targets -- -D warnings
# v0.12 — SM4-XTS opt-in clippy pass.
cargo clippy -p gmcrypto-core --features sm4-xts --all-targets -- -D warnings

# Supply chain — note: --exclude-dev (dev-deps are exempt from the ban list).
cargo deny check --exclude-dev
# v0.4 W2 / W3 / v0.8 W2-W3 / v0.12 — second pass under the opt-in runtime
# feature flags (digest/cipher/inout/crypto-common allowlisted in deny.toml;
# sm4-aead pulls gmcrypto-simd::ghash which has no new transitive deps; sm4-xts
# adds NO new dep — pure-core).
cargo deny --features gmcrypto-core/digest-traits,gmcrypto-core/cipher-traits,gmcrypto-core/sm4-bitsliced,gmcrypto-core/sm4-bitsliced-simd,gmcrypto-core/sm4-aead,gmcrypto-core/sm4-xts,gmcrypto-core/crypto-bigint-scalar check --exclude-dev

# MSRV reproducibility.
cargo +1.85 build -p gmcrypto-core
cargo +1.85 build -p gmcrypto-core --features digest-traits,cipher-traits,sm4-bitsliced,sm4-bitsliced-simd,sm4-aead,sm4-xts,crypto-bigint-scalar
cargo build -p gmcrypto-core --no-default-features  # confirms no_std posture

# v0.4 W1 — wasm32 build (caller-supplied RNG only).
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --no-default-features
# v0.12 — sm4-xts is pure-core/no_std, so it must build on wasm32 too.
cargo build -p gmcrypto-core --target wasm32-unknown-unknown --features sm4-xts --no-default-features

# v0.4 W4 — C ABI shim build + header drift check.
cargo build -p gmcrypto-c --release
cargo build -p gmcrypto-c --features regen-header   # regenerates include/gmcrypto.h
git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h
cargo test -p gmcrypto-c                            # c_smoke Rust-equivalence tests
# v0.9 W4 / v0.10 — AEAD FFI surface (single-shot + streaming SM4-GCM).
cargo test -p gmcrypto-c --features sm4-aead        # +14 AEAD c_smoke tests (6 single-shot + 8 streaming)
cargo clippy -p gmcrypto-c --features sm4-aead --all-targets -- -D warnings
# v0.13 — SM4-XTS C FFI surface.
cargo test -p gmcrypto-c --features sm4-xts         # +5 XTS c_smoke tests (whole-block/CTS equivalence + errors)
cargo clippy -p gmcrypto-c --features sm4-xts --all-targets -- -D warnings

# Dudect harness. Default 100K samples (~75s); CI smoke uses 10K.
# v0.5 W5 — the bench uses Sm2PrivateKey::from_scalar (renamed from
# `new`) which is gated on `crypto-bigint-scalar`. The [[bench]] entry
# in gmcrypto-core/Cargo.toml has required-features set, so cargo
# auto-enables it — but explicit is safer.
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features crypto-bigint-scalar  # PR-smoke budget
DUDECT_SAMPLES=100000 cargo bench --bench timing_leaks --features crypto-bigint-scalar  # nightly budget

# v0.8 W4 — AEAD dudect under the most-demanding cipher path
# (also runnable standalone via `--features sm4-aead,crypto-bigint-scalar`).
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar
# Gate: |tau| < 0.20 on ct_sm4_gcm_decrypt + ct_sm4_ccm_decrypt.
# v0.12 W3 — SM4-XTS dudect (the CI matrix's 4th slot carries all three).
DUDECT_SAMPLES=10000  cargo bench --bench timing_leaks --features sm4-xts,sm4-aead,sm4-bitsliced-simd,crypto-bigint-scalar
# Gate: |tau| < 0.20 on ct_sm4_xts_decrypt (CTS-length data unit).

# gmssl interop (gated; needs gmssl 3.1.1 installed).
GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl

# v0.14 — parser fuzzing (cargo-fuzz / libFuzzer). NIGHTLY-ONLY toolchain.
# One-time: rustup toolchain install nightly && cargo install cargo-fuzz --version 0.13.1 --locked
# Run from the REPO ROOT (the dir containing fuzz/). The fuzz crate is its
# OWN workspace + parent exclude=["fuzz"], so it does NOT affect any
# `cargo ... --workspace` / `cargo deny` / publish of the 3 crates.
cargo +nightly fuzz build                          # build all 16 targets
cargo +nightly fuzz run fuzz_pem fuzz/corpus/fuzz_pem fuzz/seeds/fuzz_pem -- \
    -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60
# Dir order: corpus FIRST (gitignored, libFuzzer writes new units here),
# seeds SECOND (committed, read-only). A crash → fuzz/artifacts/<target>/;
# minimize with `cargo +nightly fuzz tmin <target> <crash>` and commit the
# minimized input under fuzz/seeds/<target>/ as a regression seed.
```

## Dudect harness gate

Located at `crates/gmcrypto-core/benches/timing_leaks.rs`. **Thirteen
targets at the default / `sm4-bitsliced` budget; fifteen under
`sm4-bitsliced-simd`; eighteen under `sm4-bitsliced-simd,sm4-aead`;
nineteen under `sm4-bitsliced-simd,sm4-aead,sm4-xts`** (v0.3 added
`ct_pkcs8_decrypt`; v0.5 W4 phase 1 added
`ct_sm4_encrypt_block_bitsliced_simd` cfg-gated on `sm4-bitsliced-simd`;
v0.6 W6 added `ct_sm4_cbc_decrypt_fanout` cfg-gated on the same feature
per Q6.7 of `docs/v0.6-scope.md`; v0.7 W3 added `ct_sm4_ctr_encrypt`
NOT cfg-gated — runs under all three pre-W4 matrix entries per
Q7.2; v0.8 W4 added `ct_sm4_gcm_decrypt` and `ct_sm4_ccm_decrypt`
cfg-gated on `sm4-aead` per Q8.7 of `docs/v0.7-aead-scope.md`;
v0.9 W3 added `ct_sm4_gcm_decrypt_buffered` cfg-gated on `sm4-aead`
per Q9.5 of `docs/v0.9-scope.md`; v0.12 W3 added `ct_sm4_xts_decrypt`
cfg-gated on `sm4-xts` per Q12.9 of `docs/v0.12-scope.md`).
**v0.12 W3 also fixed a latent bug**: `MATRIX_FEATURES` was `env`-scoped
to the dudect bench step, so the parse step's feature-conditional gates
(`sm4-bitsliced-simd` / `sm4-aead` / `sm4-xts`) never fired — now
re-declared on the parse step in both workflows.
The PR-smoke and nightly workflows run the harness under a matrix
over
`features=[default, sm4-bitsliced, sm4-bitsliced-simd,
sm4-bitsliced-simd,sm4-aead,sm4-xts]` so the `ct_sm4_key_schedule`,
`ct_sm4_encrypt_block`, and `ct_sm4_ctr_encrypt` targets gate
under every cipher dispatch path:

| Target | Gate | Meaning |
|---|---|---|
| `negative_control` | `\|tau\| > 1.0` | MUST fire — proves harness wiring. |
| `ct_mul_g` | `\|tau\| < 0.20` | Fixed-base scalar mult. v0.3 W6 replaced the body with a comb-table walk; constant-time-designed lookup preserved. 10K-sample smoke after W6: `\|tau\| ≈ 0.04`. |
| `ct_mul_var` | `\|tau\| < 0.20` | Variable-base scalar mult. |
| `ct_sign` | `\|tau\| < 0.20` | `sign_raw_with_id`, class-split by private key `d` (NOT `sign_with_id` — DER is variable-time on public output). |
| `ct_sign_k_class` | nightly only: `\|tau\| < 0.25` | `sign_raw_with_id`, class-split by nonce `k` magnitude with `d` held fixed (W0; both retry nonces class-tied). v0.4 release-prep: **dropped from the PR-smoke (10K) allowlist** — observed values span [0.21–0.37] across seven runs on the GH Actions ubuntu-24.04 runner, with no structure tied to code changes. The 100K nightly gate at 0.25 is retained (signal-to-noise is meaningful there). The direct invert diagnostics (`ct_fn_invert` / `ct_fp_invert`) are the actual invert-leak regression guards at the PR budget; `ct_sign_k_class` is a composite that dilutes invert signal by ~50× per the v0.2 W0 analysis. The bench still runs (data lands in the artifact log) but doesn't gate at 10K. |
| `ct_fn_invert` | PR-smoke: **telemetry only**. Nightly: gross-regression sentinel at `\|tau\| ≥ 0.55`. | Direct `Fn::invert((1+d) mod n)` diagnostic (W0). Recalibrated 2026-05-13 — see `docs/v0.5-dudect-recalibration.md`. |
| `ct_fp_invert` | PR-smoke: **telemetry only**. Nightly: gross-regression sentinel at `\|tau\| ≥ 0.55`. | Direct `Fp::invert(Z)` diagnostic (W0). The 2026-05-12 GH Actions `ubuntu-24.04` runner-image update (image `20260413.86.1` → `20260512.134.1`, kernel `6.17.0-1010-azure` → `6.17.0-1013-azure`, Rust toolchain `1.94.1` → `1.95.0`) shifted the 100K noise floor on this target from ~0.006 (v0.2 baseline) to intermittent values in [0.29–0.40]. The 0.20 gate is no longer authoritative on the current shared runner; the gross-regression sentinel at 0.55 retains protection against a real cryptographic leak (the v0.1 `ConstMontyForm::invert` regression at `\|tau\| ≈ 0.70` would still fire). Authoritative fix (pinned / noise-isolated dudect runner) deferred to a future scope doc — see `docs/v0.5-dudect-recalibration.md`. |
| `ct_sm4_key_schedule` | `\|tau\| < 0.20` | SM4 key schedule, class-split by master key bytes (v0.2 W1). v0.4 CI also gates this under `features=sm4-bitsliced`. |
| `ct_sm4_encrypt_block` | `\|tau\| < 0.20` | SM4 "construct cipher + encrypt one block" timed under one window, class-split by master key bytes (v0.2 W1). v0.4 CI also gates this under `features=sm4-bitsliced`; 10K-sample smoke on the bitsliced path: `\|tau\| ≈ 0.025`. |
| `ct_sm4_ctr_encrypt` | `\|tau\| < 0.20` | v0.7 W3 — SM4-CTR encrypt timed over a fixed 256-byte plaintext (16 blocks), class-split by master key bytes. Dispatches through `Sm4Cipher::encrypt_blocks` (v0.7 W1), so this gates the constant-time discipline on every cipher path — linear-scan under default, gate-only under `sm4-bitsliced`, SIMD-packed batches under `sm4-bitsliced-simd` (two AVX2 batches on x86_64, four NEON batches on aarch64). **Not** cfg-gated on `sm4-bitsliced-simd` — runs under all three matrix entries. 5K-sample local smoke: `\|tau\| ≈ 0.064`. Per Q7.2 of `docs/v0.6-scope.md`. |
| `ct_hmac_sm3` | `\|tau\| < 0.20` | HMAC-SM3 keyed MAC, class-split by master key (v0.2 W3). Structurally covers PBKDF2-HMAC-SM3's (v0.2 W4) inner PRF, the v0.3 W5 streaming `HmacSm3` (Q7.6 deliberately skipped a separate target), and the PBKDF2 sub-path of v0.3 W2's encrypted PKCS#8 path. |
| `ct_sm2_decrypt` | `\|tau\| < 0.20` | SM2 decrypt, class-split by recipient `d_B`, fixed ciphertext encrypted to a third party so both classes fail at MAC via identical control flow (v0.2 Phase 3). |
| `ct_pkcs8_decrypt` | `\|tau\| < 0.20` | Encrypted-PKCS#8 decrypt + parse, class-split by password bytes; both classes' blobs are valid for their class's password so both succeed via identical control flow (v0.3 W2). 10K-sample smoke: `\|tau\| ≈ 0.04`. |
| `ct_sm4_encrypt_block_bitsliced_simd` | `\|tau\| < 0.20` (cfg-gated on `sm4-bitsliced-simd`) | SM4 "construct cipher + encrypt one block" timed under the SIMD-packed dispatch path (v0.5 W4). Phase 1 transparently delegates to the v0.4 single-block bitslice — byte-identical output, identical timing profile to `ct_sm4_encrypt_block` under `--features sm4-bitsliced`. Phase 2 swaps in AVX2 8-way intrinsics (runtime detect; silent fallback on non-AVX2 CPUs); phase 3 adds NEON 4-way. Same gate across all three phases. |
| `ct_sm4_cbc_decrypt_fanout` | `\|tau\| < 0.20` (cfg-gated on `sm4-bitsliced-simd`) | v0.6 W6 — Sm4CbcDecryptor's batched fanout path (`decrypt_batch`) timed under load. Class-split by master key; both classes' ciphertexts are valid encrypts under their own keys so both decrypt paths share identical control flow. Exercises `sbox_x32` (x86_64 AVX2; 8 blocks × 4 tau bytes per round = 32 bytes packed) or `sbox_x16` (aarch64 NEON; 4 blocks × 4 tau bytes per round = 16 bytes packed). Per Q6.7 of `docs/v0.6-scope.md`. |
| `ct_sm4_gcm_decrypt` | `\|tau\| < 0.20` (cfg-gated on `sm4-aead`) | v0.8 W4 — SM4-GCM decrypt timed over a fixed 256-byte plaintext + 16-byte AAD + 12-byte canonical nonce. Class-split by master key; both classes' `(ct, tag)` tuples are valid encrypts under their own keys so both decrypt paths reach tag-compare via identical control flow. Exercises key schedule, H = SM4_E(key, 0^128), GHASH chain (rides CLMUL on x86_64 / PMULL on aarch64 / software Karatsuba elsewhere), GCTR, `subtle::ConstantTimeEq`. 5K-sample local smoke on aarch64: `\|tau\| ≈ 0.073`. Per Q8.7 of `docs/v0.7-aead-scope.md`. |
| `ct_sm4_ccm_decrypt` | `\|tau\| < 0.20` (cfg-gated on `sm4-aead`) | v0.8 W4 — SM4-CCM decrypt timed under the same shape as `ct_sm4_gcm_decrypt`, fixed `tag_len = 16` and 12-byte nonce. Class-split by master key; valid `(ct‖tag)` pair per class. Exercises CBC-MAC chain (sequential `Sm4Cipher::encrypt_block` loop) + CTR stream (rides v0.7 W1 batch API + v0.6 SIMD fanout under `sm4-bitsliced-simd`) + constant-time tag compare. 5K-sample local smoke on aarch64: `\|tau\| ≈ 0.063`. Per Q8.7 of `docs/v0.7-aead-scope.md`. |
| `ct_sm4_gcm_decrypt_buffered` | `\|tau\| < 0.20` (cfg-gated on `sm4-aead`) | v0.9 W3 — incremental-input buffered SM4-GCM decrypt via `Sm4GcmDecryptor`, timed over a fixed 256-byte plaintext + 16-byte AAD + 12-byte nonce fed in two chunks (100 bytes + rest) to straddle block boundaries. Class-split by master key; both classes' `(chunked ct, tag)` verify under their own keys so both reach `finalize_verify` (commit-on-verify) via identical control flow. Exercises the running-GHASH accumulator (`GhashAcc`) + the buffered-then-decrypt path. 5K-sample local smoke on aarch64: `\|tau\| ≈ 0.029`. Per Q9.5 of `docs/v0.9-scope.md`. |
| `ct_sm4_xts_decrypt` | `\|tau\| < 0.20` (cfg-gated on `sm4-xts`) | v0.12 W3 — SM4-XTS decrypt via `mode_xts::decrypt`, timed over a fixed **CTS (non-block-multiple) data unit** (100 B = 6 blocks + 4) so the final-pair ciphertext-stealing path — the riskiest tweak arithmetic — gates, not just whole-block. Class-split by master key; both classes' data units are valid encrypts under their own 32-byte key so both decrypt via identical control flow. Exercises key schedule, `T_0 = SM4_E(Key2, tweak)`, the constant-time bit-reflected α-doubling chain (`mul_alpha`: right-shift + masked `0xE1`), the `decrypt_blocks` batch path (rides SIMD fanout under `sm4-bitsliced-simd`), and the CTS tail. 10K-sample local smoke on aarch64: `\|tau\| ≈ 0.03`. Per Q12.9 of `docs/v0.12-scope.md`. **v0.15** reuses this target for the multi-sector helper (`encrypt_sectors`/`decrypt_sectors`) — the per-sector secret-dependent work is the same `split_keys`/`encrypt_blocks`/`mul_alpha` path; the only new logic is the sector-number→LE-128-tweak arithmetic, which is on **public** sector addresses, so no new target (Q15.9). |

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

**2026-05-13 recalibration note:** the 100K-sample baseline shown above
was measured against the GH Actions `ubuntu-24.04` image `20260413.86.1`
(kernel `6.17.0-1010-azure`, Rust toolchain `1.94.1`). After the
2026-05-12 image update to `20260512.134.1` (kernel `6.17.0-1013-azure`,
Rust toolchain `1.95.0`), `ct_fn_invert` and `ct_fp_invert` started
producing intermittent `|tau|` values in [0.29–0.40] on the same source
code, with same-commit pass/fail across consecutive nightly runs. The
PR-smoke gates and 100K nightly gates for these two targets were
relaxed; see `docs/v0.5-dudect-recalibration.md` for the data + the
new sentinel posture. The CODE is unchanged from v0.2 baseline; the
CI noise floor is the moving piece.

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
    sm3.rs                  # single-file SM3 hash (impls v0.3 W5 in-crate Hash trait; v0.4 W2 impls digest::Digest under `digest-traits` — v0.11: digest 0.11, impl unchanged (Output is hybrid_array::Array))
    sm2/
      curve.rs              # Fp, Fn (ConstMontyForm wrappers), curve constants
      point.rs              # ProjectivePoint + RCB add/double (eprint 2015/1060)
      scalar_mul.rs         # mul_g (v0.3 W6: comb-table walk) + mul_var
      comb_table.rs         # v0.3 W6 — precomputed 64×16 table for k·G, spin::Once lazy init
      private_key.rs        # Sm2PrivateKey + ZeroizeOnDrop; v0.5 W5 renames `new` → `from_scalar` (under `crypto-bigint-scalar`), `from_sec1_be` → `from_bytes_be` (always-on), `to_sec1_be` → `to_bytes_be` (always-on, promoted from #[doc(hidden)])
      public_key.rs         # Sm2PublicKey; v0.3 W2 adds from_sec1_bytes / to_sec1_uncompressed + ConstantTimeEq
      sign.rs               # sign_with_id, sign_raw_with_id, compute_z, MAX_ID_LEN
      verify.rs             # verify_with_id (returns bool, rejects identity pubkey + over-long ID)
      encrypt.rs            # v0.2 Phase 3 — encrypt() + KDF + point_on_curve (pub(crate) for W2/W4)
      decrypt.rs            # v0.2 Phase 3 — decrypt() with constant-time MAC compare, zeroize on fail
      raw_ciphertext.rs     # v0.3 W4 — encode_c1c3c2 / decode_c1c3c2 / decode_c1c2c3_legacy
    sm4/                    # v0.2 W1
      cipher.rs             # Sm4Cipher (block cipher) + subtle linear-scan S-box; v0.3 W5 impls in-crate BlockCipher trait; v0.4 W2 impls cipher BlockEncrypt/Decrypt under `cipher-traits` (v0.11: cipher 0.5 BlockCipherEncrypt/Decrypt via separate Sm4Enc/DecBackend)
      sbox_bitsliced.rs     # v0.4 W3 — bitsliced GF(2^8) Itoh-Tsujii inversion; opt-in via `sm4-bitsliced`; byte-identical to linear-scan
      sbox_bitsliced_simd.rs # v0.5 W4 phase 1 — SIMD-packed dispatch path (scaffolding); opt-in via `sm4-bitsliced-simd`; phase 1 transparently delegates to sbox_bitsliced. Phase 2 (AVX2) / phase 3 (NEON) swap in real intrinsics behind the same path.
      mode_cbc.rs           # encrypt/decrypt with PKCS#7 padding; caller-supplied unpredictable IV
      cbc_streaming.rs      # v0.3 W5 — Sm4CbcEncryptor / Sm4CbcDecryptor (buffer-back-by-one on decrypt); v0.6 W6 adds decrypt_batch SIMD-fanout path
      mode_ctr.rs           # v0.7 W2 — encrypt/decrypt SM4-CTR (GM/T 0002-2012 §5.4; caller-supplied unique-per-key counter; no padding; no Option return)
      ctr_streaming.rs      # v0.7 W3 — Sm4CtrCipher (symmetric — single struct serves both directions; 16-byte leftover-keystream + position cursor state machine)
      mode_gcm.rs           # v0.8 W2 — SM4-GCM single-shot AEAD (NIST SP 800-38D / GM/T 0009 / RFC 8998; cfg-gated on `sm4-aead`); (Vec<u8>, [u8; 16]) encrypt + Option<Vec<u8>> decrypt; 12-byte canonical + arbitrary-length nonce paths; constant-time tag compare via subtle; byte-identical to gmssl 3.1.1 `sm4 -gcm`. v0.9 W1 adds GcmTagLen newtype + encrypt_with_tag_len/decrypt_with_tag_len (NIST §5.2.1.2 truncated tags {4,8,12,13,14,15,16}); inc32/derive_j0 widened to pub(super) for gcm_streaming
      mode_ccm.rs           # v0.8 W3 — SM4-CCM single-shot AEAD (NIST SP 800-38C / RFC 3610 / GM/T 0009 OID 1.2.156.10197.1.104.9; cfg-gated on `sm4-aead`); Option<Vec<u8>> encrypt (output: ct||tag) + Option<Vec<u8>> decrypt; tag_len ∈ {4,6,8,10,12,14,16}; nonce.len() ∈ [7,13]; pure-Rust CBC-MAC + CTR (no GHASH); byte-identical to OpenSSL 3.x EVP `SM4-CCM`
      gcm_streaming.rs      # v0.9 W2 — incremental-input buffered SM4-GCM (cfg-gated on `sm4-aead`). Sm4GcmEncryptor (output-streaming: update->Option<Vec<u8>>, None on >2^36-32-byte ceiling + poison; finalize/finalize_with_tag_len) + Sm4GcmDecryptor (input-incremental/output-BUFFERED: update buffers + folds GHASH, finalize_verify releases plaintext only after constant-time tag check = commit-on-verify). AAD at construction. GhashAcc incremental accumulator == single-shot ghash_a_c_lens. Differential-KAT-equal to mode_gcm across arbitrary chunking. NOT "streaming" (decryptor is O(message) memory)
      mode_xts.rs           # v0.12 — SM4-XTS single-shot tweakable mode (GB/T 17964-2021 / GM-T OID 1.2.156.10197.1.104.10; cfg-gated on `sm4-xts`; pure-core, no gmcrypto-simd dep). encrypt/decrypt(&[u8;32] Key1‖Key2, &[u8;16] tweak, &[u8] data_unit) -> Option<Vec<u8>>; full ciphertext stealing; lengths [16 B,16 MiB]; single None (len out of range or Key1==Key2). GB α-doubling = mul_alpha (bit-reflected: right-shift, masked 0xE1 into byte0 — NOT IEEE's <<1/0x87, NOT GHASH's full multiply). Whole-block bulk via Sm4Cipher::encrypt_blocks/decrypt_blocks (rides SIMD fanout). Confidentiality only, no auth. Byte-identical to OpenSSL EVP SM4-XTS xts_standard=GB. XTS_KEY_SIZE=32 re-exported. v0.15 adds encrypt_sectors/decrypt_sectors (in-place &mut [u8] -> Option<()> over a run of equal-size sectors, tweak_i = LE-128(start_sector+i); ciphers built once via split_keys + reused [[u8;16]] scratch via xts_sector_in_place; whole-block / no CTS; all validation pre-flighted so buf untouched on None; empty buf -> Some(()); no new dep/dudect target) — byte-identical to looping the single-shot per sector
    hmac.rs                 # v0.2 W3 — single-shot hmac_sm3; v0.3 W5 — streaming HmacSm3 (impls in-crate Mac trait); v0.4 W2 impls digest::Mac under `digest-traits` (v0.11: digest 0.11 — Mac is a blanket impl over Update+FixedOutput+MacMarker; HmacSm3 keeps KeyInit, construct via KeyInit::new_from_slice; crypto_common→common import)
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
    traits.rs               # v0.3 W5 — in-crate Hash / Mac / BlockCipher traits (v0.4 W2 lands RustCrypto-trait fit alongside)
  benches/timing_leaks.rs   # dudect harness — 12 targets (v0.3 added ct_pkcs8_decrypt)
  tests/                    # integration tests
    interop_gmssl.rs        # v0.2 HMAC/PBKDF2 + v0.3 W3 bidirectional SM2 sign/verify, SM2 encrypt/decrypt, SM4-CBC; v0.7 W2 adds SM4-CTR bidirectional
    v0_3_pkcs8_kat.rs       # v0.3 W2 — gmssl 3.1.1 PKCS#8/SPKI fixture round-trip
    rustcrypto_traits.rs    # v0.4 W2 — required-features-gated (digest-traits + cipher-traits); 11 trait integration tests using UFCS (v0.4 base 9 + v0.11's cipher-0.5 multi-block backend + HMAC KeyInit key-length)
    sm4_batch_api.rs        # v0.7 W1 — encrypt_blocks/decrypt_blocks byte-equivalence vs per-block + round-trip; exhaustive 0..=33
    sm4_ctr_kat.rs          # v0.7 W2 — CTR derived from SM4-ECB primitive; counter-wrap KAT; encrypt/decrypt symmetry
    sm4_gcm_kat.rs          # v0.8 W2 — SM4-GCM byte-identical to gmssl 3.1.1 across 4 KAT scenarios + tamper detection (cfg-gated on `sm4-aead`)
    sm4_ccm_kat.rs          # v0.8 W3 — SM4-CCM byte-identical to OpenSSL 3.x EVP across 8 KAT scenarios (nonce_len ∈ {7,12,13}, tag_len ∈ {4,10,16}, empty PT, empty AAD, long AAD crossing block); cfg-gated on `sm4-aead`
    data/                   # v0.3 W2 binary KAT fixtures + regen recipe (Q7.9 decision); v0.8 W3 adds sm4_ccm_oracle.c (OpenSSL EVP harness)

crates/gmcrypto-c/          # v0.4 W4 — C ABI shim (cdylib + staticlib + rlib)
  src/lib.rs                # 61 FFI entry points (44 base + v0.9 W4's 6 single-shot AEAD + v0.10's 9 streaming AEAD + v0.13's 2 single-shot XTS): opaque handles, ffi_guard catch_unwind, GMCRYPTO_ERR on every error. AEAD symbols (gmcrypto_sm4_gcm_* / gmcrypto_sm4_ccm_*) cfg-gated on a forwarding `sm4-aead` feature (= ["gmcrypto-core/sm4-aead"]). v0.10 W1-W2 adds 2 opaque types gmcrypto_sm4_gcm_{encryptor,decryptor}_t + 9 symbols (encryptor new/update/finalize/finalize_with_tag_len/free output-streaming; decryptor new/update/finalize_verify/free commit-on-verify); _finalize* consume+free. v0.13 adds gmcrypto_sm4_xts_encrypt/_decrypt (single-shot, no handles, no opaque struct) + always-on const GMCRYPTO_SM4_XTS_KEY_SIZE=32, cfg-gated on a forwarding `sm4-xts` feature (= ["gmcrypto-core/sm4-xts"]); regen-header need NOT imply sm4-xts (free fns + const emit from source regardless of cfg)
  build.rs                  # cbindgen runs only under `regen-header` feature or GMCRYPTO_C_REGEN_HEADER=1
  cbindgen.toml             # cbindgen config (C language, include_guard = "GMCRYPTO_H_")
  include/gmcrypto.h        # committed header (CI gates drift via `git diff --exit-code`). cbindgen does NOT evaluate #[cfg(feature)] for free functions (single-shot AEAD prototypes appear unconditionally) BUT it DROPS cfg-gated opaque struct types (v0.10's gmcrypto_sm4_gcm_{encryptor,decryptor}_t) when the feature is inactive. So v0.10 makes `regen-header` IMPLY `sm4-aead` — regen is then deterministic + complete and the drift gate stays green with the documented `--features regen-header` command
  examples/sm2_sign.c       # end-to-end C example
  examples/sm4_gcm_streaming.c # v0.10 — chunked SM4-GCM streaming AEAD round-trip via the C ABI (doc-only; CI does not build C examples)
  examples/sm4_xts_sector.c # v0.13 — 512-byte SM4-XTS sector encrypt/decrypt round-trip via the C ABI (sector# as tweak; doc-only)
  tests/c_smoke.rs          # 54 Rust-equivalence tests via extern "C" interop (35 default + 14 cfg-gated on sm4-aead: 6 v0.9 single-shot + 8 v0.10 streaming; + 5 cfg-gated on sm4-xts: whole-block/CTS equivalence + round-trip + short/weak-key/small-buffer errors)
  README.md                 # C/C++/Python/Go/Zig integration docs

crates/gmcrypto-simd/       # v0.5 W4 phase 2 / v0.6 W6 / v0.8 W1 — SIMD backend crate (rlib-only, opt-in via gmcrypto-core's sm4-bitsliced-simd or sm4-aead feature)
  src/lib.rs                # `#![no_std]` + `#![allow(unsafe_code)]` (per-decl noise; Cargo.toml lint stays `warn` for intent); re-exports `has_avx2()`
  src/detect.rs             # `cpufeatures::new!(..., "avx2")` + `has_avx2()` wrapper (cached); x86_64-only
  src/sm4/scalar.rs         # local re-impl of v0.4 W3 Boyar-Peralta gate sequence (sbox_byte, const fn); fallback path for every SIMD entry
  src/sm4/avx2.rs           # x86_64-only — shared AVX2 byte-parallel primitives (gf_mul, gf_inv, affine_a, parity, sbox_round) on `__m256i`
  src/sm4/neon.rs           # aarch64-only — shared NEON byte-parallel primitives on `uint8x16_t`; compile-time baseline, no runtime detect
  src/sm4/sbox_x8.rs        # AVX2 path: 8 bytes packed in low lanes of __m256i (24 wasted); used by phase 2 `tau` per-byte dispatch
  src/sm4/sbox_x32.rs       # v0.6 W6 — AVX2 32-byte full-width packed S-box; used by phase 3 8-block CBC-decrypt batch
  src/sm4/sbox_x16.rs       # v0.6 W6 — NEON 16-byte packed S-box on aarch64; used by phase 3 4-block CBC-decrypt batch
  tests/lane_equivalence.rs # v0.5 W4 phase 2 — exhaustive cross-check of sbox_x8 vs inline GB/T 32907-2016 §6.2 S-box table
  tests/lane_position_x32.rs # v0.6 W6 — lane-position-shifted exhaustive sweep for sbox_x32 (256 × 32 = 8192 cases); codex's phase 3 flag #4
  tests/lane_position_x16.rs # v0.6 W6 — same for sbox_x16 (256 × 16 = 4096 cases)
  src/ghash/mod.rs          # v0.8 W1 — public dispatch `ghash_mul(h, x) -> [u8; 16]` selects CLMUL/PMULL/software at runtime
  src/ghash/software.rs     # v0.8 W1 — constant-time bit-serial GF(2^128) fallback (mask-XOR; no branches on H or X)
  src/ghash/clmul.rs        # v0.8 W1 — x86_64 PCLMULQDQ + SSE2 schoolbook 4-multiply + bit-serial descending-order reduction
  src/ghash/pmull.rs        # v0.8 W1 — aarch64 NEON `vmull_p64` schoolbook 4-multiply + same reduction shape as clmul
  tests/ghash_kat.rs        # v0.8 W1 — NIST-derived GHASH triple (H, X, Y) regression KAT across all three dispatch paths
  tests/ghash_lane_equivalence.rs # v0.8 W1 — software vs CLMUL vs PMULL byte-equivalence sweep over 75 inputs (random + structural edges)

fuzz/                       # v0.14 — cargo-fuzz (libFuzzer) harness. ITS OWN WORKSPACE (empty [workspace] table) + parent exclude=["fuzz"] → nightly-only libfuzzer-sys/arbitrary deps never enter the published 3-crate graph; unpublished, NOT MSRV-bound, NOT in cargo deny. fuzz/Cargo.lock IS committed (.gitignore anchors /Cargo.lock to root so it isn't swallowed). 16 targets prove the failure-mode invariant (no panic/OOM/hang) on adversarial bytes; initial sweep zero crashes.
  Cargo.toml                # gmcrypto-core path dep w/ features=["sm4-aead","sm4-xts"] always on (no per-target feature juggling); 16 [[bin]] entries; empty [workspace]
  fuzz_targets/             # fuzz_pem, fuzz_pkcs8_{decode,decrypt}, fuzz_spki, fuzz_sec1, fuzz_sig, fuzz_asn1_reader, fuzz_sm2_{ciphertext_der,raw_ciphertext,pubkey_sec1,decrypt,verify}, fuzz_sm4_{cbc,gcm,ccm,xts}_decrypt. SM4 targets carve key/iv/nonce/aad/tag via FRONT-consuming arbitrary::Unstructured (so seeds are plain concatenations; pinned to arbitrary 1.4.2 order). sm2_decrypt/verify use a fixed test key via OnceLock.
  seeds/<target>/           # committed curated valid seeds (from a one-time generator using gmcrypto-core's encode/sign/encrypt). corpus/, target/, artifacts/ are gitignored.
  README.md                 # build/run/repro runbook + seed-regen recipe

.github/workflows/
  ci.yml                    # 5 jobs on self-hosted macOS aarch64: build/test (stable, full) + msrv (1.85, build-only) + cabi + cargo-deny + wasm32 matrix. Per-feature clippy passes (digest-traits, cipher-traits, sm4-bitsliced, sm4-bitsliced-simd, crypto-bigint-scalar). concurrency: cancel-in-progress. UNAFFECTED by fuzz/ (excluded).
  dudect-pr.yml             # 10K samples on ubuntu-latest, |tau| gate, matrix on features=[default, sm4-bitsliced, sm4-bitsliced-simd], path-allowlisted, concurrency: cancel-in-progress
  dudect-nightly.yml        # 100K samples on ubuntu-latest, same gate + matrix, 30-day artifact retention; concurrency: cancel-in-progress=false (a partial 100K run is wasted compute). PR #38 drops the push:main trigger in favour of cron-only (regression watch) + workflow_dispatch (manual reruns).
  fuzz-nightly.yml          # v0.14 — capped cargo-fuzz sweep over all 16 targets on the self-hosted runner (cron 06:00 UTC + workflow_dispatch w/ max_total_time input; pinned cargo-fuzz 0.13.1; -max_total_time/-rss_limit_mb/-timeout caps; crash-artifact upload 30d; concurrency cancel-in-progress=false). NOT a PR gate. >>> BEFORE PUBLIC FLIP: fuzzing runs adversarial native code — isolate/move off the self-hosted personal Mac.

docs/
  v0.1.0-release-review.md      # pre-publish reviewer checklist (template)
  v0.2.0-release-review.md      # v0.2 pre-publish reviewer checklist
  v0.3-scope.md                 # v0.3 scope doc + Q7.1–Q7.10 sign-off decisions
  v0.4-scope.md                 # v0.4 scope doc + Q4.1–Q4.19 sign-off decisions
  v0.5-scope.md                 # v0.5 scope doc + Q5.x sign-off decisions (Q5.11 SIMD architectural reset)
  v0.5-dudect-recalibration.md  # 2026-05-12 GH runner-image noise-floor analysis + sentinel posture
  v0.6-scope.md                 # v0.6 scope doc + Q6.1–Q6.10 sign-off decisions (W4 phase 3 / W6)
  v0.7-aead-scope.md            # v0.7 W4 — design cycle scope doc for v0.8 SM4-GCM + SM4-CCM (Q8.1–Q8.8 + v0.9 candidate Q-list); Q8.4 backref to W0 resolution
  v0.8-ccm-kat-sourcing.md      # v0.8 W0 — sourcing decision for SM4-CCM KAT vectors (OpenSSL 3.x EVP `SM4-CCM`; gmssl 3.1.1 lacks `-ccm`); embedded C harness + parametric coverage matrix
  v0.14-scope.md                # v0.14 W0 — parser-fuzzing scope (Q14.1–Q14.12, codex-reviewed); 16 cargo-fuzz targets over the untrusted-input decode/decrypt surface; assurance-only (clean run ⇒ no crates.io release per Q14.11); §6 v0.15 candidate Q-list
  (scope docs for v0.9–v0.13 live alongside; not all relisted here)
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

- **Self-hosted CI runner (v0.5+).** Private-repo Pro-plan minute caps
  drove a split: `ci.yml`'s five jobs (build / msrv / cabi / deny /
  wasm32) run on a **self-hosted macOS aarch64 runner labelled
  `gmcrypto`**; the two dudect workflows stay on `ubuntu-latest`
  because their `|tau|` gates were empirically calibrated against
  GitHub's `ubuntu-24.04` runner-image noise floor (v0.4 release-prep
  PR #22). Moving dudect would invalidate the calibration. See the
  `## Self-hosted CI runner setup` section below for the runbook.
- Branch model: branch + PR for all changes. Direct commits to `main` reserved
  for trivial-and-time-sensitive fixes only. CI fires on the PR (+ on the
  merge commit to `main`); dudect-pr.yml smoke is path-allowlisted so doc-only
  PRs skip the bench job. For WIP PRs that should skip CI, put `[skip ci]` /
  `[ci skip]` / `[no ci]` / `[skip actions]` in the PR title (the workflow
  `if:` checks PR title; GitHub's native skip on push events also honours
  these markers in commit messages — added in PR #38).
- Tags are SSH-signed (`gpg.format = ssh`). Verify locally with
  `git tag -v vX.Y.Z` after configuring `gpg.ssh.allowedSignersFile`.
- `cargo publish` is the irreversible step. Use `docs/v0.1.0-release-review.md`
  as the template before publishing v0.5. **Two crates ship**:
  `gmcrypto-core` first, then `gmcrypto-c` (path dep on core via
  `version = "0.5"` — core must be on crates.io before c can publish).

## Self-hosted CI runner setup

`ci.yml` runs on a self-hosted macOS aarch64 runner. One-time setup
per host machine:

```bash
# 1. Dedicated user — runner CANNOT read your daily-driver home dir.
#    `sysadminctl` is the modern macOS path (auto-assigns a free UID)
#    and avoids hand-rolled `dscl` boilerplate that can collide with
#    an existing UID 600. We intentionally do NOT set a login
#    password for ghrunner — it's a service account, no SSH/login
#    exposure, and `sudo -iu ghrunner` from the maintainer user
#    authenticates the maintainer, not ghrunner. Passwordless
#    service accounts are slightly more secure here.
sudo sysadminctl -addUser ghrunner -shell /bin/zsh \
  -home /Users/ghrunner -admin no
# Expect a "No clear text password ... will not allow user to use
# FDE" warning — benign for a service account. Note the assigned
# UID/GID in the output (typically 5xx / 20=staff).

# sysadminctl ASSIGNS but does NOT CREATE the home directory.
# Create it now or `sudo -iu ghrunner` will fail with
# "chdir to /Users/ghrunner: No such file or directory".
sudo mkdir /Users/ghrunner
sudo chown ghrunner:staff /Users/ghrunner
sudo chmod 700 /Users/ghrunner   # only ghrunner can read its own home

# Smoke-test before continuing:
sudo -iu ghrunner whoami   # should print: ghrunner
sudo -iu ghrunner pwd      # should print: /Users/ghrunner

# 2. Switch users + install rustup with the toolchains CI needs
sudo -iu ghrunner
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable
source $HOME/.cargo/env
rustup toolchain install 1.85
rustup target add wasm32-unknown-unknown --toolchain stable
rustup target add wasm32-unknown-unknown --toolchain 1.85
rustup component add clippy rustfmt --toolchain stable
# v0.14 — parser fuzzing (.github/workflows/fuzz-nightly.yml). cargo-fuzz
# needs nightly + libFuzzer (Apple clang on macOS provides it). Pin
# cargo-fuzz for reproducibility (same posture as the cbindgen 0.29 pin).
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.1 --locked

# 2b. Pre-empt git's macOS keychain credential helper. The system
#     gitconfig that ships with Xcode CLT configures `credential.helper =
#     osxkeychain` globally. When git runs as a fresh user (ghrunner),
#     the first credential lookup triggers macOS Keychain Services
#     prompting "<user> wants to use the login keychain" — and ghrunner
#     has no login keychain, so the prompt is unsatisfiable and hangs
#     the runner. Override with an empty helper in ghrunner's user-
#     scoped gitconfig (written directly to sidestep `git config`'s
#     newer "no action specified" gotcha with empty-string values).
cat > ~/.gitconfig <<'INNER'
[credential]
	helper =
[safe]
	directory = *
INNER

# 3. Register the runner.
#
# 3a. Look up the latest runner version as your MAINTAINER user
#     (NOT as ghrunner — ghrunner has no `gh` auth). The
#     unauthenticated GitHub API has a 60-req/hour-per-IP cap; `gh
#     api` auto-uses your stored auth token and has a 5000/hour
#     limit. The first version of this runbook used raw `curl
#     https://api.github.com/...` and hit the rate limit on a fresh
#     setup attempt.
#
LATEST=$(gh api /repos/actions/runner/releases/latest \
  --jq '.tag_name | ltrimstr("v")')
echo "Use this version when prompted: ${LATEST}"
#
# 3b. Get TOKEN from
#     https://github.com/frankxue831/gm-crypto-rs/settings/actions/runners/new
#     (one-time-use, ~1 hour TTL).
#
# 3c. Switch to ghrunner and download + register. Substitute the
#     literal LATEST value from 3a above (ghrunner's shell does not
#     inherit it from sudo -iu).
sudo -iu ghrunner
mkdir -p ~/actions-runner && cd ~/actions-runner
LATEST=2.319.1   # <-- paste the literal version from 3a
curl -fsSL -o runner.tar.gz \
  "https://github.com/actions/runner/releases/download/v${LATEST}/actions-runner-osx-arm64-${LATEST}.tar.gz"
tar xzf runner.tar.gz
./config.sh --url https://github.com/frankxue831/gm-crypto-rs \
  --token <TOKEN> \
  --labels self-hosted,macos,arm64,gmcrypto \
  --work _work \
  --unattended

# 4. Test interactively first:
./run.sh   # Ctrl-C to stop

# 5. Once green, install as a launchd service. On macOS the runner's
#    `svc.sh` does NOT take a username argument (Linux semantics) and
#    must be invoked WITHOUT `sudo` — it installs under the current
#    user (which is `ghrunner` here per the `sudo -iu` in step 2).
./svc.sh install
./svc.sh start
./svc.sh status   # verify "active" / "Started"
```

Operational notes:

- The runner-side `_work/` directory holds checked-out repo + build
  artifacts. Persists between jobs (good for warm Cargo cache). Wipe
  with `rm -rf /Users/ghrunner/actions-runner/_work/*` (as
  `ghrunner`, no sudo) if state ever gets corrupted.
- The labels `[self-hosted, macos, arm64, gmcrypto]` are AND-ed in
  `ci.yml` (case-insensitive). Only runners matching ALL four labels
  pick up the job. The `gmcrypto` label is specific to this repo —
  important when you one day host multiple project runners on the
  same Mac.
- **Offline-runner behaviour: queued jobs sit pending until they hit
  GitHub's 24-hour timeout and then fail.** Not "indefinite". If you
  see a job stuck in `Queued`, check the runner is still healthy at
  https://github.com/frankxue831/gm-crypto-rs/settings/actions/runners
  (status should say `Idle`). Escape hatch: revert the self-hosted
  PR's `runs-on:` to `ubuntu-latest` and `git push`. Monitoring tip:
  GitHub emails the repo owner if a job fails for `no_self_hosted_
  runner_available` after the 24-hour timeout.
- The runner's CARGO_HOME (`/Users/ghrunner/.cargo/`) is pre-populated
  in step 2 with rustup + stable + 1.85 + clippy + rustfmt +
  wasm32-unknown-unknown targets. `Swatinem/rust-cache@v2` calls in
  `ci.yml` are configured with `cache-bin: "false"` so the action's
  restore step won't evict those pre-installed binaries (the
  default `cache-bin: "true"` has a known issue on long-lived
  self-hosted runners where the restore overwrites `~/.cargo/bin/`
  with whatever was in the cached snapshot).
- `Swatinem/rust-cache@v2`'s registry / target caches live under
  `/Users/ghrunner/actions-runner/_work/_cache/`. Native macOS
  filesystem makes incremental warm-cache builds significantly
  faster than the equivalent on `ubuntu-latest` (no Docker
  bind-mount).
- The dudect workflows STAY on `ubuntu-latest`. Don't move them —
  the `|tau|` gates were calibrated against GitHub's `ubuntu-24.04`
  image.

## Don't

- Don't add a `Cargo.toml` `authors` field (privacy — removed at `982a2fc`).
- Don't reduce the SM2 retry-loop iteration count or short-circuit on first valid
  candidate. Fixed-K masked-select is the constant-time invariant.
- Don't reference any external "Java prototype" / `gm-crypto-lite-java` repo.
  The Rust repo is standalone; that prototype was personal scaffolding.
- Don't replace the default SM4 `subtle`-style linear-scan S-box with a
  direct LUT ("just for performance"). The throughput trade is
  documented as deliberate. v0.4 W3 added the opt-in bitsliced
  (table-less, gate-only) fast-path behind the `sm4-bitsliced` feature;
  default-features build is unchanged. **Don't widen `sm4-bitsliced`
  to a multi-block SIMD-packed bitsliced implementation in v0.4** —
  per Q4.11 that's deferred to v0.5+; the v0.4 path is single-block
  only and must stay byte-identical to the linear-scan path
  (exhaustive equivalence test in
  `sm4::sbox_bitsliced::tests::bitsliced_matches_table`).
- Don't expose the bitsliced helpers (`gf_mul`, `gf_inv`, `affine_a`)
  publicly. They're `pub(crate)` (or function-local) by design; the
  only public surface is the implicit S-box swap when
  `sm4-bitsliced` is enabled.
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
- `Sm2PrivateKey::to_bytes_be` (v0.5 W5; was `#[doc(hidden)] pub fn
  to_sec1_be` in v0.3-0.4) returns the secret scalar as plaintext
  bytes. **Callers must zeroize the returned `[u8; 32]` themselves**
  — the SDK can't enforce zeroization on a stack-owned array. v0.5
  promotes the method to SemVer-stable; the contract is documented
  on the method.
- `gmcrypto-c`'s FFI symbol `gmcrypto_sm2_privkey_to_sec1_be` keeps
  the `sec1` suffix for v0.4→v0.5 C-ABI backcompat even though the
  Rust method renamed to `to_bytes_be`. Don't rename the FFI symbol
  — C/Go/Zig callers can't follow a Rust-side type-alias trick.
- Don't widen `unsafe_code` in `gmcrypto-c` from `warn` to `allow`,
  and don't remove the `// SAFETY:` comment on any FFI `unsafe`
  block. Per Q4.7 in `docs/v0.4-scope.md`: warn surfaces each
  `unsafe` site in clippy without forbidding the unavoidable
  `Box::from_raw` / slice-reconstruct primitives. `gmcrypto-core`
  itself stays `unsafe_code = "forbid"` — don't relax that.
- Don't add SIMD intrinsics directly to `gmcrypto-core`. Route via
  the v0.5 W4 phase 2 sibling crate `gmcrypto-simd`
  (`unsafe_code = "warn"`). The `forbid` lint on `gmcrypto-core` is
  non-negotiable; `core::arch::x86_64::*` intrinsics are all
  `unsafe fn` and `#[target_feature(enable = "avx2")] unsafe fn` is
  the only stable-Rust path on MSRV 1.85 that combines runtime AVX2
  dispatch with intrinsic calls — neither composes with `forbid`
  in the same crate. The `gmcrypto-simd` ↔ `gmcrypto-c` precedent
  is the model: unavoidable-unsafe primitives quarantined to a
  named sibling, every block carrying a `// SAFETY:` comment.
- Don't promote `gmcrypto-simd` from rlib to cdylib/staticlib.
  `gmcrypto-c` is the single C ABI surface for the workspace.
  Adding a public SIMD dylib creates ABI / support surface without
  benefit — downstream non-Rust callers get the SIMD path
  transparently when they enable the C-ABI library's
  `sm4-bitsliced-simd` feature.
- Don't widen the `gmcrypto-simd` public API beyond Rust-internal
  use. No raw pointers across the crate boundary, no extern "C"
  shapes. The public API is `sbox_x8(&[u8; 8]) -> [u8; 8]` plus
  `has_avx2()`; phase 3 adds equivalents for NEON. Anything else
  invites the same "fixed-shape FFI primitives" problems the C-ABI
  shim already has — keep them in `gmcrypto-c`.
- Don't add a `cpufeatures` check inside an inner SM4 loop in
  `gmcrypto-core`. The detection is cached in `gmcrypto-simd`'s
  `detect.rs` already; the single per-call cost is acceptable for
  phase 2's per-`tau` shape. Phase 3's `Sm4CbcDecryptor` fanout
  amortizes the call over an 8-block batch — that's the right
  level. Don't pull `cpufeatures` into `gmcrypto-core` directly to
  "skip the indirection."
- Don't make any C ABI entry point distinguish failure modes. Every
  error path returns `GMCRYPTO_FAILED` (single failure code).
  Distinguishing wrong-password from malformed-PEM from MAC-mismatch
  through the C surface re-introduces the oracle attacks the
  Rust-side failure-mode invariant defends against.
- Don't add an RNG callback to the C ABI in v0.4. Per Q4.18, RNG is
  sourced via `getrandom::SysRng` internally; adding a callback
  shape is a v0.5+ candidate when the trade-off can be designed
  alongside multi-block bitslicing.
- Don't pull `getrandom`'s `wasm_js` backend into `gmcrypto-core`'s
  default dep graph. Per Q4.2, wasm callers wire their own
  `rand_core::Rng` impl by enabling `getrandom`'s `wasm_js` feature
  in *their own* `Cargo.toml`. Adding it to ours hides the contract
  from callers and bloats the no-wasm target.
- Don't implement SM4-XTS (`sm4::mode_xts`) per **IEEE 1619**. v0.12
  targets **GB/T 17964-2021** (`xts_standard=GB`, OpenSSL's default for
  SM4-XTS, the SM4 national standard). The two differ in the GF(2¹²⁸)
  tweak doubling: GB is **bit-reflected** (`mul_alpha` = right-shift,
  reduce `0xE1` into byte 0); IEEE is `<<1` / `0x87`. They produce
  identical block-0 output but diverge from block 1 onward. The KAT
  oracle pins `xts_standard=GB`; an IEEE impl fails it.
- Don't branch on the XTS tweak in `mul_alpha` — `T = SM4_E(Key2, ·)` is
  secret-derived. The carry reduction must stay a masked XOR
  (`t[0] ^= 0xE1 & carry.wrapping_neg()`), never an `if`.
- Don't add `gmcrypto-simd` (or any dep) to the `sm4-xts` feature. The
  XTS α-doubling is a trivial multiply-by-x, **not** GHASH's full
  carryless multiply — it lives in `gmcrypto-core`. `sm4-xts = []`.
- Don't relax `Key1 == Key2 → None` in `mode_xts`. It's a GB/T 17964 /
  FIPS weak-key guard (stricter than OpenSSL's default provider, which
  permits equal halves). The compare is constant-time (`subtle`); only
  the equal/not-equal *outcome* gates the reject.
- Don't let the XTS API generate or reuse tweaks. Per-data-unit
  tweak-uniqueness under a key is the caller's contract (the tweak is
  the sector number); reuse leaks equality structure. And XTS is
  **confidentiality only** — never imply it authenticates.
- Don't forget `MATRIX_FEATURES` must be re-declared on the dudect
  "Parse and gate" step (`env` is step-scoped). Without it the
  feature-conditional `|tau|` gates silently never fire (the v0.12 W3
  latent-bug fix).

## Agent gotchas

- **MSRV 1.85** — don't use `Integer::is_multiple_of` (stable in 1.87).
  Use `n % m == 0` / `% m != 0`. Clippy catches it at PR time, but
  the detour wastes a fmt+clippy cycle.
- **Fuzz crate (`fuzz/`) is a SEPARATE workspace.** `cargo fmt --all` /
  `cargo clippy --workspace` / `cargo test --workspace` do **NOT** touch
  it (parent `exclude=["fuzz"]` + its own empty `[workspace]`). To
  fmt/lint it, target it explicitly:
  `cargo fmt --manifest-path fuzz/Cargo.toml --all` and (nightly)
  `cargo +nightly fuzz build`. Don't expect workspace-wide commands to
  cover it.
- **`cargo fuzz run <target> <dir>` WRITES new corpus units into the
  FIRST dir.** Never pass `fuzz/seeds/<target>` as the first (write)
  dir — it pollutes the committed curated seeds with machine-generated
  files (happened in v0.14 W1; had to amend). Always
  `cargo +nightly fuzz run <t> fuzz/corpus/<t> fuzz/seeds/<t>` —
  corpus (gitignored) first, seeds (read-only) second.
- **`.gitignore` `Cargo.lock` must stay anchored as `/Cargo.lock`** (root
  only), NOT a bare `Cargo.lock` — a bare pattern also ignores
  `fuzz/Cargo.lock`, which the cargo-fuzz binary workspace pins and
  commits. (W0 codex finding.)
- **SM4 fuzz-target seed layouts are pinned to `arbitrary 1.4.2`'s
  front-consuming read order** (key/iv/nonce/aad/tag carved with
  `arbitrary::<[u8;N]>()` / `arbitrary::<u8>()` / `bytes(n)` / `take_rest`
  — all front; only `int_in_range` / collection-length read from the
  tail, which these targets avoid). Bumping `arbitrary` ⇒ re-verify the
  order and regenerate the four `fuzz_sm4_*` seeds. Pin is held by
  `fuzz/Cargo.lock`.
- **A new minor cycle does NOT always mean a crates.io release.** v0.14
  was an *assurance* cycle (parser fuzzing): clean fuzz run ⇒ published
  crates byte-unchanged ⇒ **no version bump, no publish** (per
  `docs/v0.14-scope.md` Q14.11). Don't reflexively bump
  `[workspace.package].version` or run `cargo publish` for a cycle that
  doesn't change a published crate. **v0.15.0 was that next code change**
  (the SM4-XTS sector helper), so workspace `version` went `0.13.0 →
  0.15.0` — **crates.io skips `0.14.0`** entirely (the unpublished fuzzing
  cycle named v0.14 in the docs is never a release; SemVer permits the gap).
  Don't try to publish a `0.14.0`.
- **SM4-XTS sector tweak is LE-128 of the sector number, not raw bytes.**
  `mode_xts::{encrypt_sectors,decrypt_sectors}` (v0.15) take a
  `start_sector: u128` and derive sector `i`'s 16-byte tweak as
  `(start_sector + i).to_le_bytes()` — the disk-XTS convention (matches the
  shipped `sm4_xts_sector.c` LE example). The single-shot `encrypt`/`decrypt`
  still take a **raw** `&[u8; 16]` tweak (caller-encoded). Don't conflate the
  two. The helper is **in-place** (`&mut [u8] -> Option<()>`); all validation
  is pre-flighted before the loop so `buf` is untouched on `None` — don't move
  a `checked_add(...)?` into the per-sector loop (it'd partially mutate `buf`
  before failing). No new dudect target (the per-sector path rides
  `ct_sm4_xts_decrypt`; sector numbers are public).
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
- **`dtolnay/rust-toolchain@master` with `targets:`** is known-flaky
  for non-default toolchains on GitHub-hosted Ubuntu (E0463: can't
  find crate for `core`). Always pair it with an explicit
  `rustup target add wasm32-unknown-unknown --toolchain ${MSRV}`
  step. See ci.yml's wasm32 job.
- **RustCrypto trait method resolution** (digest 0.11 / cipher 0.5 since
  v0.11): inherent methods like `HmacSm3::finalize` collide with
  `digest::Mac::finalize` when both are in scope. Use UFCS in tests:
  `<HmacSm3 as DigestMac>::finalize(chained).into_bytes()` and
  `<Sm4Cipher as CipherBlockEncrypt>::encrypt_block(&cipher, &mut block)`
  (the cipher trait is now `cipher::BlockCipherEncrypt`/`BlockCipherDecrypt`,
  not the old `BlockEncrypt`/`BlockDecrypt`). **HMAC construction** is via
  `<HmacSm3 as digest::KeyInit>::new_from_slice(key)` — `digest 0.11`'s `Mac`
  no longer carries `KeyInit`, so `Mac::new_from_slice` does not exist. Block
  values use `cipher::array::Array` (`hybrid-array`); prefer
  `KeyInit::new_from_slice` + `Array::from([u8; N])` over the deprecated
  `Array::from_slice`. See `crates/gmcrypto-core/tests/rustcrypto_traits.rs`.
- **cbindgen 0.27 doesn't recognize Rust 2024 `#[unsafe(no_mangle)]`**.
  Pin at `0.29` or later (see `gmcrypto-c/Cargo.toml`).
- **CI workflow only fires on PRs targeting `main`.** For stacked
  PRs whose base isn't `main`, fire manually via
  `gh workflow run ci.yml --ref <branch>` (workflow_dispatch added
  in `bdf4678`).
- **`cargo deny` in CI** uses the prebuilt `taiki-e/install-action@v2`
  with `tool: cargo-deny@0.19` — don't switch back to
  `cargo install --locked cargo-deny` (compiled from source, adds
  ~3 min per CI run; see `431df89`).
