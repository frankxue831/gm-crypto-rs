# SM4 Single-Block SIMD Repair Design

**Status:** Accepted
**Date:** 2026-08-22
**Issue:** GitHub #163

## Context

`sm4-bitsliced-simd` currently accelerates full batches but regresses serial
SM4 users, most visibly CCM authentication. CCM's CTR pass can use
`Sm4Cipher::encrypt_blocks`, while its CBC-MAC chain must encrypt one dependent
block at a time. That serial dependency is inherent to CCM and must not be
removed or reordered.

The regression is in the single-block S-box adapter. `cipher::tau` applies the
S-box to four bytes by calling the SIMD byte adapter four times. Each call
replicates one byte into an x8 input. On AArch64, x8 has no NEON path and falls
back to eight scalar S-box evaluations, retaining one result. One `tau`
therefore performs 32 scalar evaluations instead of four. The x16 AArch64 and
x32 x86 batch paths do useful parallel work and are not defective.

An isolated AArch64 prototype packed the four bytes from one SM4 word into one
x16 NEON invocation. On an Apple M1 Pro, 1 MiB invalid-tag CCM decryption
improved from 9.523 seconds (0.105 MiB/s) to 0.596 seconds (1.677 MiB/s), about
16 times faster, while batch throughput remained within measurement noise.
This validates the AArch64 design only; it is not evidence for x86 AVX2.

## Goals

1. Eliminate wasted scalar lanes in every single-block and key-schedule use of
   `tau` under `sm4-bitsliced-simd`.
2. Preserve the existing x16/x32 full-batch paths and their throughput.
3. Preserve constant-time-by-construction behavior, `no_std`, MSRV 1.85, and
   `unsafe_code = "forbid"` in `gmcrypto-core`.
4. Preserve all public APIs, Cargo feature semantics, wire formats, error
   behavior, and the default build.
5. Produce correctness, timing-regression, portability, and same-host
   performance evidence sufficient to close issue #163.

## Non-goals

- Restructuring CCM or attempting to parallelize its CBC-MAC chain.
- Adding Arm `SM4E`/`SM4EKEY`, Intel SM4, GFNI, AES-affine, or AVX-512
  backends.
- Replacing the existing portable S-box circuit.
- Changing fuzz-workspace features or claiming that existing fuzz targets
  exercise `sm4-bitsliced-simd`.
- Adding a dependency or a performance threshold to protected CI workflows.
- Editing the existing native-AArch64 core test legs or dudect jobs. The only
  CI additions in scope are wasm32 portability builds for the repaired feature.
- Bumping versions, publishing crates, tagging a release, or choosing a future
  release number.

## Decision

Issue #163 item 2 ("keep `encrypt_block` / `tau` on scalar bitsliced;
accelerate `encrypt_blocks` only") is **superseded** by this design.
Serial `tau` is in scope for `sbox_x4`. Four scalar gate-circuit calls
are the fallback (and the unmeasured-target production path), not the
AArch64 production path. The packed four-byte path is what closes the
CCM CBC-MAC regression; a scalar-only `tau` would leave the measured
AArch64 NEON gain unused.

### Cross-crate interface

Add a doc-hidden internal entry point following the existing lane-oriented
backend convention:

```rust
gmcrypto_simd::sm4::sbox_x4::sbox_x4(&[u8; 4]) -> [u8; 4]
```

The SIMD crate processes four independent S-box bytes and owns architecture
dispatch. It does not accept or return `u32` and therefore owns no SM4 word
endianness contract. The parent `sm4` module is already doc-hidden and excluded
from the supported SemVer surface; `tests/internal_surface.rs` will pin the new
entry point under that existing contract.

`gmcrypto-core` retains the algorithm-level transform:

```text
u32 SM4 word
  -> to_be_bytes
  -> sbox_x4 exactly once
  -> from_be_bytes
  -> L or L' transform
```

The current single-byte SIMD adapter is removed outright — not rewritten — so
production `tau` cannot regress to four x8 calls. The core-and-modes test plan
below assumes this removal.

### Architecture dispatch

`sbox_x4` is a safe fixed-size entry point. Its production branches are:

- **AArch64:** stage the four inputs in the first four lanes of one fixed x16
  buffer, fill the remaining lanes with public zero bytes, invoke the existing
  NEON x16 gate circuit once, and return the first four outputs. NEON is the
  AArch64 architectural baseline, matching the existing x16 dispatch.
- **x86_64 with AVX2:** evaluate one direct x8 AVX2 invocation against exactly
  four scalar gate-circuit calls on the same AVX2 host. The AVX2 production
  branch is selected only if its repeated median is at least 10% faster for
  both pre-keyed single-block encryption and key construction. If either
  condition is not met or cannot be measured, production uses four scalar calls
  for the single-word path. Existing x32 batch AVX2 remains unchanged.
- **x86_64 without AVX2:** exactly four scalar gate-circuit calls. This branch
  must not call the public x8 dispatcher, whose fallback performs eight calls.
- **Other targets:** exactly four scalar gate-circuit calls.

`sbox_x4` must `cfg`-gate the NEON x16 staging to `target_arch = "aarch64"`
and must never call the public `sbox_x16` or `sbox_x8` dispatchers on any
other target. A cfg-generic `sbox_x16(&[b0, b1, b2, b3, 0, …])` is sixteen
scalar evaluations on x86/wasm — worse than the regression being fixed.
The no-AVX2 / unselected-AVX2 path calls `sbox_x4_scalar` (four
`sbox_byte` evaluations), not `sbox_x8`.

Keep `sbox_x8` as an internal AVX2 candidate and test surface (Q6.9).
Removing the core one-byte adapter does not delete that module. If
production `sbox_x4` on x86_64 uses four scalar calls, `sbox_x8`
remains for `sbox_x32` comments, lane-equivalence tests, and an
`sbox_x4_avx2` candidate that tests may call directly.

The AVX2 choice is a build-time implementation decision backed by recorded
same-host evidence, not a secret- or input-dependent runtime benchmark. Runtime
feature detection, where present, depends only on public CPU capability and is
performed once per `sbox_x4` call.

The selected x86 branch carries a durable decision comment immediately above
its implementation. The comment records the measurement date, CPU model,
`rustc` version, scalar and AVX2 medians for key construction and pre-keyed
single-block encryption, the 10% rule, and the resulting selection. It contains
no local or temporary path. The Unreleased changelog summarizes the outcome so
future maintenance does not treat the choice as arbitrary.

### Core integration and blast radius

`cipher::tau` calls the four-byte adapter once when
`sm4-bitsliced-simd` is enabled. Because both `t_round` and `t_prime` use
`tau`, the repair intentionally affects:

- key expansion (`Sm4Cipher::new`);
- raw single-block encrypt/decrypt;
- serial CBC encryption and other single-block mode paths;
- short inputs and tails in CTR, GCM, CCM, and XTS;
- RustCrypto cipher and AEAD trait adapters.

Full batches continue through the current x16/x32 implementations. Neither
`sm4-aead` by itself nor the default feature set selects the new SM4 path;
selection remains exclusive to `sm4-bitsliced-simd`.

## Constant-time argument

The primary assurance is structural:

- input and output sizes are fixed;
- lane placement and filler values are public and fixed;
- every selected implementation has a fixed instruction count and loop bounds;
- the scalar and SIMD circuits contain no secret-indexed memory access;
- no branch depends on an S-box input, key byte, plaintext, or ciphertext;
- architecture selection depends only on public CPU capability;
- `gmcrypto-core` adds no `unsafe`; intrinsic `unsafe` remains quarantined in
  `gmcrypto-simd` under the existing safety-comment discipline.

Optimized AArch64 and x86 assembly is inspected to confirm that the new path
contains one vector S-box body per `tau` on the selected SIMD branches and has
no introduced secret-indexed lookup, gather, or secret-dependent branch.

Existing dudect targets remain regression evidence, not proof:

- `ct_sm4_key_schedule`;
- `ct_sm4_encrypt_block`;
- `ct_sm4_encrypt_block_bitsliced_simd`;
- `ct_sm4_ccm_decrypt` when AEAD is enabled;
- the other existing mode targets reached by the feature matrix.

No new dudect target is added because the new function is a thin composition
of an already measured gate circuit. Target comments are updated to describe
the new four-byte path accurately. AArch64 local smoke results are supporting
evidence; the hosted dudect gate remains the repository's existing x86 matrix.

## Correctness verification

### SIMD crate

1. For each of four logical input positions, sweep all 256 values while the
   other positions contain distinct fixed sentinels; compare all outputs with
   the published SM4 S-box table.
2. Test mixed inputs in which all four bytes differ, including sequential and
   high-bit patterns, to detect lane bleed or reordering.
3. Test the direct four-call scalar implementation on every target.
4. Test direct NEON and AVX2 candidates when their public CPU prerequisites are
   present, plus the safe host dispatcher.
5. Add the entry point to `crates/gmcrypto-simd/tests/internal_surface.rs` and
   keep the committed public API baseline unchanged.

### Core and modes

1. Replace the removed single-byte adapter's two 256-value sweeps with a
   feature-gated `cipher::tau` differential. For each byte position, sweep all
   256 values while the other three bytes hold distinct sentinels; compare the
   repaired `tau(u32)` result with four calls to `sbox_bitsliced::sbox`. This
   covers the core-to-sibling call and both endian conversions. Pin
   `0x0001_0203 -> 0xd690_e9fe` explicitly within the same test group.
2. Run the official SM4 block and key-schedule known-answer tests under
   `sm4-bitsliced-simd`.
3. Differentially compare single-block and batch results at existing batch
   boundaries and tails: 0, 1, N-1, N, N+1, 2N-1, 2N, and 2N+1 blocks.
4. Exercise CBC, CTR, GCM, CCM, and XTS tail/CTS cases reached by the feature.
5. Exercise CCM encrypt, valid decrypt, and invalid-tag decrypt separately.
6. Run the RustCrypto cipher/AEAD trait tests with the required feature sets.
7. Run the ignored million-round KAT explicitly under the repaired feature:

   ```bash
   cargo test -p gmcrypto-core --release --features sm4-bitsliced-simd \
     gbt32907_one_million_rounds -- --ignored
   ```

### Portability and repository gates

The implementation must pass the repository's existing format, test, clippy,
supply-chain, API-baseline, packaging, disclosure-boundary, and assurance-policy
checks, plus:

```text
Rust 1.85 full-feature build including sm4-bitsliced-simd and sm4-aead
wasm32 no-default-features build with sm4-bitsliced-simd
wasm32 no-default-features build with sm4-aead,sm4-bitsliced-simd
native AArch64 core tests with sm4-aead,sm4-bitsliced-simd
x86 SIMD tests and the existing x86 dudect feature matrix
```

Add two blocking steps to the existing `wasm32` job in `.github/workflows/ci.yml`:

```text
--no-default-features --features sm4-bitsliced-simd
--no-default-features --features sm4-aead,sm4-bitsliced-simd
```

The job's existing matrix runs each command on stable and Rust 1.85. These are
portability gates, not performance telemetry. The existing macOS-AArch64 core
test legs already exercise `sm4-bitsliced-simd` alone and with `sm4-aead`, so
they are not duplicated or edited. Update `CLAUDE.md`'s wasm command list to
match the new CI promise, then run the assurance-policy self-test even though
the wasm job is outside the protected job fingerprint set.

No protected workflow is edited merely to add performance output. Existing
fuzz targets are not cited as coverage for this feature.

## Performance evidence and acceptance

Performance comparisons use the same machine, compiler, release/bench profile,
input, warm-up, iteration count, and process conditions; only the explicitly
compared feature configuration or implementation candidate changes. Inputs and
outputs are passed through `black_box`. Results record CPU, architecture, Rust
version, features, profile, sample count, median, and spread. The existing bench
profile is not changed because it also controls dudect code generation.

Measure separately:

- key construction;
- pre-keyed single-block encrypt and decrypt;
- exact SIMD batches and batch-plus-tail shapes;
- CCM encrypt, valid decrypt, and invalid-tag decrypt;
- message lengths 0, 1, 15, 16, 17 bytes, 1 KiB, 256 KiB, and 1 MiB;
- feature configurations `sm4-aead`, `sm4-aead,sm4-bitsliced`, and
  `sm4-aead,sm4-bitsliced-simd`.

Merge acceptance on each measured architecture — for this patch, AArch64 and
x86_64 with AVX2; unmeasured targets take the four-scalar-call branch by
construction — uses at least five repeated samples per case:

1. Key construction, pre-keyed single-block encryption, and CCM encrypt/valid
   decrypt/invalid-tag decrypt at 1 KiB and 256 KiB under
   `sm4-bitsliced-simd` are not slower than `sm4-bitsliced` by repeated median.
2. Existing full-batch throughput remains within 10% of the pre-change median;
   an inconclusive result is repeated with at least 15 samples. If it remains
   inconclusive, acceptance fails rather than treating noise as a pass.
3. The selected x86 single-word implementation shows no regression versus four
   scalar calls; AVX2 is selected only when both key construction and
   pre-keyed single-block encryption satisfy the 10% improvement rule defined
   above.
4. Correctness and constant-time gates pass independently of performance.

The benchmark harness remains outside the repository for this patch and its
commands and machine-readable results form review evidence. A persistent
performance-telemetry workflow is a separate follow-up because non-blocking
telemetry is not itself a merge gate and the assurance workflows are protected.
The x4 API and removal of the byte-replication adapter provide the structural
guard against this exact regression class. The essential AVX2 selection record
is nevertheless committed beside the branch as specified above; only transient
harness paths and full raw output remain outside the repository.

## Documentation changes

Update only current, reader-facing material:

- `crates/gmcrypto-core/src/sm4/sbox_bitsliced_simd.rs`;
- the `tau` dispatch comments in `cipher.rs`, plus the module-header
  linear-scan throughput estimate there, replaced with figures from this
  patch's measurements (issue #163 shows the current estimate is far off on
  AArch64);
- the `TBD` empirical-speedup note in
  `crates/gmcrypto-core/src/sm4/sbox_bitsliced.rs`, replaced with the measured
  `sm4-bitsliced` figures this patch's evidence produces (issue #163's
  "measured rather than TBD" expectation);
- the affected dudect target comments in
  `crates/gmcrypto-core/benches/timing_leaks.rs` (comment-only; the
  assurance-policy script checks semantic anchors in that file, not a file
  hash — run its self-test after the edit regardless);
- `crates/gmcrypto-simd/src/lib.rs` and `src/sm4/mod.rs`;
- relevant Cargo feature comments;
- `.github/workflows/ci.yml` and `CLAUDE.md` for the two wasm32 feature builds;
- the Unreleased `Fixed` section of `CHANGELOG.md` with issue #163;
- the current SIMD timing-target description in `SECURITY.md`;
- the internal-surface existence test.

The comment above the x86 branch and the Unreleased changelog entry preserve
the AVX2-versus-scalar decision, including the compact benchmark facts required
to reproduce its rationale. A new release scope document is not invented before
the maintainer selects the next release cycle.

Historical v0.5/v0.6 records remain historical and are not rewritten.
Committed evidence uses repository-relative or publicly citable references;
transient benchmark paths and raw session output are not project documentation.
Release preparation and lockstep version changes remain separate
maintainer-authorized work.

## Alternatives considered

### Scalar single-block plus SIMD batches

Always route four-byte serial work through four scalar gate calls and retain
SIMD only for full batches. This is the conservative fallback and measured
about 6.9 times faster than the current AArch64 path, but leaves substantial
NEON performance unused.

### Packed four-byte path — selected

Reuse one existing vector gate circuit for the four independent bytes already
present in every SM4 word. It preserves the current assurance model and batch
backends while producing the strongest measured AArch64 result.

### New portable or hardware backends

Word-level SWAR/fixslice, Arm SM4 instructions, Intel SM4, GFNI, and AES-affine
implementations may offer additional gains. They add distinct algorithmic,
unsafe-code, hardware-detection, licensing, MSRV, and CI review surfaces and are
therefore deferred.

## Failure and rollback behavior

The transform is infallible and introduces no new error path. If a SIMD branch
fails correctness, assembly, timing, or performance acceptance, that branch is
not selected for production; `sbox_x4` uses exactly four scalar calls on that
architecture. If even that four-scalar-call composition fails acceptance
criterion 1 on a measured architecture (for example, if the cross-crate hop
and the cached capability load cost a repeatable median regression versus
`sm4-bitsliced`), core `tau` routes the single-word path on that architecture
to four calls into its own `sbox_bitsliced::sbox` instead of the sibling
entry point. The structural guard survives either way: the x8 byte-replication
adapter no longer exists, so neither fallback can reintroduce the 8-for-1
scalar amplification. Full-batch behavior remains independently unchanged, and
all API and wire compatibility is preserved.

## Final acceptance checklist

- The four-byte internal boundary and architecture branches match this design.
- All lane, mixed-input, endian, KAT, mode, tail, feature, MSRV, and wasm tests
  pass.
- Both new wasm32 feature builds gate stable and Rust 1.85 in CI, and the
  documented local commands match those steps.
- Structural constant-time review, optimized assembly inspection, and existing
  dudect gates pass.
- AArch64 and x86 evidence satisfies the performance rules independently.
- The selected x86 branch records the required CPU, compiler, medians,
  threshold, and decision next to the implementation.
- Full-batch throughput remains within the accepted tolerance.
- Current documentation accurately describes the repaired path, and the stale
  performance prose named by issue #163 (`cipher.rs` throughput estimate,
  `sbox_bitsliced.rs` TBD note) carries measured figures.
- Disclosure, API, packaging, license, and assurance-policy gates pass.
- No version, publish, tag, protected performance workflow, or deferred backend
  work is included.

## References

- Issue #163: <https://github.com/frankxue831/gm-crypto-rs/issues/163>
- RFC 3610, Counter with CBC-MAC: <https://www.rfc-editor.org/rfc/rfc3610>
- Botan's four-byte SM4 vector S-box precedent:
  <https://github.com/randombit/botan/blob/c82298632b065ebca7aca3b807b05cf915ab80a5/src/lib/block/sm4/sm4_hwaes/sm4_hwaes.cpp>
- OpenSSL's AArch64 `sbox_1word` precedent:
  <https://github.com/openssl/openssl/blob/b64f68a94e61fa2363c598c75444482b48056697/crypto/sm4/asm/vpsm4-armv8.pl>
