# Native GFNI qualification

`native-gfni.yml` is a manually dispatched, bounded qualification attempt on
the selected candidate ref. It uses two ordinary hosted Ubuntu 24.04 jobs,
each capped at 40 minutes. Hosted CPUs are not guaranteed to expose the
candidate's required GFNI/AVX2/OS state. An unavailable detector produces
**NOT QUALIFIED**, fails the job and runs no timing. A fallback success is
never native qualification. Do not rerun to search for another CPU; rerun
attempts of the same workflow run are rejected.

Each job uses the existing nightly SIMD feature string, plus
`crypto-bigint-scalar` for both correctness and timing:

- `sm4-bitsliced-simd,crypto-bigint-scalar`
- `sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp,crypto-bigint-scalar`

On the same VM, in order, the helper:

1. Checks the candidate SHA and clean tracked source, Ubuntu version,
   effective **CPython 3.14.8** and the
   existing effective Rust/Cargo/active-toolchain guard for **1.95.0**.
2. Resolves and archives one lockfile. Every subsequent Cargo command uses
   `--locked`; its digest must remain unchanged. Build/profile overrides are
   rejected. No shared compilation cache is restored.
3. Executes the existing exact detector assertion with
   `GMCRYPTO_SIMD_EXPECT_GFNI=1`, calling this candidate's `has_gfni_avx2()`.
   Zero executed tests cannot pass.
4. Runs the complete release core and backend test suites, including their
   integration executables. Required output checks include native GFNI x4/x32
   sweeps, published-table dispatch expectations, the exhaustive bitsliced
   S-box/table oracle, GB/T single-block KAT,
   all four batch API tests, CBC composition, and CTR output-oracle tests
   across eight-block boundaries, multiple batches, byte tails and counter
   carries. It then explicitly executes the ignored million-round KAT and
   requires its passing test record.
5. Runs the unchanged timing harness **100,000 samples × five processes**,
   then executes the existing nightly parser verbatim. Its thresholds,
   feature gates, negative control, sentinels, SKU rule and telemetry remain
   authoritative. Exactly five fresh numbered logs are required.

The helper imports the unchanged assurance checker before extracting the
parser with that checker's existing helpers. Both the original workflow's
source fingerprint and its Python AST fingerprint must pass, as must the
existing mutation suite. No gate/parser copy or new numerical policy is
introduced. Regression tests compare the extracted bytes and the original
parser's stdout/exit status for passing, threshold, missing-target and
negative-control cases. The frozen v1.15 study, its routing, and its pins are
not used or changed by this workflow.

Python is installed explicitly and its effective executable, full version,
implementation and version tuple are retained in `python-runtime.json`.
The existing AST fingerprints depend on Python's serialization format:
Python 3.12 emits empty fields that Python 3.13+ omits. A different runtime
fails closed before the protected-source audit; fingerprints are never
regenerated to accommodate it. `native-gfni-preflight.yml` runs the same
Python preflight and regression/mutation tests on Ubuntu 24.04 for pull
requests. It also uses effective Rust 1.95.0 and one recorded lockfile to
compile and list the release core/backend tests for **both** feature strings
above. The same receipt validator checks every required name, the ignored
million-round KAT's availability, and each x4/x16/x32 integration executable's
dispatch sweeps. Listing proves availability only: no test bodies, native
qualification or timing are executed by that regression job.

Both SIMD configurations imply `sm4-bitsliced`, so their exhaustive table
oracle is `sm4::sbox_bitsliced::tests::bitsliced_matches_table`. The scalar
`sbox_ct_matches_lut` test is compiled out in these configurations and cannot
be required. An independent output fixture catches that mismatch without
inventing successful records from the helper's expected-test list. Missing,
ignored or duplicate table-oracle records still reject executed correctness;
a compiled listing cannot substitute for a passing execution record.

The per-job artifact retains the source/build identity, actual toolchain
output, lockfile and digest, Cargo metadata, CPU flags/model, image/kernel,
commands, correctness output, all timing logs, parser source and verdict.
`result.json` starts at NOT QUALIFIED and becomes QUALIFIED only after every
stage passes. A cancelled/timed-out job or missing final result is incomplete,
never qualified; the job's terminal conclusion must also be successful. Both
feature jobs must qualify. They may use different VMs; each VM checks its own
source/graph/features before measuring them.

Correctness tests and timing are **separate executables**. Release tests and
the default bench profile share the repository's optimization settings, but
test configuration and linking differ; no machine-code identity is claimed.
This workflow adds evidence only. It does not authorize merge, release,
publication, gate relaxation or a new calibration. A workflow first added on
a branch may not be dispatchable until it exists on the default branch; that
limitation does not authorize a merge to enable it.

## 1.16.0 result

Three capped dispatches on the 1.16.0 candidate, 2026-10-09, with the helper
repaired in #234:

| Run | `sm4-bitsliced-simd` leg | combined-feature leg |
|---|---|---|
| 37987500505 | EPYC 7763, no GFNI: NOT QUALIFIED | **QUALIFIED**, EPYC 9V74 exposing GFNI |
| 37990194511 | EPYC 7763: NOT QUALIFIED | EPYC 7763: NOT QUALIFIED |
| 37990383386 | EPYC 7763: NOT QUALIFIED | EPYC 7763: NOT QUALIFIED |

The qualified leg passed every stage above under Rust 1.95.0: detector
asserted, 482 release correctness tests and the million-round KAT, and
100K × 5 timing with every primary median at or below 0.0428 under the
unchanged parser. Its `ct_sm4_cbc_decrypt_fanout` passes read 0.0417,
0.3693, 0.0100, 0.0179 and 0.0486; the median decides, and the single
0.3693 pass is recorded without an assigned cause.

This document's rule that both feature jobs must qualify was **not met**.
The maintainer accepted the combined-leg result for the SIMD-only leg on
2026-10-10, because it runs the same GFNI `sbox_x4` / `sbox_x32` code and
the same SIMD-only timing targets under a superset of features. That is a
recorded release decision for 1.16.0, not a per-leg QUALIFIED result and
not a change to this procedure.
