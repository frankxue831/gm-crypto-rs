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

1. Checks the candidate SHA and clean tracked source, Ubuntu version and the
   existing effective Rust/Cargo/active-toolchain guard for **1.95.0**.
2. Resolves and archives one lockfile. Every subsequent Cargo command uses
   `--locked`; its digest must remain unchanged. Build/profile overrides are
   rejected. No shared compilation cache is restored.
3. Executes the existing exact detector assertion with
   `GMCRYPTO_SIMD_EXPECT_GFNI=1`, calling this candidate's `has_gfni_avx2()`.
   Zero executed tests cannot pass.
4. Runs the complete release core and backend test suites, including their
   integration executables. Required output checks include native GFNI x4/x32
   sweeps, published-table dispatch expectations, GB/T single-block KAT,
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
