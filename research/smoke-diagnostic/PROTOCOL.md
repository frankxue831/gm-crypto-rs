# Smoke-alarm diagnostic D1 — predeclared before timing

Research-only branch. Never merge its workflow replacement or dependency patch
into main. This diagnostic does not start C0 or T0, change an active gate,
or replace either preserved September alarm.

Question: for the key-schedule smoke alarm in run 36327666349, what do complete
class-labelled timings and all 101 crop statistics show under the original
split, a swapped split and same-input class controls? A passing new run cannot
resolve the old alarm. This is bounded diagnostic evidence, not a sensitivity
study or proof of constant time.

## Inputs

- Crypto/harness base: a832884a95a83488d853233da7cde5e37fc6b845,
  tree 744720e2477a135a3495289a550062656e9a097b.
- Rust 1.95.0, x86_64-unknown-linux-gnu; ubuntu-24.04. Preserve effective
  compiler/cargo, exact image/kernel/CPU and environment flags. Do not target a
  CPU by retrying. Another SKU limits applicability to the original EPYC 7763.
- Full feature leg: sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp,
  crypto-bigint-scalar. Release profile unchanged.
- Frozen reconstruction lock: frozen.lock, SHA-256
  e2800837c468ba45d21e759d50e94dc115e3f72eb3139c579305a908b60ed1c8.
  This is not the missing original failed-job lock. The local-only diagnostic
  dependency override changes only dudect-bencher's source identity; preserve
  and check that all other resolved package identities stay identical.
- Fixed seeds, in order: 0xe8c9e38888bda9cf, 0x8b6bd04cb0283e17,
  0x3b2c93b5a01386fb. They reproduce class RNG draws, not elapsed timings.
- 10000 samples per benchmark per process. Exactly three seed blocks.

## Exporter qualification and build

The upstream dudect-bencher 0.7.0 raw exporter zips the two class vectors and
labels both entries 0. An isolated patch must export every sample independently,
with labels 0 and 1, and preserve within-class order. Synthetic unequal-class
regression must fail against upstream and pass against the patch. No raw sample
is dropped, relabelled by inference, or reconstructed from rounded summaries.

Append all 101 crop rows after timing: bench, crop index, threshold, left/right
counts, means, sample variances, signed t and tau, selected flag. Preserve NaN
and infinity explicitly. The selection, percentile and arithmetic functions
remain unchanged; the exporter must reproduce the existing selected statistic.
A synthetic test checks a hand-computed Welch statistic and export row counts.
Class sample order is retained within each class; cross-class chronology is
not recorded and must not be claimed.

Build two binaries using the same frozen dependency resolution. Baseline changes
only metadata seeding and the isolated after-timing exporter. Diagnostic adds
key-pair selection before the sample loop and black-boxes each key buffer before
timing. The four modes are original (A,B), swapped (B,A), same-left (A,A),
same-right (B,B). Crypto and timed closure stay unchanged. Preserve every source
patch, generated lock, binary, build log, disassembly, and SHA-256 manifest.
Compile and run synthetic tests before any timing. No compiler comparison in D1.

## One bounded measurement job

Exactly one manual hosted job, maximum 30 minutes including builds. No retries,
replacement draws or follow-up dispatches selected from the results. A timeout
is incomplete evidence; retain partial files and statuses. Synthetic preflight
jobs are separately labelled and never contribute timing observations.

For each of the three fixed seed blocks, run the full-suite baseline once,
then the four filtered key-schedule modes in these fixed orders:

1. original, swapped, same-left, same-right.
2. swapped, same-right, original, same-left.
3. same-left, original, same-right, swapped.

That is three full-suite processes plus twelve filtered processes. Before each
process, write its intended identity to a run ledger; after it finishes record
exit status without suppressing its output. Preserve failed and partial outputs.
Use the same seed for all benches in each full-suite process, explicitly recording
this metadata change. Other seeds are never substituted. The full suite supplies
three negative-control observations; require absolute reported tau >1 in all three
for diagnostic liveness. Failed liveness makes timing interpretation inconclusive.

Write raw CSV, crop CSV and standard signed summaries for every process. Validate
10000 total raw samples per measured target, correct class labels, 101 crop rows,
exact selected counts and agreement of the selected signed t/tau with the printed
five-decimal summary. Missing/malformed/nonfinite selected results are invalid,
not zero. Preserve and report every mode, including invalid ones.

## Interpretation fixed in advance

Use the existing median of three absolute five-decimal reported tau values and
strict >0.20 comparison for descriptive smoke alarms. Do not normalize by the
full budget, change the threshold, remove small crops or call a new pass clearance.

- A same-input alarm demonstrates a class/timing-analysis effect in that control
  context. It does not prove the original alarm harmless or the crypto constant
  time; setup and optimized context may differ.
- Opposite signs in original/swapped splits are descriptive key-associated
  evidence for further investigation, not a predeclared significance test.
- A failure only on a tiny selected crop is a scale diagnosis, not a physical
  causal explanation. Report uncropped and selected statistics together.
- No alarm, invalid evidence, or a different CPU does not establish a cause for
  the original failure. Report the original cause unresolved unless an actual
  mechanism is established and separately verified.
- No outcome in D1 authorizes a gate change or table activation. Existing protocol
  and its readiness, confirmation and injected-leak requirements remain in force.
