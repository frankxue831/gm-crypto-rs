---
paths:
  - ".github/workflows/dudect-*.yml"
  - ".github/scripts/check_assurance_policy.py"
  - "crates/gmcrypto-core/benches/**"
  - "docs/v0.5-dudect-recalibration.md"
---

# Dudect timing-leak gates

Thresholds: inline Python in `.github/workflows/dudect-*.yml`. Targets:
`crates/gmcrypto-core/benches/timing_leaks.rs`. Demotion record and every
recalibration: `docs/v0.5-dudect-recalibration.md`. Gate `|tau|`, not `|t|`.
Bench needs `crypto-bigint-scalar`; the 4th matrix slot carries AEAD+XTS+KX.

## Runner pool — read before calling a red slot noise

Hosted `ubuntu-24.04` is heterogeneous (EPYC 7763 / 9V74 / 9V45 / Xeon 8573C
/ 6973P-C) and composite-window targets read materially higher on some SKUs.
Both workflows print `RUNNER-CPU:` beside the verdicts. `ct_sm4_cbc_decrypt_fanout`
no-change medians reached 0.2904 on 9V74 (three false reds), so since
2026-09-01 its bound is **0.55 on EPYC 9V74 only** (a `SKU-GATE:` line marks
each application), 0.20 everywhere else incl. unknown SKUs. Never merge with
an unexplained red dudect check; a green re-run on different hardware is not
evidence.

## Editing the gates

- The workflow Python is fingerprint-pinned by `check_assurance_policy.py`.
  After a gate edit, regenerate the four reviewed fingerprints with the
  script's own helpers (import it via `importlib`, catching `SystemExit`; then
  `reviewed_source_fingerprint(job(...))` and
  `reviewed_python_heredoc(step_named(job(...), "Parse and gate"))[1]`).
  Validate on the PR smoke run **and** a dispatched nightly.
- Don't forget `MATRIX_FEATURES` on the **Parse and gate** step (`env` is
  step-scoped) or feature-conditional `|tau|` gates silently never fire.
- Don't bump `dtolnay/rust-toolchain@1.95.0` or `runs-on: ubuntu-24.04`
  casually — moving either invalidates the `|tau|` calibration and needs a
  reviewed re-baseline recorded in the recalibration doc. No self-hosted
  runner (RCE on a public repo).
- Don't move the multi-run median into `timing_leaks.rs` (loop + median live
  in workflow YAML + inline Python). `required_low`/sentinel gate the
  **median**; `negative_control` gates the **min**; a required target measured
  `< N` runs fails (completeness).
- `rust-cache` `shared-key` is `strategy.job-index`, **not**
  `${{ matrix.features }}` (commas break the cache key).

## Target policy

- Don't re-promote `ct_fn_invert` / `ct_fp_invert` to `|tau|<=0.20` because a
  calibration looks quiet (telemetry / nightly sentinel `@0.55`). Same for
  `ct_sign_k_class` and `ct_hmac_sm3` (class-split image noise; HMAC has no
  non-composite backstop). `negative_control` must fire every run
  (`|tau|>1.0`, gated on the **min**).
- Don't re-add the v0.19 fix-vs-fix relative gate (falsified). Don't turn
  `noise_twin_class_split` into a relative gate until calibration +
  injected-leak controls pass.
- Don't add a target "because the cycle touched crypto" without a
  secret-dependent window: GCM decryptor, TLCP CBC deprotect, X.509 parse are
  public inputs or already covered. A pure delegator (`Sm4CcmDecryptor` over
  `mode_ccm::decrypt_with_cipher`) earns no target; any cryptographic work
  inside it voids that and reopens the question.
- F21 `ct_sm4_cbc_unpad` stays open: the composite window is blind, so a gate
  there could never fail (`docs/v1.10-scope.md` Q10.9).
