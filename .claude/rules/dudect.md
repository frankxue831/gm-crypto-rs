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

Before writing that the dudect nightly is green, list the last 14 nightly
conclusions; every red needs a ledger entry.

## Editing the gates

- Production dudect jobs require job-level `RUSTUP_TOOLCHAIN: 1.95.0` and an
  effective rustc/cargo/active-toolchain check before cache/build. The root
  stable override defeated the old action-only pin; neither the action tag
  nor a setup message proves effective identity. Preserve these checks and
  the accepted fresh-calibration requirement in `docs/v1.15-protocol.md`.

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
- Don't re-add the v0.19 fix-vs-fix relative gate (falsified). The current
  noise-twin relative proposal is retired (v1.15 Q15.2); the twin stays
  required non-blocking telemetry. Reopening needs a materially different
  reference, fresh hosted-runner calibration and injected-leak controls.
- v1.15 calibration is a candidate-table study, not an active gate change.
  Pin the numerical protocol before implementation; freeze the table before
  prospective confirmation. Relaxed cells require target-specific injected-
  leak sensitivity evidence before activation; baseline-only results cannot
  authorize it. Sparse/unknown/incompatible cells keep current policy. See
  `docs/v1.15-scope.md` Q15.5–Q15.7; PR-smoke policy is separate.
- Don't add a target "because the cycle touched crypto" without a
  secret-dependent window: GCM decryptor, TLCP CBC deprotect, X.509 parse are
  public inputs or already covered. A pure delegator (`Sm4CcmDecryptor` over
  `mode_ccm::decrypt_with_cipher`) earns no target; any cryptographic work
  inside it voids that and reopens the question.
- F21 `ct_sm4_cbc_unpad` stays open: the composite window is blind, so a gate
  there could never fail (`docs/v1.10-scope.md` Q10.9). The narrow
  `Sm4CbcDecryptor::finalize()` window separates an early-return control on
  the pinned local host (`docs/f21-finalize-result.md`, v1.14) but is **not**
  a CI target: the window is two to three timer ticks, hosted runners are
  uncalibrated for it, and the harness's printed `max tau` is unreliable in
  that regime — normalise `|max t|` by the declared budget instead. No gate,
  no promotion.

## Isolated v1.15 study

`dudect-main.yml` owns current-main nightly regression coverage and the production
policy fingerprints; `dudect-nightly.yml` preserves the frozen study's workflow
ID and census. The study measures the full SHA in `docs/v1.15-isolation.json`,
using the unchanged original producer and execution freeze. Do not apply a
main-wide merge hold after isolation qualification. Study-launcher changes
still require review and explicit evidence identity updates. Never apply a
study-derived bound automatically to newer crypto/build or runner identities.
