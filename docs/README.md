# The method, by the receipts

These are the receipts behind the method described in [CASE-STUDY.md](../CASE-STUDY.md): the AI agent was the construction engine — it wrote the code and the tests — while the human owned scope, invariants, evidence standards, review pressure, and release authority. Crypto was the stress test, not a safety proof: cheap, strong oracles (KAT vectors, dudect, fuzzers) plus independent adversarial review make a covered failure hard to hide, which is exactly why every claim below resolves to a committed artifact. This index groups the public process/audit docs so a reader can walk the trail from "what was promised" to "what was checked."

## Scope docs (pre-registration)

Per-cycle charters — scope, forks, and sign-offs recorded for each cycle. The TLCP arc was pre-registered as a standalone v1.5 cycle before any TLCP code; the per-cycle scope docs record what's in/out and what "done" means (squash history doesn't independently prove scope-before-code for every cycle).

- [v0.3-scope.md](v0.3-scope.md) — v0.3 ASN.1/DER + PEM/PKCS#8/SPKI/SEC1 scope; Q7.1–Q7.10 sign-off decisions.
- [v0.4-scope.md](v0.4-scope.md) — v0.4 RustCrypto trait fit + bitsliced S-box + C FFI shim; Q4.1–Q4.19.
- [v0.5-scope.md](v0.5-scope.md) — v0.5 SIMD backend scope; Q5.11 SIMD architectural-reset addendum.
- [v0.6-scope.md](v0.6-scope.md) — v0.6 W4-phase-3/W6 SIMD fanout scope; Q6.1–Q6.10.
- [v0.7-aead-scope.md](v0.7-aead-scope.md) — v0.7 W4 design-cycle scope for v0.8 SM4-GCM/CCM; Q8.1–Q8.8 + v0.9 candidate Q-list.
- [v0.9-scope.md](v0.9-scope.md) — v0.9 AEAD-ergonomics scope (tag-len param, buffered GCM, single-shot AEAD FFI); Q9.1–Q9.10.
- [v0.10-scope.md](v0.10-scope.md) — v0.10 streaming-AEAD FFI scope; Q10.1–Q10.11.
- [v0.11-scope.md](v0.11-scope.md) — v0.11 digest 0.10→0.11 / cipher 0.4→0.5 trait-fit scope; Q11.1–Q11.11.
- [v0.12-scope.md](v0.12-scope.md) — v0.12 SM4-XTS single-shot (GB/T 17964) scope; Q12.1–Q12.13.
- [v0.13-scope.md](v0.13-scope.md) — v0.13 SM4-XTS C FFI scope; Q13.1–Q13.12.
- [v0.14-scope.md](v0.14-scope.md) — v0.14 parser-fuzzing scope; Q14.1–Q14.12, assurance-only (clean run ⇒ no release).
- [v0.15-scope.md](v0.15-scope.md) — v0.15 SM4-XTS multi-sector helper scope; Q15.1–Q15.12.
- [v0.16-scope.md](v0.16-scope.md) — v0.16 multi-sector XTS C FFI scope; Q16.1–Q16.12.
- [v0.17-scope.md](v0.17-scope.md) — v0.17 public-flip / CI-off-self-hosted-runner scope.
- [v0.18-scope.md](v0.18-scope.md) — v0.18 dudect-gate hardening scope (OS/toolchain pin + multi-run median); Q18.x incl. Q18.7.
- [v0.19-scope.md](v0.19-scope.md) — v0.19 self-calibrating relative dudect-gate scope; Q19.1–Q19.7 (gate later falsified).
- [v0.20-scope.md](v0.20-scope.md) — v0.20 streaming-decryptor differential fuzzing + fuzz coverage scope; Q20.1–Q20.5.
- [v0.21-scope.md](v0.21-scope.md) — v0.21 v1.0-readiness-audit scope (API/SemVer freeze, CI guards); Q21.1–Q21.9.
- [v0.22-scope.md](v0.22-scope.md) — v0.22 API-tightening (decouple crypto-bigint) scope; Q22.1–Q22.8.
- [v0.23-scope.md](v0.23-scope.md) — v0.23 pre-1.0 re-audit remediation scope (W1–W4); Q23.1–Q23.9.
- [v1.1-scope.md](v1.1-scope.md) — v1.1 SM2 key-exchange scope; Q1.1–Q1.10.
- [v1.2-scope.md](v1.2-scope.md) — v1.2 SM2-KX C FFI scope; Q2.1–Q2.10 (Q2.1–Q2.3 maintainer-signed).
- [v1.3-scope.md](v1.3-scope.md) — v1.3 X.509-with-SM2 parse+verify scope; Q3.1–Q3.11 (chains/Name-parse/TLCP deliberately OUT).
- [v1.4-scope.md](v1.4-scope.md) — v1.4 X.509 C FFI scope; Q4.1–Q4.15.
- [v1.5-scope.md](v1.5-scope.md) — v1.5 TLCP-decomposition cycle charter (non-publishing); Q5.1–Q5.5, maintainer-signed.
- [v1.6-scope.md](v1.6-scope.md) — v1.6 TLCP key schedule + no-confirm KX scope; Q6.1–Q6.10 (Q6.2/Q6.3 maintainer-signed).
- [v1.7-scope.md](v1.7-scope.md) — v1.7 TLCP record protection scope; Q7.1–Q7.11.
- [v1.8-scope.md](v1.8-scope.md) — v1.8 TLCP cert chain/pair verification scope; Q8.1–Q8.16 (incl. Q8.7b widening).
- [v1.9-scope.md](v1.9-scope.md) — v1.9 TLCP toolkit C FFI scope; Q9.1–Q9.8 (4 forks maintainer-locked).

## Design & decomposition

The "what is this and how does it break down" layer — the TLCP arc map plus per-feature design docs the human wrote/signed before the plan.

- [tlcp-decomposition.md](tlcp-decomposition.md) — the arc-opening map: GB/T 38636 TLCP wire anatomy, gap analysis G1–G5, the derived chain/pair profile (NOT server auth), record-CT API constraints, cycle map v1.6→v1.9, D-1…D-12 verification items.
- [v1.1-sm2-key-exchange-design.md](v1.1-sm2-key-exchange-design.md) — SM2-KX (GM/T 0003.3) design doc — role state-machines, typestate, key-confirmation flow — backing the v1.1 plan.
- [v1.3-x509-sm2-design.md](v1.3-x509-sm2-design.md) — X.509-with-SM2 leaf-cert design doc — strict in-repo DER profile, no-trust-decisions boundary — backing the v1.3 plan.

## Implementation plans & executed reviews

TDD task plans, each carrying the outcome of an Opus/Fable adversarial review that EXECUTED the riskiest slices in a worktree (GO-WITH-FIXES, must-fixes folded). The agent constructs; the review pressure is recorded here.

- [v1.1-sm2-key-exchange-plan.md](v1.1-sm2-key-exchange-plan.md) — v1.1 SM2-KX TDD plan + Fable-5 reviewed-plan outcome (reviewer re-ran the plan code and regenerated every KAT vector).
- [v1.3-x509-sm2-plan.md](v1.3-x509-sm2-plan.md) — v1.3 X.509 parse+verify plan + Fable-5 GO-WITH-FIXES (the inverted negative-serial-tolerance catch).
- [v1.4-x509-ffi-plan.md](v1.4-x509-ffi-plan.md) — v1.4 X.509 C FFI plan + Fable-5 GO-WITH-FIXES (the `move`-closure / ffi_guard UnwindSafe catch).
- [v1.6-tlcp-key-schedule-plan.md](v1.6-tlcp-key-schedule-plan.md) — v1.6 TLCP key-schedule + no-confirm-KX plan + Fable-5 EXECUTED review (A1–A6; reviewer ran plan code in a scratch tree).
- [v1.7-tlcp-record-protection-plan.md](v1.7-tlcp-record-protection-plan.md) — v1.7 TLCP record-protection plan + Fable-5 EXECUTED review (ran the Lucky13 core; caught 2 compile bugs + missing-ceiling chain-break + a false-assurance dudect axis).
- [v1.8-tlcp-chain-verify-plan.md](v1.8-tlcp-chain-verify-plan.md) — v1.8 cert chain/pair-verify plan + Opus EXECUTED review (Tasks 1–5 against real minted certs; 9 clippy lints incl. a hard E0433, the S1 pair-binding gap).
- [v1.9-tlcp-ffi-plan.md](v1.9-tlcp-ffi-plan.md) — v1.9 TLCP toolkit C FFI plan (Tasks 0–10) + Opus EXECUTED review (GO-WITH-FIXES, 6 must-fixes — two caught LIVE at compile time) + the 19-symbol census lock.

## Readiness & audits

Multi-model adversarial audits and GO/NO-GO gates standing between the work and an irreversible publish. The human owns the evidence bar and the release decision.

- [v1.0-readiness.md](v1.0-readiness.md) — the v1.0 GO/NO-GO readiness report + the 1.0.0 publish runbook; §3.A = the crypto-bigint-exposure decision (resolved in v0.22).
- [v1.0-reaudit.md](v1.0-reaudit.md) — multi-model pre-publish re-audit (Codex gpt-5.5 + Grok), four dimensions A–D; returned NO-GO-as-is with 2 API/ABI blockers + should-fixes (remediated in v0.23).
- [pre-opensource-audit.md](pre-opensource-audit.md) — v0.17 pre-open-source audit (codex-reviewed plan) ahead of the private→public repo flip.
- [audits/2026-06-02-release-readiness-synthesis.md](audits/2026-06-02-release-readiness-synthesis.md) — the 2026-06-02 release-readiness synthesis (0 blockers, GO-WITH-FOLLOWUP); rolls up the seven dimension audits below.
- [audits/2026-06-02-api-abi-stability-audit.md](audits/2026-06-02-api-abi-stability-audit.md) — API/ABI stability dimension of the 2026-06-02 readiness audit.
- [audits/2026-06-02-ci-gate-review.md](audits/2026-06-02-ci-gate-review.md) — CI-gate review dimension of the 2026-06-02 readiness audit.
- [audits/2026-06-02-ct-discipline-audit.md](audits/2026-06-02-ct-discipline-audit.md) — constant-time-discipline dimension of the 2026-06-02 readiness audit.
- [audits/2026-06-02-dependency-policy-audit.md](audits/2026-06-02-dependency-policy-audit.md) — dependency-policy dimension of the 2026-06-02 readiness audit.
- [audits/2026-06-02-docs-vs-code-ci-consistency.md](audits/2026-06-02-docs-vs-code-ci-consistency.md) — docs-vs-code / CI-consistency dimension of the 2026-06-02 readiness audit.
- [audits/2026-06-02-fuzz-coverage-gaps.md](audits/2026-06-02-fuzz-coverage-gaps.md) — fuzz-coverage-gaps dimension of the 2026-06-02 readiness audit.
- [audits/2026-06-02-misuse-footgun-audit.md](audits/2026-06-02-misuse-footgun-audit.md) — misuse/footgun dimension of the 2026-06-02 readiness audit.
- [v0.1.0-release-review.md](v0.1.0-release-review.md) — v0.1.0 pre-publish reviewer checklist (the template these reviews follow).
- [v0.2.0-release-review.md](v0.2.0-release-review.md) — v0.2.0 pre-publish reviewer checklist.
- [v1.0.0-release-review.md](v1.0.0-release-review.md) — v1.0.0 pre-publish reviewer checklist (the deliberate first-stable-publish gate).

## KAT sourcing

Where each known-answer-test vector came from and why that oracle is trustworthy — the evidence provenance behind every byte-for-byte cross-check.

- [v0.8-ccm-kat-sourcing.md](v0.8-ccm-kat-sourcing.md) — SM4-CCM KAT sourcing: OpenSSL 3.x EVP SM4-CCM (gmssl 3.1.1 lacks -ccm); embedded C harness + parametric coverage matrix.
- [v0.12-xts-kat-sourcing.md](v0.12-xts-kat-sourcing.md) — SM4-XTS KAT sourcing: OpenSSL EVP SM4-XTS pinned to xts_standard=GB (gmssl lacks XTS).
- [v1.1-sm2kx-kat-sourcing.md](v1.1-sm2kx-kat-sourcing.md) — SM2-KX KAT sourcing: the GM/T 0003.5 recommended-curve worked example + the default-ID-vs-ALICE/BILL diagnosis.
- [v1.6-kat-sourcing.md](v1.6-kat-sourcing.md) — TLCP key-schedule KAT sourcing: OpenSSL TLS1-PRF digest:SM3 recipe (label-in-seed) + GM/T 0003.5 reuse rationale.
- [v1.7-kat-sourcing.md](v1.7-kat-sourcing.md) — TLCP record-protection KAT sourcing: OpenSSL EVP SM4-CBC + GmSSL sm3hmac (CBC) / GmSSL sm4 -gcm (GCM).
- [v1.8-kat-sourcing.md](v1.8-kat-sourcing.md) — TLCP chain/pair KAT sourcing: the GmSSL 3-level chain fixtures (root → intermediate → [sign,enc] pair, gmssl-self-verified).

## Constant-time recalibration

The longitudinal honesty ledger for the dudect timing gate — every time CI-runner noise moved the floor, what was tried, and what was falsified rather than papered over.

- [v0.5-dudect-recalibration.md](v0.5-dudect-recalibration.md) — the running dudect noise-floor analysis: the 2026-05-12 runner-image shift, the v0.18 pin+median, the v0.19 relative-gate FALSIFICATION, and the 2026-06-07/06-17 sentinel demotions — the evidence trail behind the telemetry/sentinel posture.

## API baselines

Committed cargo-public-api snapshots — the machine-checked drift contract that turns "we froze the API" into a CI gate, not a promise.

- [api-baseline/gmcrypto-core.txt](api-baseline/gmcrypto-core.txt) — committed public-API baseline for gmcrypto-core (full surface; regenerated additively per API-adding cycle, pinned cargo-public-api 0.52.0 + nightly-2026-05-23).
- [api-baseline/gmcrypto-simd.txt](api-baseline/gmcrypto-simd.txt) — committed public-API baseline for gmcrypto-simd (the `pub mod gmcrypto_simd` doc-hidden internal-acceleration surface).
