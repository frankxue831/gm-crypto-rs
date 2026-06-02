# Constant-time discipline audit — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`) |
| **Question** | Do secret-dependent code paths still match the documented constant-time discipline? |
| **Method** | Read-only multi-agent audit (Claude Code dynamic workflow): 7-area parallel mapping → per-finding adversarial verification (refute-by-default) → dedupe/rank synthesis, + a dedicated re-read of the one area the automated pass dropped (`sm4-core`). 94 agents; ~96 secret-touching sites examined; every finding source-verified. |
| **Scope** | SM2 (nonce/key/sign/decrypt), SM4 (key schedule, S-box, SIMD, CBC/CTR/GCM/CCM/XTS), HMAC-SM3/PBKDF2/PKCS#8, all `subtle` call sites, dudect coverage vs SECURITY.md. |
| **Static vs dynamic** | **Static / source-level only.** Source was verified against the discipline and each path mapped to its dudect target; the dudect bench was **not executed** this session — no new empirical `\|tau\|` was measured. |

---

## Headline verdict

**No source-supported timing-leak finding in the audited scope.** Every secret-dependent
branch / index / loop / early-return / compare resolved to one of: (a) a documented
constant-time mechanism, (b) a value driven by **public** data, or (c) an accepted documented
exception.

- **0 confirmed leaks**
- 83 of 86 automated findings **refuted**; the 3 "confirmed" were **positive confirmations**
  of correct CT hygiene (constant-time `mul_var`, XTS tweak zeroization, HMAC key zeroization;
  info/low)
- 19 residual-assurance checkpoints (none a defect); 54 explicitly-clean scopes
- The dedicated SM4-core re-read: **0 leaks** across all 10 SM4 functions

This is *"no source-supported finding,"* **not** a proof of absence — see *Audit limits*.

---

## ▶ ACTION ITEMS (pick up later)

Only two items are worth action. **Neither is a confirmed vulnerability** — both are *assurance*
gaps.

- [ ] **(Low) Inversion timing diagnostics stay on telemetry/sentinel, not a tight gate.**
  `ct_fp_invert` (`sm2/point.rs::to_affine`, nonce `k` via `Z`) and `ct_fn_invert`
  (`sm2/sign.rs::try_sign_once`, priv key `d` via `1+d`) are PR-telemetry-only / nightly
  sentinel `@0.55`, not `|tau|<0.20`. This is the **documented, accepted** v0.19-falsification /
  v0.20-baseline posture. The only path to re-promote is the deferred **class-split-aware
  "noise-twin"** dudect reference. _Decision needed: leave as-is (documented) or schedule the
  noise-twin work post-1.0._

- [ ] **(Low–Med) Constant-time PKCS#7 unpad has no dedicated dudect target.**
  `sm4/mode_cbc.rs::strip_pkcs7_ct` (+ `cbc_streaming.rs::strip_pkcs7_block`) is constant-time in
  source (fixed 16-byte masked scan, single validity bit, **no early return**) but is gated only
  *indirectly* via `ct_sm4_cbc_decrypt_fanout` (cfg `sm4-bitsliced-simd`). _Suggested: add a
  dedicated `ct_sm4_cbc_unpad` target, class-split on pad validity, under the **default**
  (non-SIMD) feature._ Caveat: CBC is unauthenticated; SECURITY.md assigns padding-oracle
  resistance partly to the caller.

---

## 1 · Confirmed issues

**None.** No secret-derived value was shown to drive timing-observable behavior without a
constant-time mitigation, in any checked scope.

---

## 2 · Hypotheses & residual-assurance checkpoints (NOT confirmed leaks)

Severity = **residual risk on source inspection**. The workflow originally tagged the SM2 /
SM4-AEAD rows "critical" by *path-criticality* (a leak there *would* be critical); on reading the
source each already uses the documented mechanism, so residual risk is low/info.

### Tier 1 — material residual / coverage items

| Sev | Finding | Secret | Observable behavior | File / function | Dudect coverage | Recommended next check |
|---|---|---|---|---|---|---|
| Low (accepted) | Single-inversion diagnostics on telemetry/sentinel only, not a tight `\|tau\|<0.20` gate | nonce `k` (via `Z`); priv key `d` (via `1+d`) | duration of `Fp::invert(Z)` / `Fn::invert((1+d))` | `sm2/point.rs::to_affine`, `sm2/sign.rs::try_sign_once` | `ct_fp_invert` / `ct_fn_invert` — PR telemetry; nightly sentinel `@0.55` | Documented (v0.19/v0.20). Re-promotion only via class-split-aware "noise-twin". |
| Low–Med (coverage) | CT PKCS#7 unpad has no dedicated dudect target; gated only indirectly via the SIMD batch path | decrypted pad bytes / validity bit | per-block unpad time; validity-bit branch | `sm4/mode_cbc.rs::strip_pkcs7_ct` (+ `cbc_streaming.rs::strip_pkcs7_block`) | indirect — `ct_sm4_cbc_decrypt_fanout` (cfg `sm4-bitsliced-simd`) | Add `ct_sm4_cbc_unpad`, class-split on pad validity, default feature. |

### Tier 2 — "confirm-the-invariant" checkpoints (mechanism read as correct)

| Sev | Finding (mechanism present & correct) | Secret | Observable behavior | File / function | Dudect coverage | Recommended next check |
|---|---|---|---|---|---|---|
| Info | Fixed-K=2 masked-select sign retry | `d`, candidate validity | which retry produced valid (r,s) | `sm2/sign.rs::sign_raw_with_id` | `ct_sign`, `ct_sign_k_class` | `SIGN_RETRY_BUDGET=2` const; all iters run; `ct_or_else` merge |
| Info | Fixed-budget (4-draw) nonce sampler, dummy-k fallback | nonce `k`, validity | rejection-exhaustion timing | `sm2/sign.rs::sample_nonzero_scalar` | `ct_sign_k_class` | `NONCE_SAMPLE_BUDGET=4` const; no branch on found/exhaust; dummy `k=1` masked |
| Info | `(1+d)` inversion w/ CtOption masked fallback | `d`, invert validity | invert + fallback timing | `sm2/sign.rs::try_sign_once` | `ct_fn_invert`, `ct_sign` | `d∈[1,n-2]` ⇒ `1+d≠0`; fallback masked; `inv_ok` folded |
| Info | r/s/k validity via `Choice` masked fold | `k`, `d` | early-mask vs late-fold | `sm2/sign.rs::try_sign_once` | `ct_sign`, `ct_sign_k_class` | `ct_eq` not branches; no early return |
| Info | `mul_g` comb-table 16-entry linear scan | nonce `k` nibbles | lookup timing | `sm2/scalar_mul.rs::mul_g` | `ct_mul_g` | 16-iter scan; `ct_eq` on public index; `conditional_select` |
| Info | `mul_var` 4-bit window linear scan | priv key `d_B` | table-scan timing | `sm2/scalar_mul.rs::mul_var` | `ct_mul_var`, `ct_sm2_decrypt` | no secret array index; all 256 bits same path |
| Info | Decrypt MAC compare via `ConstantTimeEq` | `d_B` (via `u`) | 32-byte compare, no early exit | `sm2/decrypt.rs::decrypt` | `ct_sm2_decrypt` | `ct_eq`→`Choice` folded with `kdf_zero`; one final `bool::from`; both fail-paths same flow |
| Info | GCM tag compare + commit-on-verify | master key (via tag) | tag-compare timing; PT only after verify | `sm4/mode_gcm.rs::decrypt` | `ct_sm4_gcm_decrypt`, `_buffered` | `ct_eq`; PT not released pre-verify |
| Info | CCM tag compare + tentative-PT zeroize on fail | master key; PT on fail | MAC/CTR/compare timing | `sm4/mode_ccm.rs::decrypt` | `ct_sm4_ccm_decrypt` | `ct_eq`; tentative PT zeroized **before** `None` |
| Info | XTS α-doubling `mul_alpha` masked reduce | tweak `T=SM4_E(Key2,·)` | shift+reduce; carry branch? | `sm4/mode_xts.rs::mul_alpha` | `ct_sm4_xts_decrypt` | 16-iter fixed; `t[0]^=0xE1 & carry.wrapping_neg()` (masked, no `if`) |
| Info | Default linear-scan S-box (deliberate) | key/state byte | 256-iter scan | `sm4/cipher.rs::sbox_ct` | `ct_sm4_key_schedule`, `ct_sm4_encrypt_block` | fixed 256-iter `ct_eq` on public index + `conditional_assign`; no `S_BOX[secret]` |
| Info | Private-key `[1,n-2]` range check | `d` input bytes | range-check timing | `sm2/private_key.rs::from_bytes_be` | `ct_sign` | `ct_eq`/`ct_lt`→`Choice`; `CtOption`, no early return |
| Info | HMAC-SM3 tag verify via `ConstantTimeEq` | HMAC key (via tag) | 32-byte compare | `hmac.rs::HmacSm3::verify` | `ct_hmac_sm3` (indirect) | `ct_eq`, no byte-wise early exit |
| Info | SM4 `gf_mul` bit-serial mask-XOR (SIMD scalar) | key byte `b` | fixed 8-iter | `gmcrypto-simd/src/sm4/scalar.rs::gf_mul` | `ct_sm4_encrypt_block(_bitsliced_simd)` | `0u8.wrapping_sub(b&1)` mask, no branch |
| Info | GCM streaming finalize tag verify | master key; buffered PT | incremental verify | `sm4/gcm_streaming.rs::Sm4GcmDecryptor::finalize_verify` | `ct_sm4_gcm_decrypt_buffered` | `ct_eq`; `tag.len()` public; commit-on-verify |
| Info | PBKDF2 loop count is public iterations | password (independent) | loop count vs password | `kdf.rs::pbkdf2_hmac_sm3` | `ct_hmac_sm3`, `ct_pkcs8_decrypt` | iters parsed from public DER; password doesn't drive count |
| Info | PKCS#8 decrypt structural early-fail on public ASN.1 | blob structure (public) | malformed fails fast; valid+wrong-pw runs full | `pkcs8.rs::decrypt` | `ct_pkcs8_decrypt` | parse branches only on public OIDs/lengths, not password |

*(Bitsliced `gf_inv`, `affine_a`, `sbox` composition, the 32-round `crypt`/batch paths, and the
CTR leftover-cursor were also read directly and are constant-time — folded into the clean scopes.)*

---

## 3 · Scopes checked with no source-supported finding (refuted / clean)

54 scopes came back clean. Grouped:

- **SM2 sign/scalar-mul:** fixed-K=2 loop, nonce sampler budget=4, comb/variable-base nibble
  lookups (`ct_eq` on public index + masked select), `ct_or_else` CtOption merge, validity-mask
  fold, `Fn`/`Fp` inversions (crypto-bigint safegcd, documented exception), nonce/intermediate +
  ZeroizeOnDrop wipes (post-timing).
- **SM2 encrypt/decrypt:** off-curve `C1` guard (public coords, before `d_B` use), KDF-counter
  wrap (public length), KDF-zero rejection (CT `ct_all_zero` folded with MAC), `retrieve()`
  Montgomery reduction, identity-point check (public key), SEC1/raw-ciphertext bounds (public wire).
- **SM4 SIMD + GHASH:** AVX2/NEON `gf_mul` (8-iter mask-XOR), affine transforms (compile-time
  shifts, XOR-tree parity), software GHASH (128-iter mask-XOR, no branch on H/X), CLMUL/PMULL
  reductions (public loop bounds), CPU detect (public caps, pre-secret).
- **SM4 AEAD/XTS:** GCM length-ceiling + overflow latch (public length), commit-on-verify, CCM
  param validation + tag-mismatch branch (public validity bit, PT zeroized), XTS `Key1==Key2`
  (`ct_eq` outcome gates public reject), `mul_alpha` carry mask, XTS sector/length validation
  (public), tweak-chain zeroization.
- **MAC/KDF/SM3:** HMAC key-intermediate zeroization, HMAC key-length branch (public RFC 2104),
  no-`Drop`-on-`HmacSm3` (intentional; inner/outer wiped via `Sm3::Drop`), `Sm3::Drop` zeroize,
  SM3 buffer-length branch (public streaming metadata), PBKDF2 intermediate wipes, PKCS#8 SM4-key
  wipe.
- **RNG path:** RNG-failure early-return + buffer zeroize (explicitly documented **public**,
  non-secret — the A-3 `TryCryptoRng` contract).

---

## 4 · Audit limits & honesty caveats

1. **Static / source-level only.** Verified that the source *matches* the discipline and mapped
   each path to its dudect target; did **not execute** the bench — no new empirical `|tau|`
   measured this session. Empirical confidence still rests on the CI gates (and the documented
   telemetry/sentinel posture for the two inversions).
2. **Coverage gap closed mid-audit:** the automated `sm4-core` agent returned no structured
   output; SM4 key schedule / CTR / core bitsliced S-box would otherwise have had only
   *incidental* coverage. A dedicated re-read closed it — **0 leaks** — but the automated run was
   6/7 areas until that re-read.
3. **Trusted dependencies assumed constant-time:** `subtle` (`ct_eq`/`ct_gt`/`conditional_select`)
   and `crypto-bigint 0.7.3` (`ConstMontyForm::invert` safegcd) are taken as CT by construction;
   several "next checks" point at SemVer-drift risk there, not at gm-crypto-rs code.
4. **One unavoidable public branch** per design (`bool::from(valid)` for `Option`/`Result` shape):
   gates on a value that is **public after** the constant-time fold (tag/MAC/pad validity),
   consistent with the single-`Failed`/`None` invariant.

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`ct-discipline-audit`,
run `wf_83f18a2a-7ea`). No files edited, nothing committed/pushed/published/tagged, no CI or
secrets touched during the audit. This document is a working-tree artifact; commit/track at your
discretion (per the branch+PR rule, the agent did not commit it).
