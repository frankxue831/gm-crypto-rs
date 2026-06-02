# Misuse / footgun audit — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`) |
| **Mission** | Audit dangerous-misuse risks in the Rust + C public surfaces: key/nonce/tweak/tag-length/buffer/sector misuse; C-ABI null/aliasing/length/in-place; error-collapse distinguishability; missing docs on confidentiality-only modes, authentication, RNG failure, fallible encryption. |
| **Method** | Read-only multi-agent workflow (`misuse-footgun-audit`): 6-lens map → adversarial verify (realistic misuse? + already type-enforced/documented?) → synthesis. 55 agents; 48 findings → 11 confirmed / 37 refuted → 9 confirmed + 5 hypotheses + 15 well-guarded. **Then orchestrator re-verified the load-bearing claims against the real docstrings/header and re-rated 4 items (see Corrections).** |

**Headline meta-conclusion:** the misuse *contracts are broadly well-documented already* — nonce/IV/counter/tweak uniqueness, no-authentication warnings, the GCM plaintext ceiling, oracle-resistance, and the in-place aliasing fix all carry prominent docstrings (verified line-cites in §Well-guarded). **The one genuinely undocumented footgun is the raw ECB block API.** Everything else is C-ABI precondition consolidation + "add a worked example / recommended floor" enhancements. **No source-supported finding of an undocumented catastrophic API beyond ECB.**

**Read-only doc/source analysis** — no edits; these are ergonomics/disclosure items, not implementation defects.

---

## ▶ ACTION ITEMS (pick up later)

- [ ] **(High)** Add an ECB misuse warning to `Sm4Cipher::{encrypt,decrypt}_block` (Rust) + `gmcrypto_sm4_{encrypt,decrypt}_block` (C header) — or `#[doc(hidden)]` if internal-only.
- [ ] **(Med)** Add a consolidated **C-ABI preconditions** block to the top of `gmcrypto.h` (pointer must point to ≥ stated size; `len` must not exceed allocation; UB if violated).
- [ ] **(Med)** Note in the C header that `gmcrypto_sm2_sign`/`_encrypt` are RNG-fallible (`GMCRYPTO_ERR` on RNG failure; terminal, do not retry).
- [ ] **(Low)** Add worked CSPRNG IV/nonce/counter sourcing examples to the CBC/CTR/GCM/CCM module docstrings; a `GcmTagLen` bit-strength table; a documented `CCM_MIN_TAG_LEN = 8` recommended floor; a `start_sector` u64-range note in the XTS-sectors C docs.

---

## 1 · Confirmed findings (re-rated; severity = residual risk after reading the docs)

Columns per the mission: **footgun · affected API · realistic misuse scenario · current guard · recommended doc/test/API mitigation.**

| Sev | Footgun · `affected API` | Realistic misuse | Current guard | Recommended mitigation |
|---|---|---|---|---|
| **High** | **Raw ECB block API has no misuse warning** · `Sm4Cipher::{encrypt,decrypt}_block` (Rust) + `gmcrypto_sm4_{encrypt,decrypt}_block` (C) | Dev loops `encrypt_block` over 16-byte chunks → ECB; identical plaintext blocks → identical ciphertext (leaks structure) | Docstring says only *"Encrypt one 16-byte block in place"*; module doc covers CT/throughput/KAT but **no ECB warning**; type blocks wrong length only | Prominent `WARNING: raw ECB, no semantic security — use only as a mode building block; for messages use mode_cbc/ctr/gcm/ccm/xts`. Consider `#[doc(hidden)]` or a doc-test. Mirror on the C header. |
| **Med** | **C-ABI pointer/length preconditions not consolidated** · all `(*const u8, len)` pairs + fixed-size `iv`/`key`/`tag` ptrs (`gmcrypto_sm4_cbc_encrypt`, `_gcm_encrypt`, `gmcrypto_sm3_hash`, `gmcrypto_sm2_sign`, …) | C caller passes a 4-byte buffer where 16 are read, or a too-large `len` → OOB read in `slice::from_raw_parts` | Per-param contracts exist (header line 287 "iv is exactly 16 bytes"); `ffi_guard` null + zero-len checks; **no single "every ptr ≥ stated size; len ≤ allocation; UB if violated" block**. *(Wrong `nonce_len` is runtime-safe: CCM `[7,13]` → ERR; GCM non-canonical is a documented valid path, not a silent failure.)* | Module-level **C-ABI preconditions** section at the top of `gmcrypto.h`; optional `c_smoke` doc-test. |
| **Med** | **C callers not told encryption is RNG-fallible** · `gmcrypto_sm2_sign`, `gmcrypto_sm2_encrypt` | C dev assumes encrypt always succeeds, ignores `rc`; rare RNG failure (no `/dev/urandom`) → silent loss | Rust documents it (`sign.rs` 99-104: `Error::Failed` on RNG fail); C header says *"RNG from getrandom::SysRng"* but **not that it can fail** | Header note: *"may return `GMCRYPTO_ERR` on RNG failure; ERR is terminal, do not retry."* |
| **Med→Low** | **CCM short tags {4,6} have no recommended floor** · `mode_ccm::{encrypt,decrypt}` | IoT picks `tag_len=4` → 2³² forgery resistance | **Already documented** (`mode_ccm.rs` 45-49: "weaker forgery resistance… advisory `tag_len >= 8`") | Enhancement: bit-strength table + a documented `CCM_MIN_TAG_LEN = 8` recommended constant (non-breaking). |
| **Low** | **XTS C `start_sector` is `uint64_t`, no range note** · `gmcrypto_sm4_xts_{encrypt,decrypt}_sectors` | Cloud disk with ≥2⁶⁴ sectors; C API caps at u64 | The u64→u128 widen is **lossless** (no truncation bug — the workflow's "silent truncation" framing is wrong); just an undocumented range cap | Header note: *"`start_sector` ∈ [0, 2⁶⁴−1]; use the Rust API for u128 sector addressing."* |
| **Low** | **No worked CSPRNG examples for IV/nonce/counter sourcing** · `mode_cbc`/`ctr`/`gcm`/`ccm::encrypt` | Dev invents `iv = hash(msg‖timestamp)` (predictable) | Contracts documented; **no code snippet** shows correct `getrandom::SysRng` sourcing | Add a worked example per mode docstring showing CSPRNG IV/nonce generation. |

## 2 · Corrections to the workflow's ratings (verified against source)

1. **CTR counter reuse: workflow HIGH → Low (doc-example only).** Verified `mode_ctr.rs` has a prominent `# Counter contract` (unique-per-key, two-time-pad) **and** a `# No authenticity` section. The contract *is* documented; only a worked example is missing.
2. **GCM finalize double-free: workflow Medium → Low (doc-polish).** Header already states *"freed by this call (even on error); do NOT call `…_free` afterwards."* Ask is just per-error-mode enumeration.
3. **C FFI nonce/IV "undetectable crypto failure": partly refuted.** CCM `nonce_len ∈ [7,13]` is runtime-validated (→ `GMCRYPTO_ERR`); GCM non-canonical nonce is a *documented valid path*. Genuine residual = fixed-size-pointer OOB-read class → folded into the consolidated Medium above.
4. **XTS `uint64_t` "silent truncation": refuted.** The FFI widens `u64 → u128` losslessly; no wrap bug — downgraded to a Low doc note.

## 3 · Hypotheses / enhancements (doc-prominence judgment calls)

- **(Med/High-path)** CBC IV + GCM nonce reuse — both already documented prominently (well-guarded #4, #5); add worked nonce-sourcing examples; a `generate_gcm_nonce` helper is an optional ergonomic.
- **(Low)** `GcmTagLen` short-tag bit-strength table (4 B = 32-bit … 16 B = 128-bit) + "below 12 bytes not recommended."
- **(Info)** CBC encrypt-then-MAC worked example (HMAC-SM3, IV in the MAC input).
- **(Low)** XTS tweak-uniqueness — *"documentation already exemplary; no code change needed"* (the workflow's own verdict).

## 4 · Well-guarded (misuse already mitigated — the positive map)

Verified present (type / runtime / doc):

- **`GcmTagLen` newtype** — compile-time valid-set `{4,8,12,13,14,15,16}` via `new() -> Option`.
- **CCM `tag_len`/`nonce_len`** — runtime-rejected upfront (`validate_params` → `None`).
- **XTS `Key1==Key2`** — constant-time reject in `split_keys` before any crypto.
- **CBC IV unpredictability** — `mode_cbc.rs` 5-8, cites NIST SP800-38A App. C + BEAST.
- **GCM nonce uniqueness** — `mode_gcm.rs` 13-21 (names plaintext-XOR + H-subkey leak) + SECURITY.md + C header.
- **CTR counter uniqueness** — `mode_ctr.rs` 4-12 (two-time-pad) + `# No authenticity`.
- **XTS tweak uniqueness** — `mode_xts.rs` 29-37 + `encrypt_sectors` "what NOT to do."
- **Single-`None`/`GMCRYPTO_ERR` oracle-resistance** — intentional, documented SECURITY.md 381-395 + `gmcrypto.h` 7-10.
- **`[u8;N]` length enforcement** (Rust) + `try_slice_mut` runtime length check (C).
- **CBC constant-time PKCS#7 strip** — `subtle::ConditionallySelectable`, no pad-len timing leak.
- **XTS in-place key-copy aliasing fix** — owned `[u8;32]` before `&mut buf`; regression `sm4_xts_sectors_key_buf_overlap_ok`.
- **`out_actual_len` retry feedback** — written before the capacity check so C callers can re-size.
- **GCM 2³⁶−32 plaintext ceiling** — enforced + documented (`mode_gcm.rs` 91-99, 138-143).
- **RNG failure → single error code** — Rust `Option`/`Result`, C `GMCRYPTO_ERR` (oracle-resistance).

## 5 · Caveats

- **Read-only** doc/source analysis; no edits. Findings are *ergonomics/disclosure* — none is a code or memory-safety defect (the in-place aliasing case is already fixed + regression-tested).
- **Severities are mine, re-rated after reading the actual docstrings/header** — they differ from the raw workflow output where the workflow didn't check whether the contract was already documented.
- **The deliberate single-`Failed`/`None`/`GMCRYPTO_ERR` collapse is not a bug** — the only footgun angle is caller *understanding* (don't retry on tamper), addressed by the RNG/error-model doc items.

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`misuse-footgun-audit`, run
`wf_e0767eee-2d0`), with orchestrator re-verification of the ECB docstrings, `mode_ctr`/`mode_ccm`
docstrings, and the `gmcrypto.h` contracts. No files edited, nothing committed/pushed/published/tagged,
no CI touched. Working-tree artifact; commit/track at your discretion (per the branch+PR rule, the
agent did not commit it).
