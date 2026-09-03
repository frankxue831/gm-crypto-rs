# Version history

Per-cycle narrative for gm-crypto-rs, **newest-first**, extracted verbatim from
`CLAUDE.md` (which had accumulated 864 lines of it — 42% of the file, loaded
into every agent session). Nothing here is load-bearing for day-to-day work:
the constraints an agent must not violate live in `CLAUDE.md`, the
user-facing posture in `README.md` / `SECURITY.md`, the release log in
`CHANGELOG.md`, and each cycle's sign-off questions in `docs/vX.Y-scope.md`.

This file is the **archive**. Read it when you need to know *why* a decision
was made, what a cycle deliberately excluded, or what a past number
(`census 29 → 30`, `c_smoke 84 → 97`) referred to at the time — the counts in
these paragraphs are correct **as of their own cycle** and are deliberately not
updated as the codebase moves.

**Adding to this file:** a new cycle prepends its paragraph at the top, in the
established `**vX.Y —**` / `**Earlier — vX.Y —**` shape. `CLAUDE.md` keeps
only a condensed current-release block — see its `Don't` section.

## Cycles

**v1.12 — length-committed streaming SM4-CCM; PUBLISHED 2026-09-04 from
`b0c6679` (1.12.0, all three crates; publish delegated for this release).** `sm4::ccm_streaming::{Sm4CcmEncryptor, Sm4CcmDecryptor}`
behind the existing `sm4-aead` flag — no new feature, no new dependency, no C
ABI change; default build byte-identical. Overturns the v0.15 Q15.11
buffer-only objection with the design it never evaluated: the caller declares
`plaintext_len` so `B0` is fixed, then CBC-MAC and CTR advance per chunk at
`O(chunk)` (OpenSSL EVP is precedent for the length commitment only — it does
not stream CCM). Over-feed emits nothing and poisons; `finalize` is `None` on
poison or under-feed, stricter than `Sm4GcmEncryptor` on purpose. The
decryptor is an incremental-input buffered, commit-on-verify, latched pure
delegator over the new `pub(super) mode_ccm::decrypt_with_cipher`; **no new
dudect target** (Q12.8 — the `Sm4GcmEncryptor` and v1.11 thin-wrapper
precedents), the thinness guarded by two new differential fuzz targets
(`fuzz_sm4_ccm_streaming_{decrypt,encrypt}`, census 33 → **35**), the encrypt
one carrying a declared-length mode byte so the over-/under-feed arms actually
fire. The `mode_ccm` refactor extracted a shared `q`-byte `counter_block`
(never GCM's `inc32` — a 12-byte nonce is `q = 3`), `build_a0`,
`payload_ceiling`; single-shot API, outputs and the OpenSSL KATs unchanged;
api-baseline +29 additive lines. The maintainer's spec review pinned eight
implementer traps before code (q-byte counter vs `inc32`, `checked_add` on
`u64` for wasm32, whole-chunk rejection, the 13-byte-nonce 65 535-byte
decryptor latch, split `(ct, tag)` delegate, `pub(super)` not `pub(crate)`,
the fuzz layouts, and the stale "incompatible with streaming" premise in
`mode_ccm.rs` / `lib.rs`). Spec PR #185; implementation PR #186 (eight
commits, subagent-driven with per-task reviews; the whole-branch review's one
fix wave was docs-only). FFI projection is the v1.13 candidate; the
`Sm4GcmEncryptor` / `GhashAcc` zeroize follow-up is in the scope §6. Scope:
`docs/v1.12-scope.md`. Gate #1 PASSed against `9ccb262` (#188,
`docs/v1.12.0-gate1-evidence.md`); #189 then separated the gated SHA from
`RELEASE_SHA` in the records, and #190 dated the CHANGELOG heading to the
publish day. Post-release housekeeping: `CLAUDE.md` was cut from 360 lines to
under 200 per the official "under 200 lines" guidance, with area constraints
moved into committed path-scoped rule files (dudect, ffi, simd, sm4, sm2-sm3,
protocols, fuzz, features-and-ci, docs-and-release) and the 1.11.2 / crates.io
skips / closed-backlog narrative left to this file, where it already was.

**v1.11.2 — presentation patch; PUBLISHED 2026-08-23 from `0de98e2`.**
No crypto path, public API, C ABI, wire format, MSRV or dependency change —
the only `crates/**/*.rs` delta is two inner attributes on
`gmcrypto-core/src/lib.rs`, and `cargo-public-api` is byte-identical to
1.11.1. It needed a version because **crates.io metadata and docs.rs renders
are baked into a published version**: every defect it fixes was already
corrected in the repository and invisible to anyone who had not cloned it.
The two that mattered: `gmcrypto-simd` outranks `gmcrypto-core` in a
crates.io `sm4` search and was rendering the *workspace* README (H1
`gm-crypto-rs`, `gmcrypto-core` badges, no statement that it is an internal
`rlib` outside SemVer) — it now has its own; and every feature-gated item on
docs.rs was documented but **unbadged**, so `sm4::gcm_streaming` and
`sm2::key_exchange` named their gating feature in no rendered documentation
at all. The mechanism is one line —
`#![cfg_attr(docsrs, feature(doc_cfg))]` plus
`rustdoc-args = ["--cfg", "docsrs"]` — because **`doc_auto_cfg` was removed
in Rust 1.92 and merged into `doc_cfg`** (rust-lang/rust#138907), under which
auto-labelling is on by default: 101 badges, including compound gates like
`tlcp` + `x509`, with no per-item `doc(cfg(...))`. The plan had budgeted
eight per-item attributes as the likely path; the empirical render check made
them unnecessary. Also: a crate-root landing page with a default-features
doctest, a README Installation section, `sm4` added to keywords (missing from
a crate that implements it), `homepage` dropped workspace-wide (it duplicated
`repository`), TLCP and chain-verification rows added to the `gmcrypto-c`
README (its crates.io page had **zero** mentions of TLCP since 1.9.0), and
the stale `html_root_url` (pinned at `1.0.0`) removed rather than re-pinned.
Two accuracy fixes worth keeping: the README claimed all 20 dudect targets
were "gated" — 15 block at `|tau| <= 0.20`, four report to a `0.55` sentinel,
and **`ct_sm4_gcm_decrypt_buffered` has no threshold in either workflow**
despite `docs/v0.9-scope.md` specifying one; and "all 10 features are opt-in"
against 11. Runbook: `docs/v1.11.2-release-review.md`.

**v1.11.1 — two-defect patch, HELD then re-cut; PUBLISHED 2026-08-22 from
`26a49c3` (tag `v1.11.1`), sibling pins `=1.11.1`.** (1) #163: enabling
`sm4-bitsliced-simd` on 1.11.0 made *serial* SM4 — the CCM CBC-MAC path —
slower than scalar on AArch64, because `tau` called a one-byte-to-x8 adapter
four times per word (32 scalar S-box evaluations where four suffice). #165
replaced it with a four-byte `sbox_x4` entry; batch paths unchanged; the
repaired path **executes** only under that feature (`sm4-aead` compiles
`sbox_x4` but never selects it), and **x86_64 throughput stayed unmeasured**.
(2) The first cut `8cb4aac` was **held**: its dudect evidence failed
`ct_tlcp_cbc_deprotect` (0.30 on Xeon 8573C, 0.32–0.42 on EPYC 9V74). Root
cause predated the patch — since v1.7 the TLCP SM4-CBC deprotect equalized the
inner-HMAC SM3 compression *count* but computed the MAC through the streaming
hasher, whose buffer copy and finalize-padding branch stayed
secret-length-dependent. Fix 1 made that residual measurable. #169 rewrote it
as a fixed-schedule constant-time construction (`tlcp::record::mac_ct`): same
block count, MAC values and wire bytes unchanged, 9V74 0.32–0.42 → 0.026. It
**executes in every `tlcp` build, including `gmcrypto-c`**. The durable lesson
was procedural: the hosted `ubuntu-24.04` pool is heterogeneous (EPYC 7763 /
9V74 / Xeon 8573C / 6973P-C) and the workflows did not record which CPU ran a
slot, so the same `ct_sm4_cbc_decrypt_fanout` failure went undiagnosed on
2026-08-07 and again on 2026-08-22. #172 made both gates print `RUNNER-CPU:`
beside the verdicts; #173 established that on 9V74 that target spans
0.0396–0.2008 **on unchanged code**, i.e. its 0.20 gate sits inside the class's
noise band. Records: `docs/v1.11.1-release-review.md`,
`docs/v0.5-dudect-recalibration.md` (2026-08-23).

**v1.11 — RustCrypto `aead` 0.6 trait fit — implemented on `feat/aead-traits`;
PUBLISHED to crates.io 2026-08-01 from `613f619` (all three crates, order simd →
core → c), workspace `1.9.1` → `1.11.0`, sibling pins `=1.11.0`. crates.io skips
BOTH `1.10.0` (non-publishing assurance cycle, the v0.14→v0.15 precedent) and
`1.9.1` — the latter was a fully prepared + gate-passed licence-text packaging
patch that was superseded when `1.11.0` shipped the same fix, so **`1.11.0` is
the first published release carrying licence text** and `1.9.0` and earlier stay
without it permanently. Record kept at `docs/v1.9.1-release-review.md`.** Closes the backlog item blocked since v0.11
on "`aead` still 0.6.0-rc.10": **0.6.1 is stable**, needs only `crypto-common
0.2` + `inout 0.2` (both in-tree since v0.11), and declares **MSRV 1.85** —
exactly ours, so `aead` is the ONE new crate. New opt-in **`aead-traits =
["sm4-aead", "dep:aead"]`**; default build byte-identical. Adds `sm4::Sm4Gcm`
(fixed U12 nonce / U16 postfix tag — the canonical profile; truncated tags +
arbitrary nonces stay inherent-only) and `sm4::Sm4Ccm<M = U16, N = U12>` (tag +
nonce as type params bounded by the **sealed** `CcmTagSize` / `CcmNonceSize`,
admitting exactly the RFC 3610 §2.1 sets, so an invalid combination is a
COMPILE error not a runtime `None`). **The trait set is not a free choice**:
`aead` 0.6 **blanket-implements `Aead` for every `AeadInOut`**, so a direct
`impl Aead for Sm4Gcm` CANNOT compile — implement `KeySizeUser` + `KeyInit` +
`AeadCore` + `AeadInOut` and the Vec-returning `Aead` + the `Buffer`-based
in-place methods arrive free. (`AeadInPlace` is DEPRECATED in 0.6; there is NO
`aead::stream` module — it moved to its own crate — so `gcm_streaming` stays
inherent-only.) `aead::Error` is a unit struct, so the single-failure invariant
crosses the trait boundary **by construction**. **Both types are THIN wrappers**
over `mode_gcm`/`mode_ccm`, which is why **NO new dudect target (count stays
23)** — the measured bodies are byte-identical on the trait path and the
wrappers only move public-length data; that premise is guarded directly by the
new differential fuzz target **`fuzz_sm4_aead_traits` (census 32 → 33)**, which
asserts trait-path == inherent-path for BOTH ciphers on every input. Stated
costs, not hidden: a fresh key schedule per call (the structs hold key bytes)
and allocation inside the methods named "in place". api-baseline regenerated
**additively** (96 added lines, ZERO removals). Scope + forks:
`docs/v1.11-scope.md` Q11.1–Q11.10. **SM4-XTS gets no aead fit, ever** —
confidentiality-only, no tag.
**Earlier — v1.10 — assurance cycle, NON-PUBLISHING (on `main`).** Workspace stays
`1.9.1`; crates.io skips a `1.10.0` (the v0.14/v0.20/v0.21/v0.22/v0.23
precedent). Three follow-ups recorded at the end of v1.9.1, per
`docs/v1.10-scope.md`: **F16 CLOSED** — `ci.yml` gains an `interop-gmssl` job
running the gmssl cross-validation suite against a **pinned from-source GmSSL
3.2.0** (non-gating via `continue-on-error`; flipping it to a required check is
a maintainer action after a green track record), which also fixed the **oracle
drift that made 11/11 unreproducible** (3.2.0 renamed `pbkdf2` → `sm3_pbkdf2`,
split `sm4 -cbc/-ctr/-gcm` into `sm4_cbc`/`sm4_ctr`/`sm4_gcm`, and narrowed
`sm3hmac` keys to 12..=32 bytes; the suite now PINS its oracle version and
fails with `ORACLE DRIFT` on any other build). **Tier-A fuzz CLOSED** — census
**30 → 32** (`fuzz_sm4_xts_sectors`, `fuzz_sm4_gcm_tag_len_roundtrip`) plus the
four DER parser targets upgraded from no-panic to **byte-idempotence**.
**F21 STILL OPEN and deliberately NOT landed** — see the deferred-items
paragraph below: a `mode_cbc::decrypt` window measured 0.0129 constant-time vs
0.0185 deliberately-leaky (indistinguishable) while a 10 000× amplified control
hit 11.6, so the composite window is **blind** and landing the target would
have produced a gate that cannot fail. Only the PKCS#7 unpad dedupe landed.
**Earlier — v1.9.1 — licence-text packaging patch — prepped on `release/v1.9.1`;
publish order simd → core → c, the maintainer's per-release call.** A **patch with ZERO
runtime behavior change** — the only `src/` delta since 1.9.0 is inline
`// SAFETY:` comments in the C shim (#115), so `cargo-public-api` +
`cargo-semver-checks` stay green and a 1.9.0 consumer moves with a plain
`cargo update`. The headline is a **real packaging defect**: every `.crate`
archive through 1.9.0 shipped **NO licence text at all** — `LICENSE` lived only
at the repo root and no manifest key pointed cargo at it (cargo *will* copy from
outside the package dir when a key names it, as `readme = "../../README.md"`
already does, but `license-file` takes a single path and **cannot express a dual
licence**, so per-crate copies are the fix). Published versions are immutable, so
**1.9.1 is the first release carrying licence text**; 1.9.0 and earlier stay
without it permanently. Also ships the **`Apache-2.0` → `MIT OR Apache-2.0`
widening** (every prior use still permitted), `homepage`/`documentation` manifest
metadata (crates.io rendered neither), and doc corrections to CONTRIBUTING.md
(stale `ct_hmac_sm3` gate wording + a bench command that silently compiled out 8
of the 20 `ct_*` targets) and SECURITY.md (listed chain validation + TLCP as out
of scope while documenting both as shipped). **Gated by `docs/ECOSYSTEM.md` §8
Gate #1** — the two-phase `gmcrypto-envelope-lite` 0.1.0 RC suite, now a standing
obligation on EVERY core release (run in a temp export; the downstream `=1.9.0`
exact pin is bumped ONLY in the gate copy). Landed alongside the project's
**first external contribution** (PR #124, `ogemboeugene`, fixing #122) — note
fork PRs from first-time contributors sit at `action_required` until a maintainer
approves the workflow run; #124's CI sat unrun for two days before anyone noticed.
**Earlier — v1.9.0 — TLCP toolkit C FFI — implemented on `feat/tlcp-ffi`; publish
order simd → core → c, the maintainer's per-release call.** The **cadence FFI cycle
that closes the TLCP arc** (gap-less: `docs/tlcp-decomposition.md` §7 "one FFI
cycle for the whole toolkit", the maintainer-deferred call now made — ONE
cycle; scope `docs/v1.9-scope.md` Q9.1–Q9.8). Exposes the accumulated in-core
toolkit — v1.6 key schedule + no-confirmation SM2-KX, v1.7 record protection,
v1.8 chain/pair verification — through **`gmcrypto-c`**: a C client can now run
a full TLCP handshake end-to-end (KX → key schedule → record → cert-verify).
**19 new symbols + 2 opaque handles + ~7 consts = 85 → 104 entry points**,
ALWAYS-ON (`tlcp` added to the C shim's core-dep features; committed
`gmcrypto.h` == default build; no `regen-header` IMPLY hack — `sm4-aead`
already always-on keeps the opaque GCM typedef). **A THIN shim, crossing NO new
invariant**: every failure is one `GMCRYPTO_ERR`; `deprotect_cbc` adds NO logic
(the Lucky13 CT lives in core's `ct_tlcp_cbc_deprotect`; the shim is a pure
`Option<Vec<u8>>` → copy-out-or-single-ERR, `write_output` Some-only so the
`None` path touches NO output — `out_actual_len` genuinely untouched, the secret
post-strip length is NEVER an input param); `verify_chain`/`verify_pair` are
**STRUCTURAL trust only — NOT endpoint authentication** (identity binding stays
the caller's, PERMANENTLY; the disclaimer is loud in `gmcrypto.h`, the only
place a non-Rust consumer reads it). **The four cycle-shaping forks were
maintainer-locked to the recommended shape** (Q9.1 ONE cycle / Q9.2 opaque
`ZeroizeOnDrop` record-key handles `gmcrypto_tlcp_record_keys_{cbc,gcm}_t` —
**a deliberate REVISION of Q7.10's "keys by value, no handle", Codex consult
#2, honest-framed with a by-value fallback** / Q9.3 cert-handle-ptr array +
out-param bool + status, reconciling v1.8 Q8.15 / Q9.4 SysRng + `_with_rng`
`CallbackRng`, settling v1.7 Q7.10's open CBC-IV fork); Q9.5 agent-folded
(always-on + expose the `KeyUsage`/`BasicConstraints` readers). **Symbols:**
`gmcrypto_tlcp_{derive_master_secret,derive_key_block,finished_verify_data}`
(byte-in/byte-out, no handle, Q6.9) + `gmcrypto_sm2_kx_{initiator_derive,
responder_respond}_unconfirmed[_with_rng]` (consume+free the v1.2 handles; the
responder = `Box::from_raw` + `Fresh`-variant match, the `_finish` precedent —
**MF-4**, NOT the take-and-replace which keeps the handle alive) + record
carriers `_new/_free` + `gmcrypto_tlcp_{protect,deprotect}_{cbc,gcm}` (copy-out,
no length-in) + `gmcrypto_x509_verify_chain` + `gmcrypto_tlcp_verify_pair`
(arrays of the v1.4 const cert handle + `gmcrypto_x509_time_t*` NULL=None +
out-param) + `gmcrypto_x509_certificate_{key_usage,basic_constraints}` readers.
**One thin ADDITIVE core change (NOT a pure shim — Codex consult #3): a C
`*const *const Certificate` array isn't a contiguous `&[Certificate]` and
`Certificate` isn't `Clone`**, so core gained `#[doc(hidden)] pub`
`x509::verify_chain_refs` / `tlcp::chain::verify_pair_refs` (`&[&Certificate]`;
the public slice fns delegate), `x509::KeyUsage::bits` (**MF-6**, the FFI u16
reader), `tlcp::record::{CBC,GCM}_KEY_BLOCK_LEN` (**MF-5**, the static-assert
anchors). api-baseline regenerated additively (the 2 record consts; the
doc-hidden refs verifiers + `bits` are below the `cargo-public-api` surface).
NULL semantics: `(NULL,0)` = empty, `(NULL,n>0)`/any NULL element = `ERR`,
over-depth = `verified=0` verdict (never a structural `ERR`). Assurance:
**c_smoke 84 → 97** (key-schedule equivalence vs core; no-confirm KX handshake
agreement + `_with_rng`; record CBC/GCM round-trip + cross-deprotect vs core +
**the bad-pad ≡ bad-MAC single-ERR oracle test**, valid-pad-bad-MAC built via
seq-mismatch [SF-2]; verify_chain/pair == core + NULL semantics + role-swap
reject; readers vs core); `fuzz_c_abi` gains ops 9 (chain/pair) + 10 (record
deprotect), **modulus 9 → 11, all 3 seeds audited** (op bytes 7/1/8 still hit
ops 7/1/8; new seed `tlcp_verify_chain_op`; census stays 30); **NO new dudect
target — public-inputs-only / rides existing targets** (record →
`ct_tlcp_cbc_deprotect`, KX → `ct_sm2_key_exchange`, key schedule →
`ct_hmac_sm3`; **count stays 23**). Doc-only C examples `tlcp_handshake.c`
(KX → key schedule → record round-trip → Finished) + `tlcp_verify_pair.c`
(**a real GmSSL TLCP pair verifies end-to-end** through the ABI; both
compiled + run locally). Pipeline: understand-phase Workflow (6 readers +
synthesis) → 4 forks maintainer-locked via AskUserQuestion → scope +
**Codex scope consult** (5 findings, must-fixes folded) → plan + **Opus
EXECUTED adversarial review** (implemented the riskiest slices in a worktree,
88/88 green; GO-WITH-FIXES, **6 must-fixes — two caught LIVE at compile time**
[`alloc::vec::Vec` E0433 in the std shim; the missing `at_time` reverse-From] —
+ 5 should-fixes, all folded) → TDD. Workspace 1.8.0 → **1.9.0**, sibling pins
`=1.9.0`. **The TLCP toolkit is now complete in-core AND from C.** v2.x = the
O2 sans-I/O engine (separate decision, separate crate, uncommitted).
**Earlier — v1.8.0 — TLCP certificate-pair / chain verification — implemented on
`feat/x509-chain-verify`; publish order simd → core → c, the maintainer's
per-release call.** The third and **last *core* cycle** of the TLCP arc
(gap G4 of `docs/tlcp-decomposition.md` §4 derived chain/role profile;
scope `docs/v1.8-scope.md` Q8.1–Q8.16, the four cycle-shaping forks
maintainer-locked to the recommended shape). The decomposition's flagged
**trap** ("path validation is where small auditable cycles go to die");
the defense is the **derived profile** — verify only what the TLCP handshake
needs, name the permanent holes loudly, single `bool`. **Placement = SPLIT
(Q8.1):** the generic chain walk + keyUsage/basicConstraints **readers** in
the existing **`x509`** feature; the TLCP [sign, enc] pair profile in a new
**`tlcp::chain`** (cfg-gated `all(tlcp, x509)` — a TLCP cert-verifying
consumer enables BOTH, the GCM-record/sm2-kx "enable both" precedent).
Pure-core, NO new dep, no_std. **`x509::verify_chain(chain, anchors,
Option<X509Time>) -> bool`**: single linear caller-ordered walk (chain
leaf-first), per-edge SM2 `verify_signature` + raw issuer↔subject Name
byte-equality link, intermediate CA-ness (`keyCertSign` + basicConstraints
`CA=TRUE`), **try-all-anchors** at the top (Name necessary-NOT-sufficient —
the signature is authoritative, so CA key-rollover/duplicate-Name anchors
resolve by which key actually signed), **unknown-CRITICAL-extension reject**
(RFC 5280 §4.2; known set = exactly {keyUsage 2.5.29.15, basicConstraints
2.5.29.19}; Q8.7b maintainer-signed — the one widening of "minimal"),
optional validity window (`at.is_none_or`), `MAX_CHAIN_DEPTH = 8` cap. The
**anchor is trusted by fiat** — checked ONLY by Name + signature + window,
NEVER keyUsage/CA/leaf-role (Codex #4; imposing keyCertSign would reject
legit bare roots). **`x509::{KeyUsage, BasicConstraints}` readers** (BIT
STRING bit-0 = MSB of value[0]; basicConstraints `path_len` PARSED but NOT
enforced — D-4 depth-cap only) + `Certificate::{key_usage,
basic_constraints}` accessors. **`tlcp::chain::verify_pair(sign_chain,
enc_chain, anchors, Option<time>) -> bool`**: role keyUsage (sign MUST assert
`digitalSignature`; enc MUST assert `keyEncipherment` OR `keyAgreement` —
keyUsage MUST be present, absent ⇒ reject, stricter than gotlcp which IGNORES
keyUsage + assigns roles positionally), **leaf-NOT-CA** (Codex #5), pair
binding = non-empty + byte-equal `subject` + byte-equal `issuer` Name + the
**same issuing chain** (equal length, `tbs_raw`-equal certs from index 1 up —
the **W2 review S1 closure**: equal issuer *Name* alone doesn't pin the
issuer *key*; residual = both legs length-1 under same-DN anchors). **Single
`bool` throughout** (chain-rejection-oracle defense); **endpoint identity
binding stays the caller's, PERMANENTLY** — `verify_pair == true` is never
"the peer I dialed". D-1/D-4/D-8/D-9/D-11 resolved (gotlcp `main` /
`emmansun/gmsm v0.41.1` + GM/T 0015 Tongsuo `subca.cnf`; **three
primary-text residuals tagged** — D-1 exact MUST/SHOULD bits, D-9
serverAuth-EKU mandate, D-11 normative ordering). EKU IGNORED (D-9);
pathLenConstraint NOT read (D-4). KATs: **GmSSL 3-level chain** (root →
intermediate → [sign, enc] pair, shared subject DN, gmssl-self-verified;
`tests/data/x509_chain_*.der`, recipe in `x509_regen.md`) + hand-built minted
SM2-cert negatives; a real TLCP pair verifies end-to-end. **NO new dudect
target** — public-inputs-only (the v1.3 `x509` rationale extends; certs +
anchors + time are public, edges are the public `verify_with_id`). New fuzz
**`fuzz_x509_chain`** (census 29 → 30; BE-u16-prefixed DER blobs, chain/anchor
splittings, no-panic; 1.06M local runs clean). Pipeline: scope (4 forks
maintainer-locked + Codex consult, 5 findings folded incl. Q8.7b) → plan →
**Opus executed adversarial review** (implemented Tasks 1-5 in a worktree, 26
tests vs real minted certs, GO-WITH-FIXES — caught 9 clippy lints incl. a
hard `E0433`, the S1 pair-binding gap, all folded) → TDD. Workspace 1.7.0 →
**1.8.0**, sibling pins `=1.8.0`. v1.9 = the toolkit FFI cadence cycle.
**Earlier — v1.7.0 — TLCP record protection — implemented on
`feat/tlcp-record-protection`; publish order simd → core → c, the
maintainer's per-release call.** The second code cycle of the TLCP arc
(gap G2 of `docs/tlcp-decomposition.md`; scope `docs/v1.7-scope.md`
Q7.1–Q7.11, the four forks maintainer-delegated to a Codex consult +
4-agent adversarial-panel-verified). New module **`tlcp::record`** under the
existing opt-in `tlcp` umbrella (pure-core, NO new dep, no_std): per-direction
`ZeroizeOnDrop` key carriers (`RecordKeysCbc`/`RecordKeysGcm`, carved
`client_half`/`server_half`/`from_key_block` — public role data, not a secret
branch) + `protect_cbc`/`deprotect_cbc` + `protect_gcm`/`deprotect_gcm` +
`TLCP_RECORD_VERSION`. Engine-shaped (caller-held `seq: u64`, injected IV RNG,
`type: u8` + `version: [u8;2]` explicit; **`length` computed internally on
both sides — NEVER a deprotect param: it's the secret post-strip length**).
**SM4-CBC** (pure `tlcp`): explicit per-record IV, MAC-then-encrypt, TLS
padding, HMAC-SM3. **`deprotect_cbc` is the arc's Lucky13 item** — ONE op, CT
over THREE surfaces: (1) inner-hash SM3 compression count equalized via dummy
compressions on a throwaway state to a PUBLIC upper bound `max_plaintext_len =
body−33` (NEVER reduced; `black_box`'d vs LTO; `inner_blocks(P)=(64+13+P+9)`
ceil-div-64), **`sm3::compress` widened to `pub(crate)`** so the single
audited loop is reused not duplicated; (2) fixed `min(256,body)`-byte CT
pad-validity scan (the `strip_pkcs7_ct` mask idiom widened 16→256, no early
return); (3) data-independent MAC extraction at the secret offset; **bad-pad
STILL runs the full MAC**, single `pad_ok & mac_ok` merge, single `None`, no
plaintext on fail (`body.zeroize()`). Public-length guards (`<48` /
non-16-multiple / `>2^14+48`) run BEFORE any secret arithmetic so the u16
casts are lossless and no fallible `?` rides a secret. **SM4-GCM** (needs
`tlcp,sm4-aead` — `mode_gcm` is gated there; **NOT** `tlcp=["sm4-aead"]`,
which would pull the simd GHASH dep + break wasm32): RFC 5288 TLS-1.2 thin
wrapper over `mode_gcm` (salt(4)‖seq-derived-nonce(8); AAD seq‖type‖version‖
length; wire `explicit_nonce(8)‖ct‖tag(16)`; deprotect reads the nonce off the
wire, AAD.seq from the caller). KATs cross-validated byte-for-byte by **OpenSSL
EVP SM4-CBC + GmSSL `sm3hmac`** (CBC) and **GmSSL `sm4 -gcm -aad_hex`** (GCM) —
the "OpenSSL+GmSSL cross-check" the maintainer chose W3 (gotlcp full-transcript
replay deferred; generator `tests/data/tlcp_record_kat_gen.py`). Assurance: new
dudect **`ct_tlcp_cbc_deprotect`** (class-split by recovered-fragment length /
fixed key; the 4th dudect matrix leg gains `tlcp`; 20K smoke |tau|≈0.08) + a
constant-blocks==`HmacSm3` equivalence test (the equalization is a hard MUST;
dudect is the **residual guard**); NO new GCM dudect (rides
`ct_sm4_gcm_decrypt`); two fuzz targets `fuzz_tlcp_{cbc,gcm}_deprotect`
(census 27→29). **`(key,seq)` uniqueness is the caller's contract — the
stateless layer can't detect reuse/wrap; the hard-reject is a future stateful
wrapper's job (scope Q7.5 reconciled W3).** OUT: 5-byte header framing,
fragmentation, ClientKeyExchange (D-3), chain/pair (G4, v1.8), C FFI (v1.9).
Pipeline: scope (Codex + 4-agent panel, all must-fixes folded) → plan (Fable-5
EXECUTED review — ran the Lucky13 core in a worktree; caught 2 compile bugs +
the missing-ceiling Lucky13 chain-break + a false-assurance dudect axis, all
folded) → TDD. Workspace 1.6.0 → **1.7.0**, sibling pins `=1.7.0`.
**Earlier — v1.6.0 — TLCP key schedule + no-confirmation SM2-KX — implemented on
`feat/tlcp-key-schedule`; publish order simd → core → c, the
maintainer's per-release call.** The first code cycle of the TLCP arc
(gaps G1+G3 of `docs/tlcp-decomposition.md`; scope `docs/v1.6-scope.md`
Q6.1–Q6.10, Q6.2/Q6.3 maintainer-signed). New opt-in **`tlcp = []`**
umbrella feature (pure-core, NO new dep, no_std; carries the whole
toolkit arc — v1.7/v1.8 join it): `tlcp::key_schedule` = private
`p_sm3` (RFC 5246 §5 P_hash over `HmacSm3`, A-chain wiped) +
`derive_master_secret` (**pre_master TYPED `[u8;48]`** — TLCP pins the
PMS in both KX variants; Codex High-1) + `derive_key_block` (seed order
**FLIPS server-first** §6.5.2 — KAT-pinned trap; suite-agnostic
caller-carved out: CBC 128 B / GCM 40 B) + `finished_verify_data` +
`TlcpRole` (12 B). Engine-shaped: caller-supplied outs (pbkdf2
discipline), ZERO failure modes. **No-confirmation KX completers** land
on `sm2-key-exchange` (NOT tlcp — 32918.3 generality, Q6.3):
`derive_without_key_confirmation` / `respond_without_key_confirmation`
(loud names = the misuse defense, Codex Medium-3; responder has NO
waiting state — nothing to gate on; both reuse `shared_secret`
verbatim; confirmed flow byte-unchanged). KATs: OpenSSL 3.x **`openssl
kdf TLS1-PRF -kdfopt digest:SM3`** (verified BEFORE scoping; label
rides IN the seed, hexsecret/hexseed, default provider —
`docs/v1.6-kat-sourcing.md`) + the GM/T 0003.5 worked example pins both
completers (K precedes tags) + klen-16/48 differentials. Assurance: NO
new dudect target (ct_hmac_sm3 covers P_SM3's keyed primitive;
initiator-unconfirmed ⊂ ct_sm2_key_exchange's measured path; responder
structurally covered — SECURITY.md); `fuzz_sm2_kx` drives THREE paths
per input (no dispatch byte, seed format unchanged, census 27); CI
gains tlcp legs + the api-stability docs leg now covers
sm2-key-exchange/x509/tlcp (pre-existing gap). D-2/D-7/D-10 resolved
(gotlcp): ECDHE uses default IDs + klen 48; handshake sigs =
message-mode `sign_with_id` w/ default ID; PMS-decrypt abort OK (GM/T
0009 ct is integrity-protected). Workspace 1.4.0 → **1.6.0** (crates.io
SKIPS 1.5.0 — the v0.14→v0.15 precedent), sibling pins `=1.6.0`.
Reviews: Codex scope consult (7 findings folded) + Fable-5 adversarial
plan review GO-WITH-FIXES (A1–A6; the reviewer EXECUTED the plan code
in a scratch tree and independently regenerated every KAT vector).
**Earlier — v1.5 — TLCP decomposition (non-publishing design cycle, 2026-06-12,
on `main`)** — the arc-opening map for TLCP (GB/T 38636-2020), the
direction both the v1.1 SM2-KX and v1.3 `x509` cores were built to feed.
Deliverable: **`docs/tlcp-decomposition.md`** (+ charter
`docs/v1.5-scope.md` Q5.1–Q5.5, maintainer-signed). Headlines: TLCP wire
anatomy pinned (version 0x0101; suites `0xE011/13/51/53` — the IBC/RSA
families OUT for the whole arc; double-cert [sign, enc] model; TLS-1.2
P_hash over **SM3**; TLS-1.1-style record layer); **gap analysis says
~90% of TLCP's crypto already ships** — gaps are G1 key schedule, G2
record protection (TLS padding ≠ PKCS#7; **Lucky13-class CT** — the
`deprotect` API shape is constrained in the doc NOW: one operation,
always-MAC/dummy-equalized work, no early return, single failure, no
plaintext on failure), G3 a **no-confirmation SM2-KX path** (TLCP ECDHE
omits the S_A/S_B tags the v1.1 typestate requires; Finished plays that
role), G4 the **derived chain profile** — "chain + role (keyUsage +
basicConstraints) verification, NOT server authentication"; endpoint
identity binding is LOUDLY the caller's, pair binding = byte-equal
subject Names (the Codex W2 headline). End-state **O3 maintainer-signed**:
TLCP crypto toolkit in-core as opt-in features, every API engine-shaped;
the sans-I/O engine (O2) explicitly uncommitted; full stack (O1) rejected.
Cycle map: **v1.6 = key schedule + no-confirm KX (maintainer-signed
next)** → v1.7 record protection → v1.8 chain/pair verification → v1.9
one FFI cycle for the toolkit (per-cycle FFI-shape constraints recorded,
no ABI frozen early). 12 D-items (D-1…D-12) tagged with owning cycles —
the v0.8 sourcing posture (facts from gotlcp cross-checked vs RFC 8998/
GmSSL 3.1.1; the standard text re-verified per cycle). No pure-Rust TLCP
exists (only Tongsuo C bindings) — the toolkit is novel surface. NO code
change; workspace stays **1.4.0**; crates.io may skip a `1.5.0` (the
v0.14→v0.15 precedent).
**Earlier — v1.4.0 — C FFI for X.509-with-SM2 — implemented on `feat/x509-ffi`;
publish order simd → core → c, the maintainer's per-release call.**
Completes the core-in-vN / FFI-in-vN+1 cadence for the v1.3 `x509` core:
**13 new `gmcrypto-c` symbols + 1 opaque handle
(`gmcrypto_x509_certificate_t`, immutable — accessors take `const *`, no
consume-on-use) + 1 plain repr(C) struct (`gmcrypto_x509_time_t`: u16 year
+ five u8)** = 72 → **85** FFI entry points, ALWAYS-ON per the v0.23
posture (`x509` enabled unconditionally on the C shim's core dep; committed
`gmcrypto.h` == default build; core's own `x509` feature stays opt-in).
Full mirror (scope Q4.2, `docs/v1.4-scope.md` Q4.1–Q4.15): `_from_der`
(returns handle/NULL — the `gmcrypto_sm2_pubkey_new` convention) + `_free`;
`_verify_signature(_with_id)` against an issuer `gmcrypto_sm2_pubkey_t`
HANDLE (`id_len==0` → DEFAULT_SIGNER_ID, the v1.2 KX precedent — empty ID
unrepresentable; reuses the v1.2 helper, renamed `signer_id_or_default`
now that two domains share it); 5 copy-out raw accessors
(tbs/serial/issuer/subject/extensions) riding `write_output` two-call
discovery — **`extensions_raw` `*out_actual_len==0` ⇔ absent** (a present
Extensions TLV is never empty); `_not_before`/`_not_after` out-param
struct, NO clock; **`is_self_issued` = out-param + status** (the Codex
pick: a bare 1/0 predicate would FALSIFY the header banner's universal
"every int return is 0 on success" contract, and OK=self-issued would read
inverted in C `if()`); `_subject_public_key` returns a NEWLY allocated
`gmcrypto_sm2_pubkey_t` (caller frees; composes with verify/encrypt/KX).
The no-trust-decisions contract crosses the ABI intact. Gotcha fixed in
review (Fable-5 GO-WITH-FIXES): the shared `x509_copy_out` closure MUST be
`move` — by-ref capture of the generic getter fails `ffi_guard`'s
UnwindSafe bound. Assurance: c_smoke 76 → **84** (accessor equivalence vs
core on BOTH fixtures incl. the CA serial pad-strip pin; extensions-absent
via strip-the-`[3]`-block surgery — parse never verifies so the broken sig
is irrelevant; verify matrix; NULL sweeps); `fuzz_c_abi` op 8 (dispatch
`% 8` → `% 9` — **every committed seed's op byte audited: `sm3_abc`
(0x41 = 65: %8=1 but %9=2) rewritten to 0x01**, new `x509_leaf_op` seed;
census stays 27); NO new dudect target (thin shim over a public-inputs-only
core — the v1.3 rationale doubled). Doc-only `x509_verify.c` (compiled+run
locally). Workspace 1.3.0 → 1.4.0, sibling pins `=1.4.0`. TLCP remains the
headline direction candidate (chain validation / TLCP decomposition were
the deferred v1.4 alternatives).**
**Earlier — v1.3.0 — X.509-with-SM2 leaf certificate parse + signature
verify — implemented on `feat/x509-sm2`; publish order simd → core → c,
the maintainer's per-release call.** The second TLCP prerequisite (SM2-KX was
the first). New opt-in **`x509 = []`** feature (pure-core, NO new dep;
default build byte-identical): `x509::Certificate::from_der` (strict
in-repo DER — NO x509-cert/der dep; v3-only; GM/T 0015 profile) +
`verify_signature(_with_id)` over the EXACT wire tbsCertificate span via
`verify_with_id` (default ID `1234567812345678`, RFC 8998 §3.2.1).
**NO trust decisions** — no chains, no time/validity decision (X509Time
exposed, no clock), no extension interpretation (one-level shape-check
only, critical flags NEVER evaluated), no revocation; `verify_signature`
is deliberately NOT named "validate". Strictness: sm2-sign-with-sm3 AlgId
params absent-or-NULL with FULL-SPAN outer==inner byte equality (mixed
forms rejected); negative serials REJECTED (deliberate deviation from RFC
5280 "gracefully handle"); serial_raw = pad-stripped 1..=20 value bytes;
BIT STRING unused==0; garbage sig content PARSES but never VERIFIES
(decode_sig at verify time is the single source of truth). Composes ONLY
existing assets (asn1::reader, spki::decode, verify_with_id,
oid::SM2_SIGN_WITH_SM3) — zero new cryptographic code. KAT: gmssl
3.1.1-generated CA+leaf fixtures (chain-verified by gmssl; regen recipe in
tests/data/x509_regen.md; gotcha: certgen/reqsign list -serial_len as
required but it defaults to 12) + full per-byte tbs tamper sweep +
truncation sweep + OID-swap/negative-serial/pad-strip/unused-bits
negatives. Fuzz `fuzz_x509` (census 27). **NO dudect target — public
inputs only** (first feature since v0.11 where that holds by construction;
SECURITY.md documents it). Scope Q3.1–Q3.11 Codex-ranked ("path validation
is where small auditable cycles go to die" — chains/generation/Name
parsing/TLCP all deliberately OUT) + Fable-5 adversarial review
GO-WITH-FIXES (headline: the negative-serial tolerance the plan claimed
was inverted vs read_integer's real strictness). Workspace 1.2.0 → 1.3.0,
sibling pins `=1.3.0`. C FFI deferred (v1.4 candidate); X.509-with-SM2
feeds the TLCP direction.**
**Earlier — v1.2.0 — C FFI for SM2 key exchange — implemented on `feat/sm2-kx-ffi`;
the `cargo publish` + SSH-signed tag are the maintainer's authenticated call
(publish order simd → core → c; the v1.1.0 agent-publish was a recorded
one-off delegation, not a precedent).** Completes the core-in-vN / FFI-in-vN+1
cadence for v1.1: **9 new `gmcrypto-c` symbols + 2 opaque handles + 1 const**
(63 → 72 FFI entry points), ALWAYS-ON per the v0.23 posture
(`sm2-key-exchange` enabled unconditionally on the C shim's core dep;
committed `gmcrypto.h` == default build; `gmcrypto-core`'s own feature stays
opt-in). Handle shape (scope Q2.2, `docs/v1.2-scope.md`): the Rust 4-type
consume-on-transition typestate collapses to TWO handles —
`gmcrypto_sm2_kx_initiator_t` is **born waiting** (`_new` samples the
ephemeral internally + writes `R_A`; no pre-ephemeral state exists in C);
`_confirm`/`_finish` **consume + free** (v0.10 `_finalize*` precedent);
a FAILED `_respond` **spends** the responder handle (the Rust responder was
consumed), while a stray second `_respond` errors WITHOUT disturbing the
in-flight `Waiting` state. RNG: SysRng defaults + `_with_rng` variants riding
the v0.5 `CallbackRng` (Q2.3) — which is how c_smoke reproduces the **GM/T
0003.5 recommended-curve KAT byte-for-byte THROUGH the C ABI** (fixed standard
ephemerals; `R_A`/`R_B`/`S_B`/`K`/`S_A` all asserted). `id_len == 0` →
`DEFAULT_SIGNER_ID` (also the KAT ID). Single `GMCRYPTO_ERR` everywhere;
**the caller owns wiping `key_out`**. Assurance: c_smoke 65 → 76 (KAT-thru-FFI
+ FFI↔Rust cross-handshakes BOTH directions + tamper/off-curve/spent-handle/
misuse/null negatives); `fuzz_c_abi` op 7 (attacker peer R/S bytes; asserted
spent-handle; committed `kx_valid_transcript` seed; census stays 26); **NO new
dudect target** (thin shim — core's `ct_sm2_key_exchange` covers it; the
v0.13/v0.16 precedent). Doc-only example `sm2_key_exchange.c` (compiled + run
locally). Workspace 1.1.0 → 1.2.0, sibling pins `=1.2.0`. X.509-with-SM2 is
the v1.3 direction candidate (Q2.1).**
**Earlier — v1.1.0 — SM2 key exchange (GM/T 0003.3 ≡ GB/T 32918.3-2016) with key
confirmation — implemented on `feat/sm2-key-exchange` (PR #100); the `cargo
publish` + SSH-signed tag are the maintainer's authenticated call (publish
order simd → core → c).** Completes the SM2 family behind the opt-in
**`sm2-key-exchange = []`** feature (pure-core, NO new dep; default build
byte-identical). New `sm2/key_exchange.rs`: role state-machines
`Sm2KxInitiator` (`new` → `produce_ephemeral` → `confirm`) / `Sm2KxResponder`
(`new` → `respond` → `finish`) + `Sm2KxEphemeralPoint`/`Sm2KxConfirm`/
`Sm2SharedKey` (ZeroizeOnDrop); typestate enforces single-use ephemerals +
commit-on-confirm key release. Reuses the existing assets only: `compute_z`,
the fixed-budget masked sampler (`sample_nonzero_scalar`, called ONCE — it
already carries the 4-draw masked budget), `mul_g`/`mul_var`, the SM3 `kdf`,
`from_sec1_bytes` on-curve validation. CT: tags via `ConstantTimeEq`; `t`,
`x̄·r`, KDF input, `x_U`/`y_U` zeroized (drop-wipe on an inner `EphScalar`
wrapper — Drop can't live on the consuming waiting-structs). Single
`Error::Failed` everywhere (incl. the deliberate all-zero-K reject, scope
Q1.7). **KAT = the GM/T 0003.5-2012 RECOMMENDED-CURVE worked example**
(`K = 6C893473…`, S_A/S_B asserted byte-for-byte) — ⚠ the example uses the
**default ID `1234567812345678` for BOTH parties**, NOT ALICE/BILL (those are
the 32918.3 test-curve Annex's; using them reproduces every point but the
wrong Z/K — the Task 1.5 diagnosis, `docs/v1.1-sm2kx-kat-sourcing.md`).
Assurance: dudect `ct_sm2_key_exchange` (initiator side, class-split by
static `d_A`, per-class valid transcripts, 10K smoke ≈0.02) on the 4th matrix
leg; fuzz `fuzz_sm2_kx` (26 FUZZ_TARGETS — the post-#101 census fix also
wired #98/#99's 7 targets into the nightly sweep); clippy/deny/MSRV/wasm32 legs.
C FFI deferred to v1.2 (core-in-vN / FFI-in-vN+1). Workspace 1.0.1 → 1.1.0,
sibling pins `=1.1.0`. Per `docs/v1.1-scope.md` Q1.1–Q1.10 +
`docs/v1.1-sm2-key-exchange-design.md` + the Fable-5 reviewed plan.
**Earlier — v1.0.1 — the prior stable release, live on crates.io**
(all three crates, published `gmcrypto-simd` → `gmcrypto-core` → `gmcrypto-c`), with an
SSH-signed `v1.0.1` tag on the #92 merge commit + a published GitHub release. 1.0.1 is a
**readiness-cleanup patch** over the 1.0.0 graduation — the GO-WITH-FOLLOWUP findings of
the 2026-06-02 release-readiness synthesis
(`docs/audits/2026-06-02-release-readiness-synthesis.md`; 0 blockers): the headline
**functional fix** is the `gmcrypto-c` C ABI `gmcrypto_version()`, which had returned a
hardcoded `"0.4.0"` and now reports the real `CARGO_PKG_VERSION` (the one behavior change
that makes 1.0.1 a publish rather than a docs-only update), plus doc/CI improvements
across **6 merged PRs (#87–#92)**. **Runtime crypto wire output is byte-identical to
1.0.0** (no API/ABI change; #92 CI all-green incl. enforced `cargo-semver-checks` as the
patch-non-breaking gate) — consumers move 1.0.0 → 1.0.1 with a plain `cargo update`.
**v1.0.0 — the deliberate first stable publish** (also live) — was the graduation of the
v0.21→v0.23 readiness arc, with the two load-bearing pre-1.0 items closed (§3.A
`crypto-bigint` exposure **resolved** in v0.22; the multi-model pre-publish re-audit
findings **remediated** in v0.23, merged #83) and `docs/v1.0-readiness.md` reading
**GO**. **crates.io history jumps 0.16.0 → 1.0.0 → 1.0.1** (0.17.0–0.23.0 were
non-publishing assurance/API-finalization cycles; their changes all shipped in `1.0.0`);
the **only migration is 0.16 → 1.0**, and the breaking changes vs 0.16 are API *shape*
only — the **runtime wire output is byte-identical to 0.16.0** (KAT + gmssl 3.1.1 interop
**11/11**). The three crates always release together at one lockstep version, with
intra-workspace path-deps pinned **exactly** (`gmcrypto-core`→`gmcrypto-simd` and
`gmcrypto-c`→`gmcrypto-core` both `version = "=1.0.1"`, the §3.D lockstep contract);
`cargo-semver-checks` runs **enforced** from 1.0 (PR #86). **The `cargo publish` + the
SSH-signed tag + the GitHub release are the user's (maintainer's) call** — a deliberate
authenticated action, not the agent's; the agent path stays branch + PR.
**Earlier — v0.23 — pre-1.0 re-audit remediation
(non-publishing, on `main`)** — a multi-model adversarial pre-publish re-audit
(Codex `gpt-5.5` + Grok `--sandbox read-only`, each finding source-verified by the
orchestrator — `docs/v1.0-reaudit.md`) over four dimensions (A = API/SemVer
finality; B = adversarial crypto-correctness; C = publish mechanics; D = honest
disclosure) returned **NO-GO as-is**: the **core primitives are sound** (mutually
confirmed CT/correctness non-findings — on-curve-before-mul, `ct_eq` tag/MAC
compares, masked XTS α-doubling, RCB complete addition, fixed-K=2 masked sign
retry, `CtOption` inversions), but it surfaced **2 API/ABI BLOCKERs** + a set of
crypto/zeroize/doc should-fixes that become irreversible or harder to fix after
1.0. This cycle fixed them across **W1–W4**, then a clean re-review of the diff is
the gate to publish. **W1 (API):** `Sm2PrivateKey::public_key()` now returns
`Sm2PublicKey` (was `ProjectivePoint`); the raw EC point surface is now
`#[doc(hidden)]` (kept `pub` for in-repo dev — the v0.22 Group-A pattern): the
`sm2::point::ProjectivePoint` type + `sm2::point` module + `sm2::ProjectivePoint`
re-export, the bare `add`/`double`/`neg` / generator / identity arithmetic, and
`Sm2PublicKey::{from_point, point}` + `From<ProjectivePoint>`; `spki::{encode,
decode}` + `sec1::EcPrivateKey.public` now speak `Sm2PublicKey`; the low-level
`asn1::{reader,writer,oid}` modules + the in-crate `traits::{Hash,Mac,BlockCipher}`
module are `#[doc(hidden)]` (the wire types `asn1::{encode,decode}_sig` +
`Sm2Ciphertext` stay public). Byte output unchanged. **W2 (crypto hardening):**
single-shot `sm4::mode_gcm::{encrypt, encrypt_with_tag_len}` are now **fallible**
(`-> Option<…>`), rejecting plaintext `> 2^36−32` bytes (the GCM 32-bit-counter
ceiling; matching guards on decrypt); SM2 `sign_with_id`/`sign_raw_with_id`/`encrypt`
now take the **fallible `rand_core::TryCryptoRng`** bound (RNG failure → `Failed`,
never a panic — drops the `UnwrapErr` adapter; `rand_core` is the deliberate,
documented ecosystem RNG-interop point, NOT decoupled like `crypto-bigint`); the SM2
nonce sampler is now a fixed-budget (4-draw) **constant-time masked** sampler (no
secret-dependent branch/loop); new zeroization of the sign nonce + intermediates
(incl. `1+d`), CCM tentative-plaintext on tag-fail, and `Sm3` now `Drop`-wipes its
keyed state (making the previously-false `HmacSm3` zeroization claim true at the
field layer — do NOT `impl Drop for HmacSm3`, since `finalize(self)` moves the
fields out); plus an SM2 KDF `u32` counter-wrap guard. **W3 (C ABI):** the
SM4-GCM/CCM/XTS FFI symbols are now **always-on** in `gmcrypto-c` (dropped the
forwarding `sm4-aead`/`sm4-xts` cargo features) so the committed `gmcrypto.h` == a
default `cargo build -p gmcrypto-c` (resolves the header ⟷ build mismatch); the C
shim's default build now transitively pulls `gmcrypto-simd` (`gmcrypto-core` keeps
its own feature gates). **W4:** regenerated the `cargo-public-api` baseline + the
docs. **Repository / infra-assurance milestone, NOT a crates.io release** — the
breaking API/ABI changes ship with the deliberate `1.0.0` publish; never a published
0.x crate (the only migration is 0.16 → 1.0). Workspace stays **0.16.0**; crates.io
skips `0.23.0` (the v0.14/v0.17/v0.18/v0.19/v0.20/v0.21/v0.22 precedent). Verified
byte-identical: full KAT + gmssl 3.1.1 interop **11/11** + full-workspace tests;
per-feature clippy + fmt + `cargo doc` + 18 fuzz + MSRV-1.85 + wasm32 +
`--no-default-features`. Forks (all Codex-confirmed in W0): A-2 depth = reshape the
high-level path to keys/bytes + doc-hide the type & re-export; A-3 RNG = accept the
coupling but use the **fallible `TryCryptoRng`**; B-1 GCM = make `encrypt` fallible;
B-2 HMAC = make `Sm3` `Drop`-wipe (not `HmacSm3`); B-7 = fixed-budget masked sampler;
posture = non-publishing. Per `docs/v0.23-scope.md` Q23.1–Q23.9 + `docs/v1.0-reaudit.md`,
codex+grok-reviewed W0–W4.
**Earlier — v0.22 — API-tightening: decouple `crypto-bigint 0.7`
from the 1.0 public API (non-publishing, on `main`)** — resolved the v0.21 audit's
headline §3.A finding (the always-on public API named `crypto-bigint 0.7` types) via
**Option 2 (tighten the surface)**. After v0.22 the **always-on (default-features)
public API names ZERO `crypto-bigint` types**. Three groups: **Group A** — the
low-level SM2 curve arithmetic is now `#[doc(hidden)]` (kept `pub`): the whole
`sm2::curve` module (`Fn`/`Fp`/`NMod`/`PMod`/`b`/`b3` — module-level hiding also covers
the macro-generated `NMod`/`PMod`), the whole `sm2::scalar_mul` (`mul_g`/`mul_var`), the
`sm2::{Fn,Fp,mul_g,mul_var}` re-exports, and `ProjectivePoint::to_affine`, each with a
"not public API / not SemVer; may change in any release" contract — kept `pub` only so
the in-repo dudect bench / integration tests / fuzz reach them cross-crate (the v0.21
`gmcrypto-simd` precedent). **Group B** — the always-on byte-adjacent public types
reshaped from `U256` to `[u8;32]` **byte-output-identically**: `asn1::sig::{encode,
decode}_sig` (+ `asn1::` re-exports) and `asn1::ciphertext::Sm2Ciphertext::{x,y}`; the
DER/raw wire format + all strict-canonical / zero / `< p` / on-curve rejects are
unchanged (`decode_sig` keeps its rejects, `verify` reconstructs `U256` for the
`r!=0`/`r<n`/`Fn::new`/`t!=0` checks; `decrypt` keeps the on-curve guard since the
public `[u8;32]` fields are caller-constructible / not inherently canonical). A new
`pub(crate)` `lib.rs` helper `u256_to_be32` pins the `U256 -> [u8;32]` conversion
(crypto-bigint's `to_be_bytes` returns `EncodedUint`, not `[u8;32]`). **Group C** —
`ProjectivePoint` stays **public + unchanged** (it names no `crypto-bigint` type once
`to_affine` is hidden, so the high-level key path `public_key`/`from_point`/`spki`/`sec1`
is untouched; decouple-only, NOT point-type removal). **The one residual:** the
**opt-in** `crypto-bigint-scalar` feature's `Sm2PrivateKey::from_scalar(U256)` stays as a
**documented escape hatch** (enabling the feature is an explicit opt-in to the
`crypto-bigint 0.7` type contract; off by default). The committed (`--all-features`)
`cargo-public-api` baseline (`docs/api-baseline/gmcrypto-core.txt`, regenerated with the
pinned `cargo-public-api 0.52.0` + `nightly-2026-05-23`) records **exactly** that
residual and nothing else `crypto-bigint`-typed; an ad-hoc **default-features** run greps
**zero**. The C ABI is unchanged (the FFI never named these types — `gmcrypto.h`
drift-check stays green; 65 `c_smoke` pass). **Verified byte-identical:** full KAT +
gmssl 3.1.1 interop **11/11** + 248 core / full-workspace tests; per-feature clippy +
fmt + `cargo doc` + 18 fuzz targets + MSRV-1.85 + wasm32 + `--no-default-features`.
**Repository / infra-assurance milestone, NOT a crates.io release** — the breaking
API-*shape* change ships with the deliberate `1.0.0` publish; it never reaches a
published 0.x crate, so no 0.x consumer sees the break (the only migration is
0.16 → 1.0, a major bump anyway). Workspace stays **0.16.0**; crates.io skips `0.22.0`
(the v0.14/v0.17/v0.18/v0.19/v0.20/v0.21 precedent). `docs/v1.0-readiness.md` §3.A now
flips to **GO** — nothing pre-1.0 remains outstanding. Forks settled before planning:
depth = decouple-only (keep `ProjectivePoint` public); escape hatch = keep `from_scalar`
documented opt-in; posture = non-publishing — all three **Codex-confirmed**
(`codex exec --sandbox read-only`, gpt-5.5). Per `docs/v0.22-scope.md` Q22.1–Q22.8,
codex-reviewed W0–W3.
**Earlier — v0.21 — v1.0 readiness audit (non-publishing) — API/SemVer
freeze + CI guards + docs freeze (on `main`)** — locked + tooling-guarded the public API
ahead of a `1.0` commitment, **without** the irreversible publish. New
`.github/workflows/api-stability.yml` (4 legs): a committed **`cargo-public-api`
baseline + enforced drift-check** (`docs/api-baseline/{gmcrypto-core,gmcrypto-simd}.txt`;
the cbindgen-header-drift pattern, **pinned** `cargo-public-api 0.52.0` +
`nightly-2026-05-23`), **`cargo-semver-checks`** (informational pre-1.0 — 0.x permits
breakage; the **enforced forward gate from 1.0**), a **`cargo doc -D warnings -A
rustdoc::private_intra_doc_links`** gate, and a **`--no-default-features`/`--all-features`**
matrix. Finalized the `#[doc(hidden)]` surface for 1.0 (**Option A**, doc-attributes +
tests only, **no behavior change**): canonical "not public API / not SemVer-covered"
notes on the 3 core hidden items (`sm2::sign_raw_with_id`,
`Sm4Cbc{Encryptor,Decryptor}::take_output`) + `#[doc(hidden)]` on the whole
**`gmcrypto-simd`** surface (kept `pub` for cross-crate use; "no stable Rust API,
internal acceleration backend") so the baseline records the intended-1.0 surface;
existence tests (`tests/api_surface.rs`, `tests/internal_surface.rs`) pin the hidden
hooks. Froze the docs (README **Stability & SemVer** section + feature consolidation;
SECURITY cross-ref; CHANGELOG `[Unreleased]`; **`docs/v1.0-readiness.md`** GO/NO-GO +
publish runbook). **Headline audit finding:** the **always-on** public API names
`crypto-bigint 0.7` types (`asn1::{encode,decode}_sig` ↔ `(U256,U256)`,
`Sm2Ciphertext::{x,y}`, the `curve`/`point`/`scalar_mul` surface `Fn`/`Fp`/`mul_g`/…)
— a **load-bearing decision to resolve before 1.0** (`docs/v1.0-readiness.md` §3.A;
likely a focused pre-1.0 "API-tightening" cycle). Fixed pre-existing latent intra-doc
links surfaced by the new doc gate (doc-only). **Repository / infra-assurance milestone,
NOT a crates.io release** — doc-attributes + tests + CI + docs only; the published
library's *output* is byte-unchanged, workspace stays **0.16.0**, crates.io skips
`0.21.0` (the v0.14/v0.17/v0.18/v0.19/v0.20 precedent). Two forks settled before
planning: publish posture = non-publishing (maintainer); API-finalization depth =
Option A (Codex, focused consult). Per `docs/v0.21-scope.md` Q21.1–Q21.9, codex-reviewed
W0–W3. **v1.0 = the deliberate publish** after the §3.A decision (bump `0.16.0→1.0.0`,
exact sibling pins, publish simd→core→c, flip semver-checks to enforced).
**Earlier — v0.20 — streaming-decryptor differential fuzzing +
`cargo fuzz coverage` + codified v1.0 CT baseline (on `main`)** — two new
libFuzzer targets (`fuzz_sm4_cbc_streaming_decrypt` /
`fuzz_sm4_gcm_streaming_decrypt`) assert the **streaming** decryptors
(`Sm4CbcDecryptor` / `Sm4GcmDecryptor`, fed in **arbitrary chunk boundaries**) are
**byte-identical** to the single-shot `mode_{cbc,gcm}::decrypt` oracle — a
*differential* invariant stronger than v0.14's no-panic (catches the CBC
buffer-back-by-one PKCS#7 boundary + the GCM commit-on-verify GHASH accumulator).
Plus a **non-gating `cargo fuzz coverage`** nightly job (per-target `llvm-cov`
TOTALS artifact; report-as-deliverable, no %-gate) and the fuzz sweep grown to
**18 targets**. Initial sweep: **zero crashes, zero divergences**. Also
**codifies the settled v1.0 constant-time baseline** in `SECURITY.md`
(Codex+Grok-advised): composite dudect targets stay gated `|tau|<0.20`; the two
single-inversion diagnostics stay telemetry/sentinel @0.55 (the v0.19
falsification is the evidence), with a *narrow* revisit door (a class-split-twin
reproducing the dudect two-input geometry **without** the inversion op, or
offline/dedicated hardware — never public self-hosted CI). **Repository /
infra-assurance milestone, NOT a crates.io release** — only the workspace-excluded
`fuzz/` crate + `fuzz-nightly.yml` + docs change; the published library is
byte-unchanged, workspace stays **0.16.0**, crates.io skips `0.20.0` (the
v0.14/v0.17/v0.18/v0.19 precedent). Theme chosen after a **Codex+Grok strategy
discussion** (one more assurance cycle over a 3rd dudect cycle and over new
features); **v0.21 = the v1.0 readiness audit** (API/SemVer + docs freeze), with
v0.20's harnesses + coverage as input evidence. Per `docs/v0.20-scope.md`
Q20.1–Q20.5, codex-reviewed W0–W2.
**Earlier — v0.19 — self-calibrating relative dudect gate:
TESTED and FALSIFIED → honest fallback (on `main`)** — added two **fix-vs-fix
noise-floor probes** (`noise_floor_fn_invert` / `noise_floor_fp_invert`) to the
dudect harness (each runs the same `Fn`/`Fp` `invert` as its `ct_f{n,p}_invert`
suspect but feeds **both dudect classes one identical input**, so its `|tau|` is
pure measurement noise) plus a CI **relative gate**
`median(target) ≤ max(0.20, K=4·median(probe))` meant to re-promote
`ct_fn_invert`/`ct_fp_invert` off the v0.18 telemetry/sentinel posture by adapting
to the runner's own noise floor. **The 100K calibration FALSIFIED the matched-
sensitivity premise**: the probes stay uniformly quiet (~0.005) while the real
class-split targets spike intermittently to [0.26–0.32] (`ct_fp_invert` **median
0.2606** on the `sm4-bitsliced-simd` leg, ratio **50**) — the runner noise lives
in the **two-input class-split difference** (`z_small` vs `z_large`), **NOT** the
operation duration a same-input probe can see, so the probe cannot track it and
the relative threshold stays pinned at the `ABS_FLOOR` 0.20 the noise already
breaks. **Honest fallback (Q19.5)**: the relative gate is demoted to non-blocking
`REL-TELEMETRY`; `ct_fn_invert`/`ct_fp_invert` revert to the v0.18 posture
(telemetry PR / gross-regression **sentinel @0.55** nightly — the sole
authoritative gate again); the two probes are **KEPT as telemetry** (they are the
*evidence* that the noise is class-split-specific — the input to a v0.20
**class-split-aware "noise-twin"** reference). **Repository / infra-assurance
milestone, NOT a crates.io release** — the only `crates/` change is the dev-only
bench harness `timing_leaks.rs` (published library byte-unchanged), workspace
stays **0.16.0**, crates.io skips `0.19.0` (the v0.14 / v0.17 / v0.18 precedent).
**PR #78** (probes + relative gate, merged) **+ the resolution follow-up**
(relative gate → telemetry + fallback docs). Per `docs/v0.19-scope.md` Q19.1–Q19.7
+ `docs/v0.5-dudect-recalibration.md` (v0.19 resolution), codex-reviewed.
**Earlier — v0.18 — dudect-gate hardening (on `main`)**
— pin the dudect CI workflows' drift axes (`ubuntu-24.04` **OS-label** pin +
exact `dtolnay/rust-toolchain@1.95.0`, the load-bearing axis) and gate on a
**CI-level multi-run median** `|tau|` (PR N=3 / nightly N=5; `required_low` +
the nightly sentinel on the **median**, `negative_control` on the **min**, plus
a completeness gate that FAILs any required target measured < N runs). The bench
harness `timing_leaks.rs` is **byte-unchanged** — the loop + median live
entirely in the workflow YAML + the inline Python gate. **Repository /
infra-assurance milestone, NOT a crates.io release** — no crate code change,
workspace stays **0.16.0**, crates.io skips `0.18.0` (the v0.14 / v0.17
precedent). The v0.5 recalibration doc's "authoritative fix" (a noise-isolated
self-hosted runner) is **off the table** post-v0.17 (self-hosted on a public
repo is RCE), so robustness is now pure software on GitHub-hosted `ubuntu-24.04`.
100K×5 calibration showed `ct_fn_invert`/`ct_fp_invert` back near the ~0.006
baseline (medians 0.006–0.028), but they were **kept on the telemetry (PR) /
median-gated gross-regression sentinel @0.55 (nightly) posture — NOT
re-promoted** to a `|tau| < 0.20` gate: the noise is image-sensitive and
intermittent, so a tight gate (even a 5-run median) would re-flake if it
returns; robustness-first per `docs/v0.18-scope.md` Q18.7 +
`docs/v0.5-dudect-recalibration.md` (v0.18 resolution). A self-calibrating
relative gate is the v0.19 candidate. The dudect `rust-cache` `shared-key` was
also made comma-free (keyed on `strategy.job-index`) so the multi-feature leg
caches. **Two PRs**: #75 (pin + median + completeness) + #76 (cache key).
**Earlier — v0.17 — public-flip milestone (on `main`)**
— open-sourcing the repository. CI migrated **off the self-hosted macOS
runner** to GitHub-hosted (`ci.yml` → `macos-14`, `fuzz-nightly.yml` →
`ubuntu-latest`) so the personal-Mac runner can be retired before the repo
flips **private → public**. **Repository milestone, NOT a crates.io
release** — no crate code changes, workspace stays **0.16.0**, crates.io
skips `0.17.0` (the v0.14 precedent); **v1.0 reserved** for a later
readiness pass (dudect-gate hardening + API-stability review). Per
`docs/v0.17-scope.md` + `docs/pre-opensource-audit.md` (codex-reviewed plan).
**Earlier — v0.16.0 published to crates.io 2026-05-29**
— **C FFI for the SM4-XTS multi-sector (disk) helper**: expose the v0.15
`sm4::mode_xts::{encrypt_sectors, decrypt_sectors}` through the `gmcrypto-c`
C ABI behind the existing forwarding **`sm4-xts`** feature
(`= ["gmcrypto-core/sm4-xts"]`, no new dep), per `docs/v0.16-scope.md`
Q16.1–Q16.12 (codex-reviewed W0+W1). Two new symbols
`gmcrypto_sm4_xts_encrypt_sectors` / `_decrypt_sectors` transform a
contiguous run of equal-size sectors **in place** (`buf: *mut u8` +
`buf_len`; sector `i` under tweak = **LE-128(`start_sector + i`)**),
byte-identical to core `mode_xts::{encrypt,decrypt}_sectors`. **In-place is
a deliberate divergence** from the uniformly out-of-place single-shot XTS
FFI: it mirrors the core's `&mut [u8]` so disk callers never
double-allocate, and the transform is length-preserving so no
`out`/`out_capacity`/`out_actual_len` is needed. **`start_sector` is a
`uint64_t`** (block-layer `sector_t` width; C has no portable u128 — the
core's u128 range stays Rust-only; a consequence is the sector-number
overflow `None` is unreachable from the FFI). Single `GMCRYPTO_ERR` (bad
`sector_size`/`buf_len`-multiple/`Key1==Key2`/null) with **`buf` untouched**
on error (core pre-flights validation); `buf_len==0` → vacuous
`GMCRYPTO_OK` (key still validated). **W0 codex fix**: the in-place path is
the only FFI surface holding a `&mut` over caller memory **alongside** the
`&` key borrow, so the 32-byte key is **copied into an owned `[u8;32]`**
before the `&mut [u8]` is built (a caller `key`/`buf` overlap becomes a
benign copy, not `&`/`&mut` aliasing UB — locked in by the
`sm4_xts_sectors_key_buf_overlap_ok` test). **Confidentiality only — no
auth.** `regen-header` need **NOT** imply `sm4-xts` (two free-fn prototypes
emit unconditionally; no new opaque structs). 11 new c_smoke tests +
doc-only example `crates/gmcrypto-c/examples/sm4_xts_multisector.c`. **No
new `gmcrypto-core` API, no new dudect target** (thin shim — core's
`ct_sm4_xts_decrypt` covers it; the sector→tweak arithmetic is on **public**
addresses), no new dep. Workspace `version` **0.15.0 → 0.16.0**;
default-features build of both crates byte-unchanged. Every cipher mode is
now FFI-complete.
**Earlier — v0.15.0 (crates.io 2026-05-28)**
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
(cron + `workflow_dispatch`, GitHub-hosted `ubuntu-latest` since v0.17,
pinned `cargo-fuzz 0.13.1`, NOT a PR gate). Codex-reviewed W0+W1+W2+W3. Workspace `version` stays
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

## Throughput-win + AEAD arc retrospective

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
v0.13.0 → v1.0.1 are documented once, in the `## Cycles` prose above (the `**Earlier — vX.Y —**` paragraphs, newest-first) — not duplicated here. This arc list keeps only the `v0.5 → v0.12` throughput/AEAD/XTS sequence it was created to summarize.
