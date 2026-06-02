# Fuzz coverage-gap analysis — gm-crypto-rs `1.0.0`

| | |
|---|---|
| **Date** | 2026-06-02 |
| **Commit** | `12e26b4` (`main`, workspace `1.0.0`) |
| **Mission** | Find adversarial-input fuzz coverage gaps; propose prioritized candidate targets. |
| **Method** | Read-only multi-agent workflow (`fuzz-coverage-gap-analysis`): 6-lens map → adversarial verify (gap-real? invariant-sound?) → dedupe/rank synthesis. 69 agents; 62 candidates raised (26 confirmed / 34 refuted / 2 uncertain) → 17 prioritized + 18 well-covered scopes. |
| **Existing coverage** | 18 targets: 16 v0.14 no-panic (parser/decrypt) + 2 v0.20 differential (streaming CBC/GCM **decrypt**). Seeds: 1 per target except the 2 streaming (4 each). |

**Framing:** "Confirmed" = a *source-verified coverage gap with a sound, non-flaky invariant* — **NOT a found bug**. Severity = priority/value of adding the target. This whole family is the post-1.0-deferred *"round-trip/differential parser fuzzing"* theme. **Analysis only — no target code written, no fuzzing executed, no files changed.**

Two value tiers (the key distinction severity alone hides):
- **Tier A** — adds a genuinely **new invariant class** to a surface that only has no-panic / is uncovered.
- **Tier B** — **breadth over an invariant a deterministic unit test already asserts** (real, lower marginal value).

---

## ▶ SUGGESTED FIRST SLICE (pick up later)

Lowest risk + genuinely new invariant class:

- [ ] Upgrade the 4 DER parser targets no-panic → **roundtrip/idempotence**: `fuzz_sig`, `fuzz_sm2_ciphertext_der`, `fuzz_sm2_raw_ciphertext`, `fuzz_spki`
- [ ] **XTS `encrypt_sectors`/`decrypt_sectors` differential** vs looped single-shot (truly uncovered public surface)
- [ ] **XTS multi-sector `decrypt_sectors` no-panic** target (truly uncovered; medium risk — sector#→tweak overflow)

Then the AEAD encrypt→decrypt roundtrips (CBC/GCM/CCM/XTS) and the GCM all-tag-lengths roundtrip. All feasible in `fuzz/` with `libfuzzer-sys` + `arbitrary` only — no new deps, no `unsafe`, no API change. SM4 layouts must respect the `arbitrary 1.4.2` front-consuming seed-order pin.

---

## 1 · Confirmed candidates — Tier A (highest value)

| Pri | Candidate · `target/api` | Invariant | Input layout | Expected bug class | Risk |
|---|---|---|---|---|---|
| High | **XTS multi-sector decrypt** · `mode_xts::decrypt_sectors` | no-panic + in-place result byte-identical to looping single-shot `decrypt` per sector | `key[32]`, `sector_size∈[16,16MiB] %16`, `start_sector:u128`, `buf %sector_size` | sector#→tweak overflow panic, sector-boundary off-by-one, wrong tweak for sector N | med |
| High | **XTS sectors differential** · `mode_xts::{encrypt,decrypt}_sectors` | `encrypt_sectors` ≡ loop of single-shot `encrypt` per sector, byte-identical | `key[32]`, `sector_size∈{16,4096,65536}`, `start_sector:u128`, `1..8` sectors | sector#→tweak encoding mismatch, tweak-doubling off-by-one, sector skip | low |
| High | **Upgrade `fuzz_sig` → roundtrip** · `asn1::sig::{encode,decode}_sig` | `decode_sig(x)=Some((r,s)) ⇒ decode_sig(encode_sig(r,s))=Some((r,s))` (strict-canonical) | arbitrary DER `SEQUENCE{INTEGER r, INTEGER s}` | encoder/decoder asymmetry, INTEGER leading-zero padding mismatch | low |
| High | **Upgrade `fuzz_sm2_ciphertext_der` → roundtrip** · `asn1::ciphertext::{encode,decode}` | `decode(x)=Some(ct) ⇒ decode(encode(ct))=Some(ct)`; byte-idempotent | arbitrary DER `SEQUENCE{x,y,hash OCTET,ct OCTET}` | non-canonical INTEGER padding, field-bound validation escape | low |
| High | **Upgrade `fuzz_sm2_raw_ciphertext` → roundtrip** · `raw_ciphertext::{encode,decode}_c1c3c2` | `decode_c1c3c2(x)=Some(ct) ⇒ encode→decode round-trips` | raw `C1‖C3‖C2` (65+32+|C2|) | field-element boundary escape, on-curve validation false-negative | low |
| High | **Upgrade `fuzz_spki` → roundtrip** · `spki::{encode,decode}` | `decode(x)=Some(key) ⇒ decode(encode(key))=Some(key)` | arbitrary DER RFC-5280 SPKI | BIT STRING unused-bits mismatch, OID encoding drift | low |
| High | **SM4-CBC roundtrip** · `mode_cbc::{encrypt,decrypt}` | `decrypt(encrypt(pt))=Some(pt)`; never panics | `[key16][iv16][pt..]` | PKCS#7 strip off-by-one, block-boundary corruption | low |
| High | **SM4-XTS roundtrip** · `mode_xts::{encrypt,decrypt}` | `decrypt(encrypt(du))=Some(du)`, `du==pt` | `[key32][tweak16][du≥16]` | CTS off-by-one, tweak-doubling error, `Key1==Key2` inconsistency | low |
| High | **SM4-CCM roundtrip** · `mode_ccm::{encrypt,decrypt}` | `decrypt(encrypt(pt))=Some(pt)` | `[key16][nl7..13][nonce][al0..32][aad][tag_len∈{4,6,8,10,12,14,16}][pt..]` | CBC-MAC mismatch, CTR off-by-one, tag-extraction boundary | low |
| High | **SM4-GCM roundtrip (16-byte tag)** · `mode_gcm::{encrypt,decrypt}` | `decrypt(encrypt(pt))=Some(pt)` | `[key16][nl1..16][nonce][al1..32][aad][pt..]` | GHASH asymmetry, CTR/J0 derivation divergence | med |
| High | **SM4-GCM roundtrip × 7 tag lengths** · `mode_gcm::{encrypt,decrypt}_with_tag_len` | roundtrip holds ∀ `tag_len∈{4,8,12,13,14,15,16}` | `…[tag_len_sel:1..7][pt..]` | tag-truncation boundary, tag-len gate bypass | med |

## 2 · Confirmed candidates — Tier B (breadth over existing unit tests)

| Pri | Candidate · `target/api` | Invariant | Input layout | Expected bug class | Risk |
|---|---|---|---|---|---|
| High | **SM4-CBC streaming-encrypt differential** · `Sm4CbcEncryptor` vs `mode_cbc::encrypt` | chunked encrypt ≡ single-shot, byte-identical | `[key16][iv16][chunk_len1][pt..]` | CBC-chaining buffer misalignment, padding offset, block-call count | low |
| High | **`fuzz_sig` seeds: varying r/s byte-lengths** · `asn1::sig::decode_sig` | (seed corpus) reach 1/16/31-byte INTEGER paths (current seed only 33-byte) | DER seeds w/ r,s lengths 1,16,31,32 | leading-zero stripping off-by-one, padding reconstruction | low |
| Med | **`fuzz_pkcs8_decode` seeds: v2 + boundary scalars** · `pkcs8::decode` | (seed corpus) reach v2 `[0]/[1]` attrs + scalar edges `d=1, d=n-2` | PKCS#8 v1/v2 DER seeds | missing v2 attribute paths, scalar-boundary validation gaps | low |
| Med | **Upgrade `fuzz_pem` → roundtrip** · `pem::{encode,decode}` | `decode(text,label)=Ok(der) ⇒ decode(encode(label,der),label)=Ok(der)` | arbitrary PEM-armored text, 5 labels | base64 padding mismatch, line-wrap boundary, label case-sensitivity | low |
| Med | **Legacy `C1‖C2‖C3` cross-decoder differential** · `raw_ciphertext::decode_c1c2c3_legacy` vs `decode_c1c3c2` | both decoders extract same field values from byte-permuted forms | plaintext → derive modern, swap to legacy, cross-check | legacy field-extraction error, `C2_LEN` off-by-one, point-validation skip | low |

## 3 · Hypotheses (lower confidence / verifier-split)

| Pri | Candidate · `target/api` | Why hypothesis | Invariant / risk |
|---|---|---|---|
| Med | **Upgrade `fuzz_sec1` → roundtrip** · `sec1::{encode,decode}` | needs confirming `sec1::encode` re-emits canonical RFC-5915 incl. context-tagged field order; flaky if non-canonical inputs accepted | `decode→encode→decode` identity · risk med |
| Med | **SM4-GCM streaming-encrypt differential** · `Sm4GcmEncryptor` vs `mode_gcm::encrypt` | **re-promoted** — see inconsistency #1 | chunked ≡ single-shot · risk low |
| Low | **GCM tamper oracle** · `mode_gcm::decrypt` | unit tests assert 3 fixed bit-flips; a fuzzer mutating ct/tag/aad/nonce arbitrarily ⇒ `None` is strictly stronger | any 1-bit mutation of valid `(ct,tag,aad,nonce)` ⇒ `decrypt=None` · risk low |

---

## ⚠ Inconsistencies in the workflow's own output (reconciled)

1. **CBC vs GCM streaming-encrypt treated oppositely, and CBC double-listed.** Both `Sm4CbcEncryptor`
   and `Sm4GcmEncryptor` have deterministic fixed-chunk unit tests (`encrypt_chunked_matches_v02` over
   `[1,7,16,17,31,32,100]` / `encryptor_chunked_matches_single_shot` over
   `[1,7,15,16,17,31,32,33,100,max]`) and **neither has a fuzz target** (v0.20 added only the two
   *decryptors*). The verifiers confirmed CBC-encrypt as a high gap but refuted GCM-encrypt as
   "already unit-tested" — and the synthesis then listed CBC-encrypt in **both** the prioritized list
   *and* the well-covered list. **Honest call: they are symmetric.** Treat them together — add both
   streaming-encrypt differentials (fuzzing explores chunk-boundary patterns + the key/nonce/aad/pt
   inputs beyond the fixed unit-test set) or neither. CBC is kept at its confirmed Tier-B rank; GCM is
   re-promoted to a hypothesis at equal footing.
2. **GCM tamper oracle** was raw-confirmed `high` by one lens but demoted to well-covered by another
   (unit tests `tampered_{tag,ciphertext,aad}_fails`). A fuzzer asserting "*any* mutation ⇒ `None`"
   is broader than 3 fixed flips — listed as a Low hypothesis, not silently dropped.

---

## 4 · Scopes with no source-supported gap (well-covered / refuted)

- **DER readers / writer primitives** — all 10 `asn1::reader` primitives hit by `fuzz_asn1_reader`
  (no-panic) + writer roundtrip unit tests (`writer.rs` 146-321, `reader.rs` 255-534); higher-level
  targets transitively cover them.
- **SM4 block primitives** (`encrypt/decrypt_block(s)`) — roundtrip is tautological (Feistel); 6+
  mode-level targets exercise them transitively.
- **SM4-CTR streaming** — `chunked_update_sweep_matches_single_shot` covers chunk sizes 1..=17
  deterministically; no new invariant class for a fuzz target.
- **SM4-GCM tag-length variants (decrypt side)** — `fuzz_sm4_gcm_decrypt` already sweeps `tl%19` over
  valid+invalid lengths.
- **SM2 ciphertext variable-C2 lengths** — unit tests cover C2 = 0,1,11,300,65536; `fuzz_sm2_decrypt`
  exercises the decoder transitively.
- **`fuzz_sm2_pubkey_sec1`** — `from_sec1_bytes` no-panic + off-curve/identity rejection covered.
- **PKCS#8 PBES2 iteration bounds** — deterministic unit tests (zero / excessive iterations) + dudect
  for password CT; `fuzz_pkcs8_decrypt` explores DER mutations.
- **SEC1 named-curve OID** — `ecprivatekey_rejects_wrong_curve_oid`; `fuzz_sec1` mutates OID bytes.
- **SM2 sig roundtrip via spki/sec1/pkcs8 decoders** — `decode_sig` transitively exercised (the sig
  roundtrip *upgrade* is still listed Tier-A as a direct, stronger assertion).
- **HMAC-SM3 verify** — unit-tested; CT belongs to dudect, not libfuzzer; transitively hit via
  `fuzz_pkcs8_decrypt`.

---

## 5 · Honesty caveats

1. **Proposals only** — nothing built or run; no bug found, no file touched. Read-only throughout.
2. **"Confirmed" ≠ bug** — it means a real coverage gap with a source-verified, non-flaky invariant.
   The soundness check specifically rejected `encode(decode(x))==x` formulations for any
   non-strict-canonical decoder (flaky-target risk); surviving roundtrips use the
   `decode→encode→decode` idempotence form valid for strict-canonical readers.
3. **Implementability** — every candidate is feasible in `fuzz/` with `libfuzzer-sys` + `arbitrary`
   only (no new deps, no `unsafe`, no API change), mirroring the v0.20 differential pattern; SM4
   layouts must respect the `arbitrary 1.4.2` front-consuming seed-order pin.
4. **Priority is coverage-value, not defect-severity** — the whole family is the post-1.0-deferred
   fuzzing scope; v1.0 ships with no-panic + differential-streaming-decrypt coverage already.

---

## Provenance

Generated by a read-only Claude Code dynamic workflow (`fuzz-coverage-gap-analysis`, run
`wf_0f4fcb56-183`). No files edited, nothing committed/pushed/published/tagged, no CI or secrets
touched. Working-tree artifact; commit/track at your discretion (per the branch+PR rule, the agent
did not commit it).
