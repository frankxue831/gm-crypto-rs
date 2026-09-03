---
paths:
  - "crates/gmcrypto-core/src/sm4/**"
  - "crates/gmcrypto-core/tests/sm4_*.rs"
---

# SM4 modes — invariants that are easy to "fix" wrongly

## CBC

- Don't generate the IV inside `mode_cbc::encrypt` (caller-supplied,
  unpredictable).
- Don't make `mode_cbc::decrypt` distinguish failure modes (single `None`).

## XTS (GB/T 17964-2021, not IEEE 1619)

- `xts_standard=GB`: `mul_alpha` is bit-reflected (right-shift, `0xE1` into
  byte 0), not IEEE `<<1` / `0x87`. Don't branch on the tweak in `mul_alpha`
  (masked XOR, never `if`).
- Don't relax `Key1 == Key2 → None` in `mode_xts` (CT compare; outcome gates).
- Don't let the API generate or reuse tweaks; XTS is confidentiality-only —
  never imply it authenticates. `sm4-xts = []`: no `gmcrypto-simd` or any dep.
- Sectors: tweak is LE-128 of the sector number, not raw bytes; the helper is
  in-place; validate up front so `buf` is untouched on `None`.

## GCM

- `Sm4GcmDecryptor` is commit-on-verify and `O(message)` memory — not a
  stream. GCM's counter is `inc32`; nothing else uses it.
- The GCM pair does not zeroize yet (`Sm4GcmEncryptor` leftover keystream,
  `GhashAcc` `H`/`y`); nor do `Sm4CtrCipher` and the CBC streaming pair. That
  is the v1.13 zeroize item — until it lands, don't describe them as wiped.

## CCM (v1.12 — `ccm_streaming`, behind the existing `sm4-aead` flag)

- **The encryptor is length-committed by design.** `new` takes
  `plaintext_len` because CCM's `B0` encodes it; that commitment is what
  makes `O(chunk)` streaming possible. An over-feeding `update` emits nothing
  and poisons; `finalize` is `None` on poison **or under-feed** (stricter than
  `Sm4GcmEncryptor` — a partial stream is never tag-authenticated). Don't
  relax either.
- **The decryptor is a pure delegator** over `mode_ccm::decrypt_with_cipher`
  (buffer, latch at `payload_ceiling(q)`, gate `tag.len()`, delegate). That
  thinness is why it has **no dudect target**; it is guarded by
  `fuzz_sm4_ccm_streaming_decrypt`. Any cryptographic work inside it (a
  length-declared decryptor, incremental CBC-MAC, CTR before finalize) voids
  the argument and reopens dudect.
- **CCM's counter is `mode_ccm::counter_block`** (`q`-byte big-endian field,
  `q = 15 − nonce.len()`), shared by single-shot and streaming. Never GCM's
  `inc32` — even the 12-byte nonce is `q = 3`.
- Helpers promoted for `ccm_streaming` are `pub(super)` (the `mode_gcm`
  precedent), never `pub` / `pub(crate)`.
- Terminology: encryptor "length-committed streaming"; decryptor
  "incremental-input buffered" — never "streaming".
- `aead-traits`: implement `AeadInOut`, never `Aead`; both AEAD pairs stay
  thin over `mode_gcm` / `mode_ccm`; no `aead::stream` (the `aead` crate has
  none); XTS has no trait fit. Scope: `docs/v1.12-scope.md`.

## General

- Don't ship `encode_c1c2c3_legacy`-style legacy layouts as encoders; legacy
  forms are decrypt-only.
- `zeroize` here has no `alloc` feature: wipe a `Vec<[u8; 16]>` with
  `.iter_mut().zeroize()`, not `.zeroize()`.
