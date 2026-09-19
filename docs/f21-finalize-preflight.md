# F21 — `finalize()` input and single-consumption preflight

**Status: functional preparation only. F21 remains open.**

`docs/v1.10-scope.md` (Q10.9) records that a dudect target over the full
`mode_cbc::decrypt` window is blind to the PKCS#7 strip, and names the
follow-up: time `Sm4CbcDecryptor::finalize()` instead, with the key schedule
and both block decrypts left in the untimed `update()` prologue. It also names
the blocker: the harness takes an `Fn` closure, while `finalize(self)` consumes
the decryptor.

This note covers the first, purely functional step toward that follow-up. The
accompanying test is `crates/gmcrypto-core/tests/f21_finalize_inputs.rs`.

## What the test fixes in place

### Inputs

Two invalid-padding classes plus one valid control, all 32-byte (two-block)
SM4-CBC ciphertexts under one fixed public key and IV:

| sample | final plaintext block | expected result |
|---|---|---|
| early | fifteen bytes of `16`, one wrong byte at index 0 | `None` |
| late | fifteen bytes of `16`, one wrong byte at index 14 | `None` |
| control | sixteen bytes of `16` (valid full pad block) | `Some(first block)` |

- All samples share the first plaintext block, so ciphertext block 0 is
  byte-identical and only the final block carries the class label.
- In both invalid classes the last byte is still `16`, so the declared pad
  length is the same and the whole block is inside the scanned padding region;
  the classes differ only in *where* the single mismatch sits.
- Both invalid classes take the same `None` path. This deliberately avoids the
  validity split that Q10.4 refuted (a `Some`/`None` split measures the API's
  shape, not the scan).

The ciphertexts are built by hand from the public `Sm4Cipher` block API (XOR
with the previous block, then `encrypt_block`). The high-level encryptor cannot
be used for the invalid classes because it always appends its own valid
padding. The test re-derives each final block with an independent manual CBC
decrypt and asserts exactly one wrong byte at the intended index. The valid
control is additionally asserted byte-identical to `mode_cbc::encrypt`, which
anchors the manual construction to the library's own CBC.

Rejection is asserted for the streaming decryptor (single `update`, and one
block per `update`) and for one-shot `mode_cbc::decrypt`; both share the single
`strip_pkcs7_block` implementation.

### Single-consumption wrapper

A prepared sample is a `RefCell<Option<Sm4CbcDecryptor>>` holding a decryptor
that has already absorbed the whole ciphertext. The consuming closure takes the
decryptor out of the slot and calls `finalize()`. The test passes that closure
through a helper bounded on `Fn` (not `FnMut` / `FnOnce`), which is the bound
that made moving the decryptor in impossible.

The contract asserted:

- the first call consumes the decryptor and returns the `finalize()` result;
- a second call on the same slot fails loudly (panics; the test observes this
  with `catch_unwind(AssertUnwindSafe(..))`) and leaves the slot empty;
- every measurement therefore needs a freshly prepared sample, and freshly
  prepared samples are independent of each other and of spent ones.

## Limits — what this does **not** show

- **No timing claim of any kind.** Nothing here measures time, runs the dudect
  harness, or says whether an early-exit regression in the strip would be
  detectable through a `finalize()` window.
- **No claim about harness call counts.** The test proves the wrapper tolerates
  exactly one consumption per prepared sample. It does not show that the real
  runner invokes the closure exactly once per sample, nor what falls inside its
  measurement window. If the runner calls the closure more than once per
  prepared state, this wrapper panics rather than silently timing an empty
  slot — that behaviour is intended, and the per-sample preparation strategy
  must then be settled in the harness study.
- **Wrapper cost is unmeasured.** The `RefCell` borrow, the `Option` take, the
  move of the decryptor, and its zeroize-on-drop all land inside any window
  that times this closure. For a window as small as `finalize()` that overhead
  has to be measured, not assumed.
- **Not a sensitivity control.** The three-way control required by Q10.5 / Q10.9
  (constant-time / early-return leaky / amplified) has not been re-run for this
  window. No number from a `finalize()` target should be trusted before it is.
- **Not a statement about constant-time safety**, and not user acceptance of
  any future target. No dudect target is added, gated, or promoted here.

The key, IV and plaintext are fixed public research samples, not a
secret-bearing product path.

## Scope

Test and documentation only. No change to the production algorithm, the
zeroization behaviour, the public API, dependencies, CI gates, or versions.

## Next step (not part of this change)

With inputs and wrapper fixed, the remaining F21 work is the harness study:
confirm how the runner invokes the closure and where its window sits, decide
how a fresh sample is prepared per measurement outside the window, measure the
wrapper's own cost, and re-run the three-way sensitivity control before
drawing any conclusion.
