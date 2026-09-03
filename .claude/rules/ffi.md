---
paths:
  - "crates/gmcrypto-c/**"
---

# gmcrypto-c — the C ABI

`gmcrypto-c` is the **only** C ABI (cdylib + staticlib + committed
`include/gmcrypto.h`). `std` is fine here. AEAD/XTS FFI is always-on (no
`--features`). Every entry point is exercised by `tests/c_smoke.rs`; CI also
compiles every `examples/*.c` against the header, and `ci.yml` states the
c_smoke test count in a comment — update it when you add tests.

- `unsafe_code = "warn"`, never `allow`; every `unsafe` block carries a
  `// SAFETY:` comment. Don't relax core's `forbid` to make a shim easier.
- Every entry returns `GMCRYPTO_FAILED` only — no C ABI entry distinguishes
  failure modes (SECURITY.md failure-mode invariant).
- Handle families (`*_encryptor_t` / `*_decryptor_t`): `_new` →
  `Box::into_raw`; `_update` → `&mut *`; `_finalize*` → `Box::from_raw`
  (consumes **and frees**, even on error); `_free` is the abort path, no-op on
  NULL. Output is the `(out, out_capacity, out_actual_len)` triple via
  `write_output`. Decryptors emit nothing from `_update` (commit-on-verify).
- Don't rename `gmcrypto_sm2_privkey_to_sec1_be` (the Rust method is
  `to_bytes_be`).
- XTS: FFI takes `uint64_t start_sector`. **Copy the 32-byte key into
  `[u8; 32]`** before reconstructing `&mut buf` — a caller `key`/`buf`
  overlap is `&`/`&mut` aliasing UB otherwise.
- Header regen: `cargo build -p gmcrypto-c --features regen-header` then
  `git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h` must be clean.
  cbindgen 0.27 doesn't recognise `#[unsafe(no_mangle)]` — pin **0.29+**.
- Don't add `all-features = true` to `gmcrypto-c`'s docs.rs metadata: it
  would switch on `regen-header` and run cbindgen in the docs build.
- FFI diagnostic callback is deferred until a real consumer asks; the core
  never logs (SECURITY.md "Logging & observability").
