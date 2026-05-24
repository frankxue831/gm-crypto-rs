# gmcrypto-c

C ABI for `gmcrypto-core` — pure-Rust SM2 / SM3 / SM4 SDK exposed to
C / C++ / Python (cffi) / Go (cgo) / Zig / Ruby (FFI) callers via a
cdylib + staticlib and a cbindgen-generated header.

The library is a thin shim over [`gmcrypto-core`](../gmcrypto-core);
every cryptographic operation runs in the dudect-gated Rust core,
not in this crate. The C ABI is the language-binding surface only.

## Build

```bash
# cdylib (libgmcrypto_c.so / .dylib / .dll) + staticlib (.a / .lib) +
# rlib (for Rust consumers).
cargo build -p gmcrypto-c --release
```

Output artifacts land in `target/release/`:

- `libgmcrypto_c.so` (Linux) / `libgmcrypto_c.dylib` (macOS) /
  `gmcrypto_c.dll` (Windows) — shared library.
- `libgmcrypto_c.a` (Linux/macOS) / `gmcrypto_c.lib` (Windows) —
  static library.

## Optional features

The default build exposes SM2 / SM3 / SM4-ECB+CBC / HMAC-SM3 /
PBKDF2-HMAC-SM3. Two opt-in features add the symmetric-cipher modes
(each forwards to the corresponding `gmcrypto-core` feature; no extra
build flags are needed by C consumers beyond rebuilding the library):

| Feature | Adds | Example |
|---|---|---|
| `sm4-aead` | SM4-GCM / SM4-CCM single-shot + streaming SM4-GCM AEAD (`gmcrypto_sm4_gcm_*` / `gmcrypto_sm4_ccm_*`) | [`examples/sm4_gcm_streaming.c`](examples/sm4_gcm_streaming.c) |
| `sm4-xts` | SM4-XTS single-shot tweakable disk/sector mode (`gmcrypto_sm4_xts_encrypt` / `_decrypt`; GB/T 17964-2021) | [`examples/sm4_xts_sector.c`](examples/sm4_xts_sector.c) |

```bash
cargo build -p gmcrypto-c --release --features sm4-aead,sm4-xts
```

**SM4-XTS** takes a 32-byte key (`Key1 ‖ Key2`; `Key1 == Key2` is
rejected) and a 16-byte tweak (the per-sector data-unit identifier,
caller-unique per key). It is length-preserving and **confidentiality
only — it does not authenticate**; use an AEAD mode if you need
integrity. Sizes are exported as `GMCRYPTO_SM4_XTS_KEY_SIZE` (32) and
`GMCRYPTO_SM4_BLOCK_SIZE` (16).

## Header

The committed header at [`include/gmcrypto.h`](include/gmcrypto.h)
is the v0.4 C ABI contract. To regenerate after editing the FFI
surface in [`src/lib.rs`](src/lib.rs):

```bash
cargo build -p gmcrypto-c --features regen-header
```

CI verifies the committed header is in sync via `git diff --exit-code`
on every PR.

## Linking against C

```bash
# Compile a C consumer against the shared library.
gcc -I crates/gmcrypto-c/include \
    -L target/release -lgmcrypto_c \
    examples/sm2_sign.c -o sm2_sign

# Run (set LD_LIBRARY_PATH on Linux / DYLD_LIBRARY_PATH on macOS):
LD_LIBRARY_PATH=target/release ./sm2_sign
```

Static linking:

```bash
gcc -I crates/gmcrypto-c/include \
    examples/sm2_sign.c \
    target/release/libgmcrypto_c.a \
    -o sm2_sign-static
./sm2_sign-static
```

## Failure-mode invariant

Every entry point returning `int` follows the workspace
failure-mode discipline:

- `0` (= `GMCRYPTO_OK`) on success.
- Non-zero (= `GMCRYPTO_ERR` etc.) on failure. **All non-zero
  returns are equivalent**; do not distinguish failure modes by
  the specific value.

Per Q4.8 in [`docs/v0.4-scope.md`](../../docs/v0.4-scope.md):
distinguishing failure modes (wrong password vs. malformed PEM
vs. inner-key-parse failure) would introduce a password-oracle
attack surface. C consumers MUST treat all non-zero returns as
opaque.

## Output buffer convention

Variable-length output (signatures, ciphertexts, PKCS#8 blobs)
uses the `(out_ptr, out_capacity, out_actual_len)` shape per
Q4.13:

```c
size_t actual = 0;
int rc = gmcrypto_sm2_sign(
    key, NULL, 0,         /* signer_id = DEFAULT */
    msg, msg_len,
    sig_buf, sizeof sig_buf,
    &actual);
if (rc != GMCRYPTO_OK) {
    if (actual > sizeof sig_buf) {
        /* too-small buffer; `actual` carries the required length */
    } else {
        /* other failure */
    }
}
```

On too-small buffer: `rc != 0`, `*out_actual_len` set to the
required length, `out_ptr` unmodified.

## Handle ownership

Opaque handles (`gmcrypto_sm2_privkey_t*`, etc.) are heap-allocated
via `Box::into_raw`. Pair every `_new` with exactly one `_free`.
`_free(NULL)` is a no-op (mirrors C's `free()`).

Private-key handles inherit `ZeroizeOnDrop` from gmcrypto-core; the
inner scalar / round keys are zeroized before the heap slot is
freed.

## RNG sourcing

`gmcrypto_sm2_sign`, `gmcrypto_sm2_encrypt`, and
`gmcrypto_sm2_privkey_to_pkcs8` source randomness from
`getrandom::SysRng` internally. C consumers do not pass an RNG
callback in v0.4; a "register custom RNG" entry point may land
post-v0.4 if a use case surfaces.

## `unsafe_code` posture

Per Q4.7 in the scope doc: `gmcrypto-c` cannot satisfy
`unsafe_code = "forbid"` because raw-pointer dereferencing and
`Box::from_raw` are inherent to FFI. Every `unsafe` block carries
a `// SAFETY:` comment naming the caller-side preconditions. The
core crate [`gmcrypto-core`](../gmcrypto-core) itself stays
`unsafe_code = "forbid"`.

## SemVer

The C ABI is the v0.4 baseline. Signature changes in v0.4.x are
breaking ABI changes; v0.5 may break the C ABI without a major
Rust-side bump (since `gmcrypto-c` is a separate crate from
`gmcrypto-core`).

`gmcrypto_sm2_privkey_to_sec1_be` is NOT SemVer-stable across
v0.4.x per Q4.19 — caller MUST zeroize the returned scalar bytes;
documented in the header.
