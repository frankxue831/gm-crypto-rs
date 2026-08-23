# gmcrypto-simd

**Internal SIMD backend for [`gmcrypto-core`](https://crates.io/crates/gmcrypto-core).
Not a crate you should depend on directly.**

[![Crates.io](https://img.shields.io/crates/v/gmcrypto-simd.svg)](https://crates.io/crates/gmcrypto-simd)
[![Documentation](https://docs.rs/gmcrypto-simd/badge.svg)](https://docs.rs/gmcrypto-simd)
[![License](https://img.shields.io/crates/l/gmcrypto-simd.svg)](https://crates.io/crates/gmcrypto-simd)

## What you probably want instead

If you are here because you searched for SM4, the crate you want is
`gmcrypto-core`, with the SIMD backend switched on by feature:

```toml
[dependencies]
gmcrypto-core = { version = "1.11", features = ["sm4-bitsliced-simd"] }
```

That pulls this crate in automatically. `sm4-aead` does too, for GHASH.
Nothing in the SM4 or GHASH API is exposed here in a form intended for
outside callers.

## What this crate is

The packed-bitsliced SM4 S-box and the GHASH multiply, written against
architecture intrinsics:

| | `x86_64` | `aarch64` | elsewhere |
|---|---|---|---|
| SM4 S-box | AVX2, 8 / 32 bytes per call, runtime-detected with scalar fallback | NEON, 16 bytes per call, compile-time baseline | scalar bitsliced |
| GHASH multiply | CLMUL, runtime-detected | PMULL64, runtime-detected | constant-time software |

It exists for exactly one reason: `core::arch` intrinsics are `unsafe fn`,
and `#[target_feature(enable = "…")]` is the only stable-Rust mechanism on
MSRV 1.85 that combines runtime CPU dispatch with intrinsic calls. Putting
that here keeps `gmcrypto-core` at `unsafe_code = "forbid"` — every `unsafe`
block in this crate carries a `// SAFETY:` comment naming its architectural
or runtime-detect precondition. Same posture as the `gmcrypto-c` FFI shim.

## Stability

- **`rlib`-only.** No cdylib, no staticlib, no C ABI, no raw pointers across
  the crate boundary. `gmcrypto-c` is the project's only C ABI.
- **Every public item is `#[doc(hidden)]` and outside SemVer.** Entry points
  may change or disappear in any release without a major bump. The supported
  surfaces are the `gmcrypto-core` Rust API and the `gmcrypto-c` C ABI.
- **Lockstep-versioned** with its siblings: `gmcrypto-core` pins this crate
  at an exact `=1.11.2`, and all three crates publish together. Mixing
  versions is not a supported configuration.

Correctness is not taken on trust from the intrinsics: lane-equivalence tests
cross-check both the scalar and the SIMD paths against an inline copy of the
GB/T 32907-2016 §6.2 S-box table, and `gmcrypto-core` asserts the bitsliced
output is byte-identical to its default linear-scan S-box.

## Licence

Dual-licensed under Apache-2.0 or MIT, at your option — same as the rest of
the workspace. See [the repository](https://github.com/frankxue831/gm-crypto-rs)
for the threat model, security posture, and the full SDK.
