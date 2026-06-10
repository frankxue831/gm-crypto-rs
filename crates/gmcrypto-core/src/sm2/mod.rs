//! SM2 elliptic curve cryptography (GB/T 32918-2017).

pub(crate) mod comb_table;
// `curve` is internal low-level SM2 field/scalar arithmetic over `crypto-bigint`
// 0.7 (`Fn`, `Fp`, `NMod`, `PMod`, `b`, `b3`). v0.22 marks the whole module
// `#[doc(hidden)]`: **NOT part of the public API / NOT covered by SemVer — may
// change or be removed in any release** (including under a `crypto-bigint` major
// bump). Rust users use the high-level `sm2` API; C users use `gmcrypto-c`. Kept
// `pub` only so in-repo dev crates (the dudect bench, integration tests, fuzz)
// can reach it cross-crate. Module-level hiding also covers the macro-generated
// `NMod`/`PMod` (which cannot take a per-item attribute). See `docs/v0.22-scope.md`
// §3 Q22.3 + `docs/v1.0-readiness.md` §3.A.
#[doc(hidden)]
pub mod curve;
pub mod decrypt;
pub mod encrypt;
// v1.1 — SM2 key exchange (GM/T 0003.3 ≡ GB/T 32918.3-2016) with key
// confirmation. Opt-in via the `sm2-key-exchange` feature; default builds
// are byte-identical. See docs/v1.1-sm2-key-exchange-design.md.
#[cfg(feature = "sm2-key-exchange")]
pub mod key_exchange;
// `point` (`ProjectivePoint`) is the internal low-level curve point. Same
// posture as `curve`/`scalar_mul` above: `#[doc(hidden)]`, not public API /
// not SemVer-covered, kept `pub` only for in-repo dev crates + cross-module use.
#[doc(hidden)]
pub mod point;
pub mod private_key;
pub mod public_key;
pub mod raw_ciphertext;
// `scalar_mul` (`mul_g`/`mul_var`) takes the `crypto-bigint`-typed `Fn`. Same
// posture as `curve` above: `#[doc(hidden)]`, internal low-level arithmetic, not
// public API / not SemVer-covered, kept `pub` only for in-repo dev crates.
#[doc(hidden)]
pub mod scalar_mul;
pub mod sign;
pub mod verify;

// Re-export of the internal `crypto-bigint`-typed curve types; `#[doc(hidden)]`
// so the re-export does not re-expose them in the public API (see `mod curve`).
#[doc(hidden)]
pub use curve::{Fn, Fp};
pub use decrypt::decrypt;
pub use encrypt::encrypt;
// Re-export of the internal low-level curve point; `#[doc(hidden)]` (see
// `mod point`) — not public API / not SemVer; internal low-level curve point.
#[doc(hidden)]
pub use point::ProjectivePoint;
pub use private_key::Sm2PrivateKey;
pub use public_key::Sm2PublicKey;
// Re-export of the internal low-level scalar-mult fns; `#[doc(hidden)]` (see
// `mod scalar_mul`).
#[doc(hidden)]
pub use scalar_mul::{mul_g, mul_var};
pub use sign::{DEFAULT_SIGNER_ID, compute_z, sign_raw_with_id, sign_with_id};
pub use verify::verify_with_id;

/// SM2 module error — alias for the workspace-wide [`crate::Error`].
///
/// Prior to v0.5 each operation had its own per-module enum
/// (`SignError`, `EncryptError`, `DecryptError`) all with a single
/// `Failed` variant. v0.5 W5 collapses them into one type; migration
/// recipe is `s/SignError/sm2::Error/g`, `s/EncryptError/sm2::Error/g`,
/// `s/DecryptError/sm2::Error/g` (or use the workspace-wide path
/// `gmcrypto_core::Error` directly). The workspace-wide type is
/// `#[non_exhaustive]`, so exhaustive `match` arms must add `_ => ...`.
pub type Error = crate::Error;
