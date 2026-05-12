//! SM2 elliptic curve cryptography (GB/T 32918-2017).

pub(crate) mod comb_table;
pub mod curve;
pub mod decrypt;
pub mod encrypt;
pub mod point;
pub mod private_key;
pub mod public_key;
pub mod raw_ciphertext;
pub mod scalar_mul;
pub mod sign;
pub mod verify;

pub use curve::{Fn, Fp};
pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use point::ProjectivePoint;
pub use private_key::Sm2PrivateKey;
pub use public_key::Sm2PublicKey;
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
