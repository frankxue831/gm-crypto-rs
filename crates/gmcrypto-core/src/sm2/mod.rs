//! SM2 elliptic curve cryptography (GB/T 32918-2017).

pub mod curve;
pub mod point;
pub mod private_key;
pub mod public_key;
pub mod scalar_mul;
pub mod sign;

pub use curve::{Fn, Fp};
pub use point::ProjectivePoint;
pub use private_key::Sm2PrivateKey;
pub use public_key::Sm2PublicKey;
pub use scalar_mul::{mul_g, mul_var};
pub use sign::{compute_z, sign_with_id, SignError, DEFAULT_SIGNER_ID};
