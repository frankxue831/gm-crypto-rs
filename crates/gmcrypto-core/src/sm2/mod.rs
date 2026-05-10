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
pub use decrypt::{DecryptError, decrypt};
pub use encrypt::{EncryptError, encrypt};
pub use point::ProjectivePoint;
pub use private_key::Sm2PrivateKey;
pub use public_key::Sm2PublicKey;
pub use scalar_mul::{mul_g, mul_var};
pub use sign::{DEFAULT_SIGNER_ID, SignError, compute_z, sign_raw_with_id, sign_with_id};
pub use verify::verify_with_id;
