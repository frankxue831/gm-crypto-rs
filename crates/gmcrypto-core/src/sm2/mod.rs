//! SM2 elliptic curve cryptography (GB/T 32918-2017).

pub mod curve;
pub mod point;
pub mod scalar_mul;

pub use curve::{Fn, Fp};
pub use point::ProjectivePoint;
pub use scalar_mul::{mul_g, mul_var};
