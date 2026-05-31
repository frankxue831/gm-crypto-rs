//! v0.21 — existence pins for the `#[doc(hidden)] pub` items that are NOT part
//! of the public API but ARE consumed internally: `sign_raw_with_id` by the
//! in-repo dudect timing-leak harness, and `Sm4Cbc{Encryptor,Decryptor}::
//! take_output` by the `gmcrypto-c` FFI shim. These are explicitly **not covered
//! by `SemVer`** (see `docs/v0.21-scope.md` Q21.4). This test is not an endorsement
//! of public use — it only guards against a refactor silently dropping a hook an
//! internal consumer depends on.
//!
//! v0.22 — extends the same posture to the low-level SM2 curve arithmetic
//! surface (`docs/v0.22-scope.md` §3 Q22.3): `sm2::curve::{Fn, Fp, b, b3}`,
//! `sm2::scalar_mul::{mul_g, mul_var}` (+ the `sm2` re-exports), and
//! `ProjectivePoint::to_affine`. These were made `#[doc(hidden)]` (kept `pub`)
//! so the stable 1.0 public API names no `crypto-bigint` types; the in-repo
//! dudect bench, integration tests, and fuzz targets still reach them
//! cross-crate, so this pins their continued existence.

use getrandom::SysRng;
use gmcrypto_core::sm2::{DEFAULT_SIGNER_ID, Sm2PrivateKey, sign_raw_with_id};
use gmcrypto_core::sm4::{Sm4CbcDecryptor, Sm4CbcEncryptor};
use rand_core::UnwrapErr;

#[test]
fn sign_raw_with_id_exists() {
    let key = Sm2PrivateKey::from_bytes_be(&[0x11; 32])
        .into_option()
        .expect("0x11..11 is a valid SM2 scalar");
    let mut rng = UnwrapErr(SysRng);
    // The #[doc(hidden)] raw signer the dudect harness targets must stay
    // callable and return the un-DER-encoded (r, s) pair.
    let pair = sign_raw_with_id(&key, DEFAULT_SIGNER_ID, b"v0.21 existence probe", &mut rng);
    assert!(pair.is_ok());
}

#[test]
fn cbc_take_output_drains_exist() {
    let key = [0x22u8; 16];
    let iv = [0x33u8; 16];

    // Encryptor drain — the FFI shim emits ciphertext incrementally as `update`
    // produces full blocks.
    let mut enc = Sm4CbcEncryptor::new(&key, &iv);
    enc.update(&[0u8; 32]);
    let emitted = enc.take_output();
    assert_eq!(emitted.len() % 16, 0);

    // Decryptor drain — emits all decrypted blocks EXCEPT the held-back
    // final-candidate block (buffer-back-by-one preserved across the call).
    let mut dec = Sm4CbcDecryptor::new(&key, &iv);
    dec.update(&emitted);
    let _so_far = dec.take_output();
}

#[test]
fn group_a_low_level_curve_surface_exists() {
    // v0.22 — the low-level SM2 curve arithmetic is `#[doc(hidden)]` (kept `pub`)
    // so the stable 1.0 public API names no `crypto-bigint` types. These items
    // are NOT public API / NOT covered by SemVer, but the in-repo dudect bench,
    // integration tests, and fuzz targets reach them cross-crate, so they must
    // stay callable. Each `const _: <sig> = <path>;` is a compile-time existence +
    // signature assertion (no `crypto-bigint` value is constructed).
    use gmcrypto_core::sm2::curve::{Fn, Fp};
    use gmcrypto_core::sm2::point::ProjectivePoint;

    // Curve constants `b` / `b3` (return the hidden `Fp`).
    const _: fn() -> Fp = gmcrypto_core::sm2::curve::b;
    const _: fn() -> Fp = gmcrypto_core::sm2::curve::b3;

    // Scalar multiplication over the hidden scalar type `Fn`.
    const _: fn(&Fn) -> ProjectivePoint = gmcrypto_core::sm2::scalar_mul::mul_g;
    const _: fn(&Fn, &ProjectivePoint) -> ProjectivePoint = gmcrypto_core::sm2::scalar_mul::mul_var;

    // The `sm2`-level re-exports of the same hidden items stay reachable.
    const _: fn(&Fn) -> ProjectivePoint = gmcrypto_core::sm2::mul_g;
    const _: fn(&Fn, &ProjectivePoint) -> ProjectivePoint = gmcrypto_core::sm2::mul_var;

    // `ProjectivePoint::to_affine` returns the hidden `Fp` pair.
    const _: fn(&ProjectivePoint) -> Option<(Fp, Fp)> = ProjectivePoint::to_affine;

    // Runtime smoke: `to_affine` on the generator is finite.
    let affine = ProjectivePoint::generator().to_affine();
    assert!(affine.is_some(), "generator is finite");
}
