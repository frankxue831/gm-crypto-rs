//! v0.21 — existence pins for the `#[doc(hidden)] pub` items that are NOT part
//! of the public API but ARE consumed internally: `sign_raw_with_id` by the
//! in-repo dudect timing-leak harness, and `Sm4Cbc{Encryptor,Decryptor}::
//! take_output` by the `gmcrypto-c` FFI shim. These are explicitly **not covered
//! by `SemVer`** (see `docs/v0.21-scope.md` Q21.4). This test is not an endorsement
//! of public use — it only guards against a refactor silently dropping a hook an
//! internal consumer depends on.

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
