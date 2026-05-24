//! Fuzz target: `verify_with_id` with a FIXED public key. The DER signature
//! is attacker-controlled (id + message fixed to match the valid seed:
//! DEFAULT_SIGNER_ID + empty message). Fuzzes the DER signature parse +
//! verify path. Invariant: returns `bool` — never panics.
#![no_main]

use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey, DEFAULT_SIGNER_ID};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Fixed valid private scalar (matches the seed generator).
const FIXED_D: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
];

fn fixed_pub() -> &'static Sm2PublicKey {
    static P: OnceLock<Sm2PublicKey> = OnceLock::new();
    P.get_or_init(|| {
        let priv_key: Sm2PrivateKey =
            Option::from(Sm2PrivateKey::from_bytes_be(&FIXED_D)).unwrap();
        Sm2PublicKey::from_point(priv_key.public_key())
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::sm2::verify_with_id(fixed_pub(), DEFAULT_SIGNER_ID, b"", data);
});
