//! Fuzz target: `sm2::decrypt` with a FIXED private key (composite: DER
//! ciphertext parse + KDF + constant-time MAC). The DER ciphertext is
//! attacker-controlled. Exercises the allocate-from-parsed-length path.
//! Invariant: any input returns `Ok`/`Err` (single `Failed`) — never panics.
#![no_main]

use gmcrypto_core::sm2::Sm2PrivateKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Fixed valid private scalar (matches the seed generator).
const FIXED_D: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
];

fn fixed_priv() -> &'static Sm2PrivateKey {
    static K: OnceLock<Sm2PrivateKey> = OnceLock::new();
    K.get_or_init(|| Option::from(Sm2PrivateKey::from_bytes_be(&FIXED_D)).unwrap())
}

fuzz_target!(|data: &[u8]| {
    let _ = gmcrypto_core::sm2::decrypt(fixed_priv(), data);
});
