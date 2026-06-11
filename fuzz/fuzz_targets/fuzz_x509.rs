//! Fuzz target: X.509-with-SM2 certificate decode + verify (v1.3).
//!
//! `Certificate::from_der` over arbitrary bytes; on a successful parse,
//! both verify entry points run against a fixed public key and every
//! accessor is exercised. Invariant: no panic / no OOM / no hang — every
//! malformed input collapses to the single safe `None` (and a parsed
//! certificate's verify is a plain `bool`). Seeds are the two committed
//! gmssl KAT fixtures, so the success path (including real extensions and
//! a real signature BIT STRING) is exercised from the first run.
#![no_main]

use gmcrypto_core::sm2::{Sm2PrivateKey, Sm2PublicKey};
use gmcrypto_core::x509::Certificate;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn fixed_pub() -> &'static Sm2PublicKey {
    static K: OnceLock<Sm2PublicKey> = OnceLock::new();
    K.get_or_init(|| {
        let d: Sm2PrivateKey =
            Option::from(Sm2PrivateKey::from_bytes_be(&[0x11; 32])).expect("valid scalar");
        d.public_key()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Some(cert) = Certificate::from_der(data) {
        let _ = cert.verify_signature(fixed_pub());
        let _ = cert.verify_signature_with_id(fixed_pub(), b"fuzz-id");
        let _ = (
            cert.tbs_raw().len(),
            cert.serial_raw().len(),
            cert.issuer_raw().len(),
            cert.subject_raw().len(),
            cert.extensions_raw().map(<[u8]>::len),
            cert.not_before(),
            cert.not_after(),
            cert.is_self_issued(),
            cert.subject_public_key(),
        );
    }
});
