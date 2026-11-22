//! Fuzz target: `Sm2PublicKey::from_sec1_bytes` (65-byte uncompressed `0x04 ‖ X ‖ Y`)
//! and `Sm2PublicKey::from_sec1_compressed` (33-byte compressed `0x02/0x03 ‖ X`).
//!
//! Invariant: neither decoder panics on any byte sequence; every accepted compressed
//! point re-encodes byte-identically to the input, round-trips through uncompressed
//! SEC1, and is rejected by `from_sec1_bytes` (and vice versa).
#![no_main]

use gmcrypto_core::sm2::Sm2PublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(pk) = Sm2PublicKey::from_sec1_compressed(data) {
        assert_eq!(pk.to_sec1_compressed().as_slice(), data);
        let uncompressed = pk.to_sec1_uncompressed();
        let via_uncompressed =
            Sm2PublicKey::from_sec1_bytes(&uncompressed).expect("compressed must round-trip");
        assert_eq!(via_uncompressed.to_sec1_compressed().as_slice(), data);
        assert!(Sm2PublicKey::from_sec1_bytes(data).is_none());
    }
    if let Some(pk) = Sm2PublicKey::from_sec1_bytes(data) {
        assert_eq!(pk.to_sec1_uncompressed().as_slice(), data);
        let compressed = pk.to_sec1_compressed();
        let via_compressed =
            Sm2PublicKey::from_sec1_compressed(&compressed).expect("uncompressed must round-trip");
        assert_eq!(via_compressed.to_sec1_uncompressed().as_slice(), data);
        assert!(Sm2PublicKey::from_sec1_compressed(data).is_none());
    }
});
