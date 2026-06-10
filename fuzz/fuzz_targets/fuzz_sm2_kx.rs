//! Fuzz target: SM2 key-exchange initiator `confirm` with FIXED static keys
//! and a FIXED ephemeral — the peer's `R_B` (65 B) and `S_B` (32 B) are
//! attacker-controlled wire bytes, carved FRONT-consuming (R then S) so
//! seeds are plain concatenations (the arbitrary-1.4.2 pin convention).
//! Invariant: any input returns `Ok`/`Err` (single `Failed`) — never
//! panics, never OOMs, never hangs.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm2::key_exchange::{Sm2KxConfirm, Sm2KxEphemeralPoint, Sm2KxInitiator};
use gmcrypto_core::sm2::Sm2PrivateKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Fixed valid private scalars (match the seed generator recipe in
// fuzz/README.md).
const FIXED_D_A: [u8; 32] = [0x11; 32];
const FIXED_D_B: [u8; 32] = [0x22; 32];
// Fixed initiator ephemeral fill byte (every draw returns 0x5A bytes; the
// sampler keeps the first valid draw, so r_A is the constant itself).
const EPH_FILL: u8 = 0x5A;

/// Deterministic `TryCryptoRng` for the fixed initiator ephemeral.
struct FixedRng;

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(EPH_FILL);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for FixedRng {}

fn fixed_keys() -> &'static (Sm2PrivateKey, gmcrypto_core::sm2::Sm2PublicKey) {
    static K: OnceLock<(Sm2PrivateKey, gmcrypto_core::sm2::Sm2PublicKey)> = OnceLock::new();
    K.get_or_init(|| {
        let da = Option::from(Sm2PrivateKey::from_bytes_be(&FIXED_D_A)).unwrap();
        let db: Sm2PrivateKey = Option::from(Sm2PrivateKey::from_bytes_be(&FIXED_D_B)).unwrap();
        let pb = db.public_key();
        (da, pb)
    })
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(r_bytes) = u.arbitrary::<[u8; 65]>() else {
        return;
    };
    let Ok(s_bytes) = u.arbitrary::<[u8; 32]>() else {
        return;
    };
    let (da, pb) = fixed_keys();
    let init = Sm2KxInitiator::new(da, pb, b"a", b"b", 16).expect("fixed params are valid");
    let (_ra, iw) = init
        .produce_ephemeral(&mut FixedRng)
        .expect("fixed ephemeral is valid");
    let _ = iw.confirm(
        &Sm2KxEphemeralPoint::from_bytes(&r_bytes),
        &Sm2KxConfirm::from_bytes(&s_bytes),
    );
});
