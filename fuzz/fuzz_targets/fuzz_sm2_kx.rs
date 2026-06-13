//! Fuzz target: SM2 key-exchange peer-input surfaces with FIXED static keys
//! and a FIXED ephemeral — the peer's `R_B` (65 B) and `S_B` (32 B) are
//! attacker-controlled wire bytes, carved FRONT-consuming (R then S) so
//! seeds are plain concatenations (the arbitrary-1.4.2 pin convention).
//! Three paths run on EVERY input (no dispatch byte, no seed-format
//! change): the v1.1 initiator `confirm`, the v1.6 initiator
//! `derive_without_key_confirmation` (same `R_B` bytes), and the v1.6
//! responder `respond_without_key_confirmation` (the same 65 bytes as an
//! adversarial `R_A`). Invariant: any input returns `Ok`/`Err` (single
//! `Failed`) — never panics, never OOMs, never hangs.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm2::key_exchange::{
    Sm2KxConfirm, Sm2KxEphemeralPoint, Sm2KxInitiator, Sm2KxResponder,
};
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

/// Deterministic `TryCryptoRng` for the fixed ephemerals.
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

type Statics = (
    Sm2PrivateKey,
    gmcrypto_core::sm2::Sm2PublicKey,
    Sm2PrivateKey,
    gmcrypto_core::sm2::Sm2PublicKey,
);

/// `(d_A, P_B, d_B, P_A)` — both parties' statics, built once (the
/// responder pair was hoisted in v1.6 so the per-exec cost stays flat).
fn fixed_keys() -> &'static Statics {
    static K: OnceLock<Statics> = OnceLock::new();
    K.get_or_init(|| {
        let da: Sm2PrivateKey = Option::from(Sm2PrivateKey::from_bytes_be(&FIXED_D_A)).unwrap();
        let db: Sm2PrivateKey = Option::from(Sm2PrivateKey::from_bytes_be(&FIXED_D_B)).unwrap();
        let pa = da.public_key();
        let pb = db.public_key();
        (da, pb, db, pa)
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
    let (da, pb, db, pa) = fixed_keys();

    // Path 1 (v1.1): confirmed-flow initiator against adversarial (R_B, S_B).
    let init = Sm2KxInitiator::new(da, pb, b"a", b"b", 16).expect("fixed params are valid");
    let (_ra, iw) = init
        .produce_ephemeral(&mut FixedRng)
        .expect("fixed ephemeral is valid");
    let _ = iw.confirm(
        &Sm2KxEphemeralPoint::from_bytes(&r_bytes),
        &Sm2KxConfirm::from_bytes(&s_bytes),
    );

    // Path 2 (v1.6): no-confirmation initiator, same adversarial R_B.
    let init = Sm2KxInitiator::new(da, pb, b"a", b"b", 16).expect("fixed params are valid");
    let (_ra, iw) = init
        .produce_ephemeral(&mut FixedRng)
        .expect("fixed ephemeral is valid");
    let _ = iw.derive_without_key_confirmation(&Sm2KxEphemeralPoint::from_bytes(&r_bytes));

    // Path 3 (v1.6): no-confirmation responder — the same 65 bytes as an
    // adversarial R_A.
    let resp = Sm2KxResponder::new(db, pa, b"a", b"b", 16).expect("fixed params are valid");
    let _ = resp.respond_without_key_confirmation(
        &Sm2KxEphemeralPoint::from_bytes(&r_bytes),
        &mut FixedRng,
    );
});
