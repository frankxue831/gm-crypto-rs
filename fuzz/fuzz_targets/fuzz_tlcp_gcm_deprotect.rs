//! Fuzz target: `tlcp::record::deprotect_gcm` (SM4-GCM record deprotect,
//! RFC 5288 shape).
//! Layout (front-to-back): [key_block:40][seq:8][record:rest]. The
//! per-direction keys are carved via `client_half`; `record` is the
//! adversarial wire body (`explicit_nonce(8) ‖ ct ‖ tag(16)`).
//! Invariant: any input returns `Some`/`None` (commit-on-verify) — never
//! panics / OOMs / hangs.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::tlcp::record::{RecordKeysGcm, TLCP_RECORD_VERSION, deprotect_gcm};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let kb: [u8; 40] = u.arbitrary().unwrap_or([0u8; 40]);
    let seq: u64 = u.arbitrary().unwrap_or(0);
    let keys = RecordKeysGcm::client_half(&kb);
    let record = u.take_rest();
    let _ = deprotect_gcm(&keys, seq, 0x17, TLCP_RECORD_VERSION, record);
});
