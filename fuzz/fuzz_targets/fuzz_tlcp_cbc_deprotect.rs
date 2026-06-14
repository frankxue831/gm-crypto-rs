//! Fuzz target: `tlcp::record::deprotect_cbc` (the Lucky13-hardened SM4-CBC
//! record deprotect).
//! Layout (front-to-back): [key_block:128][seq:8][record:rest]. The
//! per-direction keys are carved via `client_half`; `record` is the
//! adversarial wire body (`explicit_IV(16) ‖ CBC_ct`).
//! Invariant: any input returns `Some`/`None` (single `None` — no padding
//! oracle, no plaintext on failure) — never panics / OOMs / hangs.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::tlcp::record::{RecordKeysCbc, TLCP_RECORD_VERSION, deprotect_cbc};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let kb: [u8; 128] = u.arbitrary().unwrap_or([0u8; 128]);
    let seq: u64 = u.arbitrary().unwrap_or(0);
    let keys = RecordKeysCbc::client_half(&kb);
    let record = u.take_rest();
    let _ = deprotect_cbc(&keys, seq, 0x17, TLCP_RECORD_VERSION, record);
});
