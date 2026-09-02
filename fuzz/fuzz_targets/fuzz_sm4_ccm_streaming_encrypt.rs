//! Fuzz target: SM4-CCM length-committed streaming encryptor
//! (`Sm4CcmEncryptor`) — DIFFERENTIAL against single-shot
//! `mode_ccm::encrypt`, plus the over-feed / under-feed arms (v1.12 Q12.9).
//!
//! Layout (front-consuming):
//! `[key:16][tl:1][nl:1][nonce:nl'][al:1][aad:al'][chunk:1][mode:1][pt:rest]`
//! with `tl' = tl % 18`, `nl' = nl % 17`, `al' = al % 33`, chunks of
//! `max(1, chunk)`, and `mode % 3` selecting the DECLARED length
//! independently of the bytes fed — the GCM encrypt template sets fed
//! length = remaining bytes, so its over-/under-feed arms can never fire:
//!
//! - `0` exact: `plaintext_len = pt.len()`. Whenever the single-shot accepts
//!   the parameters the streaming `ct ‖ tag` must byte-equal it and
//!   `mode_ccm::decrypt` must round-trip; parameter acceptance must agree.
//! - `1` under-feed: `plaintext_len = pt.len() + 1 + step`. Every `update`
//!   succeeds; `finalize` is `None`.
//! - `2` over-feed: `plaintext_len = pt.len() − 1 − step` (saturating,
//!   `pt` non-empty). The first overflowing `update` is `None` (emits
//!   nothing), every later call is `None`, `finalize` is `None`.
//!
//! Invariant: never panics.
#![no_main]

use arbitrary::Unstructured;
use gmcrypto_core::sm4::mode_ccm;
use gmcrypto_core::sm4::Sm4CcmEncryptor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key: [u8; 16] = u.arbitrary().unwrap_or([0u8; 16]);
    let tag_len = (u.arbitrary::<u8>().unwrap_or(0) % 18) as usize;
    let nl = (u.arbitrary::<u8>().unwrap_or(0) % 17) as usize;
    let nonce = match u.bytes(nl) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let al = (u.arbitrary::<u8>().unwrap_or(0) % 33) as usize;
    let aad = match u.bytes(al) {
        Ok(b) => b.to_vec(),
        Err(_) => return,
    };
    let step = (u.arbitrary::<u8>().unwrap_or(0) as usize).max(1);
    let mode = u.arbitrary::<u8>().unwrap_or(0) % 3;
    let pt = u.take_rest();

    match mode {
        0 => {
            let want = mode_ccm::encrypt(&key, &nonce, &aad, pt, tag_len);
            let enc = Sm4CcmEncryptor::new(&key, &nonce, &aad, pt.len(), tag_len);
            match (want, enc) {
                (None, None) => {}
                (Some(want), Some(mut enc)) => {
                    let mut got = Vec::with_capacity(want.len());
                    for c in pt.chunks(step) {
                        got.extend_from_slice(
                            &enc.update(c).expect("within declared length must succeed"),
                        );
                    }
                    got.extend_from_slice(
                        &enc.finalize()
                            .expect("declared length fed exactly must finalize"),
                    );
                    assert_eq!(
                        got, want,
                        "SM4-CCM streaming ct||tag diverged from single-shot"
                    );
                    let back = mode_ccm::decrypt(&key, &nonce, &aad, &want, tag_len)
                        .expect("decrypt of self-produced ct||tag must verify");
                    assert_eq!(back, pt, "SM4-CCM encrypt->decrypt round-trip mismatch");
                }
                (w, e) => panic!(
                    "parameter acceptance diverged: single-shot={} streaming={}",
                    w.is_some(),
                    e.is_some()
                ),
            }
        }
        1 => {
            let Some(declared) = pt.len().checked_add(1 + step) else {
                return;
            };
            let Some(mut enc) = Sm4CcmEncryptor::new(&key, &nonce, &aad, declared, tag_len) else {
                return;
            };
            for c in pt.chunks(step) {
                assert!(
                    enc.update(c).is_some(),
                    "under-declared feed must be accepted"
                );
            }
            assert!(enc.finalize().is_none(), "under-fed finalize must be None");
        }
        _ => {
            if pt.is_empty() {
                return;
            }
            let declared = pt.len().saturating_sub(1 + step);
            let Some(mut enc) = Sm4CcmEncryptor::new(&key, &nonce, &aad, declared, tag_len) else {
                return;
            };
            let mut fed = 0usize;
            let mut poisoned = false;
            for c in pt.chunks(step) {
                let r = enc.update(c);
                if poisoned {
                    assert!(r.is_none(), "poisoned encryptor must keep returning None");
                } else if fed + c.len() > declared {
                    assert!(r.is_none(), "over-feed must be rejected whole");
                    poisoned = true;
                } else {
                    let out = r.expect("within declared length must succeed");
                    assert_eq!(out.len(), c.len());
                    fed += c.len();
                }
            }
            assert!(poisoned, "declared < pt.len() must have tripped the bound");
            assert!(
                enc.finalize().is_none(),
                "finalize after poison must be None"
            );
        }
    }
});
