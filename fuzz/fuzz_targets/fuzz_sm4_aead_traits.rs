//! Fuzz target: the v1.11 `RustCrypto` `aead` 0.6 trait path must be
//! byte-identical to the inherent `mode_gcm` / `mode_ccm` path.
//!
//! # What this is actually testing
//!
//! The trait impls are *supposed* to be thin wrappers, and that thinness is
//! load-bearing beyond tidiness: it is the entire argument for why v1.11 adds
//! **no dudect target** (the secret-touching bodies behind `ct_sm4_gcm_decrypt`
//! / `ct_sm4_ccm_decrypt` are the same code on both paths). A divergence found
//! here would not merely be a wrapper bug — it would invalidate that assurance
//! claim. So this target is the guard on the premise, not a coverage checkbox.
//!
//! The wrappers are not *pure* delegation, which is why fuzzing them is worth
//! anything at all:
//!
//! - **CCM** splits the inherent `ct‖tag` output at `len − tag_len` on encrypt
//!   and rejoins it on decrypt. Off-by-one there is a real, reachable bug, and
//!   it is arithmetic on attacker-influenced lengths.
//! - **GCM** copies through an `InOutBuf` whose in-half and out-half must have
//!   equal length; a mismatch panics inside `copy_from_slice`.
//! - Both run through `Aead`'s blanket impl over `AeadInOut`, so the postfix
//!   tag concatenation/splitting is `aead`'s code driven by our `TAG_POSITION`.
//!
//! Both ciphers are driven on **every** input rather than behind a dispatch
//! byte (the `fuzz_sm2_kx` pattern): one corpus unit exercises both paths, and
//! seeds stay plain byte concatenations.
//!
//! # Invariants
//!
//! 1. **No panic** anywhere on the trait path.
//! 2. **Encrypt agreement** — `Aead::encrypt` output equals the inherent
//!    `ct‖tag`, byte for byte. This is the load-bearing one.
//! 3. **Round-trip** — `Aead::decrypt` recovers the plaintext from that output.
//! 4. **Failure agreement** — where the inherent call returns `None`, the trait
//!    call must return `Err`, and vice versa. A wrapper that succeeded where the
//!    core refused (or the reverse) would be a contract break even if no byte
//!    ever differed.
//!
//! # Layout
//!
//! `[key:16][nonce:12][aad_len:1][aad][plaintext:rest]`
//!
//! Both cipher types are pinned to a 12-byte nonce and a 16-byte tag (the
//! canonical `Sm4Gcm` profile and the default `Sm4Ccm` parameters), so one
//! nonce field serves both. Manual slicing, no `arbitrary::Unstructured` —
//! matching the sibling SM4 targets.
#![no_main]

use aead::{Aead, KeyInit, Payload};
use gmcrypto_core::sm4::KEY_SIZE;
use gmcrypto_core::sm4::{Sm4Ccm, Sm4Gcm, mode_ccm, mode_gcm};
use libfuzzer_sys::fuzz_target;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY_SIZE + NONCE_LEN + 1 {
        return;
    }
    let key: [u8; KEY_SIZE] = data[..KEY_SIZE].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = data[KEY_SIZE..KEY_SIZE + NONCE_LEN].try_into().unwrap();
    let mut rest = &data[KEY_SIZE + NONCE_LEN..];

    let alen = rest[0] as usize;
    rest = &rest[1..];
    if rest.len() < alen {
        return;
    }
    let aad = &rest[..alen];
    let pt = &rest[alen..];

    // ---------------------------------------------------------------- GCM
    let gcm = <Sm4Gcm as KeyInit>::new_from_slice(&key).expect("16-byte key");
    let native_gcm = mode_gcm::encrypt(&key, &nonce, aad, pt);
    let trait_gcm = Aead::encrypt(&gcm, &nonce.into(), Payload { msg: pt, aad });

    match (native_gcm, trait_gcm) {
        (Some((ct, tag)), Ok(wire)) => {
            let mut want = ct;
            want.extend_from_slice(&tag);
            assert_eq!(wire, want, "GCM: trait ct‖tag diverged from mode_gcm");

            let back = Aead::decrypt(&gcm, &nonce.into(), Payload { msg: &wire, aad })
                .expect("GCM: trait must decrypt its own output");
            assert_eq!(back, pt, "GCM: trait round-trip lost the plaintext");
        }
        (None, Err(_)) => {}
        (n, t) => panic!(
            "GCM: native and trait disagreed on success (native_some={}, trait_ok={})",
            n.is_some(),
            t.is_ok()
        ),
    }

    // ---------------------------------------------------------------- CCM
    let ccm = <Sm4Ccm as KeyInit>::new_from_slice(&key).expect("16-byte key");
    let native_ccm = mode_ccm::encrypt(&key, &nonce, aad, pt, TAG_LEN);
    let trait_ccm = Aead::encrypt(&ccm, &nonce.into(), Payload { msg: pt, aad });

    match (native_ccm, trait_ccm) {
        (Some(want), Ok(wire)) => {
            assert_eq!(wire, want, "CCM: trait ct‖tag diverged from mode_ccm");

            let back = Aead::decrypt(&ccm, &nonce.into(), Payload { msg: &wire, aad })
                .expect("CCM: trait must decrypt its own output");
            assert_eq!(back, pt, "CCM: trait round-trip lost the plaintext");
        }
        (None, Err(_)) => {}
        (n, t) => panic!(
            "CCM: native and trait disagreed on success (native_some={}, trait_ok={})",
            n.is_some(),
            t.is_ok()
        ),
    }
});
