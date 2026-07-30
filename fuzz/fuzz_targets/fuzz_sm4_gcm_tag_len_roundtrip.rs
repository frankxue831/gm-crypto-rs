//! Fuzz target: SM4-GCM **truncated-tag** round-trip across all seven
//! NIST-permitted tag lengths (`mode_gcm::{encrypt_with_tag_len,
//! decrypt_with_tag_len}`, NIST SP 800-38D §5.2.1.2).
//!
//! # What was actually missing
//!
//! `decrypt_with_tag_len` was already fuzzed — `fuzz_sm4_gcm_decrypt` drives it
//! with an adversarial `tl % 19` tag, covering valid *and* invalid lengths. The
//! real gaps are that **`encrypt_with_tag_len` is reachable from no target at
//! all**, and that **no target round-trips at a truncated length**.
//!
//! # Invariants, and which of them can actually fail
//!
//! 1. **No panic** on either call.
//! 2. **Round-trip** — `decrypt_with_tag_len` recovers the plaintext from what
//!    `encrypt_with_tag_len` produced. **This is the one that carries the
//!    value.** The two functions do not share an implementation:
//!    `encrypt_with_tag_len` delegates to `encrypt` and truncates, whereas
//!    `decrypt_with_tag_len` recomputes `h`, `J0`, GHASH and GCTR itself and
//!    compares only the first `t` bytes. So a round-trip crosses two
//!    independent code paths and a divergence between them is a real bug.
//! 3. **Delegation contract** — the ciphertext is tag-length-independent, and
//!    the truncated tag equals `full_tag[..t]`. **These are tautologies of the
//!    current implementation** (it literally truncates `encrypt`'s output), so
//!    the fuzzer cannot falsify them today. They are kept deliberately, as a
//!    pin against a future rewrite that computes the short tag separately —
//!    but labelled, so nobody reads them as evidence of anything now.
//!
//! # What is deliberately NOT asserted
//!
//! "A tag valid at length `t` must not verify at some `t' < t`." It **would**
//! verify: the recomputed expected tag truncated to `t'` equals `tag[..t']` by
//! construction. That is a known property of truncated-tag GCM, not a bug.
//! Asserting it would produce a target that fails on correct code, so it is
//! recorded here to stop a future reader from "fixing" this target by adding it.
//!
//! # Layout
//!
//! `[key:16][nonce_len:1][nonce][aad_len:1][aad][tag_sel:1][plaintext:rest]`
//!
//! Manual slicing, no `arbitrary::Unstructured` — matching the sibling
//! `fuzz_sm4_gcm_encrypt`, so a seed stays a plain byte concatenation.
#![no_main]

use gmcrypto_core::sm4::mode_gcm::{self, GcmTagLen};
use gmcrypto_core::sm4::KEY_SIZE;
use libfuzzer_sys::fuzz_target;

/// The NIST SP 800-38D §5.2.1.2 permitted set, in `GcmTagLen::new` order.
const TAG_LENS: [usize; 7] = [4, 8, 12, 13, 14, 15, 16];

fuzz_target!(|data: &[u8]| {
    if data.len() < KEY_SIZE + 1 {
        return;
    }
    let key: [u8; KEY_SIZE] = data[..KEY_SIZE].try_into().unwrap();
    let mut rest = &data[KEY_SIZE..];

    let nlen = rest[0] as usize;
    rest = &rest[1..];
    if rest.len() < nlen {
        return;
    }
    let nonce = &rest[..nlen];
    rest = &rest[nlen..];

    if rest.is_empty() {
        return;
    }
    let alen = rest[0] as usize;
    rest = &rest[1..];
    if rest.len() < alen {
        return;
    }
    let aad = &rest[..alen];
    rest = &rest[alen..];

    if rest.is_empty() {
        return;
    }
    let t = TAG_LENS[rest[0] as usize % TAG_LENS.len()];
    let pt = &rest[1..];

    let tag_len = GcmTagLen::new(t).expect("TAG_LENS holds only permitted lengths");

    // None here means the parameters were out of range (e.g. plaintext past the
    // GCTR ceiling); nothing to compare against.
    let Some((ct, tag)) = mode_gcm::encrypt_with_tag_len(&key, nonce, aad, pt, tag_len) else {
        return;
    };

    assert_eq!(
        tag.len(),
        t,
        "encrypt_with_tag_len returned the wrong tag length"
    );

    // (2) The load-bearing invariant: two independent implementations agree.
    let recovered = mode_gcm::decrypt_with_tag_len(&key, nonce, aad, &ct, &tag)
        .expect("truncated-tag decrypt of self-produced ciphertext must succeed");
    assert_eq!(
        recovered, pt,
        "SM4-GCM truncated-tag round-trip mismatch at tag_len={t}"
    );

    // (3) Delegation contract. Tautological today -- see the module docs.
    let (ct_full, tag_full) = mode_gcm::encrypt(&key, nonce, aad, pt)
        .expect("full-tag encrypt must accept the same params");
    assert_eq!(
        ct, ct_full,
        "ciphertext must not depend on tag_len (tag_len={t})"
    );
    assert_eq!(
        tag[..],
        tag_full[..t],
        "truncated tag must be the prefix of the full tag (tag_len={t})"
    );
});
