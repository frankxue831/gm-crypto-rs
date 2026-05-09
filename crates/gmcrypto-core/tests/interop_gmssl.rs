//! Cross-validation against the gmssl v3.1.1 CLI.
//!
//! Mirrors the Java SDK's `UpstreamCliCrossValidationTest`. Skipped
//! silently when `GMCRYPTO_GMSSL=1` is not set; CI sets it on one
//! matrix slot.
//!
//! # v0.1 scope reduction
//!
//! The headline goal — bidirectional Rust↔gmssl signature interop —
//! requires either:
//!
//! 1. Rust loading gmssl's PKCS#8 (encoded EC private key), or
//! 2. gmssl loading Rust's raw EC public key (which needs X.509 SPKI
//!    wrapping).
//!
//! Both routes need the ASN.1 wrappers that land in v0.3. So v0.1's
//! interop test is reduced to **binary reachability**: assert that
//! `gmssl version` produces non-empty output. This confirms the test
//! plumbing (env var gate, subprocess invocation, CI installation
//! recipe) is wired correctly so v0.3 can drop in the real interop
//! checks without scaffolding work.
//!
//! Bidirectional signature interop is tracked as a v0.3 deliverable.
//! See the v0.1 release notes for the full rationale.
//!
//! # Running
//!
//! ```text
//! cargo test --test interop_gmssl                  # skips silently
//! GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl # exercises gmssl
//! ```

use std::env;
use std::process::Command;

fn enabled() -> bool {
    env::var("GMCRYPTO_GMSSL").as_deref() == Ok("1")
}

fn gmssl_present() -> bool {
    Command::new("gmssl").arg("version").output().is_ok()
}

#[test]
fn gmssl_binary_reachable() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(
        gmssl_present(),
        "GMCRYPTO_GMSSL=1 set but `gmssl` is not on PATH"
    );

    let output = Command::new("gmssl")
        .arg("version")
        .output()
        .expect("spawn gmssl version");
    assert!(
        output.status.success(),
        "`gmssl version` exited with status {:?}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "`gmssl version` produced empty stdout"
    );
}
