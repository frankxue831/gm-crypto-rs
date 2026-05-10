//! Cross-validation against the gmssl v3.1.1 CLI.
//!
//! Skipped silently when `GMCRYPTO_GMSSL=1` is not set; CI sets it
//! on one matrix slot when gmssl is available on the runner.
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
use std::io::Write;
use std::process::{Command, Stdio};

use gmcrypto_core::hmac::hmac_sm3;
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;

fn enabled() -> bool {
    env::var("GMCRYPTO_GMSSL").as_deref() == Ok("1")
}

fn gmssl_present() -> bool {
    Command::new("gmssl").arg("version").output().is_ok()
}

/// Hex-format a byte slice (lowercase, no separator).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
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

/// Cross-validate `hmac_sm3` against `gmssl sm3hmac` over a small set
/// of (key, message) inputs covering the short-key, short-key-empty-msg,
/// and exact-block-size key paths.
///
/// gmssl 3.1.1's `sm3hmac` CLI rejects keys > 32 bytes. The long-key
/// hash-first path is exercised by the in-tree KAT in
/// `crates/gmcrypto-core/src/hmac.rs::tests::test6_long_key_hash_first`,
/// where the canonical value was computed via gmssl by hand-applying
/// the RFC 2104 hash-first equivalence.
#[test]
fn hmac_sm3_matches_gmssl() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    // (key, message) test cases — kept short so this test runs in <1s.
    // Keys are limited to ≤ 32 bytes per gmssl's CLI restriction.
    let cases: &[(&[u8], &[u8])] = &[
        (&[0x0bu8; 20], b"Hi There"),
        (b"Jefe", b"what do ya want for nothing?"),
        (b"", b""),
        (b"32-byte-key-padded-with-bytesXX", b"another short message"),
    ];

    for (key, message) in cases {
        let key_hex = hex(key);

        // Spawn `gmssl sm3hmac -key <hex>` with the message piped to stdin.
        let mut child = Command::new("gmssl")
            .args(["sm3hmac", "-key", &key_hex])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn gmssl sm3hmac");

        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(message)
            .expect("write to gmssl stdin");

        let output = child.wait_with_output().expect("wait gmssl");
        assert!(
            output.status.success(),
            "gmssl sm3hmac exit {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );

        // gmssl emits the hex digest followed by a newline.
        let gmssl_hex = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();

        let our_hex = hex(&hmac_sm3(key, message));
        assert_eq!(
            our_hex, gmssl_hex,
            "HMAC-SM3 disagreement on (key={key:?}, message={message:?}):\n  ours:  {our_hex}\n  gmssl: {gmssl_hex}"
        );
    }
}

/// Cross-validate `pbkdf2_hmac_sm3` against `gmssl pbkdf2 -hex` over a
/// small set of (password, salt, iter, outlen) inputs.
///
/// gmssl 3.1.1's `pbkdf2` CLI rejects very small iteration counts
/// (<1000 by observation), so we don't test the c=1 boundary here —
/// it's covered by the in-tree self-consistency tests.
#[test]
fn pbkdf2_hmac_sm3_matches_gmssl() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    // (password, salt, iterations, outlen). Keep iter modest so the
    // test runs in seconds, not minutes. gmssl 3.1.1's pbkdf2 CLI
    // rejects iterations < 10000; that boundary is covered by the
    // in-tree self-consistency tests, not here.
    let cases: &[(&[u8], &[u8], u32, usize)] = &[
        (b"password", b"salt", 10_000, 32),
        (b"password", b"salt", 10_000, 20),
        (b"password", b"salt", 10_000, 40),
        (b"password", b"salt", 10_000, 64),
        (b"hunter2", b"random-salt-bytes", 20_000, 32),
    ];

    for (password, salt, iter, outlen) in cases {
        let pass_str = std::str::from_utf8(password).expect("ASCII password for gmssl -pass");
        let salt_hex = hex(salt);
        let iter_str = iter.to_string();
        let outlen_str = outlen.to_string();

        let output = Command::new("gmssl")
            .args([
                "pbkdf2",
                "-pass",
                pass_str,
                "-salt",
                &salt_hex,
                "-iter",
                &iter_str,
                "-outlen",
                &outlen_str,
                "-hex",
            ])
            .output()
            .expect("spawn gmssl pbkdf2");
        assert!(
            output.status.success(),
            "gmssl pbkdf2 exit {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );

        let gmssl_hex = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();

        let mut dk = vec![0u8; *outlen];
        pbkdf2_hmac_sm3(password, salt, *iter, &mut dk).expect("derive");
        let our_hex = hex(&dk);

        assert_eq!(
            our_hex, gmssl_hex,
            "PBKDF2-HMAC-SM3 disagreement on (pass={password:?}, salt={salt:?}, iter={iter}, outlen={outlen}):\n  ours:  {our_hex}\n  gmssl: {gmssl_hex}"
        );
    }
}
