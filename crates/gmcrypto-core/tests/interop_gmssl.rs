//! Cross-validation against the `GmSSL` 3.2.0 CLI.
//!
//! Skipped silently when `GMCRYPTO_GMSSL=1` is not set. CI prepares a pinned
//! `GmSSL` oracle, sets the flag, and treats an actual interoperability mismatch
//! as blocking. Oracle infrastructure failure remains visible but non-blocking
//! and prevents the suite from running rather than reporting an interop pass.
//!
//! # v0.3 scope (W3)
//!
//! Full bidirectional cross-validation now that v0.3 W2 ships the
//! PEM / PKCS#8 / SPKI codecs:
//!
//! - **HMAC-SM3** (v0.2): one-direction, gmssl→us digest comparison.
//! - **PBKDF2-HMAC-SM3** (v0.2): same, gmssl→us.
//! - **SM2 sign/verify** (v0.3 W3): bidirectional. gmssl signs / we
//!   verify. We sign / gmssl verifies.
//! - **SM2 encrypt/decrypt** (v0.3 W3): bidirectional. gmssl encrypts
//!   / we decrypt. We encrypt / gmssl decrypts. GM/T 0009 DER on the
//!   wire.
//! - **SM4-CBC** (v0.3 W3): bidirectional, caller-supplied IV.
//! - **SM4-CTR** (v0.7 W2): bidirectional, caller-supplied counter.
//!
//! v0.1 used a binary-reachability stub here while the wire-format
//! work was still pending; v0.3 is the version where the headline
//! interop bar finally clears.
//!
//! # Running
//!
//! ```text
//! cargo test --test interop_gmssl                  # skips silently
//! GMCRYPTO_GMSSL=1 cargo test --test interop_gmssl # exercises gmssl
//! ```

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gmcrypto_core::hmac::hmac_sm3;
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
use gmcrypto_core::{pem, pkcs8, sm2, sm4};

fn enabled() -> bool {
    env::var("GMCRYPTO_GMSSL").as_deref() == Ok("1")
}

fn gmssl_present() -> bool {
    Command::new("gmssl").arg("version").output().is_ok()
}

/// The `GmSSL` release this suite is pinned to.
///
/// CI builds exactly this tag from source. The pin is load-bearing, not
/// cosmetic: subcommand names and accepted input ranges move between
/// releases (3.2.0 renamed `pbkdf2` to `sm3_pbkdf2` and `sm4 -cbc` to
/// `sm4_cbc`, and narrowed `sm3hmac` keys to 12..=32 bytes), so an
/// unpinned oracle fails deep inside an unrelated test with a confusing
/// message instead of failing here with an accurate one.
const DEFAULT_GMSSL_VERSION: &str = "GmSSL 3.2.0";

/// Expected `gmssl version` first line, overridable via
/// `GMCRYPTO_GMSSL_VERSION` so a maintainer can deliberately probe a
/// different build without editing this file.
fn expected_gmssl_version() -> String {
    env::var("GMCRYPTO_GMSSL_VERSION").unwrap_or_else(|_| DEFAULT_GMSSL_VERSION.to_string())
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
    let reported = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    assert!(
        !reported.is_empty(),
        "`gmssl version` produced empty stdout"
    );

    // This must be the FIRST thing that fails on a drifted oracle. Without
    // it, a mismatched build dies several tests later on a renamed
    // subcommand, which reads like a wire-format regression.
    let expected = expected_gmssl_version();
    assert_eq!(
        reported, expected,
        "\n\nORACLE DRIFT — this is NOT a gmcrypto-core regression.\n\
         \n    expected: {expected}\
         \n    found:    {reported}\n\
         \nThis suite pins its reference implementation, because GmSSL changes\n\
         subcommand names and input ranges between releases. A mismatch means\n\
         the gmssl build moved, not that our wire output changed.\n\
         \nFix: install the pinned release, or set GMCRYPTO_GMSSL_VERSION to the\n\
         build you deliberately want to cross-validate against.\n"
    );
}

/// Cross-validate `hmac_sm3` against `gmssl sm3hmac` over a small set of
/// (key, message) inputs spanning gmssl's admissible key-length window,
/// pinning both of its boundaries and the empty-message path.
///
/// **gmssl 3.2.0's `sm3hmac` CLI accepts keys of 12..=32 bytes only.** The
/// upper bound is unchanged from 3.1.1; the 12-byte *lower* bound is new in
/// 3.2.0 — shorter keys abort inside `sm3_digest_init()` with
/// `sm3hmac: inner error` and a non-zero exit. That is why the RFC-style
/// 4-byte `"Jefe"` and empty-key vectors are no longer cross-checked here.
///
/// Those two paths, and the long-key hash-first path that has never been
/// CLI-reachable, are covered by in-tree KATs in
/// `crates/gmcrypto-core/src/hmac.rs::tests` —
/// `test2_jefe_what_do_ya_want`, `empty_key_empty_message`, and
/// `test6_long_key_hash_first`, the last of which had its canonical value
/// computed via gmssl by hand-applying the RFC 2104 hash-first equivalence.
#[test]
fn hmac_sm3_matches_gmssl() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    // (key, message) test cases — kept short so this test runs in <1s.
    // Keys stay inside gmssl 3.2.0's 12..=32-byte CLI window; the first
    // and last entries sit exactly on its two boundaries, so a future
    // narrowing of either one fails here loudly instead of silently
    // shrinking what the oracle actually checks.
    let cases: &[(&[u8], &[u8])] = &[
        (b"twelve-bytes", b"what do ya want for nothing?"),
        (b"twelve-bytes", b""),
        (&[0x0bu8; 20], b"Hi There"),
        (&[0xccu8; 32], b"another short message"),
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

/// Cross-validate `pbkdf2_hmac_sm3` against `gmssl sm3_pbkdf2 -hex` over a
/// small set of (password, salt, iter, outlen) inputs.
///
/// gmssl 3.2.0's `sm3_pbkdf2` CLI rejects iteration counts below 10 000
/// (measured: 9 999 rejects, 10 000 is accepted), so the c=1 boundary is
/// not cross-checked here — it is covered by the in-tree self-consistency
/// tests. The subcommand was named `pbkdf2` through 3.1.1.
#[test]
fn pbkdf2_hmac_sm3_matches_gmssl() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    // (password, salt, iterations, outlen). Keep iter modest so the
    // test runs in seconds, not minutes. 10 000 is exactly gmssl
    // 3.2.0's minimum, so these entries sit on the boundary and a
    // future tightening fails here loudly.
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
                "sm3_pbkdf2",
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
            .expect("spawn gmssl sm3_pbkdf2");
        assert!(
            output.status.success(),
            "gmssl sm3_pbkdf2 exit {:?}: {}",
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

// ---------- v0.3 W3: bidirectional SM2 / SM4-CBC / PEM-PKCS8 ----------
//
// All tests below load the v0.3 W2 KAT fixtures committed at
// `tests/data/v0_3-sm2-pkcs8-encrypted.pem` (gmssl-emitted encrypted
// PKCS#8) and `tests/data/v0_3-sm2-spki.pem` (the matched SPKI public
// key). gmssl can load both with `-key priv.pem -pass passw0rd` and
// `-pubkey pub.pem`; gmcrypto-core can decrypt the former via
// `pkcs8::decrypt(blob, b"passw0rd")` and decode the latter via
// `spki::decode`.

const W3_PRIV_PEM: &str = include_str!("data/v0_3-sm2-pkcs8-encrypted.pem");
const W3_PUB_PEM: &str = include_str!("data/v0_3-sm2-spki.pem");
const W3_PASSWORD: &[u8] = b"passw0rd";
const W3_PASSWORD_STR: &str = "passw0rd";

/// Test scratch directory under `target/`. Created on first test
/// run; reused thereafter. Cleared at test entry to avoid stale
/// fixtures from a prior `cargo test` invocation.
fn scratch_dir(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    p.push(name);
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create scratch dir");
    p
}

fn write_priv_pem(dir: &Path) -> PathBuf {
    let path = dir.join("priv.pem");
    fs::write(&path, W3_PRIV_PEM).expect("write priv.pem");
    path
}

fn write_pub_pem(dir: &Path) -> PathBuf {
    let path = dir.join("pub.pem");
    fs::write(&path, W3_PUB_PEM).expect("write pub.pem");
    path
}

/// Load the W2 KAT fixture private key into an `Sm2PrivateKey`.
fn load_w3_private() -> sm2::Sm2PrivateKey {
    let der = pem::decode(W3_PRIV_PEM, "ENCRYPTED PRIVATE KEY").expect("PEM decode W3 fixture");
    pkcs8::decrypt(&der, W3_PASSWORD).expect("PKCS#8 decrypt W3 fixture")
}

/// SM2 sign: gmssl signs, gmcrypto-core verifies.
///
/// Confirms that `verify_with_id(default_id="1234567812345678", message,
/// gmssl-emitted (r,s))` accepts the signature.
#[test]
fn gmssl_sm2_sign_them_verify_us() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w3_sm2_sign_them");
    let priv_path = write_priv_pem(&dir);
    let msg_path = dir.join("msg.txt");
    let sig_path = dir.join("sig.bin");
    let message = b"v0.3 W3 SM2 sign cross-validation";
    fs::write(&msg_path, message).expect("write message");

    let output = Command::new("gmssl")
        .args([
            "sm2sign",
            "-key",
            priv_path.to_str().unwrap(),
            "-pass",
            W3_PASSWORD_STR,
            "-in",
            msg_path.to_str().unwrap(),
            "-out",
            sig_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm2sign");
    assert!(
        output.status.success(),
        "gmssl sm2sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let der_sig = fs::read(&sig_path).expect("read sig");
    let priv_key = load_w3_private();
    let pub_key = priv_key.public_key();
    let ok = sm2::verify_with_id(&pub_key, sm2::DEFAULT_SIGNER_ID, message, &der_sig);
    assert!(
        ok,
        "gmssl-emitted SM2 signature must verify under our verify_with_id"
    );
}

/// SM2 sign: gmcrypto-core signs, gmssl verifies.
///
/// Confirms that `sm2::sign_with_id(default_id, message)` produces a
/// signature gmssl accepts under the same SPKI public key.
#[test]
fn gmssl_sm2_sign_us_verify_them() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w3_sm2_sign_us");
    let pub_path = write_pub_pem(&dir);
    let msg_path = dir.join("msg.txt");
    let sig_path = dir.join("sig.bin");
    let message = b"v0.3 W3 SM2 sign-us cross-validation";
    fs::write(&msg_path, message).expect("write message");

    let priv_key = load_w3_private();
    let mut rng = getrandom::SysRng;
    let sig =
        sm2::sign_with_id(&priv_key, sm2::DEFAULT_SIGNER_ID, message, &mut rng).expect("sign");
    fs::write(&sig_path, &sig).expect("write sig");

    let output = Command::new("gmssl")
        .args([
            "sm2verify",
            "-pubkey",
            pub_path.to_str().unwrap(),
            "-in",
            msg_path.to_str().unwrap(),
            "-sig",
            sig_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm2verify");
    assert!(
        output.status.success(),
        "gmssl sm2verify rejected our signature: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// SM2 encrypt: gmssl encrypts to our pubkey, gmcrypto-core decrypts.
///
/// Confirms that `sm2::decrypt` accepts gmssl-emitted GM/T 0009 SM2
/// ciphertext and recovers the plaintext.
#[test]
fn gmssl_sm2_encrypt_them_decrypt_us() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w3_sm2_encrypt_them");
    let pub_path = write_pub_pem(&dir);
    let msg_path = dir.join("msg.txt");
    let ct_path = dir.join("ct.bin");
    let plaintext: &[u8] = b"v0.3 W3 SM2 encrypt cross-validation";
    fs::write(&msg_path, plaintext).expect("write plaintext");

    let output = Command::new("gmssl")
        .args([
            "sm2encrypt",
            "-pubkey",
            pub_path.to_str().unwrap(),
            "-in",
            msg_path.to_str().unwrap(),
            "-out",
            ct_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm2encrypt");
    assert!(
        output.status.success(),
        "gmssl sm2encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ct = fs::read(&ct_path).expect("read ct");
    let priv_key = load_w3_private();
    let recovered = sm2::decrypt(&priv_key, &ct).expect("decrypt gmssl-emitted ciphertext");
    assert_eq!(recovered, plaintext);
}

/// SM2 encrypt: gmcrypto-core encrypts, gmssl decrypts.
///
/// Confirms that `sm2::encrypt` produces gmssl-acceptable GM/T 0009
/// SM2 ciphertext.
#[test]
fn gmssl_sm2_encrypt_us_decrypt_them() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w3_sm2_encrypt_us");
    let priv_path = write_priv_pem(&dir);
    let ct_path = dir.join("ct.bin");
    let recovered_path = dir.join("recovered.bin");
    let plaintext: &[u8] = b"v0.3 W3 SM2 encrypt-us cross-validation";

    let priv_key = load_w3_private();
    let pub_key = priv_key.public_key();
    let mut rng = getrandom::SysRng;
    let ct = sm2::encrypt(&pub_key, plaintext, &mut rng).expect("encrypt");
    fs::write(&ct_path, &ct).expect("write ct");

    let output = Command::new("gmssl")
        .args([
            "sm2decrypt",
            "-key",
            priv_path.to_str().unwrap(),
            "-pass",
            W3_PASSWORD_STR,
            "-in",
            ct_path.to_str().unwrap(),
            "-out",
            recovered_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm2decrypt");
    assert!(
        output.status.success(),
        "gmssl sm2decrypt rejected our ciphertext: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recovered = fs::read(&recovered_path).expect("read recovered");
    assert_eq!(recovered, plaintext);
}

/// SM4-CBC: gmssl encrypts, gmcrypto-core decrypts.
#[test]
fn gmssl_sm4_cbc_encrypt_them_decrypt_us() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w3_sm4_cbc_them");
    let key = [0xAB; 16];
    let iv = [0xCD; 16];
    let plaintext: &[u8] = b"v0.3 W3 SM4-CBC cross-validation message";

    let pt_path = dir.join("pt.bin");
    let ct_path = dir.join("ct.bin");
    fs::write(&pt_path, plaintext).expect("write pt");

    // gmssl sm4_cbc -encrypt -key <hex> -iv <hex> -in pt -out ct
    let output = Command::new("gmssl")
        .args([
            "sm4_cbc",
            "-encrypt",
            "-key",
            &hex(&key),
            "-iv",
            &hex(&iv),
            "-in",
            pt_path.to_str().unwrap(),
            "-out",
            ct_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm4_cbc");
    assert!(
        output.status.success(),
        "gmssl sm4_cbc -encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ct = fs::read(&ct_path).expect("read ct");
    let recovered = sm4::mode_cbc::decrypt(&key, &iv, &ct).expect("our decrypt");
    assert_eq!(recovered, plaintext);
}

/// SM4-CBC: gmcrypto-core encrypts, gmssl decrypts.
#[test]
fn gmssl_sm4_cbc_encrypt_us_decrypt_them() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w3_sm4_cbc_us");
    let key = [0xAB; 16];
    let iv = [0xCD; 16];
    let plaintext: &[u8] = b"v0.3 W3 SM4-CBC encrypt-us cross-validation";

    let ct_path = dir.join("ct.bin");
    let recovered_path = dir.join("recovered.bin");
    let ct = sm4::mode_cbc::encrypt(&key, &iv, plaintext);
    fs::write(&ct_path, &ct).expect("write ct");

    let output = Command::new("gmssl")
        .args([
            "sm4_cbc",
            "-decrypt",
            "-key",
            &hex(&key),
            "-iv",
            &hex(&iv),
            "-in",
            ct_path.to_str().unwrap(),
            "-out",
            recovered_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm4_cbc");
    assert!(
        output.status.success(),
        "gmssl sm4_cbc -decrypt rejected our ciphertext: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recovered = fs::read(&recovered_path).expect("read recovered");
    assert_eq!(recovered, plaintext);
}

/// SM4-CTR (v0.7 W2): gmssl encrypts, gmcrypto-core decrypts. gmssl's
/// `-iv` flag holds the initial counter (CTR has no IV/counter split
/// in gmssl's CLI — the `-iv` value IS the initial 16-byte counter,
/// BE-incremented per block). Re-confirmed against 3.2.0, where the
/// subcommand is `sm4_ctr` rather than 3.1.1's `sm4 -ctr`.
#[test]
fn gmssl_sm4_ctr_encrypt_them_decrypt_us() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w7_sm4_ctr_them");
    let key = [0xAB; 16];
    let counter = [0xCD; 16];
    // Length deliberately not a block multiple to exercise the
    // byte-truncation tail.
    let plaintext: &[u8] = b"v0.7 W2 SM4-CTR cross-validation, partial-block tail xyz";

    let pt_path = dir.join("pt.bin");
    let ct_path = dir.join("ct.bin");
    fs::write(&pt_path, plaintext).expect("write pt");

    let output = Command::new("gmssl")
        .args([
            "sm4_ctr",
            "-encrypt",
            "-key",
            &hex(&key),
            "-iv",
            &hex(&counter),
            "-in",
            pt_path.to_str().unwrap(),
            "-out",
            ct_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm4_ctr");
    assert!(
        output.status.success(),
        "gmssl sm4_ctr -encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ct = fs::read(&ct_path).expect("read ct");
    let recovered = sm4::mode_ctr::decrypt(&key, &counter, &ct);
    assert_eq!(recovered, plaintext);
}

/// SM4-CTR (v0.7 W2): gmcrypto-core encrypts, gmssl decrypts.
#[test]
fn gmssl_sm4_ctr_encrypt_us_decrypt_them() {
    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w7_sm4_ctr_us");
    let key = [0xAB; 16];
    let counter = [0xCD; 16];
    let plaintext: &[u8] = b"v0.7 W2 SM4-CTR encrypt-us cross-validation";

    let ct_path = dir.join("ct.bin");
    let recovered_path = dir.join("recovered.bin");
    let ct = sm4::mode_ctr::encrypt(&key, &counter, plaintext);
    fs::write(&ct_path, &ct).expect("write ct");

    let output = Command::new("gmssl")
        .args([
            "sm4_ctr",
            "-decrypt",
            "-key",
            &hex(&key),
            "-iv",
            &hex(&counter),
            "-in",
            ct_path.to_str().unwrap(),
            "-out",
            recovered_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm4_ctr");
    assert!(
        output.status.success(),
        "gmssl sm4_ctr -decrypt rejected our ciphertext: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recovered = fs::read(&recovered_path).expect("read recovered");
    assert_eq!(recovered, plaintext);
}

// ============================================================
// SM4-GCM (v0.8 W2) — cfg-gated on `sm4-aead`.
//
// gmssl's `sm4_gcm -encrypt ... -aad <str>` emits `ciphertext ‖ tag`
// concatenated to the output file. Our `mode_gcm::encrypt` returns a
// tuple; the shim handles the concat/split on the gmssl boundary.
// gmssl 3.2.0 still accepts arbitrary IV lengths (re-verified locally
// at 8/12/16/24 bytes); the tests below use the canonical 12-byte
// nonce. The subcommand was `sm4 -gcm` through 3.1.1.
// ============================================================

/// SM4-GCM (v0.8 W2): gmssl encrypts, gmcrypto-core decrypts.
#[cfg(feature = "sm4-aead")]
#[test]
fn gmssl_sm4_gcm_encrypt_them_decrypt_us() {
    use gmcrypto_core::sm4::mode_gcm;

    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w8_sm4_gcm_them");
    let key = [0xAB; 16];
    let nonce: [u8; 12] = [0xCDu8; 12];
    let aad = b"v0.8 W2 GCM bidirectional interop";
    let plaintext: &[u8] = b"v0.8 W2 SM4-GCM cross-validation against gmssl 3.1.1";

    let pt_path = dir.join("pt.bin");
    let ct_path = dir.join("ct.bin");
    fs::write(&pt_path, plaintext).expect("write pt");

    let output = Command::new("gmssl")
        .args([
            "sm4_gcm",
            "-encrypt",
            "-key",
            &hex(&key),
            "-iv",
            &hex(&nonce),
            "-aad",
            std::str::from_utf8(aad).unwrap(),
            "-in",
            pt_path.to_str().unwrap(),
            "-out",
            ct_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm4_gcm");
    assert!(
        output.status.success(),
        "gmssl sm4_gcm -encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = fs::read(&ct_path).expect("read gmssl ct||tag");
    assert!(
        combined.len() >= 16,
        "gmssl output too short for ct||tag: {} bytes",
        combined.len(),
    );
    let split = combined.len() - 16;
    let ct = &combined[..split];
    let tag: [u8; 16] = combined[split..].try_into().expect("tag slice is 16 bytes");

    let recovered = mode_gcm::decrypt(&key, &nonce, aad, ct, &tag);
    assert_eq!(
        recovered.as_deref(),
        Some(plaintext),
        "gmcrypto-core failed to decrypt gmssl SM4-GCM output (tag mismatch?)",
    );
}

/// SM4-GCM (v0.8 W2): gmcrypto-core encrypts, gmssl decrypts.
#[cfg(feature = "sm4-aead")]
#[test]
fn gmssl_sm4_gcm_encrypt_us_decrypt_them() {
    use gmcrypto_core::sm4::mode_gcm;

    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("w8_sm4_gcm_us");
    let key = [0xAB; 16];
    let nonce: [u8; 12] = [0xCDu8; 12];
    let aad = b"v0.8 W2 GCM encrypt-us cross-validation";
    let plaintext: &[u8] = b"v0.8 W2 SM4-GCM encrypt-us cross-validation against gmssl 3.1.1";

    let (ct, tag) = mode_gcm::encrypt(&key, &nonce, aad, plaintext).expect("under ceiling");
    let mut combined = Vec::with_capacity(ct.len() + tag.len());
    combined.extend_from_slice(&ct);
    combined.extend_from_slice(&tag);

    let ct_path = dir.join("ct.bin");
    let recovered_path = dir.join("recovered.bin");
    fs::write(&ct_path, &combined).expect("write our ct||tag");

    let output = Command::new("gmssl")
        .args([
            "sm4_gcm",
            "-decrypt",
            "-key",
            &hex(&key),
            "-iv",
            &hex(&nonce),
            "-aad",
            std::str::from_utf8(aad).unwrap(),
            "-in",
            ct_path.to_str().unwrap(),
            "-out",
            recovered_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm4_gcm");
    assert!(
        output.status.success(),
        "gmssl sm4_gcm -decrypt rejected our (ct||tag): {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recovered = fs::read(&recovered_path).expect("read recovered");
    assert_eq!(recovered, plaintext);
}

/// PKCS#10 CSR (v1.20): gmssl `reqgen` (default & custom SM2 ID) → Rust `from_pem` + verify.
#[cfg(feature = "x509")]
#[test]
fn gmssl_pkcs10_csr_them_to_us() {
    use gmcrypto_core::x509::csr::CertificationRequest;

    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("v120_csr_them_to_us");
    let key_path = dir.join("key.pem");
    let req_default_path = dir.join("req_default.pem");

    let out = Command::new("gmssl")
        .args([
            "sm2keygen",
            "-pass",
            "test1234",
            "-out",
            key_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm2keygen");
    assert!(out.status.success(), "sm2keygen failed");

    // 1. Default SM2 ID.
    let out = Command::new("gmssl")
        .args([
            "reqgen",
            "-C",
            "CN",
            "-ST",
            "Beijing",
            "-L",
            "Haidian",
            "-O",
            "GmSSL-Interop",
            "-OU",
            "Crypto",
            "-CN",
            "them.example.cn",
            "-key",
            key_path.to_str().unwrap(),
            "-pass",
            "test1234",
            "-out",
            req_default_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl reqgen default");
    assert!(
        out.status.success(),
        "gmssl reqgen default failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let pem_default = fs::read_to_string(&req_default_path).expect("read default csr");
    let parsed_default = CertificationRequest::from_pem(&pem_default).expect("parse default csr");
    assert!(parsed_default.verify_signature());
    assert!(!parsed_default.verify_signature_with_id(b"wrong-id"));
    assert!(parsed_default.attributes_raw().is_empty());
    assert!(parsed_default.extension_request_raw().is_none());
}

#[cfg(feature = "x509")]
fn gmssl_gen_test_ca(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let ca_key_path = dir.join("ca_key.pem");
    let ca_cert_path = dir.join("ca_cert.pem");

    let out = Command::new("gmssl")
        .args([
            "sm2keygen",
            "-pass",
            "test1234",
            "-out",
            ca_key_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl sm2keygen ca");
    assert!(out.status.success(), "ca sm2keygen failed");

    let out = Command::new("gmssl")
        .args([
            "certgen",
            "-C",
            "CN",
            "-O",
            "TestCA",
            "-CN",
            "TestRootCA",
            "-days",
            "365",
            "-key",
            ca_key_path.to_str().unwrap(),
            "-pass",
            "test1234",
            "-ca",
            "-path_len_constraint",
            "1",
            "-key_usage",
            "keyCertSign",
            "-key_usage",
            "cRLSign",
            "-out",
            ca_cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl certgen");
    assert!(
        out.status.success(),
        "gmssl certgen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (ca_key_path, ca_cert_path)
}

#[cfg(feature = "x509")]
fn assert_custom_id_reqsign(
    dir: &std::path::Path,
    ca_key_path: &std::path::Path,
    ca_cert_path: &std::path::Path,
    leaf_key: &sm2::Sm2PrivateKey,
) {
    use getrandom::SysRng;
    use gmcrypto_core::x509::csr::{CsrBuilder, SubjectName};

    let custom_id = "custom-sm2-signer-id";
    let csr_custom_path = dir.join("our_req_custom.pem");
    let leaf_custom_path = dir.join("leaf_custom.pem");
    let mut rng = SysRng;
    let csr_custom = CsrBuilder::new(SubjectName::new().country("CN").common_name("custom.cn"))
        .sign_with_id(leaf_key, custom_id.as_bytes(), &mut rng)
        .expect("sign custom-id csr");
    fs::write(&csr_custom_path, csr_custom.to_pem()).expect("write custom csr");

    let out_wrong = Command::new("gmssl")
        .args([
            "reqsign",
            "-in",
            csr_custom_path.to_str().unwrap(),
            "-days",
            "30",
            "-cacert",
            ca_cert_path.to_str().unwrap(),
            "-key",
            ca_key_path.to_str().unwrap(),
            "-pass",
            "test1234",
            "-out",
            leaf_custom_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl reqsign wrong id");
    assert!(
        !out_wrong.status.success(),
        "gmssl reqsign must reject custom-ID CSR under default ID"
    );

    let out_ok = Command::new("gmssl")
        .args([
            "reqsign",
            "-in",
            csr_custom_path.to_str().unwrap(),
            "-req_sm2_id",
            custom_id,
            "-days",
            "30",
            "-cacert",
            ca_cert_path.to_str().unwrap(),
            "-key",
            ca_key_path.to_str().unwrap(),
            "-pass",
            "test1234",
            "-out",
            leaf_custom_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl reqsign custom id");
    assert!(
        out_ok.status.success(),
        "gmssl reqsign -req_sm2_id rejected our custom-ID CSR: {}",
        String::from_utf8_lossy(&out_ok.stderr)
    );
}

/// PKCS#10 CSR (v1.20): Rust `CsrBuilder` → `gmssl reqparse` + `gmssl reqsign` → Rust `x509::verify_chain`.
#[cfg(feature = "x509")]
#[test]
fn gmssl_pkcs10_csr_us_to_them_parse_and_sign() {
    use core::net::{IpAddr, Ipv4Addr};
    use getrandom::SysRng;
    use gmcrypto_core::x509::csr::{CsrBuilder, SubjectName};
    use gmcrypto_core::x509::{Certificate, KeyUsage, verify_chain};

    if !enabled() {
        eprintln!("skipping: GMCRYPTO_GMSSL != 1");
        return;
    }
    assert!(gmssl_present(), "GMCRYPTO_GMSSL=1 but no gmssl on PATH");

    let dir = scratch_dir("v120_csr_us_to_them");
    let csr_path = dir.join("our_req.pem");
    let leaf_cert_path = dir.join("leaf_cert.pem");

    let mut rng = SysRng;
    let leaf_key = sm2::Sm2PrivateKey::generate(&mut rng).expect("keygen");
    let subject = SubjectName::new()
        .country("CN")
        .state("Beijing")
        .locality("Haidian")
        .organization("RustCore")
        .organizational_unit("PKI")
        .common_name("us.example.cn");
    let csr = CsrBuilder::new(subject)
        .key_usage(
            KeyUsage::DIGITAL_SIGNATURE.union(KeyUsage::KEY_ENCIPHERMENT),
            true,
        )
        .san_dns("us.example.cn")
        .san_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        .sign(&leaf_key, &mut rng)
        .expect("sign csr");
    fs::write(&csr_path, csr.to_pem()).expect("write csr pem");

    // 1. gmssl reqparse accepts our CSR.
    let out = Command::new("gmssl")
        .args(["reqparse", "-in", csr_path.to_str().unwrap()])
        .output()
        .expect("spawn gmssl reqparse");
    assert!(
        out.status.success(),
        "gmssl reqparse rejected our CSR: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed_stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        parsed_stdout.contains("us.example.cn"),
        "expected CN in gmssl reqparse output:\n{parsed_stdout}"
    );

    // 2. Generate a GmSSL root CA and issue a leaf certificate from our CSR.
    let (ca_key_path, ca_cert_path) = gmssl_gen_test_ca(&dir);
    let out = Command::new("gmssl")
        .args([
            "reqsign",
            "-in",
            csr_path.to_str().unwrap(),
            "-days",
            "90",
            "-cacert",
            ca_cert_path.to_str().unwrap(),
            "-key",
            ca_key_path.to_str().unwrap(),
            "-pass",
            "test1234",
            "-key_usage",
            "digitalSignature",
            "-out",
            leaf_cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn gmssl reqsign");
    assert!(
        out.status.success(),
        "gmssl reqsign rejected our CSR: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 3. Parse both certificates back in Rust and verify the chain.
    let ca_pem = fs::read_to_string(&ca_cert_path).expect("read ca cert");
    let leaf_pem = fs::read_to_string(&leaf_cert_path).expect("read leaf cert");
    let ca_der = pem::decode(&ca_pem, "CERTIFICATE").expect("ca pem");
    let leaf_der = pem::decode(&leaf_pem, "CERTIFICATE").expect("leaf pem");
    let ca_cert = Certificate::from_der(&ca_der).expect("parse ca cert");
    let leaf_cert = Certificate::from_der(&leaf_der).expect("parse leaf cert");
    assert!(verify_chain(&[leaf_cert], &[ca_cert], None));

    // 4. Custom SM2 signer ID: Rust signs with custom ID; gmssl reqsign
    //    rejects under default ID and accepts under `-req_sm2_id`.
    assert_custom_id_reqsign(&dir, &ca_key_path, &ca_cert_path, &leaf_key);
}
