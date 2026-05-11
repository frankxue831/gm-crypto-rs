//! C ABI for `gmcrypto-core` (v0.4 W4).
//!
//! Exposes SM2 / SM3 / SM4 / HMAC-SM3 / PBKDF2-HMAC-SM3 plus SM2 key
//! import/export to C / C++ / Python / Go / Zig / Ruby callers via
//! opaque handles and a cbindgen-generated header at
//! `include/gmcrypto.h`.
//!
//! # Failure-mode invariant
//!
//! Every entry point returning `c_int` uses the convention:
//!
//! - `0` = success.
//! - Non-zero = failure (single-`Failed`-equivalent per the workspace
//!   failure-mode invariant; **no enumerated error codes**).
//!
//! C callers MUST treat all non-zero returns as opaque failure. Per
//! Q4.8 in `docs/v0.4-scope.md`, distinguishing failure modes would
//! introduce a padding-oracle / wrong-password-oracle attack surface.
//!
//! # Output buffer convention
//!
//! Entry points emitting variable-length output (signatures,
//! ciphertexts, PKCS#8 blobs) follow the
//! `(out_ptr, out_capacity, out_actual_len)` shape per Q4.13:
//!
//! - `out_ptr`: caller-allocated buffer.
//! - `out_capacity`: buffer length in bytes.
//! - `out_actual_len`: pointer to a `size_t` where the entry point
//!   writes the actual output length (or the required capacity if
//!   the buffer was too small).
//!
//! On too-small buffer: return non-zero, write the required length
//! to `*out_actual_len`, do not modify `out_ptr`.
//!
//! # Handle ownership
//!
//! Opaque handles are heap-allocated `Box<T>`s returned as
//! `*mut T_t`. Callers MUST pair each `_new` with exactly one
//! `_free` to avoid leaks. Double-free or use-after-free is
//! undefined behaviour (per `Box::from_raw`'s contract). Calling
//! `_free(NULL)` is a no-op (mirrors C's `free()` semantics).
//!
//! # Constant-time
//!
//! The FFI shim itself does not introduce new secret-touching paths.
//! Every cryptographic operation runs in `gmcrypto-core`'s already-
//! dudect-gated code. The null-pointer check at each entry point
//! is constant-time (single integer compare); the return-on-null
//! early-exit has a different timing signature than a successful
//! call, but the attacker who could measure this is local-host and
//! has far more invasive options.
//!
//! # Panic discipline
//!
//! Every entry point wraps its body in `std::panic::catch_unwind`.
//! Rust panics unwinding into C are undefined behaviour; on panic
//! we convert to a non-zero return. Per the failure-mode invariant,
//! the C caller cannot distinguish panic from other failure modes.

#![warn(missing_docs)]
#![allow(clippy::missing_safety_doc)]
// C consumers expect snake_case-named opaque struct types
// (`gmcrypto_sm3_t`, `gmcrypto_sm2_privkey_t`, ...); the Rust
// convention warning is suppressed crate-wide for these.
#![allow(non_camel_case_types)]
// v0.4 W4 / Q4.7 — this is the FFI shim crate; raw-pointer
// dereferencing and `Box::from_raw` are inherent. Every `unsafe`
// block carries a `// SAFETY:` comment naming the caller-side
// preconditions; the Cargo.toml lint `unsafe_code = "warn"` flags
// any new `unsafe` for reviewer attention rather than blocking
// compile. `gmcrypto-core` itself stays `unsafe_code = "forbid"`.
#![allow(unsafe_code)]

use core::ffi::{c_char, c_int};
use core::ptr;
use core::slice;

use gmcrypto_core::hmac::{HmacSm3 as InnerHmacSm3, hmac_sm3};
use gmcrypto_core::kdf::pbkdf2_hmac_sm3;
use gmcrypto_core::sm2::{
    DEFAULT_SIGNER_ID, Sm2PrivateKey, Sm2PublicKey, decrypt as sm2_decrypt, encrypt as sm2_encrypt,
    sign_with_id, verify_with_id,
};
use gmcrypto_core::sm3::{Sm3 as InnerSm3, hash as sm3_hash};
use gmcrypto_core::sm4::{
    Sm4CbcDecryptor as InnerSm4CbcDec, Sm4CbcEncryptor as InnerSm4CbcEnc, Sm4Cipher, mode_cbc,
};
use gmcrypto_core::{pem, pkcs8};
use rand_core::TryRng;

// ============================================================
// Constants exported to the C side.
// ============================================================

/// Success return code.
pub const GMCRYPTO_OK: c_int = 0;

/// Generic failure return code. All non-zero returns are equivalent
/// per the failure-mode invariant; this constant exists only as a
/// convenience for C callers that want a named symbol for the
/// not-success case.
pub const GMCRYPTO_ERR: c_int = -1;

/// SM3 digest output size in bytes (32 = 256 bits).
pub const GMCRYPTO_SM3_DIGEST_SIZE: usize = 32;

/// SM4 block size in bytes (16 = 128 bits).
pub const GMCRYPTO_SM4_BLOCK_SIZE: usize = 16;

/// SM4 key size in bytes (16 = 128 bits).
pub const GMCRYPTO_SM4_KEY_SIZE: usize = 16;

/// SEC1 uncompressed-point size for SM2 public keys
/// (`04 || X || Y` = 65 bytes).
pub const GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE: usize = 65;

/// SM2 private-key scalar size in bytes (32 = 256 bits big-endian).
pub const GMCRYPTO_SM2_SCALAR_SIZE: usize = 32;

// ============================================================
// Opaque handle types (cbindgen emits as forward-declared structs).
// ============================================================

/// Opaque handle for a streaming SM3 hasher.
pub struct gmcrypto_sm3_t {
    inner: InnerSm3,
}

/// Opaque handle for a streaming HMAC-SM3 keyed MAC.
pub struct gmcrypto_hmac_sm3_t {
    inner: InnerHmacSm3,
}

/// Opaque handle for an SM4 cipher (key-scheduled).
pub struct gmcrypto_sm4_t {
    inner: Sm4Cipher,
}

/// Opaque handle for a streaming SM4-CBC encryptor (v0.5 W1).
/// Construct with [`gmcrypto_sm4_cbc_encryptor_new`], feed plaintext via
/// [`gmcrypto_sm4_cbc_encryptor_update`], emit the trailing PKCS#7-
/// padded block(s) via [`gmcrypto_sm4_cbc_encryptor_finalize`].
pub struct gmcrypto_sm4_cbc_encryptor_t {
    inner: InnerSm4CbcEnc,
}

/// Opaque handle for a streaming SM4-CBC decryptor (v0.5 W1). Same
/// buffer-back-by-one padding-oracle defense as the v0.3 W5 Rust
/// streaming surface: the most recent decrypted block is held back
/// from emission until [`gmcrypto_sm4_cbc_decryptor_finalize`]
/// confirms it is the last block and validates the PKCS#7 padding.
pub struct gmcrypto_sm4_cbc_decryptor_t {
    inner: InnerSm4CbcDec,
}

/// Opaque handle for an SM2 private key.
pub struct gmcrypto_sm2_privkey_t {
    inner: Sm2PrivateKey,
}

/// Opaque handle for an SM2 public key.
pub struct gmcrypto_sm2_pubkey_t {
    inner: Sm2PublicKey,
}

// ============================================================
// Helpers — all `unsafe` localized here with SAFETY comments.
// ============================================================

/// Reconstruct a `&[u8]` from a `(ptr, len)` pair, treating `(NULL, 0)`
/// as an empty slice.
///
/// # Safety
/// - `ptr` must be valid for reads of `len` bytes, OR `len == 0`.
/// - The memory must not be mutated for the lifetime of the returned
///   slice.
#[allow(unsafe_code)]
unsafe fn try_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        // `(NULL, 0)` and `(non-null, 0)` both denote empty input.
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        // SAFETY: caller guarantees ptr is valid for `len` bytes.
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

/// Reconstruct a `&mut [u8]` from a `(ptr, len)` pair.
///
/// # Safety
/// - `ptr` must be valid for read+write of `len` bytes, OR `len == 0`.
/// - The memory must not be aliased.
#[allow(unsafe_code)]
unsafe fn try_slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        Some(&mut [])
    } else if ptr.is_null() {
        None
    } else {
        // SAFETY: caller guarantees ptr is valid + unaliased.
        Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
    }
}

/// Write a slice into a caller-supplied `(out, out_capacity,
/// out_actual_len)` buffer per the v0.4 W4 / Q4.13 convention.
/// Returns [`GMCRYPTO_OK`] on success or [`GMCRYPTO_ERR`] if the
/// buffer is too small (and writes the required length to
/// `*out_actual_len`).
///
/// # Safety
/// - `out` valid for `out_capacity` bytes (or `out_capacity == 0`).
/// - `out_actual_len` is a valid `*mut usize`.
#[allow(unsafe_code)]
unsafe fn write_output(
    bytes: &[u8],
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    if out_actual_len.is_null() {
        return GMCRYPTO_ERR;
    }
    // SAFETY: caller-asserted non-null.
    unsafe { ptr::write(out_actual_len, bytes.len()) };
    if bytes.len() > out_capacity {
        return GMCRYPTO_ERR;
    }
    if bytes.is_empty() {
        return GMCRYPTO_OK;
    }
    // SAFETY: out valid for at least `bytes.len() <= out_capacity` bytes.
    let dst = unsafe { try_slice_mut(out, bytes.len()) };
    match dst {
        Some(d) => {
            d.copy_from_slice(bytes);
            GMCRYPTO_OK
        }
        None => GMCRYPTO_ERR,
    }
}

/// Catch any panic and convert to a [`GMCRYPTO_ERR`] return. Per the
/// failure-mode invariant, the C caller cannot distinguish panic
/// from other failure modes — which is the intended posture.
#[inline]
fn ffi_guard<F: FnOnce() -> c_int + std::panic::UnwindSafe>(f: F) -> c_int {
    std::panic::catch_unwind(f).unwrap_or(GMCRYPTO_ERR)
}

// ============================================================
// Version string.
// ============================================================

/// Returns a NUL-terminated string with the `gmcrypto-c` version
/// (e.g. `"0.4.0"`). The returned pointer is to a static `&'static
/// CStr` and must NOT be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn gmcrypto_version() -> *const c_char {
    // The version string lives in the binary; static lifetime.
    const VERSION: &core::ffi::CStr = match core::ffi::CStr::from_bytes_with_nul(b"0.4.0\0") {
        Ok(s) => s,
        Err(_) => unreachable!(),
    };
    VERSION.as_ptr()
}

// ============================================================
// SM3 — single-shot + streaming.
// ============================================================

/// Single-shot SM3 hash. Writes 32 bytes to `out_digest`.
///
/// # Returns
/// [`GMCRYPTO_OK`] on success; [`GMCRYPTO_ERR`] on invalid input
/// (null `out_digest`, null `msg` with non-zero `msg_len`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm3_hash(
    msg: *const u8,
    msg_len: usize,
    out_digest: *mut u8,
) -> c_int {
    ffi_guard(|| {
        // SAFETY: contract documented on each helper.
        let input = match unsafe { try_slice(msg, msg_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let out = match unsafe { try_slice_mut(out_digest, GMCRYPTO_SM3_DIGEST_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let digest = sm3_hash(input);
        out.copy_from_slice(&digest);
        GMCRYPTO_OK
    })
}

/// Construct a fresh streaming SM3 hasher. Returns an opaque handle;
/// must be freed via [`gmcrypto_sm3_free`].
///
/// Returns NULL on allocation failure.
#[unsafe(no_mangle)]
pub extern "C" fn gmcrypto_sm3_new() -> *mut gmcrypto_sm3_t {
    let boxed = Box::new(gmcrypto_sm3_t {
        inner: InnerSm3::new(),
    });
    Box::into_raw(boxed)
}

/// Absorb `data` into the streaming SM3 hasher.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm3_update(
    hasher: *mut gmcrypto_sm3_t,
    data: *const u8,
    data_len: usize,
) -> c_int {
    ffi_guard(|| {
        if hasher.is_null() {
            return GMCRYPTO_ERR;
        }
        let input = match unsafe { try_slice(data, data_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        // SAFETY: `hasher` non-null per check above; caller guarantees
        // unique access for the duration of this call.
        let h = unsafe { &mut *hasher };
        h.inner.update(input);
        GMCRYPTO_OK
    })
}

/// Consume the streaming SM3 hasher and write the digest to
/// `out_digest`. The handle is **freed** by this call; do not call
/// [`gmcrypto_sm3_free`] on it afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm3_finalize(
    hasher: *mut gmcrypto_sm3_t,
    out_digest: *mut u8,
) -> c_int {
    ffi_guard(|| {
        if hasher.is_null() {
            return GMCRYPTO_ERR;
        }
        let out = match unsafe { try_slice_mut(out_digest, GMCRYPTO_SM3_DIGEST_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        // SAFETY: hasher non-null; take ownership and drop after finalize.
        let boxed = unsafe { Box::from_raw(hasher) };
        let digest = boxed.inner.finalize();
        out.copy_from_slice(&digest);
        GMCRYPTO_OK
    })
}

/// Free a streaming SM3 hasher. Passing NULL is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm3_free(hasher: *mut gmcrypto_sm3_t) {
    if hasher.is_null() {
        return;
    }
    // SAFETY: hasher came from `Box::into_raw` and the caller has not
    // freed it before.
    drop(unsafe { Box::from_raw(hasher) });
}

// ============================================================
// HMAC-SM3 — single-shot + streaming.
// ============================================================

/// Single-shot HMAC-SM3. Writes 32 bytes to `out_tag`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_hmac_sm3(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out_tag: *mut u8,
) -> c_int {
    ffi_guard(|| {
        let k = match unsafe { try_slice(key, key_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let m = match unsafe { try_slice(msg, msg_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let out = match unsafe { try_slice_mut(out_tag, GMCRYPTO_SM3_DIGEST_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let tag = hmac_sm3(k, m);
        out.copy_from_slice(&tag);
        GMCRYPTO_OK
    })
}

/// Construct a fresh streaming HMAC-SM3 instance keyed with `key`.
/// Returns NULL on invalid input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_hmac_sm3_new(
    key: *const u8,
    key_len: usize,
) -> *mut gmcrypto_hmac_sm3_t {
    let result = std::panic::catch_unwind(|| {
        let k = unsafe { try_slice(key, key_len) }?;
        Some(Box::into_raw(Box::new(gmcrypto_hmac_sm3_t {
            inner: InnerHmacSm3::new(k),
        })))
    });
    match result {
        Ok(Some(ptr)) => ptr,
        _ => ptr::null_mut(),
    }
}

/// Absorb `data` into the streaming HMAC-SM3 instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_hmac_sm3_update(
    mac: *mut gmcrypto_hmac_sm3_t,
    data: *const u8,
    data_len: usize,
) -> c_int {
    ffi_guard(|| {
        if mac.is_null() {
            return GMCRYPTO_ERR;
        }
        let input = match unsafe { try_slice(data, data_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let m = unsafe { &mut *mac };
        m.inner.update(input);
        GMCRYPTO_OK
    })
}

/// Consume the streaming HMAC-SM3 instance and write the 32-byte tag
/// to `out_tag`. The handle is **freed** by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_hmac_sm3_finalize(
    mac: *mut gmcrypto_hmac_sm3_t,
    out_tag: *mut u8,
) -> c_int {
    ffi_guard(|| {
        if mac.is_null() {
            return GMCRYPTO_ERR;
        }
        let out = match unsafe { try_slice_mut(out_tag, GMCRYPTO_SM3_DIGEST_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let boxed = unsafe { Box::from_raw(mac) };
        let tag = boxed.inner.finalize();
        out.copy_from_slice(&tag);
        GMCRYPTO_OK
    })
}

/// Consume the streaming HMAC-SM3 instance and verify the candidate
/// tag in constant time. Returns [`GMCRYPTO_OK`] on match;
/// [`GMCRYPTO_ERR`] on mismatch. The handle is **freed** by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_hmac_sm3_verify(
    mac: *mut gmcrypto_hmac_sm3_t,
    expected_tag: *const u8,
) -> c_int {
    ffi_guard(|| {
        if mac.is_null() || expected_tag.is_null() {
            return GMCRYPTO_ERR;
        }
        let expected = match unsafe { try_slice(expected_tag, GMCRYPTO_SM3_DIGEST_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let mut expected_arr = [0u8; GMCRYPTO_SM3_DIGEST_SIZE];
        expected_arr.copy_from_slice(expected);
        let boxed = unsafe { Box::from_raw(mac) };
        if boxed.inner.verify(&expected_arr) {
            GMCRYPTO_OK
        } else {
            GMCRYPTO_ERR
        }
    })
}

/// Free a streaming HMAC-SM3 instance. NULL is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_hmac_sm3_free(mac: *mut gmcrypto_hmac_sm3_t) {
    if mac.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(mac) });
}

// ============================================================
// PBKDF2-HMAC-SM3.
// ============================================================

/// Derive `out_len` bytes via PBKDF2-HMAC-SM3 over `(pwd, salt,
/// iterations)`. Writes into the caller-supplied `out` buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_pbkdf2_hmac_sm3(
    pwd: *const u8,
    pwd_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    ffi_guard(|| {
        let p = match unsafe { try_slice(pwd, pwd_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let s = match unsafe { try_slice(salt, salt_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let o = match unsafe { try_slice_mut(out, out_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        match pbkdf2_hmac_sm3(p, s, iterations, o) {
            Some(()) => GMCRYPTO_OK,
            None => GMCRYPTO_ERR,
        }
    })
}

// ============================================================
// SM4 — block cipher (single-block) + CBC (single-shot).
// ============================================================

/// Construct an SM4 cipher from a 16-byte key. Returns NULL on null
/// key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_new(key: *const u8) -> *mut gmcrypto_sm4_t {
    let result = std::panic::catch_unwind(|| {
        let k = unsafe { try_slice(key, GMCRYPTO_SM4_KEY_SIZE) }?;
        let k_arr: &[u8; GMCRYPTO_SM4_KEY_SIZE] = k.try_into().ok()?;
        Some(Box::into_raw(Box::new(gmcrypto_sm4_t {
            inner: Sm4Cipher::new(k_arr),
        })))
    });
    match result {
        Ok(Some(p)) => p,
        _ => ptr::null_mut(),
    }
}

/// Encrypt one 16-byte block in place under the SM4 cipher.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_encrypt_block(
    cipher: *const gmcrypto_sm4_t,
    block: *mut u8,
) -> c_int {
    ffi_guard(|| {
        if cipher.is_null() {
            return GMCRYPTO_ERR;
        }
        let b = match unsafe { try_slice_mut(block, GMCRYPTO_SM4_BLOCK_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let b_arr: &mut [u8; GMCRYPTO_SM4_BLOCK_SIZE] = match b.try_into() {
            Ok(a) => a,
            Err(_) => return GMCRYPTO_ERR,
        };
        let c = unsafe { &*cipher };
        c.inner.encrypt_block(b_arr);
        GMCRYPTO_OK
    })
}

/// Decrypt one 16-byte block in place under the SM4 cipher.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_decrypt_block(
    cipher: *const gmcrypto_sm4_t,
    block: *mut u8,
) -> c_int {
    ffi_guard(|| {
        if cipher.is_null() {
            return GMCRYPTO_ERR;
        }
        let b = match unsafe { try_slice_mut(block, GMCRYPTO_SM4_BLOCK_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let b_arr: &mut [u8; GMCRYPTO_SM4_BLOCK_SIZE] = match b.try_into() {
            Ok(a) => a,
            Err(_) => return GMCRYPTO_ERR,
        };
        let c = unsafe { &*cipher };
        c.inner.decrypt_block(b_arr);
        GMCRYPTO_OK
    })
}

/// Free an SM4 cipher. NULL is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_free(cipher: *mut gmcrypto_sm4_t) {
    if cipher.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(cipher) });
}

/// SM4-CBC single-shot encrypt with PKCS#7 padding. IV must be
/// caller-supplied and unpredictable (per NIST SP 800-38A
/// Appendix C). Output length is always `((pt_len / 16) + 1) * 16`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_encrypt(
    key: *const u8,
    iv: *const u8,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        let k = match unsafe { try_slice(key, GMCRYPTO_SM4_KEY_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let iv_slice = match unsafe { try_slice(iv, GMCRYPTO_SM4_BLOCK_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let p = match unsafe { try_slice(pt, pt_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k_arr: &[u8; GMCRYPTO_SM4_KEY_SIZE] = match k.try_into() {
            Ok(a) => a,
            Err(_) => return GMCRYPTO_ERR,
        };
        let iv_arr: &[u8; GMCRYPTO_SM4_BLOCK_SIZE] = match iv_slice.try_into() {
            Ok(a) => a,
            Err(_) => return GMCRYPTO_ERR,
        };
        let ciphertext = mode_cbc::encrypt(k_arr, iv_arr, p);
        unsafe { write_output(&ciphertext, out, out_capacity, out_actual_len) }
    })
}

/// SM4-CBC single-shot decrypt. Single-`Failed` return on any
/// failure mode (length not multiple of 16, bad padding, key/IV
/// mismatch) per the failure-mode invariant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_decrypt(
    key: *const u8,
    iv: *const u8,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        let k = match unsafe { try_slice(key, GMCRYPTO_SM4_KEY_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let iv_slice = match unsafe { try_slice(iv, GMCRYPTO_SM4_BLOCK_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let c = match unsafe { try_slice(ct, ct_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k_arr: &[u8; GMCRYPTO_SM4_KEY_SIZE] = match k.try_into() {
            Ok(a) => a,
            Err(_) => return GMCRYPTO_ERR,
        };
        let iv_arr: &[u8; GMCRYPTO_SM4_BLOCK_SIZE] = match iv_slice.try_into() {
            Ok(a) => a,
            Err(_) => return GMCRYPTO_ERR,
        };
        match mode_cbc::decrypt(k_arr, iv_arr, c) {
            Some(plaintext) => unsafe {
                write_output(&plaintext, out, out_capacity, out_actual_len)
            },
            None => GMCRYPTO_ERR,
        }
    })
}

// ============================================================
// SM4-CBC — streaming (v0.5 W1).
//
// Wraps `gmcrypto_core::sm4::{Sm4CbcEncryptor, Sm4CbcDecryptor}`.
// Streaming-emit pattern: each `_update` call may emit zero or more
// full 16-byte ciphertext / plaintext blocks; `_finalize` emits the
// final block(s) (encryptor: PKCS#7 padding; decryptor: PKCS#7 strip
// of the held-back final block). Encryptor and decryptor are
// independent opaque types — Q5.2 pinned this over a unified `_cbc_t`
// with mode enum.
//
// Output buffer convention matches Q5.3: every `_update` /
// `_finalize` uses `(out, out_capacity, out_actual_len)`; on too-
// small capacity we return `GMCRYPTO_ERR` and write the required
// length to `*out_actual_len` (caller-retry pattern).
//
// Buffer-back-by-one padding-oracle defense is preserved across the
// FFI boundary: the decryptor's `_finalize` never returns plaintext
// if the final block's padding is invalid.
// ============================================================

/// Construct a streaming SM4-CBC encryptor. `key` is exactly 16
/// bytes; `iv` is exactly 16 bytes and MUST be caller-supplied
/// unpredictable bytes (NIST SP 800-38A Appendix C). Returns NULL
/// on invalid pointer input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_encryptor_new(
    key: *const u8,
    iv: *const u8,
) -> *mut gmcrypto_sm4_cbc_encryptor_t {
    let result = std::panic::catch_unwind(|| {
        let k = unsafe { try_slice(key, GMCRYPTO_SM4_KEY_SIZE) }?;
        let v = unsafe { try_slice(iv, GMCRYPTO_SM4_BLOCK_SIZE) }?;
        let k_arr: &[u8; GMCRYPTO_SM4_KEY_SIZE] = k.try_into().ok()?;
        let v_arr: &[u8; GMCRYPTO_SM4_BLOCK_SIZE] = v.try_into().ok()?;
        Some(Box::into_raw(Box::new(gmcrypto_sm4_cbc_encryptor_t {
            inner: InnerSm4CbcEnc::new(k_arr, v_arr),
        })))
    });
    match result {
        Ok(Some(p)) => p,
        _ => ptr::null_mut(),
    }
}

/// Absorb plaintext into the streaming SM4-CBC encryptor and emit
/// zero or more full ciphertext blocks. The caller-allocated `out`
/// buffer MUST be at least `pt_len + 16` bytes — that is the upper
/// bound on bytes emitted by a single `_update` call (a buffered
/// partial block from a prior call can produce one extra block when
/// this call's input fills it). On insufficient capacity, the call
/// returns [`GMCRYPTO_ERR`] and the encryptor state is left mid-
/// stream (the ciphertext bytes that would have been emitted are
/// lost). Callers should size the output buffer correctly up-front.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_encryptor_update(
    enc: *mut gmcrypto_sm4_cbc_encryptor_t,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if enc.is_null() {
            return GMCRYPTO_ERR;
        }
        let input = match unsafe { try_slice(pt, pt_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        // SAFETY: enc non-null per check above; caller guarantees
        // unique access for the duration of this call.
        let e = unsafe { &mut *enc };
        e.inner.update(input);
        let emitted = e.inner.take_output();
        unsafe { write_output(&emitted, out, out_capacity, out_actual_len) }
    })
}

/// Apply PKCS#7 padding to the buffered tail and emit the final
/// ciphertext block(s). Consumes the encryptor — the handle is
/// **freed** by this call; do NOT call
/// [`gmcrypto_sm4_cbc_encryptor_free`] on it afterwards.
///
/// Output is always exactly one block (16 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_encryptor_finalize(
    enc: *mut gmcrypto_sm4_cbc_encryptor_t,
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if enc.is_null() {
            return GMCRYPTO_ERR;
        }
        // SAFETY: enc came from Box::into_raw; take ownership and drop.
        let boxed = unsafe { Box::from_raw(enc) };
        // finalize() returns ALL of self.output (including any bytes
        // previously drained via take_output) — but we drained those
        // on prior update calls, so the returned Vec contains only
        // the new final padded block(s).
        let final_bytes = boxed.inner.finalize();
        unsafe { write_output(&final_bytes, out, out_capacity, out_actual_len) }
    })
}

/// Free a streaming SM4-CBC encryptor. Passing NULL is a no-op. Do
/// NOT call after [`gmcrypto_sm4_cbc_encryptor_finalize`] — that
/// already consumed the handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_encryptor_free(enc: *mut gmcrypto_sm4_cbc_encryptor_t) {
    if enc.is_null() {
        return;
    }
    // SAFETY: enc came from Box::into_raw and has not been freed.
    drop(unsafe { Box::from_raw(enc) });
}

/// Construct a streaming SM4-CBC decryptor. `key` is exactly 16
/// bytes; `iv` is exactly 16 bytes and must match the value used
/// during encryption. Returns NULL on invalid pointer input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_decryptor_new(
    key: *const u8,
    iv: *const u8,
) -> *mut gmcrypto_sm4_cbc_decryptor_t {
    let result = std::panic::catch_unwind(|| {
        let k = unsafe { try_slice(key, GMCRYPTO_SM4_KEY_SIZE) }?;
        let v = unsafe { try_slice(iv, GMCRYPTO_SM4_BLOCK_SIZE) }?;
        let k_arr: &[u8; GMCRYPTO_SM4_KEY_SIZE] = k.try_into().ok()?;
        let v_arr: &[u8; GMCRYPTO_SM4_BLOCK_SIZE] = v.try_into().ok()?;
        Some(Box::into_raw(Box::new(gmcrypto_sm4_cbc_decryptor_t {
            inner: InnerSm4CbcDec::new(k_arr, v_arr),
        })))
    });
    match result {
        Ok(Some(p)) => p,
        _ => ptr::null_mut(),
    }
}

/// Absorb ciphertext into the streaming SM4-CBC decryptor and emit
/// zero or more full plaintext blocks. The final-candidate block is
/// HELD BACK from emission until `_finalize` validates the trailing
/// padding (buffer-back-by-one padding-oracle defense). Same buffer-
/// size contract as the encryptor's `_update`: caller MUST allocate
/// `out_capacity >= ct_len + 16` (strict upper bound on bytes emitted
/// in one call). On insufficient capacity returns [`GMCRYPTO_ERR`]
/// and the decryptor state is left mid-stream; size the buffer
/// up-front.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_decryptor_update(
    dec: *mut gmcrypto_sm4_cbc_decryptor_t,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if dec.is_null() {
            return GMCRYPTO_ERR;
        }
        let input = match unsafe { try_slice(ct, ct_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        // SAFETY: dec non-null per check above.
        let d = unsafe { &mut *dec };
        d.inner.update(input);
        let emitted = d.inner.take_output();
        unsafe { write_output(&emitted, out, out_capacity, out_actual_len) }
    })
}

/// Strip PKCS#7 padding from the held-back final block and emit the
/// last plaintext bytes. Consumes the decryptor — the handle is
/// **freed** by this call; do NOT call
/// [`gmcrypto_sm4_cbc_decryptor_free`] on it afterwards.
///
/// Returns [`GMCRYPTO_ERR`] on any failure mode (length not multiple
/// of 16, no full blocks seen, or padding-strip rejection) — single
/// uninformative failure code per the failure-mode invariant. The
/// caller-supplied `out_actual_len` is set to `0` on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_decryptor_finalize(
    dec: *mut gmcrypto_sm4_cbc_decryptor_t,
    out: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if dec.is_null() {
            return GMCRYPTO_ERR;
        }
        // SAFETY: dec came from Box::into_raw; take ownership and drop.
        let boxed = unsafe { Box::from_raw(dec) };
        if let Some(final_bytes) = boxed.inner.finalize() {
            // SAFETY: write_output's contract documented at its decl.
            unsafe { write_output(&final_bytes, out, out_capacity, out_actual_len) }
        } else {
            if !out_actual_len.is_null() {
                // SAFETY: caller-asserted non-null.
                unsafe { ptr::write(out_actual_len, 0) };
            }
            GMCRYPTO_ERR
        }
    })
}

/// Free a streaming SM4-CBC decryptor. Passing NULL is a no-op. Do
/// NOT call after [`gmcrypto_sm4_cbc_decryptor_finalize`] — that
/// already consumed the handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm4_cbc_decryptor_free(dec: *mut gmcrypto_sm4_cbc_decryptor_t) {
    if dec.is_null() {
        return;
    }
    // SAFETY: dec came from Box::into_raw and has not been freed.
    drop(unsafe { Box::from_raw(dec) });
}

// ============================================================
// SM2 key construction + I/O.
// ============================================================

/// Construct an SM2 private key from a 32-byte big-endian scalar.
/// Returns NULL on out-of-range scalar (must be in `[1, n-2]`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_privkey_new(d_be: *const u8) -> *mut gmcrypto_sm2_privkey_t {
    let result = std::panic::catch_unwind(|| {
        let bytes = unsafe { try_slice(d_be, GMCRYPTO_SM2_SCALAR_SIZE) }?;
        let arr: &[u8; GMCRYPTO_SM2_SCALAR_SIZE] = bytes.try_into().ok()?;
        // Use SEC1 import path — does the range check via Sm2PrivateKey::from_sec1_be.
        let key_opt: Option<Sm2PrivateKey> = Sm2PrivateKey::from_sec1_be(arr).into_option();
        key_opt.map(|inner| Box::into_raw(Box::new(gmcrypto_sm2_privkey_t { inner })))
    });
    match result {
        Ok(Some(p)) => p,
        _ => ptr::null_mut(),
    }
}

/// Construct an SM2 public key from a SEC1 uncompressed-point byte
/// string (`04 || X || Y`, 65 bytes). Returns NULL on
/// invalid input (off-curve, identity point, non-uncompressed
/// prefix).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_pubkey_new(
    sec1_uncompressed: *const u8,
) -> *mut gmcrypto_sm2_pubkey_t {
    let result = std::panic::catch_unwind(|| {
        let bytes = unsafe { try_slice(sec1_uncompressed, GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE) }?;
        let key = Sm2PublicKey::from_sec1_bytes(bytes)?;
        Some(Box::into_raw(Box::new(gmcrypto_sm2_pubkey_t {
            inner: key,
        })))
    });
    match result {
        Ok(Some(p)) => p,
        _ => ptr::null_mut(),
    }
}

/// Export the SM2 private key as a 32-byte big-endian scalar.
///
/// **Caller MUST zeroize the output buffer** after use. Per Q4.19,
/// this entry point exists as `#[doc(hidden)]`-equivalent on the
/// Rust side and is NOT SemVer-stable across v0.4.x.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_privkey_to_sec1_be(
    key: *const gmcrypto_sm2_privkey_t,
    out: *mut u8,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let o = match unsafe { try_slice_mut(out, GMCRYPTO_SM2_SCALAR_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        let bytes = k.inner.to_sec1_be();
        o.copy_from_slice(&bytes);
        // The caller is responsible for zeroizing `out`. The
        // temporary `bytes` is a `[u8; 32]` on the stack; Rust's
        // stack lifetime is the wipe boundary.
        GMCRYPTO_OK
    })
}

/// Export the SM2 public key as a SEC1 uncompressed-point byte
/// string (`04 || X || Y`, 65 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_pubkey_to_sec1_uncompressed(
    key: *const gmcrypto_sm2_pubkey_t,
    out: *mut u8,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let o = match unsafe { try_slice_mut(out, GMCRYPTO_SM2_SEC1_UNCOMPRESSED_SIZE) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        let bytes = k.inner.to_sec1_uncompressed();
        o.copy_from_slice(&bytes);
        GMCRYPTO_OK
    })
}

/// Free an SM2 private key. NULL is a no-op. The inner scalar is
/// zeroized via `ZeroizeOnDrop` before the heap slot is freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_privkey_free(key: *mut gmcrypto_sm2_privkey_t) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Free an SM2 public key. NULL is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_pubkey_free(key: *mut gmcrypto_sm2_pubkey_t) {
    if key.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(key) });
}

/// Emit a password-encrypted PKCS#8 PEM blob containing the SM2
/// private key. PBES2 / PBKDF2-HMAC-SM3 / SM4-CBC per RFC 8018.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_privkey_to_pkcs8(
    key: *const gmcrypto_sm2_privkey_t,
    password: *const u8,
    pwd_len: usize,
    pbkdf2_iters: u32,
    out_pem: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let pwd = match unsafe { try_slice(password, pwd_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        // Generate a fresh 16-byte salt and IV from SysRng. PBKDF2's
        // salt is public; SM4-CBC's IV must be unpredictable (NIST
        // SP 800-38A Appendix C). SysRng satisfies both.
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 16];
        if getrandom::SysRng.try_fill_bytes(&mut salt).is_err() {
            return GMCRYPTO_ERR;
        }
        if getrandom::SysRng.try_fill_bytes(&mut iv).is_err() {
            return GMCRYPTO_ERR;
        }
        let der = match pkcs8::encrypt(&k.inner, pwd, &salt, pbkdf2_iters, &iv) {
            Ok(d) => d,
            Err(_) => return GMCRYPTO_ERR,
        };
        let pem_blob = pem::encode("ENCRYPTED PRIVATE KEY", &der);
        unsafe { write_output(pem_blob.as_bytes(), out_pem, out_capacity, out_actual_len) }
    })
}

/// Load an SM2 private key from a password-encrypted PKCS#8 PEM blob.
/// On success, writes the new handle to `*out_key` and returns
/// [`GMCRYPTO_OK`]. Caller MUST free via [`gmcrypto_sm2_privkey_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_privkey_from_pkcs8(
    pem: *const u8,
    pem_len: usize,
    password: *const u8,
    pwd_len: usize,
    out_key: *mut *mut gmcrypto_sm2_privkey_t,
) -> c_int {
    ffi_guard(|| {
        if out_key.is_null() {
            return GMCRYPTO_ERR;
        }
        let pem_bytes = match unsafe { try_slice(pem, pem_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let pwd = match unsafe { try_slice(password, pwd_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let pem_str = match core::str::from_utf8(pem_bytes) {
            Ok(s) => s,
            Err(_) => return GMCRYPTO_ERR,
        };
        let der = match pem::decode(pem_str, "ENCRYPTED PRIVATE KEY") {
            Ok(d) => d,
            Err(_) => return GMCRYPTO_ERR,
        };
        let key = match pkcs8::decrypt(&der, pwd) {
            Ok(k) => k,
            Err(_) => return GMCRYPTO_ERR,
        };
        let boxed = Box::into_raw(Box::new(gmcrypto_sm2_privkey_t { inner: key }));
        // SAFETY: out_key non-null per check above.
        unsafe { ptr::write(out_key, boxed) };
        GMCRYPTO_OK
    })
}

// ============================================================
// SM2 — sign / verify / encrypt / decrypt.
// ============================================================

/// Sign `msg` with the SM2 private key using the supplied
/// `signer_id` (or [`DEFAULT_SIGNER_ID`] = `"1234567812345678"` if
/// `signer_id_len == 0`). Output is DER-encoded
/// `SEQUENCE { r, s }`. RNG is sourced from `getrandom::SysRng`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_sign(
    key: *const gmcrypto_sm2_privkey_t,
    signer_id: *const u8,
    signer_id_len: usize,
    msg: *const u8,
    msg_len: usize,
    out_der_sig: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let id: &[u8] = if signer_id_len == 0 {
            DEFAULT_SIGNER_ID
        } else {
            match unsafe { try_slice(signer_id, signer_id_len) } {
                Some(s) => s,
                None => return GMCRYPTO_ERR,
            }
        };
        let m = match unsafe { try_slice(msg, msg_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let sig = match sign_with_id(&k.inner, id, m, &mut rng) {
            Ok(s) => s,
            Err(_) => return GMCRYPTO_ERR,
        };
        unsafe { write_output(&sig, out_der_sig, out_capacity, out_actual_len) }
    })
}

/// Verify a DER-encoded `(r, s)` signature against `msg` using the
/// SM2 public key and `signer_id`. Returns [`GMCRYPTO_OK`] on
/// valid; [`GMCRYPTO_ERR`] on invalid or any error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_verify(
    key: *const gmcrypto_sm2_pubkey_t,
    signer_id: *const u8,
    signer_id_len: usize,
    msg: *const u8,
    msg_len: usize,
    der_sig: *const u8,
    der_sig_len: usize,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let id: &[u8] = if signer_id_len == 0 {
            DEFAULT_SIGNER_ID
        } else {
            match unsafe { try_slice(signer_id, signer_id_len) } {
                Some(s) => s,
                None => return GMCRYPTO_ERR,
            }
        };
        let m = match unsafe { try_slice(msg, msg_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let sig = match unsafe { try_slice(der_sig, der_sig_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        if verify_with_id(&k.inner, id, m, sig) {
            GMCRYPTO_OK
        } else {
            GMCRYPTO_ERR
        }
    })
}

/// SM2 public-key encrypt. Output is GM/T 0009-2012 DER. RNG from
/// `getrandom::SysRng`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_encrypt(
    key: *const gmcrypto_sm2_pubkey_t,
    pt: *const u8,
    pt_len: usize,
    out_der_ct: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let p = match unsafe { try_slice(pt, pt_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let ct = match sm2_encrypt(&k.inner, p, &mut rng) {
            Ok(c) => c,
            Err(_) => return GMCRYPTO_ERR,
        };
        unsafe { write_output(&ct, out_der_ct, out_capacity, out_actual_len) }
    })
}

/// SM2 private-key decrypt of a GM/T 0009-2012 DER ciphertext.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmcrypto_sm2_decrypt(
    key: *const gmcrypto_sm2_privkey_t,
    der_ct: *const u8,
    der_ct_len: usize,
    out_pt: *mut u8,
    out_capacity: usize,
    out_actual_len: *mut usize,
) -> c_int {
    ffi_guard(|| {
        if key.is_null() {
            return GMCRYPTO_ERR;
        }
        let c = match unsafe { try_slice(der_ct, der_ct_len) } {
            Some(s) => s,
            None => return GMCRYPTO_ERR,
        };
        let k = unsafe { &*key };
        match sm2_decrypt(&k.inner, c) {
            Ok(pt) => unsafe { write_output(&pt, out_pt, out_capacity, out_actual_len) },
            Err(_) => GMCRYPTO_ERR,
        }
    })
}
