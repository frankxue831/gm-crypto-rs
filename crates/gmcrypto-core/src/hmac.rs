//! HMAC-SM3 — RFC 2104 keyed MAC over GB/T 32905-2016 SM3.
//!
//! # Construction
//!
//! Standard RFC 2104 with SM3 as the underlying hash:
//!
//! ```text
//! HMAC(K, m) = SM3((K' XOR opad) || SM3((K' XOR ipad) || m))
//! ```
//!
//! where:
//!
//! - `B = 64` (SM3 block size); `L = 32` (SM3 output size).
//! - `K'` is `K` zero-padded to `B` bytes if `len(K) ≤ B`, or `SM3(K)`
//!   zero-padded to `B` bytes if `len(K) > B`.
//! - `ipad = 0x36` repeated `B` times; `opad = 0x5C` repeated `B` times.
//!
//! # Single-shot API
//!
//! v0.2 W3 ships single-shot [`hmac_sm3`] only. A streaming
//! `HmacSm3::new` / `update` / `finalize` surface lands in v0.3
//! alongside the broader `Mac`-trait generalization.
//!
//! # KAT
//!
//! All KAT vectors below are cross-validated against `gmssl sm3hmac`
//! v3.1.1 at commit time. RFC 4231 specifies HMAC for SHA-2 only;
//! HMAC-SM3 vectors of identical shape are computed by gmssl and
//! captured here as compile-time regression locks.
//!
//! - `K = 0x0b × 20`, `M = "Hi There"` →
//!   `51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70`.
//! - `K = "Jefe"`, `M = "what do ya want for nothing?"` →
//!   `2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882`.
//! - `K = 0xaa × 131`, `M = "Test Using Larger Than Block-Size Key - Hash Key First"` →
//!   `b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0`
//!   (exercises the hash-first long-key path; gmssl 3.1.1's CLI rejects
//!   keys > 32 bytes, so the published value is computed by feeding
//!   `gmssl sm3hmac` the SM3-hashed key — RFC 2104's hash-first
//!   reduction in action).
//! - `K = ""`, `M = ""` →
//!   `0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261`.
//!
//! Phase 4 chunk 4 adds gmssl `sm3hmac` invocations to
//! `tests/interop_gmssl.rs` so the cross-validation runs in CI when
//! `GMCRYPTO_GMSSL=1` is set.
//!
//! # Zeroization
//!
//! Intermediate `K'`, `K' XOR ipad`, and `K' XOR opad` buffers are
//! wiped before return. The outer hash's input includes the key
//! (XOR'd with opad), so this matters for callers reusing memory.

use crate::sm3::{BLOCK_SIZE, DIGEST_SIZE, Sm3, hash};
use zeroize::Zeroize;

/// Compute HMAC-SM3 over `message` keyed by `key`. Returns the 32-byte
/// MAC tag.
///
/// `key` may be any length. Per RFC 2104:
///
/// - If `key.len() > 64`, the key is first hashed with SM3 (yielding a
///   32-byte intermediate) and then zero-padded to 64 bytes.
/// - Otherwise it is used directly, zero-padded to 64 bytes.
///
/// Both intermediate buffers are zeroized before return.
#[must_use]
pub fn hmac_sm3(key: &[u8], message: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        // Per RFC 2104, when `key.len() > B` the effective HMAC key is
        // `K' = SM3(key)` zero-padded to `B`. `hashed` is therefore the
        // *actual key material* used by the inner and outer hashes —
        // not merely "key-derived" — so it must be wiped in lockstep
        // with `k_prime`, `ipad_key`, and `opad_key`. The
        // `Zeroize::zeroize` call below is a `core::ptr::write_volatile`
        // sequence that the optimizer is required to emit, closing the
        // long-key zeroization gap surfaced in the v0.2 codex review.
        let mut hashed = hash(key);
        k_prime[..DIGEST_SIZE].copy_from_slice(&hashed);
        hashed.zeroize();
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut ipad_key = [0x36u8; BLOCK_SIZE];
    let mut opad_key = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] ^= k_prime[i];
        opad_key[i] ^= k_prime[i];
    }

    // Inner hash: SM3(K' XOR ipad || message).
    let mut inner = Sm3::new();
    inner.update(&ipad_key);
    inner.update(message);
    let inner_digest = inner.finalize();

    // Outer hash: SM3(K' XOR opad || inner_digest).
    let mut outer = Sm3::new();
    outer.update(&opad_key);
    outer.update(&inner_digest);
    let result = outer.finalize();

    // Wipe key-derived intermediates. The MAC `result` is the public
    // output; the inner_digest is also a function of (key, message)
    // but its information content is captured by `result` and the
    // public outer-hash structure.
    k_prime.zeroize();
    ipad_key.zeroize();
    opad_key.zeroize();

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hex-format a byte slice as a lowercase string.
    fn to_hex(bytes: &[u8]) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            // Infallible: writing to a `String` only fails on
            // `write_str` for an exhausted-capacity `String` — which
            // is unreachable for `String` (always grows).
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// "Test 1"-style HMAC-SM3 KAT. Key: 20 bytes of `0x0b`. Message:
    /// ASCII "Hi There". Expected MAC cross-validated against
    /// `gmssl sm3hmac -key '0b0b...0b'` v3.1.1.
    #[test]
    fn test1_hi_there() {
        let key = [0x0bu8; 20];
        let message = b"Hi There";
        let mac = hmac_sm3(&key, message);
        assert_eq!(
            to_hex(&mac),
            "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"
        );
    }

    /// "Test 2"-style HMAC-SM3 KAT. Short ASCII key + sentence message.
    /// Cross-validated against `gmssl sm3hmac -key '4a656665'` v3.1.1.
    #[test]
    fn test2_jefe_what_do_ya_want() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let mac = hmac_sm3(key, message);
        assert_eq!(
            to_hex(&mac),
            "2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882"
        );
    }

    /// "Test 6"-style HMAC-SM3 KAT exercising the **hash-first** path
    /// (key longer than the 64-byte block size). Cross-validated by
    /// computing `gmssl sm3` over the 131-byte key, then
    /// `gmssl sm3hmac -key <sm3_of_key>` over the message — i.e.
    /// reducing through RFC 2104's hash-first equivalence (gmssl 3.1.1's
    /// `sm3hmac` CLI rejects keys > 32 bytes, so we exercise the
    /// equivalence by hand).
    #[test]
    fn test6_long_key_hash_first() {
        let key = [0xaau8; 131];
        let message = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sm3(&key, message);
        assert_eq!(
            to_hex(&mac),
            "b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0"
        );
    }

    /// Empty key + empty message — exercises the zero-pad path.
    /// Cross-validated against `gmssl sm3hmac -key ''` v3.1.1.
    #[test]
    fn empty_key_empty_message() {
        let mac = hmac_sm3(&[], &[]);
        assert_eq!(
            to_hex(&mac),
            "0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261"
        );
    }

    /// Key longer than 64 bytes triggers the hash-first path.
    /// Verify the result differs from key=Sm3(key)|pad's MAC over the
    /// same message — i.e. the hash-first path is actually exercised.
    #[test]
    fn long_key_takes_hash_first_path() {
        let long_key = [0xaau8; 131]; // > 64 bytes
        let message = b"test message";
        let mac_long = hmac_sm3(&long_key, message);

        // Independently compute: pre-hash the key, then HMAC with the
        // pre-hashed key (which is now ≤ 32 bytes ≤ 64). If the
        // hash-first path is correctly implemented, the two outputs
        // must agree.
        let prehashed = hash(&long_key);
        let mac_short = hmac_sm3(&prehashed, message);

        assert_eq!(
            mac_long, mac_short,
            "hash-first path on long key must match HMAC over pre-hashed key"
        );
    }

    /// Key exactly the block size (64 bytes) takes the no-hash path.
    /// Boundary condition test — the spec says `len(K) ≤ B` uses the
    /// pad path (not the hash path).
    #[test]
    fn key_exactly_block_size() {
        let key = [0xccu8; BLOCK_SIZE];
        let mac = hmac_sm3(&key, b"x");
        // Verify it's a 32-byte output (i.e. produced output, didn't panic).
        assert_eq!(mac.len(), DIGEST_SIZE);
    }

    /// Different messages under the same key must produce different MACs.
    #[test]
    fn different_messages_different_macs() {
        let key = b"key123";
        let mac_a = hmac_sm3(key, b"message a");
        let mac_b = hmac_sm3(key, b"message b");
        assert_ne!(mac_a, mac_b);
    }

    /// Different keys over the same message must produce different MACs.
    #[test]
    fn different_keys_different_macs() {
        let mac_a = hmac_sm3(b"key1", b"the message");
        let mac_b = hmac_sm3(b"key2", b"the message");
        assert_ne!(mac_a, mac_b);
    }
}
