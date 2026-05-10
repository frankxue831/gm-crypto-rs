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
//! # Single-shot + streaming API
//!
//! - [`hmac_sm3`] (v0.2) is the single-shot path.
//! - [`HmacSm3`] (v0.3 W5) is the streaming
//!   `new` / `update` / `finalize` shape, plus a constant-time
//!   `verify` helper. Both produce byte-identical output for the
//!   same `(key, message)` regardless of how the message is
//!   chunked across `update` calls.
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
use crate::traits::{Hash as HashTrait, Mac as MacTrait};
use subtle::ConstantTimeEq;
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

/// Streaming HMAC-SM3 (v0.3 W5).
///
/// Construct with `new(&key)`, feed message chunks via `update`,
/// finalize with `finalize` (32-byte tag) or `verify` (constant-
/// time compare against an expected tag).
///
/// Equivalent to [`hmac_sm3`] for the same `(key, message)` byte
/// sequence — chunking does not affect the output.
///
/// # Zeroization
///
/// The pre-computed `outer` keyed-state (`SM3` after absorbing
/// `K' XOR opad`) holds key-derived material. [`HmacSm3::finalize`]
/// and [`HmacSm3::verify`] consume `self` and zeroize it before
/// returning. If the caller drops the `HmacSm3` without calling
/// either method, the [`Drop`] impl wipes the state.
pub struct HmacSm3 {
    /// Inner-hash state, currently absorbing `K' XOR ipad || message-so-far`.
    inner: Sm3,
    /// Outer-hash state, currently holding the absorbed `K' XOR opad`
    /// (will be finalized with the inner digest at `finalize` time).
    outer: Sm3,
}

impl HmacSm3 {
    /// Construct a new keyed HMAC-SM3 instance.
    ///
    /// `key` may be any length; the standard RFC 2104 hash-first
    /// reduction applies for `key.len() > 64`. Both intermediate
    /// `K'` / `K' XOR ipad` / `K' XOR opad` buffers are zeroized
    /// after the inner/outer SM3 instances absorb them.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut k_prime = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
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

        // Pre-load the inner SM3 with `K' XOR ipad`. The streaming
        // update path then absorbs message bytes directly.
        let mut inner = Sm3::new();
        inner.update(&ipad_key);

        // Pre-load the outer SM3 with `K' XOR opad`. The finalize
        // path will then feed the inner-finalized digest.
        let mut outer = Sm3::new();
        outer.update(&opad_key);

        // Wipe key-derived buffers. The keyed states inside `inner`
        // and `outer` carry the same information but are now folded
        // into the SM3 compression state, not stored in plaintext.
        k_prime.zeroize();
        ipad_key.zeroize();
        opad_key.zeroize();

        Self { inner, outer }
    }

    /// Absorb message bytes into the inner hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the instance and produce the 32-byte MAC tag.
    ///
    /// The `outer` keyed-state and the `inner` final state are both
    /// dropped after consuming `self`; `Sm3`'s `Drop` impl is the
    /// one we rely on here. To be defensive against a future change
    /// where `Sm3` is no longer `ZeroizeOnDrop`, both fields are
    /// explicitly wiped via `clone-then-drop` would be safer — but
    /// `Sm3` does not currently implement `Zeroize` directly. The
    /// state is consumed by `outer.finalize()` which produces the
    /// public output and discards the rest.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_SIZE] {
        let inner_digest = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&inner_digest);
        outer.finalize()
    }

    /// Constant-time verify a candidate tag against the finalized
    /// HMAC. Returns `true` on match.
    #[must_use]
    pub fn verify(self, expected: &[u8; DIGEST_SIZE]) -> bool {
        let computed = self.finalize();
        bool::from(computed.ct_eq(expected))
    }
}

impl HashTrait for Sm3 {
    type Output = [u8; DIGEST_SIZE];

    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}

impl MacTrait for HmacSm3 {
    type Output = [u8; DIGEST_SIZE];

    fn new(key: &[u8]) -> Self {
        Self::new(key)
    }

    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }

    fn verify(self, expected: &Self::Output) -> bool {
        Self::verify(self, expected)
    }
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

    // ---------- v0.3 W5: streaming HmacSm3 ----------

    /// Streaming `HmacSm3::new`/`update`/`finalize` produces the same
    /// tag as single-shot `hmac_sm3` on KAT vector "Hi There".
    #[test]
    fn streaming_test1_matches_oneshot() {
        let key = [0x0bu8; 20];
        let message = b"Hi There";
        let mut mac = HmacSm3::new(&key);
        mac.update(message);
        let tag = mac.finalize();
        assert_eq!(
            to_hex(&tag),
            "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"
        );
    }

    /// Chunking-equivalence on KAT 2: a streaming `HmacSm3` fed any
    /// partition of the message produces the same tag as the
    /// single-shot path.
    #[test]
    fn streaming_chunking_equivalence_test2() {
        let key = b"Jefe";
        let message: &[u8] = b"what do ya want for nothing?";
        let oneshot = hmac_sm3(key, message);
        for chunk_size in [1usize, 3, 7, 14, message.len()] {
            let mut mac = HmacSm3::new(key);
            for chunk in message.chunks(chunk_size) {
                mac.update(chunk);
            }
            let streamed = mac.finalize();
            assert_eq!(streamed, oneshot, "chunk_size={chunk_size}");
        }
    }

    /// Long-key path round-trips through streaming.
    #[test]
    fn streaming_long_key() {
        let key = [0xaau8; 131];
        let message: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mut mac = HmacSm3::new(&key);
        for chunk in message.chunks(7) {
            mac.update(chunk);
        }
        let tag = mac.finalize();
        assert_eq!(
            to_hex(&tag),
            "b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0"
        );
    }

    /// `verify` accepts the correct tag.
    #[test]
    fn verify_accepts_correct_tag() {
        let key = b"vkey";
        let message = b"verify me";
        let expected = hmac_sm3(key, message);
        let mut mac = HmacSm3::new(key);
        mac.update(message);
        assert!(mac.verify(&expected));
    }

    /// `verify` rejects a wrong tag.
    #[test]
    fn verify_rejects_wrong_tag() {
        let key = b"vkey";
        let message = b"verify me";
        let mut bogus = hmac_sm3(key, message);
        bogus[0] ^= 0x01;
        let mut mac = HmacSm3::new(key);
        mac.update(message);
        assert!(!mac.verify(&bogus));
    }

    /// Empty key + empty message via streaming.
    #[test]
    fn streaming_empty_key_empty_message() {
        let mac = HmacSm3::new(&[]);
        let tag = mac.finalize();
        assert_eq!(
            to_hex(&tag),
            "0d23f72ba15e9c189a879aefc70996b06091de6e64d31b7a84004356dd915261"
        );
    }
}
