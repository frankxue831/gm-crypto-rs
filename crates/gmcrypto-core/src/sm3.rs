//! SM3 hash function (GB/T 32905-2016).
//!
//! 256-bit Merkle-Damgård hash. Block size 512 bits, output 256 bits.

use core::convert::TryInto;

const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

const T_J_LOW: u32 = 0x79cc_4519; // T_j for 0..=15
const T_J_HIGH: u32 = 0x7a87_9d8a; // T_j for 16..=63

/// SM3 digest output size in bytes (32 = 256 bits).
pub const DIGEST_SIZE: usize = 32;

/// Internal block size in bytes (64 = 512 bits).
pub const BLOCK_SIZE: usize = 64;

/// One-shot SM3 hash. Returns the 32-byte digest.
#[must_use]
pub fn hash(message: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sm3::new();
    hasher.update(message);
    hasher.finalize()
}

/// Streaming SM3 hasher.
#[derive(Clone, Debug)]
pub struct Sm3 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64, // total input bytes; SM3 length field is 64 bits big-endian
}

impl Default for Sm3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3 {
    /// Create a fresh SM3 hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: IV,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Absorb input bytes.
    #[allow(clippy::missing_panics_doc)]
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Fill the partial buffer first if there is one.
        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == BLOCK_SIZE {
                let block = self.buffer;
                compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks directly out of `data`.
        while data.len() >= BLOCK_SIZE {
            let (block, rest) = data.split_at(BLOCK_SIZE);
            compress(
                &mut self.state,
                block.try_into().expect("BLOCK_SIZE-len slice"),
            );
            data = rest;
        }

        // Stash the trailing partial block.
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Produce the final digest, consuming the hasher.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        // SM3 padding: append 0x80, then zeros, then 64-bit big-endian bit length.
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > BLOCK_SIZE - 8 {
            // Not enough room for the length field; flush this block, then a final
            // block of zeros + length.
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffer = [0u8; BLOCK_SIZE];
            self.buffer_len = 0;
        }

        for byte in &mut self.buffer[self.buffer_len..BLOCK_SIZE - 8] {
            *byte = 0;
        }
        self.buffer[BLOCK_SIZE - 8..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        compress(&mut self.state, &block);

        let mut out = [0u8; DIGEST_SIZE];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

#[inline]
const fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}
#[inline]
const fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}
#[inline]
const fn ff_low(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
#[inline]
const fn ff_high(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
#[inline]
const fn gg_low(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
#[inline]
const fn gg_high(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[allow(clippy::many_single_char_names)]
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    // Message expansion: W[0..16] from block, W[16..68] derived, W'[0..64] = W[j] XOR W[j+4].
    let mut w = [0u32; 68];
    for j in 0..16 {
        w[j] = u32::from_be_bytes(block[j * 4..(j + 1) * 4].try_into().expect("4-byte slice"));
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }
    let mut wp = [0u32; 64];
    for j in 0..64 {
        wp[j] = w[j] ^ w[j + 4];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for j in 0..64 {
        let t_j = if j < 16 { T_J_LOW } else { T_J_HIGH };
        #[allow(clippy::cast_possible_truncation)]
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(t_j.rotate_left((j % 32) as u32))
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let (ff, gg) = if j < 16 {
            (ff_low(a, b, c), gg_low(e, f, g))
        } else {
            (ff_high(a, b, c), gg_high(e, f, g))
        };
        let tt1 = ff.wrapping_add(d).wrapping_add(ss2).wrapping_add(wp[j]);
        let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

#[cfg(feature = "digest-traits")]
mod digest_impl {
    //! `digest::Digest`-compatible impl for [`Sm3`] (v0.4 W2; Q4.3).
    //!
    //! Behind the `digest-traits` feature flag. Default-features build
    //! does not pull `digest` into the dep graph.

    use super::{DIGEST_SIZE, Sm3};
    use digest::{
        FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
        consts::U32,
    };

    impl HashMarker for Sm3 {}

    impl OutputSizeUser for Sm3 {
        type OutputSize = U32;
    }

    impl Update for Sm3 {
        fn update(&mut self, data: &[u8]) {
            Self::update(self, data);
        }
    }

    impl FixedOutput for Sm3 {
        fn finalize_into(self, out: &mut Output<Self>) {
            let digest: [u8; DIGEST_SIZE] = Self::finalize(self);
            out.copy_from_slice(&digest);
        }
    }

    impl Reset for Sm3 {
        fn reset(&mut self) {
            *self = Self::new();
        }
    }

    impl FixedOutputReset for Sm3 {
        fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
            let mut taken = Self::new();
            core::mem::swap(self, &mut taken);
            let digest: [u8; DIGEST_SIZE] = Self::finalize(taken);
            out.copy_from_slice(&digest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// GB/T 32905-2016 Appendix A.1 — empty input.
    #[test]
    fn hash_empty() {
        assert_eq!(
            hash(&[]),
            hex!("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
        );
    }

    /// GB/T 32905-2016 Appendix A.1 — input "abc".
    #[test]
    fn hash_abc() {
        assert_eq!(
            hash(b"abc"),
            hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        );
    }

    /// GB/T 32905-2016 Appendix A.2 — 64-byte input ("abcd" repeated 16 times).
    #[test]
    fn hash_sixteen_abcd() {
        let input = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        assert_eq!(
            hash(input),
            hex!("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        );
    }

    /// 63 zero bytes (just below block boundary). Source: gmssl CLI output.
    #[test]
    fn hash_sixty_three_zeroes() {
        let zeroes = [0u8; 63];
        assert_eq!(
            hash(&zeroes),
            hex!("5241dc10cb3c700e46446943d27b971fefa7e88115f866d6f83d502ff1bc06c2"),
        );
    }

    /// Streaming API: feeding "ab" then "c" must equal one-shot hash("abc").
    #[test]
    fn streaming_matches_one_shot() {
        let mut h = Sm3::new();
        h.update(b"ab");
        h.update(b"c");
        assert_eq!(h.finalize(), hash(b"abc"));
    }
}
