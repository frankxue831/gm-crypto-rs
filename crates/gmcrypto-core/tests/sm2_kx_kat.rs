//! GB/T 32918.5-2017 / GM/T 0003.5 SM2 key-exchange worked example on the
//! RECOMMENDED SM2 curve (p = FFFFFFFE…) — the curve this library hard-codes.
//! NOT the GB/T 32918.3 `8542D69E…` test-curve Annex (those vectors cannot
//! reproduce here; see docs/v1.1-sm2kx-kat-sourcing.md).
//! cfg-gated on `sm2-key-exchange`.
#![cfg(feature = "sm2-key-exchange")]
#![allow(dead_code)] // constants land first (Task 0.2); tests consume them later

use hex_literal::hex;

const ID_A: &[u8] = b"ALICE123@YAHOO.COM";
const ID_B: &[u8] = b"BILL456@YAHOO.COM";
const KLEN: usize = 16; // 128-bit example

// Static private keys (big-endian, 32 bytes) — recommended-curve example,
// confident (multiple independent sources agree):
const D_A: [u8; 32] =
    hex!("81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029");
const D_B: [u8; 32] =
    hex!("785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5");

// Ephemeral private keys (fed via a fixed-scalar TryCryptoRng) — HUMAN-GATED:
// transcribe from the recommended-curve worked example + cross-verify against
// gmsm/GmSSL test code before trusting. Do NOT reuse the test-curve values;
// do NOT invent hex. Uncommented in Task 1.5 once supplied/confirmed.
// pub const R_A_EPH: [u8; 32] = hex!("<FILL: recommended-curve r_A>");
// pub const R_B_EPH: [u8; 32] = hex!("<FILL: recommended-curve r_B>");

// EXPECTED OUTPUTS — K is the documented recommended-curve value (confident):
const EXPECT_K: [u8; KLEN] = hex!("6C89347354DE2484C60B4AB1FDE4C6E5");
// S_A / S_B confirmation tags — HUMAN-GATED, same discipline as the ephemerals
// (filled in Task 2.3):
// pub const EXPECT_S_A: [u8; 32] = hex!("<FILL>");
// pub const EXPECT_S_B: [u8; 32] = hex!("<FILL>");
