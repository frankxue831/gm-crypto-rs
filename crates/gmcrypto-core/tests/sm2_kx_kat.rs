//! GB/T 32918.5-2017 / GM/T 0003.5 SM2 key-exchange worked example on the
//! RECOMMENDED SM2 curve (p = FFFFFFFE…) — the curve this library hard-codes.
//! NOT the GB/T 32918.3 `8542D69E…` test-curve Annex (those vectors cannot
//! reproduce here; see docs/v1.1-sm2kx-kat-sourcing.md).
//!
//! Human-gated values transcribed from the recommended-curve worked example
//! (maintainer-verified against /private/tmp/sm2pdf/params-hi-01.png + -02.png,
//! 2026-06-10). cfg-gated on `sm2-key-exchange`.
#![cfg(feature = "sm2-key-exchange")]

use gmcrypto_core::sm2::key_exchange::{Sm2KxInitiator, Sm2KxResponder};
use gmcrypto_core::sm2::{Sm2PrivateKey, compute_z};
use hex_literal::hex;

// Both parties use the DEFAULT ID "1234567812345678" in the GM/T
// 0003.5-2012 recommended-curve worked example. The ALICE123@YAHOO.COM /
// BILL456@YAHOO.COM identities belong to the GB/T 32918.3 *test-curve*
// Annex — using them here reproduces every point but derives the wrong
// Z_A/Z_B (and hence K); see docs/v1.1-sm2kx-kat-sourcing.md.
const ID_A: &[u8] = b"1234567812345678";
const ID_B: &[u8] = b"1234567812345678";
const KLEN: usize = 16; // 128-bit example

// Static private keys (big-endian, 32 bytes) — recommended-curve example:
const D_A: [u8; 32] =
    hex!("81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029");
const D_B: [u8; 32] =
    hex!("785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5");

// Ephemeral private keys (fed via the fixed-scalar TryCryptoRng below) —
// human-gated, maintainer-confirmed from the recommended-curve example:
const R_A_EPH: [u8; 32] =
    hex!("D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3");
const R_B_EPH: [u8; 32] =
    hex!("7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6");

// Intermediate values from the worked example (staged assertions localize
// any divergence to the exact step that introduced it):
// Static public points P_A / P_B (SEC1 uncompressed 04‖X‖Y).
const P_A_SEC1: [u8; 65] = hex!(
    "04160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F"
);
const P_B_SEC1: [u8; 65] = hex!(
    "046AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D"
);
// Ephemeral public points R_A / R_B.
const R_A_SEC1: [u8; 65] = hex!(
    "0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0"
);
const R_B_SEC1: [u8; 65] = hex!(
    "04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE"
);
// Party hashes Z_A / Z_B as printed in the worked example's KDF input.
const Z_A_STD: [u8; 32] =
    hex!("3B85A57179E11E7E513AA622991F2CA74D1807A0BD4D4B38F90987A17AC245B1");
const Z_B_STD: [u8; 32] =
    hex!("79C988D63229D97EF19FE02CA1056E01E6A7411ED24694AA8F834F4A4AB022F7");
// Shared point U = V (not API-observable; recorded for documentation —
// the K assertion covers it transitively):
//   x_U = C558B44BEE5301D9F52B44D939BB59584D75B9034DD6A9FC826872109A65739F
//   y_U = 3252B35B191D8AE01CD122C025204334C5EACF68A0CB4854C6A7D367ECAD4DE7

// EXPECTED OUTPUTS:
const EXPECT_K: [u8; KLEN] = hex!("6C89347354DE2484C60B4AB1FDE4C6E5");
// Confirmation tags (asserted from Task 2.3; inner hash for reference:
// SM3(x_U‖Z_A‖Z_B‖x1‖y1‖x2‖y2) =
//   90E2A628E4F57ABD78339EA33F967D11A154117BEA442F7B627D4F4DD047B7F6).
const EXPECT_S_B: [u8; 32] =
    hex!("D3A0FE15DEE185CEAE907A6B595CC32A266ED7B3367E9983A896DC32FA20F8EB");
const EXPECT_S_A: [u8; 32] =
    hex!("18C7894B3816DF16CF07B05C5EC0BEF5D655D58F779CC1B400A4F3884644DB88");

/// Fixed-bytes `TryCryptoRng` — integration tests cannot reach the
/// module-private `#[cfg(test)]` helper, so the 3-line impl is inlined
/// here (plan amendment S10).
struct FixedScalarRng([u8; 32]);

impl rand_core::TryRng for FixedScalarRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(dst.len(), 32);
        dst.copy_from_slice(&self.0);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for FixedScalarRng {}

/// Stage 1: the static key pairs and the party hashes. A failure here
/// means the d→P derivation or `compute_z` diverges from the standard
/// before any key-exchange math runs.
#[test]
fn statics_and_z_match_standard() {
    let da = Sm2PrivateKey::from_bytes_be(&D_A).unwrap();
    let db = Sm2PrivateKey::from_bytes_be(&D_B).unwrap();
    let (pa, pb) = (da.public_key(), db.public_key());

    assert_eq!(pa.to_sec1_uncompressed(), P_A_SEC1, "P_A != standard");
    assert_eq!(pb.to_sec1_uncompressed(), P_B_SEC1, "P_B != standard");

    assert_eq!(compute_z(&pa, ID_A), Z_A_STD, "Z_A != standard");
    assert_eq!(compute_z(&pb, ID_B), Z_B_STD, "Z_B != standard");
}

/// Stage 2: the ephemeral points from the fixed standard ephemerals.
#[test]
fn ephemerals_match_standard() {
    let da = Sm2PrivateKey::from_bytes_be(&D_A).unwrap();
    let db = Sm2PrivateKey::from_bytes_be(&D_B).unwrap();
    let (pa, pb) = (da.public_key(), db.public_key());

    let init = Sm2KxInitiator::new(&da, &pb, ID_A, ID_B, KLEN).unwrap();
    let (ra, _iw) = init
        .produce_ephemeral(&mut FixedScalarRng(R_A_EPH))
        .unwrap();
    assert_eq!(ra.to_bytes(), R_A_SEC1, "R_A != standard");

    let resp = Sm2KxResponder::new(&db, &pa, ID_A, ID_B, KLEN).unwrap();
    let (rb, _sb, _rw) = resp
        .respond(&ra, &mut FixedScalarRng(R_B_EPH))
        .unwrap();
    assert_eq!(rb.to_bytes(), R_B_SEC1, "R_B != standard");
}

/// Stage 3: the full agreement — K must be byte-identical to the
/// worked example on both sides.
#[test]
fn annex_shared_key_matches_standard() {
    let da = Sm2PrivateKey::from_bytes_be(&D_A).unwrap();
    let db = Sm2PrivateKey::from_bytes_be(&D_B).unwrap();
    let (pa, pb) = (da.public_key(), db.public_key());
    let mut rng_a = FixedScalarRng(R_A_EPH);
    let mut rng_b = FixedScalarRng(R_B_EPH);

    let init = Sm2KxInitiator::new(&da, &pb, ID_A, ID_B, KLEN).unwrap();
    let (ra, iw) = init.produce_ephemeral(&mut rng_a).unwrap();
    let resp = Sm2KxResponder::new(&db, &pa, ID_A, ID_B, KLEN).unwrap();
    let (rb, sb, rw) = resp.respond(&ra, &mut rng_b).unwrap();
    // Confirmation tags byte-identical to the worked example (Task 2.3):
    // S_B is the page's 选项 S_1 (0x02 prefix), S_A the 选项 S_A (0x03).
    assert_eq!(sb.to_bytes(), EXPECT_S_B, "S_B != standard value");
    let (k_a, sa) = iw.confirm(&rb, &sb).unwrap();
    assert_eq!(sa.to_bytes(), EXPECT_S_A, "S_A != standard value");
    let k_b = rw.finish(&sa).unwrap();

    assert_eq!(k_a.as_bytes(), EXPECT_K, "K != standard value");
    assert_eq!(k_a.as_bytes(), k_b.as_bytes(), "K_A != K_B");
}
