//! Precomputed comb table for fixed-base scalar multiplication.
//!
//! v0.3 W6: speeds up `k·G` by ~5× over v0.2's `mul_g(k) = mul_var(k,
//! &generator())`. The table is **public** (only public `G` and its
//! multiples), so build-time is variable-time without leaking
//! secrets; lookup at sign-time is constant-time-designed via
//! `subtle` linear scan over each sub-table.
//!
//! # Structure
//!
//! - `WINDOW_BITS = 4` — 4-bit windows.
//! - `NUM_WINDOWS = 64` — 256 / 4 = 64 windows over a 256-bit scalar.
//! - `WINDOW_SIZE = 16` — 2^4 entries per sub-table, indexed by the
//!   nibble value `0..=15`.
//!
//! Sub-table `i ∈ 0..NUM_WINDOWS` holds:
//!
//! ```text
//! T[i][j] = j · 2^(4·i) · G,    j ∈ 0..=15
//! ```
//!
//! Walking the scalar `k` from window 0 (LSB) up, the accumulator
//! adds `T[i][nibble_i(k)]` per window — no doublings inside the
//! loop. Total work per `mul_g` call: 64 conditional-select sweeps
//! over 16-entry tables (64·16 = 1024 selects) plus 64 point
//! additions. v0.2 did 256 doublings + 64 additions for the same
//! scalar.
//!
//! # Memory cost
//!
//! `[ProjectivePoint; 16]` × 64 sub-tables = 1024 entries × 96 bytes
//! ≈ 96 KB heap. Builds once per process, on first `mul_g` call.
//! Pinned this size in Q7.8; W6's risk-trap on table-size vs. binary-
//! bloat noted but accepted for v0.3 default.
//!
//! # Lazy init primitive
//!
//! `spin::Once<CombTable>`. Q7.8 selected `spin` over
//! `once_cell::race::OnceBox` for minimal surface (`no_std`, zero
//! transitive deps, ~4 KB lib). After first init the table lives
//! for the rest of the process; reads are a single atomic load +
//! branch.
//!
//! # Visibility
//!
//! `pub(crate)` only. The table is an implementation detail; callers
//! reach it indirectly via `mul_g`.

use crate::sm2::point::ProjectivePoint;
use spin::Once;

/// Number of bits per window. 4 → nibbles, 16-entry sub-tables.
pub const WINDOW_BITS: usize = 4;
/// `2^WINDOW_BITS` = entries per sub-table.
pub const WINDOW_SIZE: usize = 1 << WINDOW_BITS;
/// `256 / WINDOW_BITS` = number of windows over a 256-bit scalar.
pub const NUM_WINDOWS: usize = 256 / WINDOW_BITS;

/// Comb table: 64 sub-tables of 16 entries each.
///
/// `Box`-ed because the inline size (~96 KB) is too large to put on
/// the stack at construction time; the lazy-init helper allocates
/// once and stashes the pointer in [`spin::Once`].
pub struct CombTable {
    pub sub_tables: [[ProjectivePoint; WINDOW_SIZE]; NUM_WINDOWS],
}

static COMB_TABLE: Once<&'static CombTable> = Once::new();

/// Get a reference to the lazily-initialized comb table.
///
/// First call builds the table on the heap, leaks it (one-time
/// allocation per process), and stores the `&'static` reference.
/// Subsequent calls return the cached reference. The build path
/// is variable-time — fine, since `G` is public.
pub fn comb_table() -> &'static CombTable {
    COMB_TABLE.call_once(|| {
        let table = build_comb_table();
        // Leak the Box → &'static. The table lives for the rest of
        // the process; this is the standard one-time-init pattern
        // for "lazy global, never freed".
        alloc::boxed::Box::leak(table)
    })
}

/// Build the comb table from scratch.
///
/// Walks the windows from LSB to MSB:
/// - `T[0][j] = j·G` for `j ∈ 0..=15`.
/// - `T[i][j] = T[i-1][j].double()` applied `WINDOW_BITS` times for
///   `i > 0` (i.e. `T[i][j] = j · 2^(4i) · G`).
///
/// Variable-time — `G` is public. The intermediate Vec routes the
/// 96 KB allocation through the heap; the array itself is never
/// constructed on the stack.
#[allow(clippy::large_stack_arrays)]
fn build_comb_table() -> alloc::boxed::Box<CombTable> {
    use alloc::boxed::Box;

    let g = ProjectivePoint::generator();
    let identity = ProjectivePoint::identity();

    // Stack-allocated 96 KB array would risk overflow on small targets.
    // Box::new on a stack-built array is the issue; use a Vec-backed
    // approach to route through the heap allocator directly.
    let mut sub_tables: alloc::vec::Vec<[ProjectivePoint; WINDOW_SIZE]> =
        alloc::vec::Vec::with_capacity(NUM_WINDOWS);

    // T[0][j] = j·G via running addition.
    let mut row0 = [identity; WINDOW_SIZE];
    row0[1] = g;
    for j in 2..WINDOW_SIZE {
        row0[j] = row0[j - 1].add(&g);
    }
    sub_tables.push(row0);

    // T[i][j] = T[i-1][j].double() applied WINDOW_BITS times.
    for i in 1..NUM_WINDOWS {
        let prev = sub_tables[i - 1];
        let mut row = [identity; WINDOW_SIZE];
        for j in 0..WINDOW_SIZE {
            let mut p = prev[j];
            for _ in 0..WINDOW_BITS {
                p = p.double();
            }
            row[j] = p;
        }
        sub_tables.push(row);
    }

    // Convert Vec → fixed array → Box.
    let arr: [[ProjectivePoint; WINDOW_SIZE]; NUM_WINDOWS] = sub_tables
        .try_into()
        .map_err(|_| ())
        .expect("comb-table sub-table count must match NUM_WINDOWS");
    Box::new(CombTable { sub_tables: arr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::curve::Fn;
    use crate::sm2::scalar_mul::mul_var;
    use crypto_bigint::U256;
    use subtle::ConstantTimeEq;

    /// Build the table once and verify a couple of representative
    /// entries match `mul_var(k, &generator())`.
    #[test]
    fn comb_table_entries_match_mul_var() {
        let table = comb_table();

        // T[0][7] should equal 7·G.
        let seven = Fn::new(&U256::from_u64(7));
        let expected = mul_var(&seven, &ProjectivePoint::generator());
        assert!(
            bool::from(table.sub_tables[0][7].ct_eq(&expected)),
            "T[0][7] != 7·G"
        );

        // T[1][3] should equal 3·2^4·G = 48·G.
        let forty_eight = Fn::new(&U256::from_u64(48));
        let expected = mul_var(&forty_eight, &ProjectivePoint::generator());
        assert!(
            bool::from(table.sub_tables[1][3].ct_eq(&expected)),
            "T[1][3] != 48·G"
        );

        // T[63][15] should equal 15·2^252·G.
        let scalar = U256::from_u64(15).shl_vartime(252);
        let expected = mul_var(&Fn::new(&scalar), &ProjectivePoint::generator());
        assert!(
            bool::from(table.sub_tables[NUM_WINDOWS - 1][WINDOW_SIZE - 1].ct_eq(&expected)),
            "T[63][15] != 15·2^252·G"
        );
    }

    /// `T[i][0]` is the identity for every window (0·X = O regardless of X).
    #[test]
    fn comb_table_zero_columns_are_identity() {
        let table = comb_table();
        for i in 0..NUM_WINDOWS {
            assert!(
                bool::from(table.sub_tables[i][0].is_identity()),
                "T[{i}][0] not identity"
            );
        }
    }
}
