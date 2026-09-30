//! v1.16 Q16.2 — the build script's compiler-version parser.
//!
//! `build.rs` enables the GFNI S-box only on compilers where the `gfni`
//! intrinsics are stable (Rust 1.89+). Anything it cannot parse must leave
//! the GFNI path compiled out.

#[path = "../build/rustc_version.rs"]
mod rustc_version;

use rustc_version::gfni_intrinsics_stable;

#[test]
fn gates_at_rust_1_89() {
    assert!(!gfni_intrinsics_stable(
        "rustc 1.85.0 (4d91de4e4 2025-02-17)"
    ));
    assert!(!gfni_intrinsics_stable(
        "rustc 1.88.0 (6b00bc388 2025-06-23)"
    ));
    assert!(gfni_intrinsics_stable(
        "rustc 1.89.0 (29483883e 2025-08-04)"
    ));
    assert!(gfni_intrinsics_stable(
        "rustc 1.95.0 (59807616e 2026-04-14)"
    ));
    assert!(gfni_intrinsics_stable(
        "rustc 1.97.0-nightly (abcdef012 2026-06-01)"
    ));
    assert!(gfni_intrinsics_stable(
        "rustc 1.90.0-beta.3 (abcdef012 2025-09-01)"
    ));
    assert!(gfni_intrinsics_stable("rustc 2.0.0 (abcdef012 2030-01-01)"));
}

/// Early 1.89 nightlies predate the stabilization (rust-lang/rust#138940),
/// so every 1.89 pre-release fails closed; 1.90+ pre-releases do not.
#[test]
fn rejects_1_89_prereleases() {
    for early in [
        "rustc 1.89.0-nightly (0123456789 2025-05-20)",
        "rustc 1.89.0-beta.1 (0123456789 2025-06-27)",
        "rustc 1.89.0-dev",
    ] {
        assert!(
            !gfni_intrinsics_stable(early),
            "{early:?} must not enable GFNI"
        );
    }
}

#[test]
fn fails_closed_on_unparseable_versions() {
    for bad in [
        "",
        "rustc",
        "rustc x.y.z",
        "cargo 1.95.0",
        "rustc 1.",
        "rustc 1.x.0",
    ] {
        assert!(!gfni_intrinsics_stable(bad), "{bad:?} must not enable GFNI");
    }
}
