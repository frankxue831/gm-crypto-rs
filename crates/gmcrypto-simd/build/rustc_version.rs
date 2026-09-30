//! Compiler-version gate for the GFNI S-box (v1.16 Q16.2).
//!
//! The `gfni` target feature and its intrinsics were stabilized in Rust
//! 1.89.0 (rust-lang/rust#138940). The workspace MSRV is 1.85, so the GFNI
//! path is compiled only when the compiler is new enough. Shared by
//! `build.rs` and `tests/build_version.rs`.

/// Returns `true` when `version` (the output of `rustc -V`) names a compiler
/// on which the GFNI intrinsics are stable. Anything unparseable returns
/// `false`, which compiles today's AVX2/scalar code only.
pub fn gfni_intrinsics_stable(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("rustc ") else {
        return false;
    };
    let mut parts = rest.split(['.', '-', ' ']);
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => (major, minor) >= (1, 89),
        _ => false,
    }
}
