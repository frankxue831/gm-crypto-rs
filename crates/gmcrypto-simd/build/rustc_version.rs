//! Compiler-version gate for the GFNI S-box (v1.16 Q16.2).
//!
//! The `gfni` target feature and its intrinsics were stabilized in Rust
//! 1.89.0 (rust-lang/rust#138940). The workspace MSRV is 1.85, so the GFNI
//! path is compiled only when the compiler is new enough. Shared by
//! `build.rs` and `tests/build_version.rs`.

/// Returns `true` when `version` (the output of `rustc -V`) names a compiler
/// on which the GFNI intrinsics are stable. Anything unparseable returns
/// `false`, which compiles today's AVX2/scalar code only.
///
/// A 1.89 pre-release (`-nightly`, `-beta`, `-dev`) returns `false`: early
/// 1.89 nightlies predate the stabilization. Pre-releases of 1.90 and later
/// were all cut after it.
pub fn gfni_intrinsics_stable(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("rustc ") else {
        return false;
    };
    let release = rest.split(' ').next().unwrap_or_default();
    let prerelease = release.contains('-');
    let mut parts = release.split(['.', '-']);
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => {
            (major, minor) > (1, 89) || ((major, minor) == (1, 89) && !prerelease)
        }
        _ => false,
    }
}
