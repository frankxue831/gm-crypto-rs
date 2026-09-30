//! Emits `cfg(gmcrypto_simd_gfni)` when the compiler can build the GFNI
//! S-box (v1.16 Q16.2, `docs/v1.16-scope.md`). No build dependencies.

#[path = "build/rustc_version.rs"]
mod rustc_version;

use std::env;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(gmcrypto_simd_gfni)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=build/rustc_version.rs");
    println!("cargo::rerun-if-env-changed=RUSTC");

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_default();
    if rustc_version::gfni_intrinsics_stable(version.trim()) {
        println!("cargo::rustc-cfg=gmcrypto_simd_gfni");
    }
}
