//! `gmcrypto-c` build script.
//!
//! Per Q4.12 in `docs/v0.4-scope.md`: cbindgen runs only when the
//! `regen-header` feature is enabled (or `GMCRYPTO_C_REGEN_HEADER=1`
//! is set in the environment). Default builds use the committed
//! header at `include/gmcrypto.h` and skip cbindgen entirely — saves
//! ~5s per build and avoids the cbindgen transitive dep tree.
//!
//! CI verifies the committed header matches a fresh cbindgen run via
//! `git diff --exit-code crates/gmcrypto-c/include/gmcrypto.h` in the
//! `cabi-build-and-header-drift` job.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-env-changed=GMCRYPTO_C_REGEN_HEADER");

    let regen_via_feature = cfg!(feature = "regen-header");
    let regen_via_env = std::env::var("GMCRYPTO_C_REGEN_HEADER")
        .ok()
        .is_some_and(|v| !v.is_empty() && v != "0");

    if regen_via_feature || regen_via_env {
        regenerate_header();
    }
}

#[cfg(feature = "regen-header")]
fn regenerate_header() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let output_path = std::path::Path::new(&crate_dir)
        .join("include")
        .join("gmcrypto.h");

    let config = cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml"))
        .expect("read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen generation failed")
        .write_to_file(&output_path);

    println!(
        "cargo:warning=Regenerated {} via cbindgen",
        output_path.display(),
    );
}

#[cfg(not(feature = "regen-header"))]
fn regenerate_header() {
    println!(
        "cargo:warning=GMCRYPTO_C_REGEN_HEADER set but `regen-header` feature not enabled — skipping cbindgen run. Re-run with `cargo build -p gmcrypto-c --features regen-header`.",
    );
}
