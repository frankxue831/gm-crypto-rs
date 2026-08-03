# gmcrypto Rust Ecosystem Charter

**Status:** Normative

This charter is the authoritative definition of the official `gmcrypto-core`-centered Rust ecosystem. It records scope, layering, names, release coupling, security expectations, admission rules, and downstream compatibility gates.

## 1. Mission and scope

The ecosystem provides layered Rust support for GM/SM cryptography centered on `gmcrypto-core`. The core supplies SM2, SM3, and SM4 primitives plus standards-level cryptographic building blocks such as encoding, X.509 support, and the optional TLCP key-schedule, record-protection, and certificate-pair toolkit. Transport I/O, connection or session orchestration, application envelope formats, endpoint policy, and partner-specific mappings are outside the core boundary and belong to higher layers.

**Verification:** the core workspace manifests and feature documentation identify the standards-level building blocks present today. The placement of future functionality at the correct layer is a policy-only architecture review until an automated architecture check exists.

## 2. Layering and encapsulation

The ecosystem has three layers: the core family, independently versioned public protocol crates, and private deployment adapters. A public ecosystem crate outside the core family must not expose `gmcrypto-core` types, traits, or macros in its public API and must not re-export them. The envelope crate is the first reference implementation of this boundary.

**Verification in `gmcrypto-envelope-lite`:** `grep -RIn "pub use gmcrypto" src/` must produce no matches, `cargo test --test public_api` must pass, and `./ci/check-public-api.sh` must show no unreviewed core types in the public API snapshot. Applying the same encapsulation rule to a future crate is policy-only until that crate adds an equivalent gate.

## 3. Official names and identity

The `gmcrypto-*` crate-name prefix is reserved by project policy for officially maintained, charter-governed crates at every layer. It is not an enforceable crates.io namespace. For an unpublished crate, official identity requires an entry in this charter together with verified source-repository and maintainer identity. Once an official crate is published, its crates.io publisher metadata must also match that identity. A prefix or crate name alone never establishes official status. The initial official list is `gmcrypto-core`, `gmcrypto-c`, `gmcrypto-simd`, and `gmcrypto-envelope-lite`.

The unpublished `gm-crypto-rs-demo` project is a supporting example and published-version smoke test, not an official published crate. Historical Java projects are independent and are not members of this Rust ecosystem.

**Licensing.** Every official crate is published under the Rust-conventional dual `MIT OR Apache-2.0`, and every published crate must ship both licence texts inside its `.crate` archive. A licence file sitting at the repository root does not reach the archive on its own: cargo will copy a file from outside the package directory when a manifest key names it (`readme` and `license-file` both do this), but absent such a key and absent an in-crate copy, nothing is collected. `license-file` cannot express a dual licence — it takes a single path — so the requirement is a per-crate copy of each text. `gmcrypto-core`, `gmcrypto-c`, and `gmcrypto-simd` satisfy this from **1.11.0** onward; the archives published up to and including 1.9.0 contain no licence text and cannot be corrected retroactively, since a published version is immutable. (1.9.1 was prepared as the minimal fix for exactly this defect but was never published — `1.11.0` shipped the same change first.) `gmcrypto-envelope-lite` aligned to the dual licence at its 0.1.0 cut: its manifest declares `MIT OR Apache-2.0` and per-crate copies of both texts ship inside the package. Because it is unpublished, that requirement is verified against `cargo package --list` rather than against a published archive.

**Verification:** compare the authoritative list above with workspace and downstream manifests plus verified source-repository and maintainer identity; for each published crate, also compare its crates.io publisher record and linked source repository. For licensing, check `license` in each manifest and confirm `cargo package --list` shows `LICENSE-APACHE` and `LICENSE-MIT` for every published crate. Prefix reservation and third-party naming remain policy-only because crates.io cannot enforce this charter.

## 4. Version coupling and MSRV

The core workspace family (`gmcrypto-core`, `gmcrypto-c`, and `gmcrypto-simd`) shares one workspace version, uses exact intra-workspace pins, and releases in lockstep. Independently versioned downstream crates use their own release cadence. Such a crate pins the exact core version while it is in development, and relaxes that pin to a caret requirement at its publication cut. `gmcrypto-envelope-lite` made that transition at its 0.1.0 cut and now requires core `1.11`; publication was subsequently parked, so it is currently unpublished *with* a caret requirement, and it stays caret. Every downstream core-version change requires the full downstream test and boundary suite before it lands.

A caret requirement removes the pin bump that would otherwise announce a core upgrade downstream, so from this point the compatibility gate in section 8 is the only mechanism that tests a core candidate against this crate.

The ecosystem MSRV equals the published `rust-version` of `gmcrypto-core`, currently Rust 1.85. An official crate must not require a newer toolchain without a charter update, and every MSRV increase must be recorded in the affected changelogs.

**Verification:** inspect the core workspace version and exact member requirements, inspect each official downstream `Cargo.toml`, and run its MSRV CI job. Lockstep release behavior and the publication-time caret transition are policy-only release checks.

## 5. Public and private boundary

Partner-specific mappings, identities, fixtures, denylist entries, and exact-wire compatibility suites belong only in access-controlled private repositories or systems. Untracked files in a public checkout are not a secrecy boundary. Before any publication step, the public source export and Cargo package must pass a release-boundary scan. Publishing a previously private tree uses a fresh reviewed export or repository, unless a history rewrite and subsequent fresh-clone history scan receive separate approval.

**Verification in `gmcrypto-envelope-lite`:** run `sh tests/open_source_boundary.sh`, `./ci/check-open-source-boundary.sh --worktree .`, and the package scan performed by `./ci/check-cargo-package.sh`. Approval of a fresh export, repository migration, or history rewrite is a policy-only human gate.

## 6. Per-repository security baseline

Every repository containing an official crate must provide a security policy, RustSec advisory monitoring through `cargo-deny` or an equivalent CI gate, and fuzz coverage wherever it parses untrusted structured input. One repository-level baseline covers all official crates in a workspace; member crates do not duplicate it. Repository-level living security documentation must state the audit status and scope of every official crate it covers. Until an independent audit has occurred, it must say so explicitly. Documentation must not overstate an audit's scope, universal constant-time behavior, or protection from a compromised process.

**Verification:** check the repository-level `SECURITY.md`, advisory workflow or deny configuration, parser fuzz targets, and explicit non-claims in living security documentation. Whether new parsing code needs additional fuzz targets is policy-only security review until a coverage contract is added.

## 7. Admission and repository creation

A new official public crate requires a concrete consumer, a named owner, and the complete security baseline from section 6 on its first day. Empty placeholder crates and workspaces are prohibited. A public ecosystem workspace is created only with its first admitted crate that does not belong in an existing repository. A language-binding repository requires a real consumer that `gmcrypto-c` cannot serve. A shared test-vector repository requires demonstrated duplication or drift of the same corpus across at least two official repositories.

A governance or tooling meta-repository is created only after at least three independently released official public repositories exist and duplicated release tooling or policy maintenance is concrete. Supporting repositories such as the unpublished demo do not count toward that threshold.

**Policy-only:** admission, ownership, repository-creation triggers, and the meta-repository threshold are maintainer decisions recorded by updating this charter; no repository is created automatically.

## 8. Compatibility gates

The charter maintains a registry of downstream gates that a core release must respect. Gate #1 is the `gmcrypto-envelope-lite` 0.1.0 RC suite. From a clean envelope checkout, its local gate is:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --doc --locked
sh tests/open_source_boundary.sh
./ci/check-open-source-boundary.sh --worktree .
```

Before every `gmcrypto-core` release, run the compatibility gate in two phases in a temporary envelope export. Before applying the candidate override, validate the strict `release_documents` integration target and cryptographic inventory against the pristine committed registry lock. Do not weaken the normal release-document or inventory assertions.

Then inject the core release candidate through a temporary path dependency or Cargo `[patch]` override. Run the Cargo behavioral operations without `--locked` so Cargo may rewrite only the disposable lockfile; the committed downstream lockfile remains untouched. Keep the formatting and boundary commands unchanged. Against the patched candidate, run Clippy, unit tests, examples, documentation tests, and every dynamically discovered behavioral integration target. `release_documents` is the sole deliberate post-patch exclusion because it validates registry metadata rather than runtime or API compatibility, and path packages have no registry checksum. If the candidate version no longer satisfies the downstream exact pin, change that pin only in the temporary gate copy. A breaking result requires a documented migration note before the core release ships.

On the downstream side, the same gate runs for every exact core-pin bump while the crate is unpublished. After first publication with a caret requirement, downstream CI must cover both the minimum supported and newest compatible core versions.

**Verification:** preserve both phases' command output and the exact tested core and envelope commits as release evidence. Operation is manual and policy-only in this phase; cross-repository CI is deferred until repeated maintenance justifies it.
