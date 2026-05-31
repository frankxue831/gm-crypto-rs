# gmcrypto-fuzz — cargo-fuzz harness

`cargo-fuzz` (libFuzzer) coverage over the **untrusted-input decode/decrypt
surface** of `gmcrypto-core`. The invariant under test is the project's
failure-mode invariant on adversarial bytes: **every malformed input collapses
to the single safe `None` / `Error::Failed` (or `false`) return — no panic, no
unbounded allocation, no hang.** See `docs/v0.14-scope.md` for the full design.

v0.20 adds two **differential** targets (`fuzz_sm4_{cbc,gcm}_streaming_decrypt`)
with a stronger invariant: the *streaming* decryptor fed in **arbitrary chunk
boundaries** must be **byte-identical** to the *single-shot* oracle fed
all-at-once. See `docs/v0.20-scope.md`.

This crate is its **own** Cargo workspace (note the empty `[workspace]` table in
`Cargo.toml`) and is **excluded** from the published 3-crate workspace. Its
`libfuzzer-sys` / `arbitrary` deps never enter the published dependency graph.
It is **unpublished** and **nightly-only** — MSRV 1.85 does not apply here.

## Prerequisites (one-time)

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.1   # pinned for reproducibility
```

(Apple clang / a system LLVM provides libFuzzer; no extra step on macOS.)

## Run a target

```bash
# From the repo root (the directory that contains this `fuzz/`):
cargo +nightly fuzz run fuzz_pem fuzz/corpus/fuzz_pem fuzz/seeds/fuzz_pem -- \
    -max_len=16384 -rss_limit_mb=2048 -timeout=25 -max_total_time=60
```

- **Dir order matters.** libFuzzer reads *all* listed corpus dirs but writes new
  coverage-increasing inputs only to the **first** one. So `fuzz/corpus/<target>`
  (gitignored, grown) goes first and `fuzz/seeds/<target>` (committed, curated,
  read-only) goes second — that way the curated seeds are never mutated.
- `fuzz/seeds/<target>/` is a **committed** curated set of valid encodings (+ any
  minimized crash regression inputs) that bootstraps coverage. The runtime-grown
  corpus (`fuzz/corpus/`), build output (`fuzz/target/`), and crash repros
  (`fuzz/artifacts/`) are gitignored.
- A crash writes a reproducer to `fuzz/artifacts/<target>/`. Re-run it with:
  ```bash
  cargo +nightly fuzz run fuzz_pem fuzz/artifacts/fuzz_pem/crash-<hash>
  ```
- Minimize a crash before filing/fixing:
  ```bash
  cargo +nightly fuzz tmin fuzz_pem fuzz/artifacts/fuzz_pem/crash-<hash>
  ```
  A minimized crash input is committed under `fuzz/seeds/<target>/` as a
  permanent regression seed.

## Build all targets (no run)

```bash
cargo +nightly fuzz build
```

## Coverage report (v0.20)

The nightly workflow renders per-target `llvm-cov` region/line coverage over the
**committed seed corpus** and uploads a `SUMMARY.txt` artifact. It is
**non-gating** — the report is the deliverable, not a coverage-% threshold. To
render locally:

```bash
rustup component add llvm-tools-preview --toolchain nightly
T=fuzz_sm4_gcm_streaming_decrypt
cargo +nightly fuzz coverage "$T" "fuzz/corpus/$T" "fuzz/seeds/$T"
LLVM_COV="$(find "$(rustc +nightly --print sysroot)" -name llvm-cov -type f | head -1)"
BIN="$(find fuzz/target "$HOME/.cargo" -type f -name "$T" | grep -E '/(coverage|release)/' | head -1)"
"$LLVM_COV" report "$BIN" -instr-profile="fuzz/coverage/$T/coverage.profdata"
```

Coverage % is reported over the **whole linked `gmcrypto-core` crate**, so a
single decrypt target shows a small fraction (it exercises only its own path);
the signal is the per-target trend, not an absolute number.

## Targets

| Target | Entry point under test |
|---|---|
| `fuzz_pem` | `pem::decode` (RFC 7468 armor + base64) |
| `fuzz_pkcs8_decode` | `pkcs8::decode` (OneAsymmetricKey) |
| `fuzz_pkcs8_decrypt` | `pkcs8::decrypt` (PBES2; fixed password) |
| `fuzz_spki` | `spki::decode` (SubjectPublicKeyInfo) |
| `fuzz_sec1` | `sec1::decode` (ECPrivateKey) |
| `fuzz_sig` | `asn1::sig::decode_sig` (SEQUENCE { r, s }) |
| `fuzz_asn1_reader` | low-level DER reader primitives |
| `fuzz_sm2_ciphertext_der` | `asn1::ciphertext::decode` (GM/T 0009) |
| `fuzz_sm2_raw_ciphertext` | `decode_c1c3c2` + `decode_c1c2c3_legacy` |
| `fuzz_sm2_pubkey_sec1` | `Sm2PublicKey::from_sec1_bytes` |
| `fuzz_sm2_decrypt` | `sm2::decrypt` (fixed key; parse + KDF + MAC) |
| `fuzz_sm2_verify` | `verify_with_id` (fixed key; sig DER parse) |

(v0.14 W3 added the SM4 single-shot decrypts: `fuzz_sm4_cbc_decrypt` /
`_gcm_decrypt` / `_ccm_decrypt` / `_xts_decrypt` — negative-input, see
`docs/v0.14-scope.md` Q14.3. **v0.20** added two **differential**
streaming-decryptor targets, `fuzz_sm4_cbc_streaming_decrypt` /
`fuzz_sm4_gcm_streaming_decrypt`, which assert the streaming decryptor fed in
arbitrary chunks is byte-identical to the single-shot oracle — not merely
crash-free; see `docs/v0.20-scope.md`. **18 targets total.**)

### Regenerating seeds

The curated seeds in `fuzz/seeds/<target>/` are cryptographically-valid
encodings produced by a one-time generator using gmcrypto-core's public
encode/sign/encrypt APIs under a fixed test private key. They bootstrap
coverage off real structure. To regenerate, see `docs/v0.14-scope.md` Q14.6.

**Seed-layout pin (W3 codex note):** the SM4 decrypt targets carve their
`key/iv/nonce/aad/tag/...` fields from the fuzz buffer with `arbitrary`'s
**front-consuming** reads, so the committed `fuzz_sm4_*` seeds are plain
field concatenations that depend on `arbitrary 1.4.2`'s consumption order
(pinned in `fuzz/Cargo.lock`). If you ever bump `arbitrary`, re-verify the
front-vs-tail consumption order and regenerate those seeds. The v0.20
streaming targets' layouts are:

- `fuzz_sm4_cbc_streaming_decrypt`: `[key:16][iv:16][chunk_len:1][ct:rest]`
- `fuzz_sm4_gcm_streaming_decrypt`:
  `[key:16][tag:16][nonce_len:1][nonce][aad_len:1][aad][chunk_len:1][ct:rest]`
  where the source reads `nonce_len` as `u8 % 17` (0..=16) and `aad_len` as
  `u8 % 33` (0..=32), so both valid and malformed nonce/aad lengths are explored;
  the GCM `tag` is a fixed 16 bytes (the `mode_gcm::decrypt` path).

where `chunk_len` (a `u8`, fed as `max(1, chunk_len)` so `0` ⇒ 1-byte chunks) sets the streaming chunk size the
ciphertext is fed in. Their seeds are valid encrypts generated under a fixed key.
