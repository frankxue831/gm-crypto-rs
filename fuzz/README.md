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
cargo install cargo-fuzz --version 0.13.2   # pinned for reproducibility
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
**committed seed corpus**, uploads a `SUMMARY.txt` artifact, and prints the same
table into the run's **job summary** so it is readable without downloading
anything.

It is **non-gating on the coverage percentage** — no threshold, the report is
the deliverable. It *does* fail the job if any target reports
`coverage-build-failed`, which means that target produced no coverage data at
all (a profdata that merely failed to render reports `profdata OK` instead and
does not trip it). That line is the general check that a target is actually
running: it read `coverage-build-failed` for both `fuzz_tlcp_*_deprotect`
targets for 44 consecutive nights while they executed zero inputs.

To render locally:

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
| `fuzz_sm2_kx` | key-exchange initiator `confirm` (fixed keys; adversarial peer `R_B`+`S_B`) |
| `fuzz_sm4_cbc_decrypt` | `sm4::mode_cbc::decrypt` (+ PKCS#7 unpad) |
| `fuzz_sm4_gcm_decrypt` | `sm4::mode_gcm::decrypt` + `decrypt_with_tag_len` |
| `fuzz_sm4_ccm_decrypt` | `sm4::mode_ccm::decrypt` (CBC-MAC + CTR) |
| `fuzz_sm4_xts_decrypt` | `sm4::mode_xts::decrypt` (GB/T 17964; CTS tail) |
| `fuzz_sm4_cbc_streaming_decrypt` | `Sm4CbcDecryptor` — DIFFERENTIAL vs single-shot `mode_cbc::decrypt` |
| `fuzz_sm4_gcm_streaming_decrypt` | `Sm4GcmDecryptor` — DIFFERENTIAL vs single-shot `mode_gcm::decrypt` |
| `fuzz_sm3` | `sm3::hash` — DIFFERENTIAL vs streaming `Sm3` |
| `fuzz_hmac_sm3` | `hmac_sm3` — DIFFERENTIAL vs streaming `HmacSm3`, + constant-time `verify` |
| `fuzz_c_abi` | `gmcrypto-c` `extern "C"` surface (raw pointers; opaque-handle lifecycle) |
| `fuzz_sm4_cbc_encrypt` | `mode_cbc::encrypt` — DIFFERENTIAL vs streaming, + round-trip |
| `fuzz_sm4_gcm_encrypt` | `mode_gcm::encrypt` — DIFFERENTIAL vs streaming, + round-trip with AAD |
| `fuzz_sm4_ccm_encrypt` | `mode_ccm::encrypt` — encrypt→decrypt round-trip + tag tamper |
| `fuzz_sm4_xts_encrypt` | `mode_xts::encrypt` — encrypt→decrypt round-trip (CTS tail) |
| `fuzz_x509` | `x509::Certificate::from_der` + `verify_signature(_with_id)` + accessors |
| `fuzz_tlcp_cbc_deprotect` | `tlcp::record::deprotect_cbc` (Lucky13-hardened) |
| `fuzz_tlcp_gcm_deprotect` | `tlcp::record::deprotect_gcm` (RFC 5288 shape) |
| `fuzz_x509_chain` | `x509::verify_chain` + `tlcp::chain::verify_pair` |
| `fuzz_sm4_xts_sectors` | `mode_xts::{encrypt,decrypt}_sectors` — DIFFERENTIAL vs the looped single-shot, + buf-untouched-on-`None` |
| `fuzz_sm4_gcm_tag_len_roundtrip` | `mode_gcm::{encrypt,decrypt}_with_tag_len` — truncated-tag round-trip over all 7 permitted lengths |
| `fuzz_sm4_aead_traits` | `Sm4Gcm` / `Sm4Ccm` (`aead` 0.6) — DIFFERENTIAL vs inherent `mode_gcm` / `mode_ccm`, both ciphers per input |

(v0.14 W3 added the SM4 single-shot decrypts: `fuzz_sm4_cbc_decrypt` /
`_gcm_decrypt` / `_ccm_decrypt` / `_xts_decrypt` — negative-input, see
`docs/v0.14-scope.md` Q14.3. **v0.20** added two **differential**
streaming-decryptor targets, `fuzz_sm4_cbc_streaming_decrypt` /
`fuzz_sm4_gcm_streaming_decrypt`, which assert the streaming decryptor fed in
arbitrary chunks is byte-identical to the single-shot oracle — not merely
crash-free; see `docs/v0.20-scope.md`. The **post-1.0 hardening cycle**
(PRs #98/#99) added seven more: primitive one-shot-vs-streaming
differentials `fuzz_sm3` / `fuzz_hmac_sm3`, the C-ABI surface `fuzz_c_abi`
(raw-pointer `extern "C"` entry points), encrypt-side differentials +
round-trips `fuzz_sm4_cbc_encrypt` / `fuzz_sm4_gcm_encrypt`, and
encrypt→decrypt round-trips `fuzz_sm4_ccm_encrypt` / `fuzz_sm4_xts_encrypt`.
**v1.1** added `fuzz_sm2_kx` (adversarial peer wire bytes into the
key-exchange initiator's `confirm`); **v1.3** added `fuzz_x509`
(X.509-with-SM2 certificate decode + verify, seeded with the committed
gmssl KAT fixtures); **v1.2/v1.4** extended `fuzz_c_abi` with a
key-exchange op and an X.509 op (the dispatch is `op % 11` since v1.9;
every committed seed's first byte is audited whenever the modulus
changes — the v1.4 widening silently remapped `sm3_abc` until its op
byte was rewritten). **v1.7** added `fuzz_tlcp_{cbc,gcm}_deprotect`,
**v1.8** added `fuzz_x509_chain`, and **v1.9** extended `fuzz_c_abi`
with a chain/pair op and a record-deprotect op.

**v1.10** upgraded the four DER parser targets — `fuzz_sig`, `fuzz_spki`,
`fuzz_sm2_ciphertext_der`, `fuzz_sm2_raw_ciphertext` — from no-panic to
**byte-idempotence** (`encode(decode(x)) == x`, i.e. the decoder accepts
exactly one encoding per value), which needs no `PartialEq` on a published
type and catches a decoder that starts admitting a second spelling; the raw
target also gained a guard-parity differential between the modern and legacy
decoders, whose validation prologues are duplicated. v1.10 also added
`fuzz_sm4_xts_sectors` and `fuzz_sm4_gcm_tag_len_roundtrip`. v1.11 added
`fuzz_sm4_aead_traits`, which asserts the new `aead` 0.6 trait path is
byte-identical to the inherent `mode_gcm` / `mode_ccm` path — that thinness is
the argument behind v1.11 adding no dudect target, so a divergence there would
invalidate an assurance claim rather than merely be a wrapper bug. **33 targets
total** — the census must
equal both `fuzz/Cargo.toml`'s `[[bin]]` entries and the `FUZZ_TARGETS`
list in `.github/workflows/fuzz-nightly.yml`; a target absent from that
list still compiles in CI but is never fuzzed nor coverage-measured. That
pairing is now **enforced** by a preflight step in `fuzz-nightly.yml` rather
than left to prose.)

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

**v1.1 — `fuzz_sm2_kx` layout:** `[R_B:65][S_B:32]`, both FRONT-consuming
fixed-size `arbitrary` reads (a plain 97-byte concatenation). The target
drives a fixed-key (`d_A = 0x11*32`, `d_B = 0x22*32`, ids `a`/`b`,
`klen = 16`), fixed-ephemeral (`0x5A`-fill draws) initiator's `confirm`
against the carved peer bytes — no panic / single `Failed` invariant. The
committed `seeds/fuzz_sm2_kx/basic` is the responder's real `(R_B ‖ S_B)`
reply (responder ephemeral `0x3C`-fill) to that exact deterministic
initiator, so the seed exercises the full success path including both
confirmation-tag computations.

**v1.7 — `fuzz_tlcp_{cbc,gcm}_deprotect` layouts:** `[key_block:128][seq:8][record:rest]`
(CBC) and `[key_block:40][seq:8][record:rest]` (GCM). Both leading fields are
FRONT-consuming `arbitrary` reads, so a seed is a plain concatenation; `seq` is
read **little-endian**, i.e. seq bytes `01 02 03 04 05 06 07 08` carve to
`0x0807060504030201`. The per-direction keys come from `client_half`, and
`record` is the adversarial wire body (`explicit_IV(16) ‖ CBC_ct` /
`explicit_nonce(8) ‖ ct ‖ tag(16)`).

Each target commits two seeds — `valid_record` (25-byte plaintext) and
`valid_empty` (empty plaintext, the minimum-length boundary) — built by
`protect_{cbc,gcm}` against the key block and seq **recovered through the
target's own carving**, with the CBC explicit IV pinned by a deterministic
`0x20`-incrementing `TryCryptoRng` so the bytes are reproducible. Each was
verified by re-parsing the emitted seed and asserting `deprotect_*` returns the
original plaintext, so both seeds land on the success path rather than bouncing
off a public-length guard.

> **Why these seeds are load-bearing.** These two targets originally shipped
> with no `seeds/` dir. libFuzzer treats a nonexistent corpus dir as fatal
> (`No such file or directory: <dir>; exiting`) and exits non-zero *before
> running a single input*, which `fuzz-nightly.yml` reported as `CRASH` — 44
> consecutive red nightlies (2026-06-14 → 2026-07-27) that were not crashes,
> while the Lucky13-hardened `deprotect_cbc` path was never actually fuzzed.
> The workflow now **preflights** a seeds dir for every target in
> `FUZZ_TARGETS` and fails with a distinct "config drift, NOT a crash"
> message, and passes only corpus dirs that exist. If you add a target,
> add its seeds dir in the same commit.

**v1.10 — `fuzz_sm4_xts_sectors` layout:**
`[key:32][start_sector:16 big-endian][sector_size_sel:1][buf:rest]`. Manual
slicing, **no `arbitrary`** (matching `fuzz_sm4_xts_encrypt`), so the seed is a
plain concatenation with no consumption-order dependency. `sector_size_sel`
indexes `[16, 32, 512]` modulo 3; the run is capped at 8 sectors and `buf` is
truncated to a whole multiple of the sector size. `start_sector` is read
**big-endian** purely so the seed reads left-to-right — the *tweak* derived
from it is little-endian, per the disk-XTS convention. Equal key halves are
perturbed (`key[16] ^= 1`) so a weak key still reaches real work, which means
**sector-number overflow is the only rejection the target can reach**; every
`None` therefore exercises the buf-untouched-on-`None` contract.

Three committed seeds, each verified by replaying the target's own carve:

| seed | `start_sector` | sectors | what it pins |
|---|---|---|---|
| `basic` | 1 | 4 × 16 B | the ordinary multi-sector path |
| `high_lba` | `u128::MAX - 2` | 3 × 16 B | a run ending **exactly** at `u128::MAX` |
| `overflow` | `u128::MAX` | 3 × 16 B | the overflow rejection + buf-untouched |

**v1.10 — `fuzz_sm4_gcm_tag_len_roundtrip` layout:**
`[key:16][nonce_len:1][nonce][aad_len:1][aad][tag_sel:1][plaintext:rest]`.
Manual slicing, no `arbitrary` (matching `fuzz_sm4_gcm_encrypt`). `tag_sel`
indexes the NIST-permitted set `[4, 8, 12, 13, 14, 15, 16]` modulo 7. Committed
seeds `tag16` (`tag_sel = 6`) and `tag4` (`tag_sel = 0`, maximal truncation),
both with a 12-byte nonce and 4-byte AAD.
