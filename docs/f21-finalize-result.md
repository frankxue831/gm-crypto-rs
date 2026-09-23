# F21 — `finalize()` narrow-window result (v1.14)

**Label: `distinguishable-on-this-host`. Annotations: none.** Protocol v4
(`docs/v1.14-scope.md` §3 + §3a), executed once on 2026-09-23 on the pinned
host. Consequence per Q14.6 (b): **F21 stays open, re-scoped** — the narrow
`Sm4CbcDecryptor::finalize()` window separates an early-return regression in
the PKCS#7 strip from the shipping constant-time implementation *on this
host*. It is not a CI gate, not promoted, and not a constant-time claim about
`strip_pkcs7_block` or SM4-CBC; `SECURITY.md` is unchanged.

A first execution under protocol v3 the same day is recorded in §6. Its
mechanical label was `still-blind`; the criteria's observable was found
defective and v4 was pinned by the maintainer *knowing that data existed*.
Nothing from the v3 run enters the judgment above.

Independent review (Q14.5): see §7.

## 1. Provenance

| item | identity |
|---|---|
| governing text | `docs/v1.14-scope.md` §2, §3, §3a (this repository, `main`) |
| protocol v2 (source of §3; research clone, untracked) | SHA-256 `6dea2068f1b65b08e4d396ea625aa93bd6c390ebd5a566a28c940794b465c22e` |
| research clone baseline | commit `c1ce4036d53fe7e3fd17b4d588e16fb3c584857b` (not on `origin`); index and tracked tree verified equal to `HEAD` before setup and again before the v4 run |
| T1 bench `crates/gmcrypto-core/benches/f21_finalize.rs` | `2ba44c0ee2b72a6e0515144e178823c0eed4914365f7a2a860d515b7f0b3d068` (identical in all three exports) |
| unpatched `mode_cbc.rs` (constant-time export) | `a373a4dedd72ffc9adb427b0fc7cd679b4b5ca3a2744267de4fe60214bc72968` |
| `research/f21/early-return.patch` → patched `mode_cbc.rs` | `d39ce7ddad58ad80042edb2424c41a445a56820fa175972cb58f5831d6dfb3de` → `9831b0765177d4b58486d76160e3e52a9e3ecdfc580a983e0086829e7feda95b` (`git apply --numstat`: `6 0`, one file) |
| `research/f21/amplified.patch` → patched `mode_cbc.rs` | `0eecb55f2f01f77623e2f33937d5140582defff2e8a22650c032f6b19bb8ff89` → `dcee556475fa2163f7e0778a740668ea737770e8790103292340955e535c5930` (`git apply --numstat`: `12 2`, one file) |
| `Cargo.lock` copied into each export (three byte-identical copies) | `a9ba91939eeba1c86f946914f38859d2ca9a9324029ef26837c66153585031dc`; `dudect-bencher` 0.7.0 checksum `6a6174adfb35811a6845001876823965032406784c36e795edb84a74353455e1` |
| pre-check program `research/f21/precheck.rs` (research clone, untracked) | `4daf943053af73d9df60fb21c80b75ecd167a33064b6501fa2705e193089334f` |
| judgment script `research/f21/judge.py` (research clone, untracked; fixed before the v4 run) | `87db88bf5ca112e35c4195c568a0a7639e9f9aff8efcce37aa72d12bcae62ffa` |

Builds: three `git archive c1ce403…` exports (constant-time, early-return,
amplified), each with its own target directory, pre-compiled with
`cargo bench --no-run --offline --locked -p gmcrypto-core --bench f21_finalize`
before any budget started; a fourth constant-time export carried the
pre-check program as an example. The leaky patches were applied inside their
exports only; the research clone's `crates/` was never written. No run log
contains a `Compiling` line.

## 2. Host and preconditions (v4 run)

Recorded 2026-09-23T15:25:01Z, immediately before the pre-check:

- Apple M1 Pro, `aarch64-apple-darwin`; macOS 27.0 (26A428); `hw.tbfrequency`
  24 000 000.
- rustc 1.94.1 (e408947bf 2026-03-25); cargo 1.94.1 (29ea6fb6a 2026-03-24).
- AC power ("Now drawing from 'AC Power'") before the pre-check, before every
  run, and throughout. Load averages 3.28 / 3.10 / 2.81 (an IDE's helper
  processes; nothing building or benchmarking).
- Research clone `HEAD` = `c1ce403…`; `git diff --quiet` and
  `git diff --cached --quiet` clean.
- Export identities re-hashed and equal to §1.

Three preconditions are **not evidenced in the v4 log itself** (raised by the
independent review, §7) and are stated here instead:

- `run_one` structure re-check: read from the checksummed crate source before
  the v3 run the same day (`ctbench.rs` 341–358: `F: Fn() -> T`, one
  `black_box(f())` between two `Instant::now()` reads, the return dropped at
  the end of that statement, before the second read), and confirmed
  independently by the reviewer. The v4 preconditions script did not repeat
  the read.
- Host triple: the script recorded only the first line of `rustc -Vv`, so
  `host: aarch64-apple-darwin` is not in the log. Apple M1 Pro, macOS 27.0 and
  `hw.tbfrequency` 24 000 000 are; the triple follows from them.
- "Nothing else building or benchmarking" rests on the recorded load averages
  (3.28 / 3.10 / 2.81) and on a process listing taken before the v3 setup that
  showed only an IDE's helper processes; the v4 log holds no process listing.

## 3. Pre-check (v4 run; §3, Q14.2)

Verbatim program output, 2026-09-23T15:25:01Z – 15:25:06Z:

```text
f21 pre-check (protocol v3); nominal tick 41.667 ns
(a) tick: min non-zero delta = 41 ns over 2000000 consecutive reads
(b) f21_wrapper_only closure: n=20000 min=0 ns (0.00 ticks) median=83 ns (1.99 ticks) mean=71.9 ns (1.73 ticks)
(b) f21_wrapper_only closure: most common readings: 83ns×8370 42ns×4702 84ns×4150 41ns×2304 125ns×161 167ns×106 166ns×57 208ns×40
(b) ct_sm4_cbc_finalize closure: n=20000 min=41 ns (0.98 ticks) median=125 ns (3.00 ticks) mean=107.6 ns (2.58 ticks)
(b) ct_sm4_cbc_finalize closure: most common readings: 125ns×9700 83ns×6556 84ns×3291 208ns×115 167ns×99 250ns×86 166ns×54 209ns×46
(extra) empty closure: n=20000 min=0 ns (0.00 ticks) median=0 ns (0.00 ticks) mean=16.7 ns (0.40 ticks)
(extra) empty closure: most common readings: 0ns×12004 42ns×5333 41ns×2657 125ns×4 84ns×2
```

Median `ct_sm4_cbc_finalize` reading 125 ns = **3 ticks** (nearest integer,
§3a) → the *sub-tick regime* annotation does **not** apply to this run.
**That decision sits on a knife-edge**: 9 847 of 20 000 readings are the
2-tick value (83 ns × 6 556 + 84 ns × 3 291) and 9 700 are the 3-tick value
(125 ns); the median lands on 125 ns only because the remaining ~450
readings lie above it. The v3 pre-check on the byte-identical program and
build, earlier the same day, read a median of 84 ns = 2 ticks and *would*
have carried the annotation. The label does not depend on the annotation;
a reader should nonetheless treat this window as two-to-three ticks, not
three. The `finalize()` body itself costs about 0.9 tick over the wrapper
(means 107.6 vs 71.9 ns). The program's banner says "protocol v3" because it
predates §3a and was deliberately left byte-identical (same SHA-256 in both
runs).

## 4. The fifteen runs (v4)

2026-09-23T15:25:06Z – 15:26:09Z, 63 s total; each run exit 0; each
`DUDECT_SAMPLES=20000`; order constant-time → early-return → amplified in
every round; no re-run, no exclusion. `|tau|` = `|max t| / √20000` (§3a).
Printed `n` and `max tau` are recorded verbatim and not judged.

| round | build | `ct_sm4_cbc_finalize` printed n / max t / max tau → `\|tau\|` | `f21_wrapper_only` → `\|tau\|` | `negative_control` → `\|tau\|` |
|---|---|---|---|---|
| 1 | ct | 0.006M / −1.12335 / −0.01412 → **0.00794** | 0.020M / −0.56721 / −0.00405 → 0.00401 | 0.016M / +4719.56879 / +37.22896 → 33.372 |
| 1 | er | 0.020M / −88.19270 / −0.63053 → **0.62362** | 0.020M / +1.43423 / +0.01014 → 0.01014 | 0.016M / +4719.49463 / +37.16829 → 33.372 |
| 1 | amp | 0.017M / −6246.87446 / −48.09416 → **44.172** | 0.002M / +1.00000 / +0.02093 → 0.00707 | 0.016M / +4607.90756 / +36.43212 → 32.583 |
| 2 | ct | 0.020M / −2.17333 / −0.01554 → **0.01537** | 0.007M / −1.21959 / −0.01461 → 0.00862 | 0.016M / +4690.02256 / +37.01547 → 33.163 |
| 2 | er | 0.020M / −87.66685 / −0.62712 → **0.61990** | 0.020M / −1.95312 / −0.01381 → 0.01381 | 0.014M / +4244.75814 / +35.27026 → 30.015 |
| 2 | amp | 0.017M / −4399.55507 / −33.75894 → **31.110** | 0.007M / +2.31251 / +0.02763 → 0.01635 | 0.016M / +4593.24348 / +36.69315 → 32.479 |
| 3 | ct | 0.020M / −2.25573 / −0.01607 → **0.01595** | 0.002M / +1.34436 / +0.02840 → 0.00951 | 0.016M / +4614.22601 / +36.58169 → 32.628 |
| 3 | er | 0.020M / −89.12499 / −0.63736 → **0.63021** | 0.007M / −2.11606 / −0.02549 → 0.01496 | 0.016M / +4625.52410 / +36.73829 → 32.707 |
| 3 | amp | 0.011M / −4979.16878 / −48.24151 → **35.208** | 0.015M / +1.21436 / +0.00981 → 0.00859 | 0.016M / +4691.80005 / +37.37922 → 33.176 |
| 4 | ct | 0.000M / −2.82843 / −0.94281 → **0.02000** | 0.020M / −1.98391 / −0.01403 → 0.01403 | 0.016M / +4610.78839 / +36.59586 → 32.603 |
| 4 | er | 0.020M / −87.65338 / −0.62765 → **0.61980** | 0.002M / −1.60987 / −0.03363 → 0.01138 | 0.016M / +4624.82996 / +36.76177 → 32.702 |
| 4 | amp | 0.017M / −6885.75178 / −53.11524 → **48.690** | 0.020M / +1.17530 / +0.00836 → 0.00831 | 0.015M / +4511.82132 / +36.27377 → 31.903 |
| 5 | ct | 0.020M / +0.96823 / +0.00685 → **0.00685** | 0.002M / +1.41482 / +0.02943 → 0.01000 | 0.016M / +4592.64655 / +36.35011 → 32.475 |
| 5 | er | 0.020M / −86.19646 / −0.61622 → **0.60950** | 0.002M / +2.00271 / +0.04226 → 0.01416 | 0.016M / +4759.71088 / +37.40506 → 33.656 |
| 5 | amp | 0.017M / −6284.26475 / −48.49137 → **44.436** | 0.020M / +0.41019 / +0.00290 → 0.00290 | 0.016M / +4730.04123 / +37.10435 → 33.446 |

Round 4 constant-time shows the harness artifact §3a describes: printed
`max tau` −0.94281 at printed `n` ≈ 0 (`|t|` 2.83 over eight cropped
samples), which v4 normalises to 0.02000. The phenomenon recurred; the
normalisation handled it as intended.

The table transcribes every `bench … max tau` line of the fifteen run logs
(values verbatim; the reviewer re-derived each `|tau|` from the logs, §7).
The logs additionally carry the harness's `seeded with 0x…` line per target
and cargo's `Running <path>` line, which names a local directory; those lines
are deliberately not reproduced here (§5 of the spec), and the archive in
§10 is where they live. Per-run wall-clock was 4–5 s, below the ≈ 8 s that
protocol v2's trial had measured.

## 5. Derived values and mechanical judgment (v4)

From `ct_sm4_cbc_finalize`, mechanically:

- constant-time `|tau|` per round: 0.00794, 0.01537, 0.01595, 0.02000,
  0.00685 → **max 0.02000, median 0.01537**
- early-return `|tau|` per round: 0.62362, 0.61990, 0.63021, 0.61980,
  0.60950 → **median 0.61990**
- amplified `|tau|` per round: 44.172, 31.110, 35.208, 48.690, 44.436
- `negative_control` `|tau|` minimum over the 15 runs: 30.015
- constant-time `f21_wrapper_only` `|tau|` per round: 0.00401, 0.00862,
  0.00951, 0.01403, 0.01000

Criteria in order (§3):

1. **Validity:** amplified > 1.0 in every round — yes; `negative_control`
   > 1.0 in every run — yes. Valid.
2. **Distinguishable:** every early-return round > constant-time maximum
   (0.02000) — yes; early-return median 0.61990 ≥ 3 × constant-time median
   (0.04610) — yes. → **`distinguishable-on-this-host`**.

Annotations: *noise-dominated* — no round of constant-time
`f21_wrapper_only` exceeds 0.20; *sub-tick regime* — pre-check median 3
ticks, not ≤ 2. **None.**

## 6. The v3 run (record only; not judged under v4)

Same exports, identities, host and toolchain; pre-check 14:56:57Z –
14:57:01Z; fifteen runs 14:57:23Z – 14:58:27Z (64 s), every exit 0, no
recompile, AC power throughout. Pre-check median `ct_sm4_cbc_finalize` = 84 ns
= 2 ticks (mean 108.0 ns; wrapper mean 72.3 ns).

Printed `max tau` for `ct_sm4_cbc_finalize` (the observable v3 judged on):

| build | rounds 1–5 |
|---|---|
| constant-time | +0.01553 (n 0.010M), +0.01702 (0.007M), +0.00516 (0.020M), +0.01837 (0.020M), **−0.81650 (n 0.000M: `max t` −2.00000 over six cropped samples)** |
| early-return | −0.61024, −0.63585, −0.63893, −0.65728, −0.66011 (all n 0.020M; `max t` −85.3 … −92.1) |
| amplified | −60.03128, −49.20302, −75.31681, −50.20273, −73.30311 |

`negative_control` printed `max tau` ≥ 36.09 in every run; constant-time
`f21_wrapper_only` ≤ 0.02023 in every round.

Mechanical v3 label: validity held; "every early-return round exceeds the
constant-time maximum" failed against 0.81650 → **`still-blind`**, with the
*sub-tick regime* annotation (median 2 ticks). The 0.81650 is
`dudect-bencher`'s largest-|t| test taken over a percentile crop that kept
six samples — a property of dividing by the cropped subset's size under
quantized readings, not of the strip (§3a). The maintainer pinned v4 on the
same day with that data in view; the v4 numbers in §4 come from a fresh
execution, and this record exists so that fact is not hidden.

## 7. Independent review (Q14.5)

One independent reviewer (a separate agent session with read-only access,
no re-runs), working from the archived outputs, the research-clone sources
and the harness source, checked the eight points Q14.5 names and
**recomputed every `|tau|` from the raw run logs, not from the judgment
script**. Its values equal §4 and §5 to five decimals; its label and
annotations are `distinguishable-on-this-host`, none — agreeing with the
script. It confirmed: the class split and inputs (`f21_finalize.rs`
108–141, 193–197; both classes return `None` through `mode_cbc.rs`
153–185); the window contents and `run_one`'s single call with the return
dropped before the second clock read (`ctbench.rs` 341–358); the patches'
scope (single-file, loop-body only; numstat `6 0` and `12 2`) and every
SHA-256 in §1, including re-deriving the two patched `mode_cbc.rs` values
by applying the patches to scratch copies; fifteen runs in the fixed order,
`DUDECT_SAMPLES=20000` each, exit 0 each, no `Compiling`, 63 s of a
1 800 s budget; the pre-check before round 1 with §3a's rounding.

Review items: **3 raised, 3 fixed, 0 declined, open disagreement: none.**

1. Verbatim console lines carry a local path with a user name — fixed: the
   result document transcribes the `bench` lines only and says so (§4); no
   such line appears in this file.
2. Three preconditions not evidenced in the v4 log (the `run_one` re-check,
   the host triple, the process listing) — fixed by stating them as such in
   §2 rather than claiming the log shows them.
3. The *sub-tick regime* annotation was decided at the boundary — fixed by
   disclosing the reading distribution and the v3 pre-check's 2-tick median
   in §3.

For the record, also noted by the reviewer and accepted without change:
per-run wall-clock 4–5 s versus the spec's ≈ 8 s; the spec cites
`ctbench.rs` 341–347 for a function spanning 341–358 (the cited range covers
both clock reads); the judgment script hard-codes 20 000 rather than reading
each run's header (all fifteen headers say 20 000); the exports and binaries
date from the v3 setup and were re-hashed before the v4 run, as §3a permits.

## 8. What this does and does not establish

- On this host, OS, toolchain, harness, baseline and inputs, the
  `finalize()` window separates the early-return control from the shipping
  implementation in five of five rounds by a factor of about 30 in `|tau|`,
  with the amplified control and the liveness control firing every time.
- It says nothing about other hardware, hosted runners, other compilers,
  other input shapes, or the constant-time safety of `strip_pkcs7_block`.
  The wrapper, the decryptor's zeroize-on-drop and the return's drop are all
  inside the window; the window is two to three timer ticks.
- The harness's printed `max tau` is unreliable in this regime (§3a); any
  future use of this window must normalise by the declared budget or use a
  finer clock.
- No CI gate is added, enabled or promoted. The T1 bench and the leaky
  patches remain research-only, identified by SHA-256 above.

## 9. Applied per Q14.6 (b)

`CLAUDE.md`: the current-cycle block and the Open-backlog F21 line;
`.claude/rules/dudect.md`: the F21 line. Nothing else.

## 10. Evidence archive

The complete console output of every run, the pre-check output, the
preconditions log, the setup log (exports, identity checks, patch
application, pre-compilation), the scripts and the two research programs are
archived locally as private research material, not in this repository. Their
SHA-256 values:

v4 run:

```text
115e3f6419342d941bfb621b8abf69b03b5c045ee656b1ba4e850eebdd719740  00-preconditions.log
e46b42f7c62873673c3fa068ec1a1d4170de58840d32fa601ff98b929c18fac1  01-precheck.log
04baebc22bc4733eed8e84ac8a434b5430b8aa6e55826601310f7669e35572f9  02-rounds.log
e6ed19afe37b4b0c674c5ad79da37564b11031699d03c6073302f1365b3cf1e6  03-judgment.log
3ded93f68ebd311c18eff53f59723905bafc8b361454dba71190ef5be87625a0  r1-ct.log
261d932fbbb856bdc1170d91aa18e74e1b3634545a24529b134c10d27af8b259  r1-er.log
81c9988bc647ae392dafaf0e47614a46bb5c6362238e346a37b7dea62fd2f13f  r1-amp.log
8e57cbb346b92ff3c9f18e02f90cc25b7fa35f0269eb437f5a97239a12e59cd5  r2-ct.log
c06bd52566a6b1272aa8647dc854b01c59dd03d7891b1acc7216f94af0bc462b  r2-er.log
c6ccf14189eb6b0b4ba71880bdea16cbc8ca24de576d7b41449d6f6b36edf462  r2-amp.log
acd8bcd50d94648512dced7d692b8a5092ba27989711f63e28151e189a172e6d  r3-ct.log
34f36704f3c23fb3add377afd1a317b185761dd9428e3f886851acc35993533c  r3-er.log
ece62be05a8648364f14cf7014996ee940c307e802ce2908827332cde7649f8b  r3-amp.log
bda4052d428786cb01c395a71593e78b47dd25df03be26d8281336ffb378dfe3  r4-ct.log
e4ebb379ed95b88107c5d2eaa62e84f35689d2ac9a6c98e5f96e08b6cc081e10  r4-er.log
0562a74cd10dca37ea28072dde6ba3fcd8f9ddbf63364084623ae06c63c649d9  r4-amp.log
f22c5f9fcbda89f78c570c66ab273351590b854bd5118e1b72099ec354699232  r5-ct.log
d5f8b019ba25547643dd74d651603eab66a7855defb9c06523b5d16ecf618886  r5-er.log
105673dd8ba414f17cc51f6ca96bf41b440da65bd514bcf7623d9c521674bf83  r5-amp.log
e0296fb30f0765048b767367c5e3fcbfc2f8d64598b867b63125f8d2cb36384a  run-v4.sh
4daf943053af73d9df60fb21c80b75ecd167a33064b6501fa2705e193089334f  precheck.rs
87db88bf5ca112e35c4195c568a0a7639e9f9aff8efcce37aa72d12bcae62ffa  judge.py
```

v3 run (record only):

```text
177355b6afdd8730ef666ccfee22ea44e758f890257408626249962ad799b2b1  00-setup.log
9003283cb77543ec7039e18dfb0d21593d52690b3a27b9943c8846eb58ebdbf4  01-precheck.log
97966a8c86006c79ca448bba6e1ee5c357c31d48808aebc937bae90d2b982736  02-rounds.log
```

The key, IV and plaintexts are fixed public research samples; nothing here is
a secret-bearing product path.
