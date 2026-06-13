# TLCP decomposition — mapping GB/T 38636-2020 onto gmcrypto cycles

Status: v1.5 deliverable (non-publishing design cycle, 2026-06-12).
Maintainer-locked direction per `docs/v1.5-scope.md` Q5.1. This document
answers two questions the v1.3/v1.4 cycles deliberately deferred:

1. **How much of TLCP is crypto we should ship, and how much is protocol
   machinery we shouldn't?**
2. **What X.509 chain-validation profile does TLCP actually need?** —
   derived from the protocol's requirements, not from RFC 5280 (the
   Codex-flagged trap: "path validation is where small auditable cycles
   go to die").

## 0. Sourcing

GB/T 38636-2020 (TLCP) is a Chinese national standard without a freely
redistributable English text. Wire-level facts below are sourced from the
**gotlcp** reference implementation (Trisia/gotlcp, Go, explicitly
section-annotated against GB/T 38636-2020), cross-checked against
RFC 8998 (curveSM2 = 41, suite naming), the openEuler TLCP stack
documentation, and GmSSL 3.1.1's TLCP implementation. Facts that MUST be
re-verified against the standard text (or empirically against two
independent oracles) before implementation are tagged **[D-n]** and
collected in §8 — the v0.8 CCM-sourcing posture, applied per cycle.

## 1. Protocol anatomy

TLCP is structurally TLS 1.1 with SM algorithms, a double-certificate
peer model, and an SM2-specific key-exchange layer. Record version on
the wire is **0x0101**.

### 1.1 Cipher suites (GB/T 38636 §6.4.5.2.1 Table 2)

| Suite | ID | KX | Cipher | MAC/AEAD |
|---|---|---|---|---|
| `ECDHE_SM4_CBC_SM3` | `0xE011` | SM2-KX (no confirmation) | SM4-CBC | HMAC-SM3 |
| `ECC_SM4_CBC_SM3` | `0xE013` | SM2-encrypt key transport | SM4-CBC | HMAC-SM3 |
| `ECDHE_SM4_GCM_SM3` | `0xE051` | SM2-KX (no confirmation) | SM4-GCM | (AEAD) |
| `ECC_SM4_GCM_SM3` | `0xE053` | SM2-encrypt key transport | SM4-GCM | (AEAD) |
| `IBSDH_*` / `IBC_*` / `RSA_*` | `0xE015–0xE05A` | IBC / RSA | — | — |

The IBC and RSA families are **out of scope for the whole arc** (no IBC
primitives in this SDK and no plan for them; RSA-SM4 suites are not part
of the SM2 story). The arc targets the four SM2-family suites. CBC key/
MAC/IV lengths: 16/32/16; GCM: key 16, implicit-IV (salt) 4, tag 16.

### 1.2 The double-certificate model

A TLCP server presents **two certificates in one Certificate message, in
fixed order [signature, encryption]**:

- the **signature certificate** authenticates the server: its key signs
  ServerKeyExchange (and CertificateVerify on the client side);
- the **encryption certificate**'s key receives the key-exchange input:
  the SM2-encrypted pre-master secret (ECC suites) or the static half of
  the SM2 key agreement (ECDHE suites).

This is the v1.3 `x509` core's natural consumer: both certs are leaf
certificates parsed by `Certificate::from_der`, and the encryption cert's
key surfaces through the existing `subject_public_key` path into
`sm2::encrypt` / the KX constructors. The split is enforced by
**keyUsage**: digitalSignature(+nonRepudiation) on the signature cert vs
keyEncipherment/dataEncipherment/keyAgreement on the encryption cert
**[D-1: exact required bit set per GM/T 0015 + 38636]** — the first
place this SDK would ever *interpret* an extension (§4).

### 1.3 Handshake flow

TLS-1.x message sequence: ClientHello → ServerHello → Certificate(×2) →
ServerKeyExchange → [CertificateRequest] → ServerHelloDone →
[Certificate, client] → ClientKeyExchange → [CertificateVerify] →
ChangeCipherSpec → Finished (both directions). Session resumption by
session ID exists; ALPN rides the standard extension; compression is
null-only.

**ECC suites (key transport, §6.4.5.4):**
- ServerKeyExchange = SM2 signature (by the *signature* cert's key,
  DER `SEQUENCE{r,s}`) over `client_random(32) ‖ server_random(32) ‖
  encryption_certificate_DER`.
- ClientKeyExchange = 2-byte-length-prefixed GM/T 0009 SM2 ciphertext of
  the 48-byte pre-master secret (`version(2) ‖ random(46)`), encrypted
  to the **encryption** cert's public key.

**ECDHE suites (SM2 key agreement):**
- The GB/T 32918.3 SM2 key exchange **without the optional key
  confirmation tags** — S_A/S_B never cross the wire; the Finished
  exchange provides confirmation. Pre-master = the KX KDF output
  (48 bytes).
- ServerKeyExchange = ECParameters + server ephemeral point + SM2
  signature over `client_random ‖ server_random ‖ ECParameters ‖
  ephemeral_point`.
- The client certificate is **required** for ECDHE (§6.4.5.8) — the
  client's static encryption key participates in the agreement.
- **[D-2]**: which IDs feed the Z-values (default `1234567812345678` vs
  certificate-derived identities) — gotlcp threads caller-supplied IDs;
  must be pinned against the standard + an oracle transcript before the
  v1.6 KX API freezes.

### 1.4 Key schedule (§6.5)

TLS 1.2-style PRF (`P_hash`) instantiated with **HMAC-SM3**:

- `master_secret(48) = PRF(pre_master, "master secret",
  client_random ‖ server_random)`
- `key_block = PRF(master_secret, "key expansion",
  server_random ‖ client_random)`, carved in order: client MAC key,
  server MAC key, client key, server key, client IV, server IV.
- Finished `verify_data(12) = PRF(master_secret,
  "client finished" | "server finished", SM3(transcript))`.

### 1.5 Record protection

5-byte header (type, version 0x0101, length); max plaintext 2^14.

- **CBC suites**: TLS-1.1-style **explicit per-record random IV**,
  **MAC-then-encrypt**. MAC = HMAC-SM3 over
  `seq_num(8) ‖ type(1) ‖ version(2) ‖ length(2) ‖ plaintext`. Padding
  is **TLS padding** (every padding byte equals the padding-length byte)
  — NOT PKCS#7, so the existing `mode_cbc` does not directly apply.
  Decrypt-side padding+MAC checking is Lucky13 territory: the check must
  be constant-time over padding validity AND MAC compare, with a single
  failure mode (§6 CT posture).
- **GCM suites**: nonce = 4-byte implicit salt (from the key block) ‖
  8-byte explicit per-record nonce; AAD = `seq_num ‖ type ‖ version ‖
  length`; 16-byte tag. This composes the existing `mode_gcm` machinery
  (J0/GCTR/GHASH) with a TLS-shaped nonce/AAD layer.

## 2. Gap analysis — TLCP requirement vs existing asset

| # | TLCP requirement | Existing asset | Gap |
|---|---|---|---|
| — | SM2 sign/verify (handshake sigs, DER r‖s) | `sign_with_id`/`verify_with_id` + `asn1::encode_sig` | exact signed-byte definitions + ID rules per message **[D-7]** |
| — | SM2 key transport (ECC suites) | `sm2::encrypt`/`decrypt` (GM/T 0009 DER) | wire encoding **[D-3]**; PMS decrypt/version-check failure handling must not create a decrypt oracle — the TLS random-PMS-substitution countermeasure is consumer guidance this SDK must document **[D-10]** |
| — | SM3 transcript hash (streaming) | `Sm3` streaming | none |
| — | HMAC-SM3 (record MAC, PRF inner) | `hmac_sm3` + streaming `HmacSm3` | none |
| — | X.509 leaf parse + sig verify + subject-key extraction | v1.3 `x509` | none |
| G1 | TLS-1.2 PRF over SM3 + master-secret/key-block/Finished derivation | `hmac_sm3` | small pure-core composition, new KAT surface |
| G2 | Record protection: SM4-CBC + TLS padding + MAC-then-encrypt (CT!); SM4-GCM with TLS nonce/AAD shape; sequence/nonce lifecycle (GCM nonce uniqueness, seq wrap, CBC IV generation) **[D-12]** | `Sm4Cipher`, `mode_gcm` internals | new record-layer module; the CBC decrypt path is the arc's headline CT engineering item |
| G3 | SM2-KX **without** confirmation tags | v1.1 typestate API (requires S_A/S_B) | additive no-confirmation path on `sm2/key_exchange.rs`; wire math identical |
| G4 | Verify a [sign, enc] cert pair against caller-supplied trust anchors (server-side in mutual-auth/ECDHE, the same primitive verifies the *client's* pair) | v1.3 single-cert `verify_signature` | chain walk + the §4 keyUsage/pair profile — the deferred chain-validation question, now requirement-scoped |
| G5 | Handshake/state machine, alerts, session cache, I/O | — | deliberately NOT crypto; §5 end-state decision |

The summary the arc rests on: **~90% of TLCP's cryptography already
ships**; the gaps are two thin composition layers (G1, G3), one genuinely
new CT-sensitive module (G2), and one carefully-scoped X.509 extension
(G4).

## 3. What this SDK ships vs what it doesn't

Crypto we ship (per-cycle, KAT-able, CT-disciplined, no_std-compatible):
key schedule, record protection primitives, handshake key-exchange
crypto, certificate-pair verification. Protocol machinery we don't
(at least not in `gmcrypto-core`): handshake state machines, alert
logic, session caches, retransmission/fragmentation, sockets. That
machinery is where protocol CVEs live (state confusion, downgrade,
renegotiation) and it is not testable by KAT — it would change the
character of the SDK's assurance story.

## 4. The chain-validation profile TLCP actually needs (G4)

The handshake requires exactly this of a client: establish that the
server's signature cert and encryption cert are issued (directly or via
intermediates) by a CA the *caller* trusts, and that each cert is usable
for its role. Derived profile — deliberately named **certificate-pair /
chain *signature* verification, NOT "validation" and NOT server
authentication**. Said loudly, because this is the profile's biggest
attacker-facing hole if misread: **endpoint identity binding (the TLCP
equivalent of hostname verification — "is this cert pair *the server I
dialed*?") is the caller's job, permanently.** A consumer that treats
"chain verifies + keyUsage correct" as "server authenticated" will
accept *any* trusted-CA-issued cert pair, from anyone (the Codex W2
headline finding). The profile verifies issuance and role, nothing
about *whose* certs they are — except one structural check the pair
model makes cheap: the sign and enc certs' subject Names must be
byte-identical (pair binding **[D-8]**), so a caller's single identity
decision covers both.

1. **Chain walk**: leaf → … → caller-supplied trust anchor(s);
   issuer↔subject linking by byte-equality of the raw Name TLVs (the
   existing `is_self_issued` byte-match discipline — no Name parsing);
   `verify_signature` at each edge (existing v1.3 primitive); explicit
   depth cap.
2. **keyUsage split**: signature cert must carry digitalSignature;
   encryption cert must carry the encipherment/agreement bits **[D-1]**;
   CA certs must carry keyCertSign + basicConstraints CA=TRUE. This is
   the SDK's first extension *interpretation* — confined to exactly two
   extensions (keyUsage, basicConstraints), both simple BIT STRING /
   SEQUENCE reads on the existing strict DER reader.
3. **Time**: caller passes a comparison time (or opts out); the SDK
   never reads a clock — the v1.3 `X509Time`-exposed-no-decision posture
   extended, not breached.
4. **NOT included, permanently out for the arc**: endpoint identity
   binding (above — the caller's, always); revocation (CRL/OCSP);
   policy processing; name constraints and EKU (**[D-9]**: under
   *delegated* CA trust these are the next-biggest holes — the v1.8
   cycle must decide required/ignored/rejected per the GM/T cert
   profile, and the doc contract must state the residual risk of
   whatever it picks); path-length handling beyond a simple depth cap
   **[D-4: whether pathLenConstraint must be honored for the TLCP
   profile or the depth cap suffices]**; cross-signing/multiple-path
   discovery (single linear chain only — the caller supplies the chain
   in order, as the TLS Certificate message already does **[D-11: how
   intermediates are ordered in a double-cert Certificate message]**).

Single failure mode throughout (`Option`/`bool` per the workspace
invariant): a C caller or TLS stack must not learn *why* a chain was
rejected.

## 5. End-state options

- **O1 — full TLCP stack (sockets, I/O)**: rejected. Out of identity for
  a no_std crypto SDK; duplicates gotlcp/Tongsuo; drags in async/net.
- **O2 — sans-I/O TLCP protocol engine** (rustls-style: bytes-in/
  bytes-out connection state machine, probably a fourth crate
  `gmcrypto-tlcp`): plausible eventual end-state — it is what would make
  the SDK *usable* for TLCP without a consumer writing a handshake. But
  it is protocol engineering with a different assurance model, and it
  should not be committed to before the toolkit exists.
- **O3 — TLCP crypto toolkit in `gmcrypto-core`** (recommended): close
  G1–G4 as normal opt-in-feature cycles. Every piece is independently
  KAT-able, dudect-able where secrets flow, fuzzable, and useful to any
  consumer building TLCP (including a future O2). **Recommendation:
  commit to O3 now; revisit O2 as a separate maintainer decision after
  the toolkit ships** — with real information about whether demand
  exists. Not committing to O2 does NOT mean ignoring it: every toolkit
  API is designed **as if a sans-I/O engine may own it later** —
  explicit roles, transcript bytes in/out, caller-held sequence numbers
  and times, injected RNG, no hidden policy, no global state (the Codex
  W2 discipline). An API an engine could not drive is a design defect
  at review time even though no engine exists. Equally arc-wide: the
  workspace **failure-mode invariant** governs every toolkit surface —
  `Option`/`bool`/single-`Failed`, never an error that distinguishes
  *why* (§4's chain rule and §6's record rule are instances, not
  exceptions).

## 6. Assurance strategy for the arc

- **Oracles**: GmSSL 3.1.1 ships `tlcp_client`/`tlcp_server` locally
  (negotiates `ECC_SM4_CBC_SM3`, the mandatory suite; **[D-5]** whether
  3.1.1 negotiates the GCM suites). gotlcp (Go) and Tongsuo (C) are
  independent second oracles — gotlcp also generates deterministic
  per-primitive vectors (PRF, key block, Finished) cheaply. Wireshark
  ≥4.x can decrypt `ECC_SM4_CBC_SM3` given keys — transcript harvesting
  for record-layer KATs.
- **KAT pattern**: per-primitive vectors first (PRF/key-block/Finished
  from a gotlcp harness — the v0.8 OpenSSL-oracle pattern); full
  handshake-transcript replay tests once enough pieces exist. If v1.6
  claims the key schedule covers session resumption, the KAT set must
  include abbreviated-handshake Finished vectors — no claimed-but-
  unvectored surface (Codex W2).
- **CT posture**: the CBC record decrypt (G2) is the arc's headline
  dudect surface — Lucky13-class. The **API shape is constrained NOW**,
  before v1.7 designs it (Codex W2): ONE `deprotect`-style operation —
  no public decrypt-then-check composition for callers to mis-assemble;
  no early return on padding failure; the MAC path ALWAYS runs, with
  HMAC compression-function count **equalized across padding-length
  interpretations** (dummy work as needed — the canonical Lucky13
  countermeasure; a MUST-constraint of the API, not measurement
  guidance); single failure mode; no plaintext escapes on failure.
  Measurement: a dudect target class-split by padding shape is
  necessary but NOT sufficient — Lucky13's signal is exactly the
  MAC-work variation the equalization constraint exists to remove;
  dudect guards the residual. The PRF/key-schedule (G1) operates on
  secrets but with public lengths/structure — dudect target decision per
  cycle. G4 is public-inputs-only (the v1.3 no-dudect rationale extends).
- **Fuzzing**: each new decode/decrypt surface gets a fuzz target
  (record deprotection is the big one: attacker-controlled records);
  the census discipline (#102 must-match-`[[bin]]`) continues.

## 7. Cycle map (proposal)

Sized against shipped precedent; each cycle = its own scope doc +
Q-list + review + KATs. Cadence: core-in-vN / FFI-in-vN+1 has been
per-feature; for this arc the FFI question is **deferred to the end of
the core sequence** (one FFI cycle for the whole toolkit is likely
better than three small ones — but that is a maintainer call at v1.9
time, not now). The corollary (Codex W2): each core cycle's scope doc
records the **FFI-shape constraints** its API implies (handle vs plain
struct, copy-out vs in-place, consume-on-use) so v1.9 inherits decisions
instead of discovering conflicts — but no C ABI is frozen before v1.9.

- **v1.6 — TLCP key schedule (G1 + G3)**: the P_SM3 PRF (master
  secret, key block, Finished verify_data) + the no-confirmation SM2-KX
  path. Pure-core, no new dep, opt-in feature (feature/module naming
  **[D-6]**: `tlcp` umbrella vs per-piece — the cycle's scope doc
  decides placement). KATs from a gotlcp vector harness. Size ≈ v1.1.
- **v1.7 — TLCP record protection (G2)**: TLS-CBC (explicit IV,
  MAC-then-encrypt, TLS padding, CT deprotect) + GCM record shape
  (salt‖explicit nonce, TLS AAD). New dudect target(s) for CBC
  deprotect; fuzz target for record deprotection. The arc's riskiest
  cycle — Lucky13 discipline. Size ≈ v0.8.
- **v1.8 — certificate-pair / chain verification (G4)**: the §4
  profile (placement within or alongside the `x509` feature = the
  cycle's scope doc). The first extension interpretation — keyUsage +
  basicConstraints only. Size ≈ v1.3.
- **v1.9 — TLCP FFI** (cadence cycle): the accumulated toolkit surface
  through `gmcrypto-c`, shape decided then.
- **v2.x — O2 sans-I/O engine**: separate decision, separate crate, only
  if recommitted after the toolkit ships.

Ordering rationale: v1.6 is the smallest and unblocks per-primitive
KATs for everything later; v1.7 before v1.8 because record protection
is self-contained and KAT-able against transcripts immediately, while
chain verification benefits from the longest design soak (it is the
acknowledged trap); no cycle depends on a later one.

## 8. Verification items (resolve at the owning cycle's design time)

- **[D-1]** Exact required keyUsage bit sets for sign/enc/CA certs per
  GB/T 38636 + GM/T 0015 (owning cycle: v1.8).
- **[D-2]** ECDHE Z-value identities: default ID vs cert-derived
  (v1.6; pin via oracle transcript before freezing the KX API).
- **[D-3]** ClientKeyExchange SM2 ciphertext wire encoding = GM/T 0009
  DER, plus the 2-byte length prefix (v1.6 or v1.7 KAT work).
- **[D-4]** pathLenConstraint: honored or depth-cap-only (v1.8).
- **[D-5]** GmSSL 3.1.1 GCM-suite negotiability; if absent, gotlcp/
  Tongsuo carry GCM interop (v1.7).
- **[D-6]** Feature naming: one `tlcp` umbrella feature vs per-piece
  (v1.6 scope Q-list).
- **[D-7]** Exact signed-byte definitions + SM2 ID rules for
  ServerKeyExchange and CertificateVerify (v1.6; pin via oracle
  transcript).
- **[D-8]** Endpoint identity + sign/enc cert pair binding rules — what
  the standard requires vs what stays the caller's (v1.8).
- **[D-9]** EKU / GM/T certificate-profile OIDs: required, ignored, or
  rejected — and the documented residual risk of the choice (v1.8).
- **[D-10]** ECC key-transport PMS decrypt/version-check failure
  behavior — the anti-oracle (random-PMS substitution) guidance and
  where it lives (v1.6 docs or the eventual consumer guidance).
- **[D-11]** Certificate message ordering when intermediates accompany
  the double-cert pair (v1.8).
- **[D-12]** GCM per-record nonce/sequence limits (wrap behavior) and
  CBC explicit-IV generation requirements (v1.7).

## 9. Out of scope for the entire arc

IBC/RSA suite families; revocation; certificate/CSR generation; session
resumption *logic* (the crypto is just the same key schedule); ALPN/
extension negotiation; any I/O; TLS 1.2/1.3 (RFC 8998 suites are a
different protocol — a possible separate arc, not this one).
