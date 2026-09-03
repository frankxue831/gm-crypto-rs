---
paths:
  - "crates/gmcrypto-core/src/tlcp/**"
  - "crates/gmcrypto-core/src/x509.rs"
  - "crates/gmcrypto-core/tests/tlcp_*.rs"
  - "crates/gmcrypto-core/tests/x509_*.rs"
---

# TLCP and X.509 (opt-in `tlcp`, `x509`)

- TLCP `deprotect_*`: the plaintext length is computed internally — **never**
  a deprotect parameter (the post-strip length is secret).
- `verify_chain` / `verify_pair` are structural trust, **not** endpoint
  authentication. Don't describe them as such.
- Randomness for records and key exchange comes through the existing
  `CallbackRng`; don't add a second callback shape.
- These are public-input parsers: no dudect target "because the cycle touched
  crypto" (see `.claude/rules/dudect.md`).
- Intra-doc links from always-compiled docs to these cfg-gated items become
  `-D warnings` failures in the cargo-doc job — use plain code spans.
