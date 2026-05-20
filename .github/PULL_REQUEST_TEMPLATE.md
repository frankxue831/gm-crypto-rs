<!--
Thanks for contributing! This is a single-maintainer personal project;
review is best-effort. Security vulnerability? Do NOT open a PR — report
privately via SECURITY.md.
-->

## Summary

<!-- What this changes and why. -->

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check --exclude-dev`
- [ ] Public items have rustdoc; new crypto primitives cite a spec + KAT source
- [ ] No `unsafe` added to `gmcrypto-core` (`forbid`); any `unsafe` in
      `gmcrypto-c` / `gmcrypto-simd` carries a `// SAFETY:` comment
- [ ] Failure modes stay collapsed (no "more helpful" error variants — see SECURITY.md)

## Constant-time impact

<!--
Did you touch sm2/, sm4/, hmac.rs, kdf.rs, pkcs8.rs, or benches/? If so,
run the dudect harness and paste the |tau| for the relevant targets:

  DUDECT_SAMPLES=10000 cargo bench --bench timing_leaks --features crypto-bigint-scalar

negative_control must report |tau| > 1.0; the relevant ct_* targets must
report |tau| < 0.20. See CONTRIBUTING.md for the per-area target list.
Write "N/A — no secret-dependent code touched" if not applicable.
-->
